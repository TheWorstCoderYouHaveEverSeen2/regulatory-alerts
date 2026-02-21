"""Observability primitives: structured logging, request tracking, metrics.

Provides:
- JSONFormatter: structured JSON log output for production
- configure_logging(): centralized logging config via dictConfig
- RequestLoggingMiddleware: pure ASGI middleware for request/response logging
- SchedulerMetrics: thread-safe scheduler cycle tracking
- ErrorCounter: thread-safe error counting by module
- request_id_var: ContextVar for request correlation
- Uptime tracking: record_app_start() / get_uptime_seconds()
"""

import contextvars
import dataclasses
import json
import logging
import logging.config
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Request ID propagation
# ---------------------------------------------------------------------------

request_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "request_id", default=None
)

# ---------------------------------------------------------------------------
# JSON Formatter
# ---------------------------------------------------------------------------


class JSONFormatter(logging.Formatter):
    """Produce one JSON object per log line for structured log aggregation."""

    def format(self, record: logging.LogRecord) -> str:
        # Resolve %-style args into record.message
        super().format(record)

        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.message,
            "module": record.module,
        }

        # Attach request_id if set (within a request scope)
        req_id = request_id_var.get(None)
        if req_id is not None:
            payload["request_id"] = req_id

        # Attach exception info if present
        if record.exc_info and record.exc_info[0] is not None:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str)


# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------


def configure_logging(log_level: str = "INFO", log_format: str = "json") -> None:
    """Apply centralized logging configuration.

    Args:
        log_level: Root log level (DEBUG, INFO, WARNING, ERROR).
        log_format: "json" for structured JSON output, "text" for human-readable.
    """
    if log_format == "json":
        formatter_config = {
            "()": f"{__name__}.JSONFormatter",
        }
    else:
        formatter_config = {
            "format": "%(asctime)s %(levelname)-8s %(name)s — %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        }

    config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": formatter_config,
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "default",
                "stream": "ext://sys.stdout",
            },
        },
        "loggers": {
            # Suppress noisy third-party loggers
            "apscheduler": {"level": "WARNING"},
            "apscheduler.scheduler": {"level": "WARNING"},
            "apscheduler.executors": {"level": "WARNING"},
            "uvicorn.access": {"level": "WARNING"},
        },
        "root": {
            "level": log_level.upper(),
            "handlers": ["console"],
        },
    }

    logging.config.dictConfig(config)
    logger.debug("Logging configured: level=%s, format=%s", log_level, log_format)


# ---------------------------------------------------------------------------
# Uptime tracking
# ---------------------------------------------------------------------------

_app_started_at: datetime | None = None


def record_app_start() -> None:
    """Record the application start time for uptime tracking."""
    global _app_started_at
    _app_started_at = datetime.now(timezone.utc)


def get_uptime_seconds() -> float:
    """Return seconds since the application started."""
    if _app_started_at is None:
        return 0.0
    return (datetime.now(timezone.utc) - _app_started_at).total_seconds()


def reset_uptime() -> None:
    """Reset uptime tracking (for tests)."""
    global _app_started_at
    _app_started_at = None


# ---------------------------------------------------------------------------
# Scheduler Metrics (thread-safe singleton)
# ---------------------------------------------------------------------------

_MAX_ERROR_LENGTH = 200


@dataclasses.dataclass
class SchedulerMetrics:
    """Thread-safe metrics for scheduler fetch cycles."""

    _lock: threading.Lock = dataclasses.field(default_factory=threading.Lock)
    total_cycles: int = 0
    successful_cycles: int = 0
    partial_cycles: int = 0
    failed_cycles: int = 0
    last_run_at: datetime | None = None
    last_duration_seconds: float | None = None
    last_status: str = "idle"  # idle | running | success | partial | error
    last_error: str | None = None

    def record_start(self) -> None:
        """Mark a new cycle as starting."""
        with self._lock:
            self.last_status = "running"
            self.last_run_at = datetime.now(timezone.utc)

    def record_success(self, duration: float, any_failures: bool = False) -> None:
        """Mark a cycle as completed."""
        with self._lock:
            self.total_cycles += 1
            self.last_duration_seconds = duration
            self.last_error = None
            if any_failures:
                self.partial_cycles += 1
                self.last_status = "partial"
            else:
                self.successful_cycles += 1
                self.last_status = "success"

    def record_failure(self, error: Exception, duration: float) -> None:
        """Mark a cycle as failed. Truncates error to type+message only.

        SECURITY: last_error stores only "{ExcType}: {message}" truncated to
        200 chars. Never full traceback (could expose API keys, file paths,
        DB credentials). MUST NOT be exposed in API responses — use to_dict()
        which intentionally excludes it.
        """
        with self._lock:
            self.total_cycles += 1
            self.failed_cycles += 1
            self.last_duration_seconds = duration
            self.last_status = "error"
            # Security: only store type + message, never full traceback
            err_str = f"{type(error).__name__}: {error}"
            self.last_error = err_str[:_MAX_ERROR_LENGTH]

    def to_dict(self) -> dict[str, Any]:
        """Return metrics as a dict for the health endpoint."""
        with self._lock:
            return {
                "status": self.last_status,
                "total_cycles": self.total_cycles,
                "successful_cycles": self.successful_cycles,
                "partial_cycles": self.partial_cycles,
                "failed_cycles": self.failed_cycles,
                "last_run_at": self.last_run_at.isoformat() if self.last_run_at else None,
                "last_duration_seconds": self.last_duration_seconds,
            }

    def reset(self) -> None:
        """Reset all metrics (for test isolation)."""
        with self._lock:
            self.total_cycles = 0
            self.successful_cycles = 0
            self.partial_cycles = 0
            self.failed_cycles = 0
            self.last_run_at = None
            self.last_duration_seconds = None
            self.last_status = "idle"
            self.last_error = None


scheduler_metrics = SchedulerMetrics()


# ---------------------------------------------------------------------------
# Error Counter (thread-safe singleton)
# ---------------------------------------------------------------------------


class ErrorCounter:
    """Thread-safe error counter with per-module breakdown."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.total: int = 0
        self.by_module: dict[str, int] = {}

    def record(self, module: str) -> None:
        """Record an error from the given module."""
        with self._lock:
            self.total += 1
            self.by_module[module] = self.by_module.get(module, 0) + 1

    def to_dict(self) -> dict[str, Any]:
        """Return counts as a dict for the health endpoint."""
        with self._lock:
            return {
                "total": self.total,
                "by_module": dict(self.by_module),
            }

    def reset(self) -> None:
        """Reset all counts (for test isolation)."""
        with self._lock:
            self.total = 0
            self.by_module.clear()


error_counter = ErrorCounter()


# ---------------------------------------------------------------------------
# Prometheus Metrics (bridge to prometheus_client)
# ---------------------------------------------------------------------------


class PrometheusMetrics:
    """Bridge between internal singletons and prometheus_client exposition.

    Wraps prometheus_client gauges/counters for /metrics scraping. Uses a
    delta-inc pattern for counters: tracks previous singleton values so
    Prometheus counters only increment by the difference on each collect().

    Pass a custom ``registry`` for test isolation (avoids duplicate collector
    errors from the global registry).
    """

    def __init__(self, registry: "Any | None" = None) -> None:
        from prometheus_client import CollectorRegistry, Counter, Gauge

        if registry is None:
            from prometheus_client import REGISTRY
            registry = REGISTRY

        self.registry = registry

        # Gauges (set on every scrape)
        self.uptime = Gauge(
            "regulatory_alerts_uptime_seconds",
            "Seconds since application started",
            registry=registry,
        )
        self.scheduler_cycle_duration = Gauge(
            "regulatory_alerts_scheduler_cycle_duration_seconds",
            "Duration of the last scheduler cycle in seconds",
            registry=registry,
        )
        self.feed_sources = Gauge(
            "regulatory_alerts_feed_sources_total",
            "Number of configured feed sources",
            registry=registry,
        )
        self.documents = Gauge(
            "regulatory_alerts_documents_total",
            "Total feed documents in database",
            registry=registry,
        )
        self.alerts = Gauge(
            "regulatory_alerts_alerts_total",
            "Total processed alerts in database",
            registry=registry,
        )
        self.users = Gauge(
            "regulatory_alerts_users_total",
            "Total users by subscription tier",
            ["tier"],
            registry=registry,
        )
        self.channels = Gauge(
            "regulatory_alerts_notification_channels_total",
            "Total notification channels",
            registry=registry,
        )

        # Counters (monotonic, delta-inc from singletons)
        self.scheduler_cycles = Counter(
            "regulatory_alerts_scheduler_cycles_total",
            "Total scheduler cycles",
            ["status"],
            registry=registry,
        )
        self.errors = Counter(
            "regulatory_alerts_errors_total",
            "Total errors by module",
            ["module"],
            registry=registry,
        )
        self.http_requests = Counter(
            "regulatory_alerts_http_requests_total",
            "Total HTTP requests",
            ["method", "status"],
            registry=registry,
        )

        # Delta-inc tracking: store previous absolute values from singletons
        self._prev_successful: int = 0
        self._prev_partial: int = 0
        self._prev_failed: int = 0
        self._prev_errors: dict[str, int] = {}

    def collect_from_singletons(self) -> None:
        """Snapshot scheduler_metrics + error_counter into Prometheus metrics."""
        # Uptime
        self.uptime.set(get_uptime_seconds())

        # Scheduler cycle duration
        with scheduler_metrics._lock:
            dur = scheduler_metrics.last_duration_seconds
            if dur is not None:
                self.scheduler_cycle_duration.set(dur)

            # Delta-inc for cycle counters
            succ = scheduler_metrics.successful_cycles
            part = scheduler_metrics.partial_cycles
            fail = scheduler_metrics.failed_cycles

        delta_succ = succ - self._prev_successful
        delta_part = part - self._prev_partial
        delta_fail = fail - self._prev_failed
        if delta_succ > 0:
            self.scheduler_cycles.labels(status="success").inc(delta_succ)
        if delta_part > 0:
            self.scheduler_cycles.labels(status="partial").inc(delta_part)
        if delta_fail > 0:
            self.scheduler_cycles.labels(status="error").inc(delta_fail)
        self._prev_successful = succ
        self._prev_partial = part
        self._prev_failed = fail

        # Delta-inc for error counter
        with error_counter._lock:
            current_by_module = dict(error_counter.by_module)

        for module, count in current_by_module.items():
            prev = self._prev_errors.get(module, 0)
            delta = count - prev
            if delta > 0:
                self.errors.labels(module=module).inc(delta)
        self._prev_errors = current_by_module

    def collect_from_db(self, session: "Any") -> None:
        """Snapshot DB counts into Prometheus gauges.

        Wrapped in try/except so a DB failure never crashes /metrics.
        """
        try:
            from sqlalchemy import func, select

            from regulatory_alerts.models import (
                FeedDocument,
                FeedSource,
                NotificationChannel,
                ProcessedAlert,
                User,
            )

            self.feed_sources.set(
                session.scalar(select(func.count(FeedSource.id))) or 0
            )
            self.documents.set(
                session.scalar(select(func.count(FeedDocument.id))) or 0
            )
            self.alerts.set(
                session.scalar(select(func.count(ProcessedAlert.id))) or 0
            )
            self.channels.set(
                session.scalar(select(func.count(NotificationChannel.id))) or 0
            )

            # Users by tier
            tier_rows = session.execute(
                select(User.subscription_tier, func.count(User.id)).group_by(
                    User.subscription_tier
                )
            ).all()
            # Reset all tier labels to 0 first so removed tiers go to 0
            for tier in ("free", "pro", "team", "enterprise"):
                self.users.labels(tier=tier).set(0)
            for tier, count in tier_rows:
                self.users.labels(tier=tier or "free").set(count)
        except Exception:
            logger.debug("Prometheus DB collection failed", exc_info=True)

    def reset(self) -> None:
        """Reset delta-inc state (for tests)."""
        self._prev_successful = 0
        self._prev_partial = 0
        self._prev_failed = 0
        self._prev_errors = {}


prometheus_metrics = PrometheusMetrics()


# ---------------------------------------------------------------------------
# Request Logging Middleware (pure ASGI — NOT BaseHTTPMiddleware)
# ---------------------------------------------------------------------------


class RequestLoggingMiddleware:
    """Pure ASGI middleware for request logging and request-id injection.

    - Generates a unique request_id per request
    - Sets request_id_var ContextVar for log correlation
    - Injects x-request-id response header
    - Logs method, path, status, duration for every HTTP request
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = uuid.uuid4().hex[:12]
        request_id_var.set(request_id)

        status_code = 500  # default if response never starts
        response_started = False

        async def send_wrapper(message: dict) -> None:
            nonlocal status_code, response_started
            if message["type"] == "http.response.start":
                status_code = message["status"]
                response_started = True
                # Inject x-request-id header (explicit dict rebuild)
                headers = list(message.get("headers", []))
                headers.append((b"x-request-id", request_id.encode()))
                message = dict(message)
                message["headers"] = headers
            await send(message)

        method = scope.get("method", "")
        path = scope.get("path", "")
        start = time.perf_counter()

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception:
            error_counter.record("middleware")
            raise
        finally:
            duration_ms = (time.perf_counter() - start) * 1000
            # Only log if we have meaningful request info
            if method:
                logger.info(
                    "%s %s %d %.1fms",
                    method,
                    path,
                    status_code,
                    duration_ms,
                )
                try:
                    prometheus_metrics.http_requests.labels(
                        method=method, status=str(status_code)
                    ).inc()
                except Exception:
                    pass  # Never break requests for metrics
