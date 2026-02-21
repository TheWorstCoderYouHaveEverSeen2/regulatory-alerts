"""Tests for observability: JSON logging, request middleware, health metrics, scheduler metrics."""

import json
import logging
import os
import sys
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Ensure src is on path
_src = str(Path(__file__).resolve().parents[1] / "src")
if _src not in sys.path:
    sys.path.insert(0, _src)

os.environ["DATABASE_URL_SYNC"] = "sqlite:///:memory:"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["ANTHROPIC_API_KEY"] = "test-key-not-real"
os.environ["API_KEYS"] = ""

from regulatory_alerts.models import Base
from regulatory_alerts.observability import (
    ErrorCounter,
    JSONFormatter,
    RequestLoggingMiddleware,
    SchedulerMetrics,
    configure_logging,
    error_counter,
    get_uptime_seconds,
    record_app_start,
    request_id_var,
    reset_uptime,
    scheduler_metrics,
)


def _enable_sqlite_fk(dbapi_conn, connection_record):
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


_test_engine = create_engine(
    "sqlite:///:memory:",
    echo=False,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
event.listen(_test_engine, "connect", _enable_sqlite_fk)
Base.metadata.create_all(_test_engine)
_TestSession = sessionmaker(_test_engine, expire_on_commit=False)


def _mock_sync_engine():
    return _test_engine


def _mock_sync_session_factory():
    return _TestSession


@pytest.fixture(autouse=True)
def _reset_singletons():
    """Reset observability singletons between tests."""
    scheduler_metrics.reset()
    error_counter.reset()
    reset_uptime()
    yield


@pytest.fixture(autouse=True)
def _clean_tables():
    with _TestSession() as session:
        for table in reversed(Base.metadata.sorted_tables):
            session.execute(table.delete())
        session.commit()
    yield


@pytest.fixture()
def client():
    """TestClient with mocked DB and scheduler, CSRF bypassed, configure_logging mocked."""
    from regulatory_alerts.csrf import validate_csrf
    from tests.conftest import noop_csrf

    with patch("regulatory_alerts.api.get_sync_engine", _mock_sync_engine), \
         patch("regulatory_alerts.api.get_sync_session_factory", _mock_sync_session_factory), \
         patch("regulatory_alerts.rate_limit.get_sync_session_factory", _mock_sync_session_factory), \
         patch("regulatory_alerts.dashboard.get_sync_session_factory", _mock_sync_session_factory), \
         patch("regulatory_alerts.auth.get_sync_session_factory", _mock_sync_session_factory), \
         patch("regulatory_alerts.billing.get_sync_session_factory", _mock_sync_session_factory), \
         patch("regulatory_alerts.admin.get_sync_session_factory", _mock_sync_session_factory), \
         patch("regulatory_alerts.core.scheduler.start_scheduler", return_value=MagicMock()), \
         patch("regulatory_alerts.core.scheduler.stop_scheduler"), \
         patch("regulatory_alerts.observability.configure_logging"):
        from regulatory_alerts.api import app
        app.dependency_overrides[validate_csrf] = noop_csrf
        with TestClient(app) as c:
            yield c
        app.dependency_overrides.pop(validate_csrf, None)


# ---------------------------------------------------------------------------
# JSONFormatter
# ---------------------------------------------------------------------------


class TestJSONFormatter:
    def test_json_output_structure(self):
        """Output is valid JSON with all required keys."""
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="hello world",
            args=None,
            exc_info=None,
        )
        output = formatter.format(record)
        data = json.loads(output)

        assert "timestamp" in data
        assert data["level"] == "INFO"
        assert data["logger"] == "test.logger"
        assert data["message"] == "hello world"
        assert "module" in data

    def test_request_id_included(self):
        """request_id_var value appears in JSON output."""
        formatter = JSONFormatter()
        token = request_id_var.set("abc123req")
        try:
            record = logging.LogRecord(
                name="test", level=logging.INFO, pathname="t.py",
                lineno=1, msg="test", args=None, exc_info=None,
            )
            output = formatter.format(record)
            data = json.loads(output)
            assert data["request_id"] == "abc123req"
        finally:
            request_id_var.reset(token)

    def test_request_id_absent_when_unset(self):
        """request_id is omitted when ContextVar has no value."""
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="t.py",
            lineno=1, msg="test", args=None, exc_info=None,
        )
        output = formatter.format(record)
        data = json.loads(output)
        assert "request_id" not in data

    def test_exception_included(self):
        """exc_info is rendered in 'exception' key."""
        formatter = JSONFormatter()
        try:
            raise ValueError("boom")
        except ValueError:
            import sys
            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="test", level=logging.ERROR, pathname="t.py",
            lineno=1, msg="error", args=None, exc_info=exc_info,
        )
        output = formatter.format(record)
        data = json.loads(output)
        assert "exception" in data
        assert "ValueError" in data["exception"]
        assert "boom" in data["exception"]

    def test_percent_args_resolved(self):
        """%-style args are resolved into message."""
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="t.py",
            lineno=1, msg="x=%d y=%s", args=(5, "hello"), exc_info=None,
        )
        output = formatter.format(record)
        data = json.loads(output)
        assert data["message"] == "x=5 y=hello"


# ---------------------------------------------------------------------------
# configure_logging
# ---------------------------------------------------------------------------


class TestConfigureLogging:
    @pytest.fixture(autouse=True)
    def _save_restore_root_logger(self):
        """Save and restore root logger handlers to prevent cross-test contamination."""
        root = logging.getLogger()
        original_handlers = root.handlers[:]
        original_level = root.level
        yield
        root.handlers = original_handlers
        root.level = original_level

    def test_json_format_applied(self):
        """After configure with json, root logger handler uses JSONFormatter."""
        configure_logging("INFO", "json")
        root = logging.getLogger()
        json_handlers = [
            h for h in root.handlers
            if isinstance(h.formatter, JSONFormatter)
        ]
        assert len(json_handlers) >= 1

    def test_text_format_applied(self):
        """After configure with text, root logger uses standard Formatter."""
        configure_logging("INFO", "text")
        root = logging.getLogger()
        non_json = [
            h for h in root.handlers
            if h.formatter is not None and not isinstance(h.formatter, JSONFormatter)
        ]
        assert len(non_json) >= 1


# ---------------------------------------------------------------------------
# RequestLoggingMiddleware
# ---------------------------------------------------------------------------


class TestRequestLoggingMiddleware:
    def test_request_id_header(self, client):
        """Response has x-request-id header."""
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert "x-request-id" in resp.headers
        # 12-char hex
        assert len(resp.headers["x-request-id"]) == 12

    def test_request_logging_output(self, client, caplog):
        """Request log contains method, path, status code."""
        with caplog.at_level(logging.INFO, logger="regulatory_alerts.observability"):
            resp = client.get("/api/health")
        assert resp.status_code == 200
        # Find the request log line
        log_messages = [r.message for r in caplog.records if "GET" in r.message and "/api/health" in r.message]
        assert len(log_messages) >= 1
        assert "200" in log_messages[0]

    def test_non_http_passthrough(self):
        """Non-http scope types are passed through without processing."""
        inner_called = False

        async def inner_app(scope, receive, send):
            nonlocal inner_called
            inner_called = True

        middleware = RequestLoggingMiddleware(inner_app)

        import asyncio

        async def run():
            await middleware({"type": "websocket"}, None, None)

        asyncio.run(run())
        assert inner_called

    def test_error_counted_on_exception(self):
        """Exception in handler increments error_counter."""
        async def failing_app(scope, receive, send):
            raise RuntimeError("handler crash")

        middleware = RequestLoggingMiddleware(failing_app)

        import asyncio

        async def mock_send(message):
            pass

        async def mock_receive():
            return {"type": "http.disconnect"}

        async def run():
            with pytest.raises(RuntimeError, match="handler crash"):
                await middleware(
                    {"type": "http", "method": "GET", "path": "/test"},
                    mock_receive,
                    mock_send,
                )

        asyncio.run(run())
        assert error_counter.total == 1
        assert error_counter.by_module.get("middleware") == 1


# ---------------------------------------------------------------------------
# Enhanced Health Endpoint
# ---------------------------------------------------------------------------


class TestHealthEndpoint:
    def test_health_has_uptime(self, client):
        """Health response includes uptime_seconds (> 0 since record_app_start runs in lifespan)."""
        resp = client.get("/api/health")
        data = resp.json()
        assert "uptime_seconds" in data
        assert isinstance(data["uptime_seconds"], (int, float))

    def test_health_has_scheduler(self, client):
        """Health response includes scheduler field with status."""
        resp = client.get("/api/health")
        data = resp.json()
        assert "scheduler" in data
        assert data["scheduler"]["status"] == "idle"
        assert data["scheduler"]["total_cycles"] == 0

    def test_health_has_errors(self, client):
        """Health response includes errors field."""
        resp = client.get("/api/health")
        data = resp.json()
        assert "errors" in data
        assert data["errors"]["total"] == 0
        assert data["errors"]["by_module"] == {}

    def test_health_backward_compat(self, client):
        """Original 5 fields are still present."""
        resp = client.get("/api/health")
        data = resp.json()
        assert "status" in data
        assert "feed_sources" in data
        assert "total_documents" in data
        assert "total_alerts" in data
        assert "notification_channels" in data

    def test_health_degraded_on_db_failure(self):
        """Status is 'degraded' when database is unreachable."""
        from regulatory_alerts.csrf import validate_csrf
        from tests.conftest import noop_csrf

        def _broken_session_factory():
            raise RuntimeError("DB down")

        with patch("regulatory_alerts.api.get_sync_engine", _mock_sync_engine), \
             patch("regulatory_alerts.api.get_sync_session_factory", _broken_session_factory), \
             patch("regulatory_alerts.rate_limit.get_sync_session_factory", _mock_sync_session_factory), \
             patch("regulatory_alerts.dashboard.get_sync_session_factory", _mock_sync_session_factory), \
             patch("regulatory_alerts.auth.get_sync_session_factory", _mock_sync_session_factory), \
             patch("regulatory_alerts.billing.get_sync_session_factory", _mock_sync_session_factory), \
             patch("regulatory_alerts.core.scheduler.start_scheduler", return_value=MagicMock()), \
             patch("regulatory_alerts.core.scheduler.stop_scheduler"), \
             patch("regulatory_alerts.observability.configure_logging"):
            from regulatory_alerts.api import app
            app.dependency_overrides[validate_csrf] = noop_csrf
            with TestClient(app) as c:
                resp = c.get("/api/health")
            app.dependency_overrides.pop(validate_csrf, None)

        data = resp.json()
        assert data["status"] == "degraded"
        assert data["database_connected"] is False


# ---------------------------------------------------------------------------
# SchedulerMetrics
# ---------------------------------------------------------------------------


class TestSchedulerMetrics:
    def test_record_success(self):
        """Successful cycle increments counters correctly."""
        scheduler_metrics.record_start()
        assert scheduler_metrics.last_status == "running"

        scheduler_metrics.record_success(duration=1.5, any_failures=False)
        assert scheduler_metrics.total_cycles == 1
        assert scheduler_metrics.successful_cycles == 1
        assert scheduler_metrics.last_status == "success"
        assert scheduler_metrics.last_duration_seconds == 1.5
        assert scheduler_metrics.last_error is None

    def test_record_partial(self):
        """Partial success (some sources failed) tracked correctly."""
        scheduler_metrics.record_start()
        scheduler_metrics.record_success(duration=2.0, any_failures=True)

        assert scheduler_metrics.total_cycles == 1
        assert scheduler_metrics.partial_cycles == 1
        assert scheduler_metrics.successful_cycles == 0
        assert scheduler_metrics.last_status == "partial"

    def test_record_failure(self):
        """Failed cycle stores truncated error."""
        scheduler_metrics.record_start()
        err = RuntimeError("something went wrong with the database connection")
        scheduler_metrics.record_failure(err, duration=0.5)

        assert scheduler_metrics.total_cycles == 1
        assert scheduler_metrics.failed_cycles == 1
        assert scheduler_metrics.last_status == "error"
        assert scheduler_metrics.last_error is not None
        assert "RuntimeError" in scheduler_metrics.last_error
        assert len(scheduler_metrics.last_error) <= 200

    def test_to_dict_no_last_error(self):
        """to_dict() does NOT expose last_error (security)."""
        scheduler_metrics.record_start()
        scheduler_metrics.record_failure(RuntimeError("secret"), duration=0.1)

        d = scheduler_metrics.to_dict()
        assert "last_error" not in d
        assert d["status"] == "error"
        assert d["total_cycles"] == 1

    def test_reset(self):
        """reset() zeros all metrics."""
        scheduler_metrics.record_start()
        scheduler_metrics.record_success(1.0)
        scheduler_metrics.reset()

        assert scheduler_metrics.total_cycles == 0
        assert scheduler_metrics.last_status == "idle"
        assert scheduler_metrics.last_run_at is None


# ---------------------------------------------------------------------------
# ErrorCounter
# ---------------------------------------------------------------------------


class TestErrorCounter:
    def test_record_increments(self):
        """record() increments total and by_module."""
        error_counter.record("scheduler")
        error_counter.record("scheduler")
        error_counter.record("middleware")

        assert error_counter.total == 3
        assert error_counter.by_module["scheduler"] == 2
        assert error_counter.by_module["middleware"] == 1

    def test_reset_clears(self):
        """reset() zeros everything."""
        error_counter.record("test")
        error_counter.reset()

        assert error_counter.total == 0
        assert error_counter.by_module == {}

    def test_to_dict(self):
        """to_dict() returns correct structure."""
        error_counter.record("mod1")
        d = error_counter.to_dict()

        assert d["total"] == 1
        assert d["by_module"]["mod1"] == 1

    def test_thread_safety(self):
        """Concurrent record() calls produce correct total."""
        num_threads = 10
        increments_per_thread = 100

        def worker():
            for _ in range(increments_per_thread):
                error_counter.record("concurrent")

        threads = [threading.Thread(target=worker) for _ in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        expected = num_threads * increments_per_thread
        assert error_counter.total == expected
        assert error_counter.by_module["concurrent"] == expected


# ---------------------------------------------------------------------------
# Uptime tracking
# ---------------------------------------------------------------------------


class TestUptime:
    def test_uptime_zero_before_start(self):
        """get_uptime_seconds() returns 0 before record_app_start()."""
        assert get_uptime_seconds() == 0.0

    def test_uptime_positive_after_start(self):
        """get_uptime_seconds() returns > 0 after record_app_start()."""
        record_app_start()
        import time
        time.sleep(0.01)
        assert get_uptime_seconds() > 0


# ---------------------------------------------------------------------------
# Integration: metrics → health endpoint
# ---------------------------------------------------------------------------


class TestHealthMetricsIntegration:
    """Integration tests verifying observability singletons flow through to health response."""

    def test_scheduler_metrics_reflected_in_health(self, client):
        """Scheduler metrics set before health call appear in response."""
        scheduler_metrics.record_start()
        scheduler_metrics.record_success(duration=2.5, any_failures=False)

        resp = client.get("/api/health")
        data = resp.json()

        assert data["scheduler"]["status"] == "success"
        assert data["scheduler"]["total_cycles"] == 1
        assert data["scheduler"]["successful_cycles"] == 1
        assert data["scheduler"]["last_duration_seconds"] == 2.5
        assert data["scheduler"]["last_run_at"] is not None

    def test_error_counter_reflected_in_health(self, client):
        """Error counter set before health call appears in response."""
        error_counter.record("scheduler")
        error_counter.record("scheduler")
        error_counter.record("middleware")

        resp = client.get("/api/health")
        data = resp.json()

        assert data["errors"]["total"] == 3
        assert data["errors"]["by_module"]["scheduler"] == 2
        assert data["errors"]["by_module"]["middleware"] == 1

    def test_scheduler_error_triggers_degraded(self, client):
        """Health status is 'degraded' when scheduler is in error state."""
        scheduler_metrics.record_start()
        scheduler_metrics.record_failure(RuntimeError("fetch crashed"), duration=0.1)

        resp = client.get("/api/health")
        data = resp.json()

        assert data["status"] == "degraded"
        assert data["scheduler"]["status"] == "error"

    def test_scheduler_partial_does_not_degrade(self, client):
        """Health status is 'ok' when scheduler is in partial state (not degraded)."""
        scheduler_metrics.record_start()
        scheduler_metrics.record_success(duration=1.0, any_failures=True)

        resp = client.get("/api/health")
        data = resp.json()

        assert data["status"] == "ok"
        assert data["scheduler"]["status"] == "partial"


# ---------------------------------------------------------------------------
# Edge cases: SchedulerMetrics
# ---------------------------------------------------------------------------


class TestSchedulerMetricsEdgeCases:
    def test_to_dict_all_fields_present(self):
        """to_dict() returns all expected keys."""
        scheduler_metrics.record_start()
        scheduler_metrics.record_success(duration=1.0)

        d = scheduler_metrics.to_dict()
        expected_keys = {
            "status", "total_cycles", "successful_cycles",
            "partial_cycles", "failed_cycles", "last_run_at",
            "last_duration_seconds",
        }
        assert set(d.keys()) == expected_keys

    def test_error_truncation_at_boundary(self):
        """Error message exceeding 200 chars is truncated to exactly 200."""
        long_msg = "A" * 300
        scheduler_metrics.record_start()
        scheduler_metrics.record_failure(RuntimeError(long_msg), duration=0.1)

        assert scheduler_metrics.last_error is not None
        assert len(scheduler_metrics.last_error) == 200
        assert scheduler_metrics.last_error.startswith("RuntimeError: ")

    def test_multiple_sequential_cycles(self):
        """Multiple cycles accumulate correctly."""
        # Cycle 1: success
        scheduler_metrics.record_start()
        scheduler_metrics.record_success(duration=1.0)

        # Cycle 2: partial
        scheduler_metrics.record_start()
        scheduler_metrics.record_success(duration=2.0, any_failures=True)

        # Cycle 3: failure
        scheduler_metrics.record_start()
        scheduler_metrics.record_failure(RuntimeError("fail"), duration=0.5)

        assert scheduler_metrics.total_cycles == 3
        assert scheduler_metrics.successful_cycles == 1
        assert scheduler_metrics.partial_cycles == 1
        assert scheduler_metrics.failed_cycles == 1
        assert scheduler_metrics.last_status == "error"
        assert scheduler_metrics.last_duration_seconds == 0.5


# ---------------------------------------------------------------------------
# Health Probes: liveness / readiness
# ---------------------------------------------------------------------------


class TestHealthProbes:
    """Tests for /api/health/live and /api/health/ready endpoints."""

    def test_liveness_returns_ok(self, client):
        """Liveness probe returns 200 with status ok."""
        resp = client.get("/api/health/live")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "uptime_seconds" in data

    def test_liveness_no_db_fields(self, client):
        """Liveness response has only status and uptime_seconds."""
        resp = client.get("/api/health/live")
        data = resp.json()
        assert set(data.keys()) == {"status", "uptime_seconds"}

    def test_liveness_works_when_db_down(self):
        """Liveness returns 200 even when DB is unreachable."""
        from regulatory_alerts.csrf import validate_csrf
        from tests.conftest import noop_csrf

        def _broken_session_factory():
            raise RuntimeError("DB down")

        with patch("regulatory_alerts.api.get_sync_engine", _mock_sync_engine), \
             patch("regulatory_alerts.api.get_sync_session_factory", _broken_session_factory), \
             patch("regulatory_alerts.rate_limit.get_sync_session_factory", _mock_sync_session_factory), \
             patch("regulatory_alerts.dashboard.get_sync_session_factory", _mock_sync_session_factory), \
             patch("regulatory_alerts.auth.get_sync_session_factory", _mock_sync_session_factory), \
             patch("regulatory_alerts.billing.get_sync_session_factory", _mock_sync_session_factory), \
             patch("regulatory_alerts.core.scheduler.start_scheduler", return_value=MagicMock()), \
             patch("regulatory_alerts.core.scheduler.stop_scheduler"), \
             patch("regulatory_alerts.observability.configure_logging"):
            from regulatory_alerts.api import app
            app.dependency_overrides[validate_csrf] = noop_csrf
            with TestClient(app) as c:
                resp = c.get("/api/health/live")
            app.dependency_overrides.pop(validate_csrf, None)

        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_readiness_returns_full_health(self, client):
        """Readiness probe returns all health fields."""
        resp = client.get("/api/health/ready")
        assert resp.status_code == 200
        data = resp.json()
        expected_keys = {
            "status", "feed_sources", "total_documents", "total_alerts",
            "notification_channels", "uptime_seconds", "database_connected",
            "scheduler", "errors",
        }
        assert set(data.keys()) == expected_keys

    def test_readiness_matches_health(self, client):
        """Readiness and health endpoints return identical data (excluding uptime drift)."""
        resp_ready = client.get("/api/health/ready")
        resp_health = client.get("/api/health")

        ready_data = resp_ready.json()
        health_data = resp_health.json()

        # Compare all fields except uptime_seconds (may differ by ms)
        for key in ready_data:
            if key != "uptime_seconds":
                assert ready_data[key] == health_data[key], f"Mismatch on key: {key}"

    def test_readiness_degraded_on_scheduler_error(self, client):
        """Readiness returns degraded when scheduler is in error state."""
        scheduler_metrics.record_start()
        scheduler_metrics.record_failure(RuntimeError("crash"), duration=0.1)

        resp = client.get("/api/health/ready")
        data = resp.json()
        assert data["status"] == "degraded"

    def test_liveness_has_request_id_header(self, client):
        """Liveness response includes x-request-id from middleware."""
        resp = client.get("/api/health/live")
        assert "x-request-id" in resp.headers
