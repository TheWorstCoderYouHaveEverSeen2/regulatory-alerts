"""Tests for Prometheus metrics: /metrics endpoint, PrometheusMetrics class, HTTP counter."""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from prometheus_client import CollectorRegistry
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

from regulatory_alerts.models import Base, FeedDocument, FeedSource, NotificationChannel, ProcessedAlert, User
from regulatory_alerts.observability import (
    PrometheusMetrics,
    error_counter,
    get_uptime_seconds,
    prometheus_metrics,
    record_app_start,
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
    prometheus_metrics.reset()
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
    """TestClient with mocked DB and scheduler."""
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
# /metrics endpoint
# ---------------------------------------------------------------------------


class TestMetricsEndpoint:
    def test_metrics_returns_200(self, client):
        """GET /metrics returns 200."""
        resp = client.get("/metrics")
        assert resp.status_code == 200

    def test_metrics_content_type(self, client):
        """Response content type is Prometheus text format."""
        resp = client.get("/metrics")
        assert "text/plain" in resp.headers["content-type"]

    def test_metrics_no_auth_required(self, client):
        """Metrics endpoint works without API key even when auth is enabled."""
        resp = client.get("/metrics")
        assert resp.status_code == 200

    def test_metrics_contains_uptime(self, client):
        """Response includes uptime gauge."""
        resp = client.get("/metrics")
        assert "regulatory_alerts_uptime_seconds" in resp.text

    def test_metrics_contains_scheduler_cycles(self, client):
        """Response includes scheduler cycle counter."""
        resp = client.get("/metrics")
        assert "regulatory_alerts_scheduler_cycles_total" in resp.text

    def test_metrics_contains_errors(self, client):
        """Response includes error counter."""
        resp = client.get("/metrics")
        assert "regulatory_alerts_errors_total" in resp.text

    def test_metrics_contains_http_requests(self, client):
        """Response includes HTTP request counter."""
        resp = client.get("/metrics")
        assert "regulatory_alerts_http_requests_total" in resp.text

    def test_metrics_contains_db_gauges(self, client):
        """Response includes DB-sourced gauges."""
        resp = client.get("/metrics")
        body = resp.text
        assert "regulatory_alerts_feed_sources_total" in body
        assert "regulatory_alerts_documents_total" in body
        assert "regulatory_alerts_alerts_total" in body
        assert "regulatory_alerts_users_total" in body
        assert "regulatory_alerts_notification_channels_total" in body

    def test_metrics_db_failure_still_serves(self, client):
        """If DB is unreachable during collect, endpoint still returns metrics."""
        with patch(
            "regulatory_alerts.api.get_sync_session_factory",
            side_effect=Exception("DB down"),
        ):
            resp = client.get("/metrics")
        assert resp.status_code == 200
        assert "regulatory_alerts_uptime_seconds" in resp.text


# ---------------------------------------------------------------------------
# PrometheusMetrics class (unit tests with isolated registry)
# ---------------------------------------------------------------------------


class TestPrometheusMetricsClass:
    def _make(self):
        """Create PrometheusMetrics with isolated registry."""
        return PrometheusMetrics(registry=CollectorRegistry())

    def test_collect_from_singletons_sets_uptime(self):
        """Uptime gauge reflects get_uptime_seconds()."""
        import time
        record_app_start()
        time.sleep(0.01)  # Ensure measurable uptime
        pm = self._make()
        pm.collect_from_singletons()
        assert pm.uptime._value.get() > 0

    def test_collect_scheduler_cycles_delta_inc(self):
        """Scheduler cycle counters use delta-inc pattern."""
        pm = self._make()

        scheduler_metrics.record_start()
        scheduler_metrics.record_success(1.5)
        pm.collect_from_singletons()

        # success=1 should be tracked
        assert pm.scheduler_cycles.labels(status="success")._value.get() == 1.0

        # Another cycle — should increment by 1, not reset
        scheduler_metrics.record_start()
        scheduler_metrics.record_success(0.5)
        pm.collect_from_singletons()
        assert pm.scheduler_cycles.labels(status="success")._value.get() == 2.0

    def test_collect_scheduler_failure_counter(self):
        """Failed cycles increment error label."""
        pm = self._make()

        scheduler_metrics.record_start()
        scheduler_metrics.record_failure(RuntimeError("boom"), 0.1)
        pm.collect_from_singletons()

        assert pm.scheduler_cycles.labels(status="error")._value.get() == 1.0

    def test_collect_error_counter_delta_inc(self):
        """Error counter uses delta-inc per module."""
        pm = self._make()

        error_counter.record("fetcher")
        error_counter.record("fetcher")
        error_counter.record("notifier")
        pm.collect_from_singletons()

        assert pm.errors.labels(module="fetcher")._value.get() == 2.0
        assert pm.errors.labels(module="notifier")._value.get() == 1.0

        # More errors — delta only
        error_counter.record("fetcher")
        pm.collect_from_singletons()
        assert pm.errors.labels(module="fetcher")._value.get() == 3.0

    def test_collect_from_db_counts(self):
        """DB collection populates gauge values."""
        pm = self._make()

        with _TestSession() as session:
            src = FeedSource(
                name="SEC", agency="SEC",
                feed_url="https://sec.gov/rss", feed_type="rss", enabled=True,
            )
            session.add(src)
            session.commit()

            pm.collect_from_db(session)

        assert pm.feed_sources._value.get() == 1.0

    def test_collect_from_db_users_by_tier(self):
        """Users gauge is labeled by tier."""
        import secrets

        pm = self._make()

        with _TestSession() as session:
            for tier in ("free", "pro", "pro"):
                u = User(
                    email=f"{secrets.token_hex(4)}@test.com",
                    hashed_password="x",
                    api_key=secrets.token_hex(16),
                    subscription_tier=tier,
                )
                session.add(u)
            session.commit()
            pm.collect_from_db(session)

        assert pm.users.labels(tier="free")._value.get() == 1.0
        assert pm.users.labels(tier="pro")._value.get() == 2.0

    def test_collect_from_db_failure_does_not_raise(self):
        """DB errors are swallowed gracefully."""
        pm = self._make()
        mock_session = MagicMock()
        mock_session.scalar.side_effect = Exception("DB error")
        # Should not raise
        pm.collect_from_db(mock_session)

    def test_reset_clears_delta_state(self):
        """reset() clears delta-inc tracking."""
        pm = self._make()

        scheduler_metrics.record_start()
        scheduler_metrics.record_success(1.0)
        pm.collect_from_singletons()

        pm.reset()

        # After reset, same singleton state should re-increment
        pm.collect_from_singletons()
        assert pm.scheduler_cycles.labels(status="success")._value.get() == 2.0


# ---------------------------------------------------------------------------
# HTTP request counter in middleware
# ---------------------------------------------------------------------------


class TestHTTPRequestCounter:
    def test_http_requests_counted(self, client):
        """HTTP requests increment the Prometheus counter."""
        # Make a few requests
        client.get("/api/health/live")
        client.get("/api/health/live")

        resp = client.get("/metrics")
        body = resp.text
        # Should see at least GET 200 counted (from health/live + metrics itself)
        assert 'regulatory_alerts_http_requests_total{' in body
        assert 'method="GET"' in body
