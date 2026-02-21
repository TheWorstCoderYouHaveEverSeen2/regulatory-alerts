"""Integration tests for the FastAPI REST API."""

import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

# Ensure src is on path
_src = str(Path(__file__).resolve().parents[1] / "src")
if _src not in sys.path:
    sys.path.insert(0, _src)

os.environ["DATABASE_URL_SYNC"] = "sqlite:///:memory:"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["ANTHROPIC_API_KEY"] = "test-key-not-real"
os.environ["API_KEYS"] = ""

from regulatory_alerts.models import (
    Base,
    FeedDocument,
    FeedSource,
    NotificationChannel,
    ProcessedAlert,
)


def _enable_sqlite_fk(dbapi_conn, connection_record):
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


# Shared test engine — StaticPool + check_same_thread=False for cross-thread SQLite
from sqlalchemy.pool import StaticPool

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
def _clean_tables():
    """Clear all tables before each test."""
    with _TestSession() as session:
        for table in reversed(Base.metadata.sorted_tables):
            session.execute(table.delete())
        session.commit()
    yield


@pytest.fixture(autouse=True)
def _reset_singletons():
    """Reset observability singletons to prevent state leaks."""
    from regulatory_alerts.observability import error_counter, reset_uptime, scheduler_metrics
    scheduler_metrics.reset()
    error_counter.reset()
    reset_uptime()
    yield


@pytest.fixture()
def client():
    """Provide a TestClient with test DB and scheduler disabled."""
    with patch("regulatory_alerts.api.get_sync_engine", _mock_sync_engine), \
         patch("regulatory_alerts.api.get_sync_session_factory", _mock_sync_session_factory), \
         patch("regulatory_alerts.rate_limit.get_sync_session_factory", _mock_sync_session_factory), \
         patch("regulatory_alerts.admin.get_sync_session_factory", _mock_sync_session_factory), \
         patch("regulatory_alerts.core.scheduler.start_scheduler", return_value=MagicMock()), \
         patch("regulatory_alerts.core.scheduler.stop_scheduler"), \
         patch("regulatory_alerts.observability.configure_logging"):
        from regulatory_alerts.api import app
        with TestClient(app) as c:
            yield c


@pytest.fixture()
def seeded_data():
    """Seed data into the test DB."""
    with _TestSession() as session:
        source = FeedSource(
            name="SEC Press Releases",
            agency="SEC",
            feed_url="https://www.sec.gov/news/pressreleases.rss",
            feed_type="rss",
        )
        session.add(source)
        session.flush()

        doc = FeedDocument(
            feed_source_id=source.id,
            external_id="api-test-001",
            title="SEC Enforcement Action Against Acme",
            url="https://www.sec.gov/test",
            published_at=datetime(2026, 2, 7, 12, 0, 0, tzinfo=timezone.utc),
            agency="SEC",
            processing_status="completed",
        )
        session.add(doc)
        session.flush()

        alert = ProcessedAlert(
            feed_document_id=doc.id,
            summary="SEC charged Acme Corp with fraud.",
            key_points=["Fraud charges", "Penalty pending"],
            topics='["enforcement", "fraud"]',
            relevance_score=0.9,
            document_type="enforcement_action",
            ai_model="claude-haiku-4-5-20241022",
        )
        session.add(alert)
        session.commit()

        return {"source": source, "document": doc, "alert": alert}


class TestHealthEndpoint:
    def test_health_returns_ok(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "feed_sources" in data
        assert "notification_channels" in data


class TestUpdatesEndpoint:
    def test_list_updates_empty(self, client):
        resp = client.get("/api/updates")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 0
        assert data["updates"] == []

    def test_list_updates_with_data(self, client, seeded_data):
        resp = client.get("/api/updates")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        update = data["updates"][0]
        assert update["agency"] == "SEC"
        assert update["summary"] == "SEC charged Acme Corp with fraud."
        assert update["relevance_score"] == 0.9

    def test_filter_by_agency(self, client, seeded_data):
        resp = client.get("/api/updates?agency=CFTC")
        assert resp.status_code == 200
        assert resp.json()["count"] == 0

        resp = client.get("/api/updates?agency=SEC")
        assert resp.status_code == 200
        assert resp.json()["count"] == 1

    def test_get_update_by_id(self, client, seeded_data):
        doc_id = seeded_data["document"].id
        resp = client.get(f"/api/updates/{doc_id}")
        assert resp.status_code == 200
        assert resp.json()["title"] == "SEC Enforcement Action Against Acme"

    def test_get_update_not_found(self, client):
        resp = client.get("/api/updates/9999")
        assert resp.status_code == 404


class TestChannelsEndpoint:
    def test_list_channels_empty(self, client):
        resp = client.get("/api/channels")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_create_webhook_channel(self, client):
        resp = client.post("/api/channels", json={
            "name": "My Webhook",
            "channel_type": "webhook",
            "webhook_url": "https://hooks.example.com/test",
            "min_relevance_score": 0.7,
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "My Webhook"
        assert data["channel_type"] == "webhook"

    def test_create_email_channel(self, client):
        resp = client.post("/api/channels", json={
            "name": "Email Alerts",
            "channel_type": "email",
            "email_address": "test@example.com",
        })
        assert resp.status_code == 201
        assert resp.json()["email_address"] == "test@example.com"

    def test_create_channel_validation(self, client):
        resp = client.post("/api/channels", json={
            "name": "Bad",
            "channel_type": "webhook",
        })
        assert resp.status_code == 400

    def test_delete_channel(self, client):
        resp = client.post("/api/channels", json={
            "name": "To Delete",
            "channel_type": "webhook",
            "webhook_url": "https://example.com/hook",
        })
        channel_id = resp.json()["id"]

        resp = client.delete(f"/api/channels/{channel_id}")
        assert resp.status_code == 204

        resp = client.get("/api/channels")
        assert len(resp.json()) == 0

    def test_delete_channel_not_found(self, client):
        resp = client.delete("/api/channels/9999")
        assert resp.status_code == 404


class TestApiAuth:
    def test_no_auth_required_when_keys_empty(self, client):
        resp = client.get("/api/updates")
        assert resp.status_code == 200

    def test_auth_required_when_keys_set(self, client):
        """When API_KEYS is set, requests without key should get 401."""
        from regulatory_alerts import api as api_mod
        original = api_mod.settings.API_KEYS
        api_mod.settings.API_KEYS = "test-key-abc"
        try:
            resp = client.get("/api/updates")
            assert resp.status_code == 401
        finally:
            api_mod.settings.API_KEYS = original

    def test_valid_key_passes(self, client):
        from regulatory_alerts import api as api_mod
        original = api_mod.settings.API_KEYS
        api_mod.settings.API_KEYS = "test-key-abc"
        try:
            resp = client.get("/api/updates", headers={"X-API-Key": "test-key-abc"})
            assert resp.status_code == 200
        finally:
            api_mod.settings.API_KEYS = original

    def test_health_no_auth(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200


class TestRateLimiting:
    def test_rate_limit_returns_429(self, client):
        """Exceeding the rate limit should return 429."""
        from regulatory_alerts import api as api_mod
        original_free = api_mod.settings.FREE_RATE_LIMIT
        api_mod.settings.FREE_RATE_LIMIT = "2/minute"
        # Reset limiter storage so previous tests don't count
        api_mod.limiter.reset()
        try:
            resp1 = client.get("/api/updates")
            assert resp1.status_code == 200
            resp2 = client.get("/api/updates")
            assert resp2.status_code == 200
            resp3 = client.get("/api/updates")
            assert resp3.status_code == 429
        finally:
            api_mod.settings.FREE_RATE_LIMIT = original_free
            api_mod.limiter.reset()

    def test_health_not_rate_limited(self, client):
        """Health endpoint should never be rate limited."""
        from regulatory_alerts import api as api_mod
        original_free = api_mod.settings.FREE_RATE_LIMIT
        api_mod.settings.FREE_RATE_LIMIT = "2/minute"
        api_mod.limiter.reset()
        try:
            for _ in range(5):
                resp = client.get("/api/health")
                assert resp.status_code == 200
        finally:
            api_mod.settings.FREE_RATE_LIMIT = original_free
            api_mod.limiter.reset()
