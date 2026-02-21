"""Tests for the dashboard HTML frontend routes."""

import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

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

from regulatory_alerts.models import (
    Base,
    FeedDocument,
    FeedSource,
    NotificationChannel,
    ProcessedAlert,
    User,
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
def _clean_tables():
    with _TestSession() as session:
        for table in reversed(Base.metadata.sorted_tables):
            session.execute(table.delete())
        session.commit()
    yield


@pytest.fixture()
def client():
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
         patch("regulatory_alerts.core.scheduler.stop_scheduler"):
        from regulatory_alerts.api import app
        app.dependency_overrides[validate_csrf] = noop_csrf
        with TestClient(app) as c:
            # Register a test user (auto-login via session cookie)
            c.post("/register", data={
                "email": "test@example.com",
                "password": "testpass123",
                "password_confirm": "testpass123",
            })
            # Upgrade to pro so free-tier restrictions don't interfere with tests
            with _TestSession() as session:
                user = session.query(User).filter(User.email == "test@example.com").first()
                user.subscription_tier = "pro"
                session.commit()
            yield c
        app.dependency_overrides.pop(validate_csrf, None)


@pytest.fixture()
def seeded_data():
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
            external_id="dash-test-001",
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
            ai_cost_usd=0.000123,
        )
        session.add(alert)
        session.commit()

        return {"source": source, "document": doc, "alert": alert}


# --- Dashboard Home ---

class TestDashboardHome:
    def test_dashboard_returns_html(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "Dashboard" in resp.text

    def test_dashboard_shows_stats(self, client, seeded_data):
        resp = client.get("/")
        assert resp.status_code == 200
        # Stats should show counts
        assert "Feed Sources" in resp.text
        assert "AI Alerts" in resp.text

    def test_dashboard_shows_recent_alerts(self, client, seeded_data):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "SEC Enforcement Action Against Acme" in resp.text
        assert "SEC" in resp.text


# --- Alerts List ---

class TestAlertsList:
    def test_alerts_page_returns_html(self, client):
        resp = client.get("/alerts")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "Regulatory Alerts" in resp.text

    def test_alerts_page_with_data(self, client, seeded_data):
        resp = client.get("/alerts")
        assert resp.status_code == 200
        assert "SEC Enforcement Action Against Acme" in resp.text
        assert "90%" in resp.text  # relevance score formatted

    def test_alerts_filter_by_agency(self, client, seeded_data):
        resp = client.get("/alerts?agency=CFTC")
        assert resp.status_code == 200
        assert "SEC Enforcement Action Against Acme" not in resp.text

        resp = client.get("/alerts?agency=SEC")
        assert resp.status_code == 200
        assert "SEC Enforcement Action Against Acme" in resp.text

    def test_alerts_filter_by_score(self, client, seeded_data):
        resp = client.get("/alerts?min_score=0.95")
        assert resp.status_code == 200
        assert "SEC Enforcement Action Against Acme" not in resp.text

        resp = client.get("/alerts?min_score=0.5")
        assert resp.status_code == 200
        assert "SEC Enforcement Action Against Acme" in resp.text

    def test_alerts_htmx_returns_fragment(self, client, seeded_data):
        resp = client.get("/alerts?agency=SEC", headers={"HX-Request": "true"})
        assert resp.status_code == 200
        # HTMX fragment should NOT contain full page wrapper
        assert "<!DOCTYPE html>" not in resp.text
        # But should contain alert data
        assert "SEC Enforcement Action Against Acme" in resp.text

    def test_alerts_empty_state(self, client):
        resp = client.get("/alerts")
        assert resp.status_code == 200
        assert "No alerts found" in resp.text


# --- Alert Detail ---

class TestAlertDetail:
    def test_alert_detail_returns_html(self, client, seeded_data):
        doc_id = seeded_data["document"].id
        resp = client.get(f"/alerts/{doc_id}")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    def test_alert_detail_shows_summary(self, client, seeded_data):
        doc_id = seeded_data["document"].id
        resp = client.get(f"/alerts/{doc_id}")
        assert resp.status_code == 200
        assert "SEC charged Acme Corp with fraud." in resp.text
        assert "Fraud charges" in resp.text
        assert "enforcement" in resp.text

    def test_alert_detail_not_found(self, client):
        resp = client.get("/alerts/9999")
        assert resp.status_code == 404


# --- Channels ---

class TestChannelsPage:
    def test_channels_page_returns_html(self, client):
        resp = client.get("/channels")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "Notification Channels" in resp.text

    def test_create_webhook_channel(self, client):
        resp = client.post("/channels", data={
            "name": "Test Hook",
            "channel_type": "webhook",
            "webhook_url": "https://example.com/hook",
            "webhook_secret": "",
            "email_address": "",
            "min_relevance_score": "",
            "agency_filter": "",
            "topic_filter": "",
        })
        assert resp.status_code == 200
        assert "Test Hook" in resp.text

    def test_create_email_channel(self, client):
        resp = client.post("/channels", data={
            "name": "Team Email",
            "channel_type": "email",
            "webhook_url": "",
            "webhook_secret": "",
            "email_address": "team@example.com",
            "min_relevance_score": "",
            "agency_filter": "",
            "topic_filter": "",
        })
        assert resp.status_code == 200
        assert "Team Email" in resp.text

    def test_create_channel_validation_error(self, client):
        resp = client.post("/channels", data={
            "name": "Bad",
            "channel_type": "webhook",
            "webhook_url": "",
            "webhook_secret": "",
            "email_address": "",
            "min_relevance_score": "",
            "agency_filter": "",
            "topic_filter": "",
        })
        assert resp.status_code == 200
        assert "Webhook URL is required" in resp.text

    def test_delete_channel(self, client):
        # Create a channel first
        client.post("/channels", data={
            "name": "To Delete",
            "channel_type": "webhook",
            "webhook_url": "https://example.com/hook",
            "webhook_secret": "",
            "email_address": "",
            "min_relevance_score": "",
            "agency_filter": "",
            "topic_filter": "",
        })

        # Find the channel ID
        with _TestSession() as session:
            ch = session.query(NotificationChannel).first()
            ch_id = ch.id

        resp = client.delete(f"/channels/{ch_id}")
        assert resp.status_code == 200

    def test_delete_channel_not_found(self, client):
        resp = client.delete("/channels/9999")
        assert resp.status_code == 404


# --- About/Landing ---

class TestAboutPage:
    def test_about_returns_html(self, client):
        resp = client.get("/about")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "AI-Powered" in resp.text
