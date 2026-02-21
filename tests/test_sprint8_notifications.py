"""Tests for Sprint 8: Notification Enhancements.

Covers:
- Phase 1: Channel Enable/Disable Toggle (API + Dashboard)
- Phase 2: Slack Channel Type (notifier + API + Dashboard)
- Phase 3: Channel Test Button (Dashboard)
- Phase 4: Notification History (Dashboard + API)
"""

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
    NotificationLog,
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
    """Dashboard test client with login session."""
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
            c.post("/register", data={
                "email": "sprint8@example.com",
                "password": "testpass123",
                "password_confirm": "testpass123",
            })
            # Upgrade to pro so free-tier restrictions don't interfere
            with _TestSession() as session:
                user = session.query(User).filter(User.email == "sprint8@example.com").first()
                user.subscription_tier = "pro"
                session.commit()
            yield c
        app.dependency_overrides.pop(validate_csrf, None)


@pytest.fixture()
def api_client():
    """API-only test client (no login session)."""
    with patch("regulatory_alerts.api.get_sync_engine", _mock_sync_engine), \
         patch("regulatory_alerts.api.get_sync_session_factory", _mock_sync_session_factory), \
         patch("regulatory_alerts.rate_limit.get_sync_session_factory", _mock_sync_session_factory), \
         patch("regulatory_alerts.dashboard.get_sync_session_factory", _mock_sync_session_factory), \
         patch("regulatory_alerts.auth.get_sync_session_factory", _mock_sync_session_factory), \
         patch("regulatory_alerts.billing.get_sync_session_factory", _mock_sync_session_factory), \
         patch("regulatory_alerts.core.scheduler.start_scheduler", return_value=MagicMock()), \
         patch("regulatory_alerts.core.scheduler.stop_scheduler"), \
         patch("regulatory_alerts.observability.configure_logging"):
        from regulatory_alerts.api import app
        with TestClient(app) as c:
            yield c


@pytest.fixture()
def seeded_channel(client):
    """Create a webhook channel via dashboard and return its ID."""
    client.post("/channels", data={
        "name": "Sprint8 Webhook",
        "channel_type": "webhook",
        "webhook_url": "https://example.com/hook",
        "webhook_secret": "",
        "email_address": "",
        "min_relevance_score": "",
        "agency_filter": "",
        "topic_filter": "",
    })
    with _TestSession() as session:
        ch = session.query(NotificationChannel).filter_by(name="Sprint8 Webhook").first()
        return ch.id


@pytest.fixture()
def seeded_data_with_logs(client):
    """Seed full data: source, doc, alert, channel, and notification logs."""
    # Create channel via dashboard
    client.post("/channels", data={
        "name": "Log Test Channel",
        "channel_type": "webhook",
        "webhook_url": "https://example.com/hook",
        "webhook_secret": "",
        "email_address": "",
        "min_relevance_score": "",
        "agency_filter": "",
        "topic_filter": "",
    })

    with _TestSession() as session:
        # Get user and channel
        user = session.query(User).first()
        channel = session.query(NotificationChannel).first()

        # Seed feed source + doc + alert
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
            external_id="sprint8-test-001",
            title="SEC Enforcement Against TestCorp",
            url="https://www.sec.gov/test",
            published_at=datetime(2026, 2, 15, 12, 0, 0, tzinfo=timezone.utc),
            agency="SEC",
            processing_status="completed",
        )
        session.add(doc)
        session.flush()

        alert = ProcessedAlert(
            feed_document_id=doc.id,
            summary="SEC charged TestCorp with fraud.",
            key_points=["Fraud charges"],
            topics='["enforcement"]',
            relevance_score=0.9,
            document_type="enforcement_action",
            ai_model="claude-haiku-4-5-20241022",
        )
        session.add(alert)
        session.flush()

        # Create notification logs
        log_sent = NotificationLog(
            channel_id=channel.id,
            alert_id=alert.id,
            status="sent",
            sent_at=datetime(2026, 2, 15, 12, 5, 0, tzinfo=timezone.utc),
            retry_count=0,
        )
        log_failed = NotificationLog(
            channel_id=channel.id,
            alert_id=alert.id,
            status="failed",
            error_message="Connection refused",
            retry_count=1,
        )
        session.add_all([log_sent, log_failed])
        session.commit()

        return {
            "user": user,
            "channel": channel,
            "source": source,
            "document": doc,
            "alert": alert,
            "log_sent": log_sent,
            "log_failed": log_failed,
        }


# =============================================================================
# Phase 1: Channel Enable/Disable Toggle
# =============================================================================


class TestToggleAPI:
    """API PATCH /api/channels/{id} toggle endpoint."""

    def test_toggle_enable(self, api_client):
        # Create channel
        resp = api_client.post("/api/channels", json={
            "name": "Toggle Test",
            "channel_type": "webhook",
            "webhook_url": "https://example.com/hook",
        })
        ch_id = resp.json()["id"]
        assert resp.json()["enabled"] is True

        # Disable
        resp = api_client.patch(f"/api/channels/{ch_id}", json={"enabled": False})
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False

    def test_toggle_disable(self, api_client):
        resp = api_client.post("/api/channels", json={
            "name": "Toggle Disable",
            "channel_type": "webhook",
            "webhook_url": "https://example.com/hook",
        })
        ch_id = resp.json()["id"]

        # Enable (already enabled, set again)
        resp = api_client.patch(f"/api/channels/{ch_id}", json={"enabled": True})
        assert resp.status_code == 200
        assert resp.json()["enabled"] is True

    def test_toggle_not_found(self, api_client):
        resp = api_client.patch("/api/channels/9999", json={"enabled": False})
        assert resp.status_code == 404


class TestToggleDashboard:
    """Dashboard POST /channels/{id}/toggle."""

    def test_toggle_via_dashboard(self, client, seeded_channel):
        # Toggle to disabled
        resp = client.post(f"/channels/{seeded_channel}/toggle")
        assert resp.status_code == 200
        assert "disabled" in resp.text.lower()

        # Toggle back to enabled
        resp = client.post(f"/channels/{seeded_channel}/toggle")
        assert resp.status_code == 200
        assert "enabled" in resp.text.lower()

    def test_toggle_requires_login(self):
        """Unauthenticated toggle should redirect to login."""
        with patch("regulatory_alerts.api.get_sync_engine", _mock_sync_engine), \
             patch("regulatory_alerts.api.get_sync_session_factory", _mock_sync_session_factory), \
             patch("regulatory_alerts.rate_limit.get_sync_session_factory", _mock_sync_session_factory), \
             patch("regulatory_alerts.dashboard.get_sync_session_factory", _mock_sync_session_factory), \
             patch("regulatory_alerts.auth.get_sync_session_factory", _mock_sync_session_factory), \
             patch("regulatory_alerts.billing.get_sync_session_factory", _mock_sync_session_factory), \
             patch("regulatory_alerts.core.scheduler.start_scheduler", return_value=MagicMock()), \
             patch("regulatory_alerts.core.scheduler.stop_scheduler"), \
             patch("regulatory_alerts.observability.configure_logging"):
            from regulatory_alerts.csrf import validate_csrf
            from tests.conftest import noop_csrf
            from regulatory_alerts.api import app
            app.dependency_overrides[validate_csrf] = noop_csrf
            with TestClient(app, follow_redirects=False) as c:
                resp = c.post("/channels/1/toggle")
                assert resp.status_code == 302
                assert "/login" in resp.headers.get("location", "")
            app.dependency_overrides.pop(validate_csrf, None)

    def test_toggle_not_found(self, client):
        resp = client.post("/channels/9999/toggle")
        assert resp.status_code == 404

    def test_toggle_cross_user_404(self, client, seeded_channel):
        """Toggling another user's channel returns 404."""
        # Create a second user and reassign channel
        import bcrypt, secrets
        with _TestSession() as session:
            other_user = User(
                email="other@example.com",
                hashed_password=bcrypt.hashpw(b"pass", bcrypt.gensalt()).decode(),
                api_key=secrets.token_hex(16),
            )
            session.add(other_user)
            session.flush()
            channel = session.get(NotificationChannel, seeded_channel)
            channel.user_id = other_user.id
            session.commit()

        resp = client.post(f"/channels/{seeded_channel}/toggle")
        assert resp.status_code == 404


# =============================================================================
# Phase 2: Slack Channel Type
# =============================================================================


class TestSlackNotifier:
    """Unit tests for Slack payload builder and sender."""

    def test_build_slack_payload_structure(self, seed_alert, seed_document):
        from regulatory_alerts.core.notifier import _build_slack_payload

        payload = _build_slack_payload(seed_alert, seed_document)
        assert "blocks" in payload
        blocks = payload["blocks"]

        # Should have: header, section, context, actions, divider
        assert len(blocks) == 5
        assert blocks[0]["type"] == "header"
        assert blocks[1]["type"] == "section"
        assert blocks[2]["type"] == "context"
        assert blocks[3]["type"] == "actions"
        assert blocks[4]["type"] == "divider"

    def test_build_slack_payload_truncates_title(self, seed_alert, seed_document):
        from regulatory_alerts.core.notifier import _build_slack_payload

        seed_document.title = "A" * 200  # Long title
        payload = _build_slack_payload(seed_alert, seed_document)
        header_text = payload["blocks"][0]["text"]["text"]
        # [agency] + first 140 chars of title
        assert len(header_text) <= 150

    def test_build_slack_payload_no_topics_fallback(self, seed_alert, seed_document):
        from regulatory_alerts.core.notifier import _build_slack_payload

        seed_alert.topics = None
        payload = _build_slack_payload(seed_alert, seed_document)
        context_text = payload["blocks"][2]["elements"][0]["text"]
        assert "General" in context_text

    def test_send_slack_success(self, seed_alert, seed_document):
        from regulatory_alerts.core.notifier import _send_slack

        mock_resp = MagicMock()
        mock_resp.text = "ok"
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.post.return_value = mock_resp

        channel = NotificationChannel(
            name="Slack Test", channel_type="slack",
            webhook_url="https://hooks.slack.com/services/T/B/xxx",
        )
        with patch("regulatory_alerts.core.notifier._http_client", mock_client):
            success, error = _send_slack(channel, seed_alert, seed_document)
        assert success is True
        assert error == ""

    def test_send_slack_api_error(self, seed_alert, seed_document):
        from regulatory_alerts.core.notifier import _send_slack

        mock_resp = MagicMock()
        mock_resp.text = "invalid_payload"
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.post.return_value = mock_resp

        channel = NotificationChannel(
            name="Slack Bad", channel_type="slack",
            webhook_url="https://hooks.slack.com/services/T/B/xxx",
        )
        with patch("regulatory_alerts.core.notifier._http_client", mock_client):
            success, error = _send_slack(channel, seed_alert, seed_document)
        assert success is False
        assert "Slack API error" in error

    def test_send_slack_network_error(self, seed_alert, seed_document):
        from regulatory_alerts.core.notifier import _send_slack

        mock_client = MagicMock()
        mock_client.post.side_effect = Exception("Connection refused")

        channel = NotificationChannel(
            id=99, name="Slack Error", channel_type="slack",
            webhook_url="https://hooks.slack.com/services/T/B/xxx",
        )
        with patch("regulatory_alerts.core.notifier._http_client", mock_client):
            success, error = _send_slack(channel, seed_alert, seed_document)
        assert success is False
        assert "Connection refused" in error

    def test_dispatch_routes_to_slack(self, seed_alert, seed_document):
        from regulatory_alerts.core.notifier import _dispatch_notification

        channel = NotificationChannel(
            name="Slack Route", channel_type="slack",
            webhook_url="https://hooks.slack.com/services/T/B/xxx",
        )
        with patch("regulatory_alerts.core.notifier._send_slack") as mock_send:
            mock_send.return_value = (True, "")
            success, _ = _dispatch_notification(channel, seed_alert, seed_document)
            mock_send.assert_called_once()
            assert success is True

    def test_dispatch_routes_to_webhook(self, seed_alert, seed_document):
        from regulatory_alerts.core.notifier import _dispatch_notification

        channel = NotificationChannel(
            name="Webhook Route", channel_type="webhook",
            webhook_url="https://example.com/hook",
        )
        with patch("regulatory_alerts.core.notifier._send_webhook") as mock_send:
            mock_send.return_value = (True, "")
            success, _ = _dispatch_notification(channel, seed_alert, seed_document)
            mock_send.assert_called_once()
            assert success is True

    def test_dispatch_routes_to_email(self, seed_alert, seed_document):
        from regulatory_alerts.core.notifier import _dispatch_notification

        channel = NotificationChannel(
            name="Email Route", channel_type="email",
            email_address="test@example.com",
        )
        with patch("regulatory_alerts.core.notifier._send_email") as mock_send:
            mock_send.return_value = (True, "")
            success, _ = _dispatch_notification(channel, seed_alert, seed_document)
            mock_send.assert_called_once()
            assert success is True

    @patch("regulatory_alerts.core.notifier._send_slack")
    def test_retry_routes_to_slack(self, mock_send, db_session, seed_alert, seed_document):
        """retry_failed_notifications should route Slack channels through _send_slack."""
        from regulatory_alerts.core.notifier import retry_failed_notifications

        mock_send.return_value = (True, "")

        channel = NotificationChannel(
            name="Retry Slack", channel_type="slack",
            webhook_url="https://hooks.slack.com/services/T/B/xxx",
            enabled=True,
        )
        db_session.add(channel)
        db_session.flush()

        log = NotificationLog(
            channel_id=channel.id,
            alert_id=seed_alert.id,
            status="failed",
            error_message="Previous error",
            retry_count=0,
            next_retry_at=datetime(2020, 1, 1, tzinfo=timezone.utc),  # in the past
        )
        db_session.add(log)
        db_session.commit()

        count = retry_failed_notifications(db_session)
        assert count == 1
        mock_send.assert_called_once()
        assert log.status == "sent"


class TestSlackAPI:
    """API tests for Slack channel creation."""

    def test_create_slack_channel(self, api_client):
        resp = api_client.post("/api/channels", json={
            "name": "Slack Compliance",
            "channel_type": "slack",
            "webhook_url": "https://hooks.slack.com/services/T123/B456/xxx",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["channel_type"] == "slack"
        assert data["name"] == "Slack Compliance"

    def test_create_slack_bad_url(self, api_client):
        resp = api_client.post("/api/channels", json={
            "name": "Bad Slack",
            "channel_type": "slack",
            "webhook_url": "https://example.com/not-slack",
        })
        assert resp.status_code == 400
        assert "hooks.slack.com" in resp.json()["detail"]

    def test_create_slack_missing_url(self, api_client):
        resp = api_client.post("/api/channels", json={
            "name": "No URL Slack",
            "channel_type": "slack",
        })
        assert resp.status_code == 400
        assert "webhook_url required" in resp.json()["detail"]


class TestSlackDashboard:
    """Dashboard tests for Slack channel creation."""

    def test_create_slack_channel_dashboard(self, client):
        resp = client.post("/channels", data={
            "name": "Slack Dashboard",
            "channel_type": "slack",
            "webhook_url": "https://hooks.slack.com/services/T/B/xxx",
            "webhook_secret": "",
            "email_address": "",
            "min_relevance_score": "",
            "agency_filter": "",
            "topic_filter": "",
        })
        assert resp.status_code == 200
        assert "Slack Dashboard" in resp.text

    def test_create_slack_bad_url_dashboard(self, client):
        resp = client.post("/channels", data={
            "name": "Bad Slack",
            "channel_type": "slack",
            "webhook_url": "https://example.com/not-slack",
            "webhook_secret": "",
            "email_address": "",
            "min_relevance_score": "",
            "agency_filter": "",
            "topic_filter": "",
        })
        assert resp.status_code == 200
        assert "hooks.slack.com" in resp.text

    def test_create_slack_missing_url_dashboard(self, client):
        resp = client.post("/channels", data={
            "name": "Missing URL Slack",
            "channel_type": "slack",
            "webhook_url": "",
            "webhook_secret": "",
            "email_address": "",
            "min_relevance_score": "",
            "agency_filter": "",
            "topic_filter": "",
        })
        assert resp.status_code == 200
        assert "Webhook URL is required" in resp.text

    def test_slack_shows_in_channel_list(self, client):
        client.post("/channels", data={
            "name": "Visible Slack",
            "channel_type": "slack",
            "webhook_url": "https://hooks.slack.com/services/T/B/xxx",
            "webhook_secret": "",
            "email_address": "",
            "min_relevance_score": "",
            "agency_filter": "",
            "topic_filter": "",
        })
        resp = client.get("/channels")
        assert resp.status_code == 200
        assert "Visible Slack" in resp.text
        assert "slack" in resp.text.lower()


# =============================================================================
# Phase 3: Channel Test Button
# =============================================================================


class TestTestButton:
    """Dashboard POST /channels/{id}/test."""

    @patch("regulatory_alerts.core.notifier._send_webhook")
    def test_test_webhook_success(self, mock_send, client, seeded_channel):
        mock_send.return_value = (True, "")
        resp = client.post(f"/channels/{seeded_channel}/test")
        assert resp.status_code == 200
        assert "successfully" in resp.text.lower()

    @patch("regulatory_alerts.core.notifier._send_webhook")
    def test_test_failure_shows_error(self, mock_send, client, seeded_channel):
        mock_send.return_value = (False, "Connection refused")
        resp = client.post(f"/channels/{seeded_channel}/test")
        assert resp.status_code == 200
        assert "Connection refused" in resp.text

    @patch("regulatory_alerts.core.notifier._send_slack")
    def test_test_slack_channel(self, mock_send, client):
        mock_send.return_value = (True, "")

        # Create a slack channel
        client.post("/channels", data={
            "name": "Slack To Test",
            "channel_type": "slack",
            "webhook_url": "https://hooks.slack.com/services/T/B/xxx",
            "webhook_secret": "",
            "email_address": "",
            "min_relevance_score": "",
            "agency_filter": "",
            "topic_filter": "",
        })
        with _TestSession() as session:
            ch = session.query(NotificationChannel).filter_by(name="Slack To Test").first()
            ch_id = ch.id

        resp = client.post(f"/channels/{ch_id}/test")
        assert resp.status_code == 200
        assert "successfully" in resp.text.lower()
        mock_send.assert_called_once()

    @patch("regulatory_alerts.core.notifier.send_raw_email")
    def test_test_email_channel(self, mock_send, client):
        mock_send.return_value = (True, "")

        client.post("/channels", data={
            "name": "Email To Test",
            "channel_type": "email",
            "webhook_url": "",
            "webhook_secret": "",
            "email_address": "test@example.com",
            "min_relevance_score": "",
            "agency_filter": "",
            "topic_filter": "",
        })
        with _TestSession() as session:
            ch = session.query(NotificationChannel).filter_by(name="Email To Test").first()
            ch_id = ch.id

        resp = client.post(f"/channels/{ch_id}/test")
        assert resp.status_code == 200
        assert "successfully" in resp.text.lower()

    def test_test_not_found(self, client):
        resp = client.post("/channels/9999/test")
        assert resp.status_code == 404

    def test_test_cross_user_404(self, client, seeded_channel):
        import bcrypt, secrets
        with _TestSession() as session:
            other_user = User(
                email="other2@example.com",
                hashed_password=bcrypt.hashpw(b"pass", bcrypt.gensalt()).decode(),
                api_key=secrets.token_hex(16),
            )
            session.add(other_user)
            session.flush()
            channel = session.get(NotificationChannel, seeded_channel)
            channel.user_id = other_user.id
            session.commit()

        resp = client.post(f"/channels/{seeded_channel}/test")
        assert resp.status_code == 404

    def test_test_disabled_channel_error(self, client, seeded_channel):
        """Testing a disabled channel should show an error."""
        # Disable the channel
        client.post(f"/channels/{seeded_channel}/toggle")

        resp = client.post(f"/channels/{seeded_channel}/test")
        assert resp.status_code == 200
        assert "disabled" in resp.text.lower() or "enable" in resp.text.lower()

    def test_send_test_notification_dispatches(self, seed_alert, seed_document):
        """send_test_notification should call _dispatch_notification."""
        from regulatory_alerts.core.notifier import send_test_notification

        channel = NotificationChannel(
            name="Test Dispatch", channel_type="webhook",
            webhook_url="https://example.com/hook",
        )
        with patch("regulatory_alerts.core.notifier._dispatch_notification") as mock_disp:
            mock_disp.return_value = (True, "")
            success, _ = send_test_notification(channel, seed_alert, seed_document)
            mock_disp.assert_called_once_with(channel, seed_alert, seed_document)
            assert success is True


# =============================================================================
# Phase 4: Notification History
# =============================================================================


class TestNotificationHistoryDashboard:
    """Dashboard GET /notifications."""

    def test_page_returns_html(self, client):
        resp = client.get("/notifications")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "Notification History" in resp.text

    def test_requires_login(self):
        with patch("regulatory_alerts.api.get_sync_engine", _mock_sync_engine), \
             patch("regulatory_alerts.api.get_sync_session_factory", _mock_sync_session_factory), \
             patch("regulatory_alerts.rate_limit.get_sync_session_factory", _mock_sync_session_factory), \
             patch("regulatory_alerts.dashboard.get_sync_session_factory", _mock_sync_session_factory), \
             patch("regulatory_alerts.auth.get_sync_session_factory", _mock_sync_session_factory), \
             patch("regulatory_alerts.billing.get_sync_session_factory", _mock_sync_session_factory), \
             patch("regulatory_alerts.core.scheduler.start_scheduler", return_value=MagicMock()), \
             patch("regulatory_alerts.core.scheduler.stop_scheduler"), \
             patch("regulatory_alerts.observability.configure_logging"):
            from regulatory_alerts.api import app
            with TestClient(app, follow_redirects=False) as c:
                resp = c.get("/notifications")
                assert resp.status_code == 302
                assert "/login" in resp.headers.get("location", "")

    def test_empty_state(self, client):
        resp = client.get("/notifications")
        assert resp.status_code == 200
        assert "No notification logs yet" in resp.text

    def test_shows_logs(self, client, seeded_data_with_logs):
        resp = client.get("/notifications")
        assert resp.status_code == 200
        assert "sent" in resp.text.lower()
        assert "failed" in resp.text.lower()
        assert "Log Test Channel" in resp.text

    def test_filter_by_channel(self, client, seeded_data_with_logs):
        ch_id = seeded_data_with_logs["channel"].id
        resp = client.get(f"/notifications?channel_id={ch_id}")
        assert resp.status_code == 200
        assert "Log Test Channel" in resp.text

    def test_filter_by_status(self, client, seeded_data_with_logs):
        resp = client.get("/notifications?status=sent")
        assert resp.status_code == 200
        # Should show sent logs
        assert "sent" in resp.text.lower()

    def test_htmx_returns_fragment(self, client, seeded_data_with_logs):
        resp = client.get("/notifications", headers={"HX-Request": "true"})
        assert resp.status_code == 200
        # Should NOT contain full HTML wrapper
        assert "<!DOCTYPE html>" not in resp.text
        # But should contain log data
        assert "Log Test Channel" in resp.text

    def test_history_nav_link_in_base(self, client):
        """The base template should have a History nav link."""
        resp = client.get("/")
        assert resp.status_code == 200
        assert "/notifications" in resp.text
        assert "History" in resp.text


class TestNotificationHistoryAPI:
    """API GET /api/notifications."""

    def test_list_empty(self, api_client):
        resp = api_client.get("/api/notifications")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 0
        assert data["logs"] == []

    def test_list_with_data(self, client, seeded_data_with_logs):
        """Use dashboard client (logged in) to test API with session auth."""
        resp = client.get("/api/notifications")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 2
        assert len(data["logs"]) == 2

        # Check response structure
        log = data["logs"][0]
        assert "channel_name" in log
        assert "status" in log
        assert "retry_count" in log

    def test_filter_by_status_api(self, client, seeded_data_with_logs):
        resp = client.get("/api/notifications?status=sent")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        assert data["logs"][0]["status"] == "sent"

    def test_scoped_to_user(self, client, seeded_data_with_logs):
        """API should only return logs for the user's channels."""
        import bcrypt, secrets
        with _TestSession() as session:
            other_user = User(
                email="other3@example.com",
                hashed_password=bcrypt.hashpw(b"pass", bcrypt.gensalt()).decode(),
                api_key=secrets.token_hex(16),
            )
            session.add(other_user)
            session.flush()
            ch = seeded_data_with_logs["channel"]
            channel = session.get(NotificationChannel, ch.id)
            channel.user_id = other_user.id
            session.commit()

        resp = client.get("/api/notifications")
        assert resp.status_code == 200
        assert resp.json()["count"] == 0
