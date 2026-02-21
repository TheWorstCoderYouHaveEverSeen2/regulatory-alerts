"""Tests for Phase 1-3 improvements:
- Phase 1: Auth rate limiting, list_channels session user scoping, dashboard 404 on cross-user delete
- Phase 2: Notification retry system (model, logic, scheduler integration)
- Phase 3: Consolidated filter logic, asyncio loop reuse
"""

import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

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
from regulatory_alerts.csrf import validate_csrf


async def noop_csrf():
    return None


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


@pytest.fixture(autouse=True)
def _reset_observability_singletons():
    from regulatory_alerts.observability import scheduler_metrics, error_counter, reset_uptime
    scheduler_metrics.reset()
    error_counter.reset()
    reset_uptime()
    yield


@pytest.fixture()
def client():
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


def _create_user(email="test@example.com", password="password123") -> User:
    """Create a user in the test DB and return it."""
    import bcrypt as _bcrypt
    salt = _bcrypt.gensalt()
    hashed = _bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")
    with _TestSession() as session:
        user = User(
            email=email,
            hashed_password=hashed,
            api_key="test-api-key-" + email.split("@")[0],
            is_active=True,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        return user


def _login(client, email="test@example.com", password="password123"):
    """Log in a user via session."""
    return client.post("/login", data={"email": email, "password": password})


def _seed_alert():
    """Create a source, document, and alert. Returns (source, doc, alert)."""
    with _TestSession() as session:
        source = FeedSource(
            name="SEC Test", agency="SEC",
            feed_url="https://www.sec.gov/test.rss", feed_type="rss",
        )
        session.add(source)
        session.flush()

        doc = FeedDocument(
            feed_source_id=source.id, external_id="retry-test-001",
            title="Test Alert", url="https://sec.gov/test",
            published_at=datetime(2026, 2, 15, tzinfo=timezone.utc),
            discovered_at=datetime(2026, 2, 15, tzinfo=timezone.utc),
            agency="SEC", processing_status="completed",
            content_hash="abc123",
        )
        session.add(doc)
        session.flush()

        alert = ProcessedAlert(
            feed_document_id=doc.id,
            summary="Test alert for retry",
            topics='["enforcement"]',
            relevance_score=0.9,
            document_type="enforcement_action",
            ai_model="test-model",
        )
        session.add(alert)
        session.commit()
        session.refresh(source)
        session.refresh(doc)
        session.refresh(alert)
        return source, doc, alert


# ============================================================
# Phase 1: Auth Rate Limiting
# ============================================================

class TestAuthRateLimiting:
    """Rate limits on POST /login (5/min), POST /register (3/min), POST /forgot-password (3/min)."""

    def test_login_rate_limited(self, client):
        """POST /login should be rate limited to 5/minute."""
        _create_user()
        for _ in range(5):
            resp = client.post("/login", data={"email": "test@example.com", "password": "wrong"})
            assert resp.status_code != 429

        resp = client.post("/login", data={"email": "test@example.com", "password": "wrong"})
        assert resp.status_code == 429

    def test_register_rate_limited(self, client):
        """POST /register should be rate limited to 3/minute."""
        for i in range(3):
            resp = client.post("/register", data={
                "email": f"user{i}@example.com",
                "password": "password123",
                "password_confirm": "password123",
            }, follow_redirects=False)
            assert resp.status_code != 429
            # Clear session so rate limiter keys by IP consistently
            client.cookies.clear()

        resp = client.post("/register", data={
            "email": "overflow@example.com",
            "password": "password123",
            "password_confirm": "password123",
        }, follow_redirects=False)
        assert resp.status_code == 429

    def test_forgot_password_rate_limited(self, client):
        """POST /forgot-password should be rate limited to 3/minute."""
        for _ in range(3):
            resp = client.post("/forgot-password", data={"email": "nobody@example.com"})
            assert resp.status_code != 429

        resp = client.post("/forgot-password", data={"email": "nobody@example.com"})
        assert resp.status_code == 429


# ============================================================
# Phase 1: list_channels Session User Scoping
# ============================================================

class TestListChannelsSessionUser:
    """list_channels should filter by session user_id when no API key user is present."""

    def test_list_channels_scoped_to_session_user(self, client):
        """Session-authenticated user should only see their own channels."""
        user1 = _create_user("alice@example.com")
        user2 = _create_user("bob@example.com")

        with _TestSession() as session:
            ch1 = NotificationChannel(
                name="Alice Webhook", channel_type="webhook",
                webhook_url="https://hooks.example.com/alice", user_id=user1.id,
            )
            ch2 = NotificationChannel(
                name="Bob Webhook", channel_type="webhook",
                webhook_url="https://hooks.example.com/bob", user_id=user2.id,
            )
            session.add_all([ch1, ch2])
            session.commit()

        # Log in as alice
        _login(client, "alice@example.com")
        # Since API_KEYS="" (disabled), the API doesn't require auth header.
        # But session user_id should still scope the results.
        resp = client.get("/api/channels")
        assert resp.status_code == 200
        channels = resp.json()
        names = [c["name"] for c in channels]
        assert "Alice Webhook" in names
        assert "Bob Webhook" not in names


# ============================================================
# Phase 1: Dashboard channels_delete 404 for cross-user
# ============================================================

class TestDashboardChannelDelete404:
    """Dashboard DELETE /channels/{id} should return 404 (not 403) for cross-user attempts."""

    def test_cross_user_delete_returns_404(self, client):
        """Attempting to delete another user's channel returns 404."""
        user1 = _create_user("alice@example.com")
        user2 = _create_user("bob@example.com")

        with _TestSession() as session:
            ch = NotificationChannel(
                name="Bob's Channel", channel_type="webhook",
                webhook_url="https://hooks.example.com/bob", user_id=user2.id,
            )
            session.add(ch)
            session.commit()
            channel_id = ch.id

        # Log in as alice
        _login(client, "alice@example.com")
        resp = client.delete(f"/channels/{channel_id}")
        assert resp.status_code == 404


# ============================================================
# Phase 2: Notification Retry — Model
# ============================================================

class TestNotificationRetryModel:
    """NotificationLog should have retry_count and next_retry_at columns."""

    def test_retry_columns_exist(self):
        """NotificationLog has retry_count (default 0) and next_retry_at (nullable)."""
        _, _, alert = _seed_alert()
        with _TestSession() as session:
            ch = NotificationChannel(
                name="Test Channel", channel_type="webhook",
                webhook_url="https://hooks.example.com/test",
            )
            session.add(ch)
            session.flush()

            log = NotificationLog(
                channel_id=ch.id, alert_id=alert.id,
                status="failed", error_message="timeout",
            )
            session.add(log)
            session.commit()
            session.refresh(log)

            assert log.retry_count == 0
            assert log.next_retry_at is None

    def test_retry_columns_can_be_set(self):
        """retry_count and next_retry_at can be updated."""
        _, _, alert = _seed_alert()
        now = datetime.now(timezone.utc)
        with _TestSession() as session:
            ch = NotificationChannel(
                name="Test Channel", channel_type="webhook",
                webhook_url="https://hooks.example.com/test",
            )
            session.add(ch)
            session.flush()

            log = NotificationLog(
                channel_id=ch.id, alert_id=alert.id,
                status="failed", retry_count=2,
                next_retry_at=now + timedelta(hours=2),
            )
            session.add(log)
            session.commit()
            session.refresh(log)

            assert log.retry_count == 2
            assert log.next_retry_at is not None


# ============================================================
# Phase 2: Notification Retry — Logic
# ============================================================

class TestNotificationRetryLogic:
    """Tests for retry_failed_notifications() in notifier.py."""

    def test_next_retry_time_backoff(self):
        """Retry backoff: 5min, 30min, 2hr."""
        from regulatory_alerts.core.notifier import _next_retry_time

        now = datetime(2026, 2, 15, 12, 0, 0, tzinfo=timezone.utc)
        t1 = _next_retry_time(now, 0)
        assert t1 == now + timedelta(minutes=5)

        t2 = _next_retry_time(now, 1)
        assert t2 == now + timedelta(minutes=30)

        t3 = _next_retry_time(now, 2)
        assert t3 == now + timedelta(minutes=120)

    def test_next_retry_time_max(self):
        """After MAX_RETRIES, returns None (give up)."""
        from regulatory_alerts.core.notifier import _next_retry_time, MAX_RETRIES

        now = datetime(2026, 2, 15, 12, 0, 0, tzinfo=timezone.utc)
        result = _next_retry_time(now, MAX_RETRIES)
        assert result is None

    def test_retry_succeeds(self):
        """Failed notification retried successfully transitions to 'sent'."""
        from regulatory_alerts.core.notifier import retry_failed_notifications

        _, _, alert = _seed_alert()
        past = datetime.now(timezone.utc) - timedelta(hours=1)

        with _TestSession() as session:
            ch = NotificationChannel(
                name="Retry Channel", channel_type="webhook",
                webhook_url="https://hooks.example.com/retry", enabled=True,
            )
            session.add(ch)
            session.flush()

            log = NotificationLog(
                channel_id=ch.id, alert_id=alert.id,
                status="failed", retry_count=0,
                next_retry_at=past, error_message="timeout",
            )
            session.add(log)
            session.commit()
            log_id = log.id

        with _TestSession() as session, \
             patch("regulatory_alerts.core.notifier._send_webhook", return_value=(True, "")):
            count = retry_failed_notifications(session)
            session.commit()

            assert count == 1
            log = session.get(NotificationLog, log_id)
            assert log.status == "sent"
            assert log.retry_count == 1
            assert log.next_retry_at is None
            assert log.sent_at is not None

    def test_retry_fails_increments_count(self):
        """Failed retry increments retry_count and sets next_retry_at."""
        from regulatory_alerts.core.notifier import retry_failed_notifications

        _, _, alert = _seed_alert()
        past = datetime.now(timezone.utc) - timedelta(hours=1)

        with _TestSession() as session:
            ch = NotificationChannel(
                name="Retry Channel", channel_type="webhook",
                webhook_url="https://hooks.example.com/retry", enabled=True,
            )
            session.add(ch)
            session.flush()

            log = NotificationLog(
                channel_id=ch.id, alert_id=alert.id,
                status="failed", retry_count=0,
                next_retry_at=past, error_message="timeout",
            )
            session.add(log)
            session.commit()
            log_id = log.id

        with _TestSession() as session, \
             patch("regulatory_alerts.core.notifier._send_webhook", return_value=(False, "still broken")):
            count = retry_failed_notifications(session)
            session.commit()

            assert count == 0
            log = session.get(NotificationLog, log_id)
            assert log.status == "failed"
            assert log.retry_count == 1
            assert log.next_retry_at is not None
            assert log.error_message == "still broken"

    def test_retry_gives_up_after_max_retries(self):
        """After MAX_RETRIES, next_retry_at is set to None (no more retries)."""
        from regulatory_alerts.core.notifier import retry_failed_notifications, MAX_RETRIES

        _, _, alert = _seed_alert()
        past = datetime.now(timezone.utc) - timedelta(hours=1)

        with _TestSession() as session:
            ch = NotificationChannel(
                name="Retry Channel", channel_type="webhook",
                webhook_url="https://hooks.example.com/retry", enabled=True,
            )
            session.add(ch)
            session.flush()

            log = NotificationLog(
                channel_id=ch.id, alert_id=alert.id,
                status="failed", retry_count=MAX_RETRIES - 1,
                next_retry_at=past,
            )
            session.add(log)
            session.commit()
            log_id = log.id

        with _TestSession() as session, \
             patch("regulatory_alerts.core.notifier._send_webhook", return_value=(False, "permanent")):
            retry_failed_notifications(session)
            session.commit()

            log = session.get(NotificationLog, log_id)
            assert log.retry_count == MAX_RETRIES
            assert log.next_retry_at is None  # Gave up

    def test_retry_skips_future_scheduled(self):
        """Notifications with next_retry_at in the future are not retried yet."""
        from regulatory_alerts.core.notifier import retry_failed_notifications

        _, _, alert = _seed_alert()
        future = datetime.now(timezone.utc) + timedelta(hours=1)

        with _TestSession() as session:
            ch = NotificationChannel(
                name="Retry Channel", channel_type="webhook",
                webhook_url="https://hooks.example.com/retry", enabled=True,
            )
            session.add(ch)
            session.flush()

            log = NotificationLog(
                channel_id=ch.id, alert_id=alert.id,
                status="failed", retry_count=0,
                next_retry_at=future,
            )
            session.add(log)
            session.commit()

        with _TestSession() as session:
            count = retry_failed_notifications(session)
            assert count == 0

    def test_retry_skips_disabled_channel(self):
        """Disabled channels get their retry logs permanently failed (no more retries)."""
        from regulatory_alerts.core.notifier import retry_failed_notifications

        _, _, alert = _seed_alert()
        past = datetime.now(timezone.utc) - timedelta(hours=1)

        with _TestSession() as session:
            ch = NotificationChannel(
                name="Disabled Channel", channel_type="webhook",
                webhook_url="https://hooks.example.com/retry", enabled=False,
            )
            session.add(ch)
            session.flush()

            log = NotificationLog(
                channel_id=ch.id, alert_id=alert.id,
                status="failed", retry_count=0,
                next_retry_at=past,
            )
            session.add(log)
            session.commit()
            log_id = log.id

        with _TestSession() as session:
            count = retry_failed_notifications(session)
            session.commit()

            assert count == 0
            log = session.get(NotificationLog, log_id)
            assert log.next_retry_at is None  # Permanently failed

    def test_new_failure_sets_next_retry(self):
        """notify_new_alerts sets next_retry_at on failure."""
        from regulatory_alerts.core.notifier import notify_new_alerts

        _, _, alert = _seed_alert()

        with _TestSession() as session:
            ch = NotificationChannel(
                name="Failing Channel", channel_type="webhook",
                webhook_url="https://hooks.example.com/fail", enabled=True,
            )
            session.add(ch)
            session.commit()

            # Reload alert with feed_document relationship
            alert = session.get(ProcessedAlert, alert.id)
            alert.feed_document = session.get(FeedDocument, alert.feed_document_id)

            with patch("regulatory_alerts.core.notifier._send_webhook", return_value=(False, "timeout")):
                notify_new_alerts(session, [alert])
                session.commit()

            from sqlalchemy import select
            log = session.scalars(
                select(NotificationLog).where(NotificationLog.channel_id == ch.id)
            ).first()
            assert log is not None
            assert log.status == "failed"
            assert log.retry_count == 0
            assert log.next_retry_at is not None


# ============================================================
# Phase 3: Consolidated Filter Logic
# ============================================================

class TestConsolidatedFilters:
    """API endpoints should use query_updates() from dashboard.py."""

    def test_api_list_updates_uses_shared_filter(self, client):
        """GET /api/updates should use the same filter logic as the dashboard."""
        _seed_alert()
        resp = client.get("/api/updates")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1

    def test_api_list_updates_topic_filter(self, client):
        """GET /api/updates?topic=enforcement should filter correctly."""
        _seed_alert()
        resp = client.get("/api/updates?topic=enforcement")
        assert resp.status_code == 200
        assert resp.json()["count"] == 1

        resp = client.get("/api/updates?topic=nonexistent")
        assert resp.status_code == 200
        assert resp.json()["count"] == 0

    def test_api_export_uses_shared_filter(self, client):
        """GET /api/updates/export should produce CSV data."""
        _seed_alert()
        resp = client.get("/api/updates/export")
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]
        content = resp.content.decode("utf-8-sig")
        assert "Test Alert" in content


# ============================================================
# Phase 3: Asyncio Event Loop Reuse
# ============================================================

class TestAsyncioLoopReuse:
    """Scheduler should create a single event loop for all sources."""

    def test_single_loop_for_multiple_sources(self):
        """_run_fetch_cycle should create one event loop, not one per source."""
        from regulatory_alerts.core.scheduler import _run_fetch_cycle
        from regulatory_alerts.observability import scheduler_metrics, error_counter, reset_uptime

        # Create two sources
        with _TestSession() as session:
            s1 = FeedSource(
                name="SEC", agency="SEC",
                feed_url="https://sec.gov/rss", feed_type="rss", enabled=True,
            )
            s2 = FeedSource(
                name="CFTC", agency="CFTC",
                feed_url="https://cftc.gov/press", feed_type="html", enabled=True,
            )
            session.add_all([s1, s2])
            session.commit()

        loop_mock = MagicMock()
        loop_mock.run_until_complete.return_value = []  # No entries

        with patch("regulatory_alerts.core.scheduler.get_sync_session_factory", _mock_sync_session_factory), \
             patch("regulatory_alerts.core.scheduler.asyncio.new_event_loop", return_value=loop_mock):
            _run_fetch_cycle()

        # Should have been called exactly once (one loop for both sources)
        # But run_until_complete called twice (once per source)
        assert loop_mock.run_until_complete.call_count == 2
        loop_mock.close.assert_called_once()


# ============================================================
# Migration 006
# ============================================================

class TestMigration006:
    """Migration 006 adds retry_count and next_retry_at columns."""

    def test_notification_log_table_has_retry_columns(self):
        """Verify the notification_logs table has the new columns."""
        from sqlalchemy import inspect
        inspector = inspect(_test_engine)
        columns = {c["name"] for c in inspector.get_columns("notification_logs")}
        assert "retry_count" in columns
        assert "next_retry_at" in columns
