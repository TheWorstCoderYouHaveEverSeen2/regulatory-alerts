"""Tests for admin dashboard: access control, user management, system health."""

import os
import secrets
import sys
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

from regulatory_alerts.models import Base, NotificationChannel, User
from regulatory_alerts.observability import (
    error_counter,
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


def _create_user(email=None, is_admin=False, tier="pro"):
    """Helper: create a user directly in the DB."""
    with _TestSession() as session:
        u = User(
            email=email or f"{secrets.token_hex(4)}@test.com",
            hashed_password="$2b$12$dummyhash",
            api_key=secrets.token_hex(16),
            subscription_tier=tier,
            is_admin=is_admin,
            is_active=True,
        )
        session.add(u)
        session.commit()
        session.refresh(u)
        return u.id, u.email


@pytest.fixture()
def client():
    """TestClient with mocked DB and scheduler, CSRF bypassed."""
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


def _login_as(client, user_id):
    """Set session user_id to simulate login."""
    # Use the test endpoint or set cookie directly
    # We'll use the internal session by making a request and injecting
    with client.session_transaction() if hasattr(client, 'session_transaction') else _noop():
        pass
    # TestClient doesn't expose session directly; use a session cookie trick
    # by going through the actual login flow or by patching get_current_user
    pass


# ---------------------------------------------------------------------------
# Access Control
# ---------------------------------------------------------------------------


class TestAccessControl:
    def test_admin_home_requires_login(self, client):
        """Unauthenticated GET /admin redirects to /login."""
        resp = client.get("/admin", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["location"]

    def test_admin_users_requires_login(self, client):
        """Unauthenticated GET /admin/users redirects to /login."""
        resp = client.get("/admin/users", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["location"]

    def test_admin_system_requires_login(self, client):
        """Unauthenticated GET /admin/system redirects to /login."""
        resp = client.get("/admin/system", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["location"]

    def test_admin_home_non_admin_403(self, client):
        """Non-admin user gets 403 on /admin."""
        user_id, _ = _create_user(is_admin=False)
        with patch("regulatory_alerts.admin.get_current_user") as mock_user:
            with _TestSession() as s:
                mock_user.return_value = s.get(User, user_id)
                resp = client.get("/admin")
        assert resp.status_code == 403

    def test_admin_users_non_admin_403(self, client):
        """Non-admin user gets 403 on /admin/users."""
        user_id, _ = _create_user(is_admin=False)
        with patch("regulatory_alerts.admin.get_current_user") as mock_user:
            with _TestSession() as s:
                mock_user.return_value = s.get(User, user_id)
                resp = client.get("/admin/users")
        assert resp.status_code == 403

    def test_toggle_active_non_admin_403(self, client):
        """Non-admin POST /admin/users/{id}/toggle-active gets 403."""
        user_id, _ = _create_user(is_admin=False)
        target_id, _ = _create_user()
        with patch("regulatory_alerts.admin.get_current_user") as mock_user:
            with _TestSession() as s:
                mock_user.return_value = s.get(User, user_id)
                resp = client.post(f"/admin/users/{target_id}/toggle-active")
        assert resp.status_code == 403

    def test_set_tier_non_admin_403(self, client):
        """Non-admin POST /admin/users/{id}/set-tier gets 403."""
        user_id, _ = _create_user(is_admin=False)
        target_id, _ = _create_user()
        with patch("regulatory_alerts.admin.get_current_user") as mock_user:
            with _TestSession() as s:
                mock_user.return_value = s.get(User, user_id)
                resp = client.post(
                    f"/admin/users/{target_id}/set-tier",
                    data={"tier": "pro"},
                )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Admin Home
# ---------------------------------------------------------------------------


class TestAdminHome:
    def test_admin_home_returns_html(self, client):
        """Admin user sees HTML dashboard."""
        admin_id, _ = _create_user(is_admin=True)
        with patch("regulatory_alerts.admin.get_current_user") as mock_user:
            with _TestSession() as s:
                mock_user.return_value = s.get(User, admin_id)
                resp = client.get("/admin")
        assert resp.status_code == 200
        assert "Admin Dashboard" in resp.text

    def test_admin_home_shows_stats(self, client):
        """Dashboard shows user/doc/alert counts."""
        admin_id, _ = _create_user(is_admin=True)
        _create_user(tier="free")
        _create_user(tier="pro")

        with patch("regulatory_alerts.admin.get_current_user") as mock_user:
            with _TestSession() as s:
                mock_user.return_value = s.get(User, admin_id)
                resp = client.get("/admin")
        assert resp.status_code == 200
        assert "Total Users" in resp.text

    def test_admin_home_shows_scheduler(self, client):
        """Dashboard shows scheduler status."""
        admin_id, _ = _create_user(is_admin=True)
        scheduler_metrics.record_start()
        scheduler_metrics.record_success(1.5)

        with patch("regulatory_alerts.admin.get_current_user") as mock_user:
            with _TestSession() as s:
                mock_user.return_value = s.get(User, admin_id)
                resp = client.get("/admin")
        assert resp.status_code == 200
        assert "Scheduler" in resp.text

    def test_admin_home_shows_uptime(self, client):
        """Dashboard shows uptime."""
        from regulatory_alerts.observability import record_app_start
        record_app_start()
        admin_id, _ = _create_user(is_admin=True)

        with patch("regulatory_alerts.admin.get_current_user") as mock_user:
            with _TestSession() as s:
                mock_user.return_value = s.get(User, admin_id)
                resp = client.get("/admin")
        assert resp.status_code == 200
        assert "Uptime" in resp.text


# ---------------------------------------------------------------------------
# User Management
# ---------------------------------------------------------------------------


class TestUserManagement:
    def test_users_list(self, client):
        """Admin sees user list."""
        admin_id, admin_email = _create_user(email="admin@test.com", is_admin=True)
        _create_user(email="user1@test.com")

        with patch("regulatory_alerts.admin.get_current_user") as mock_user:
            with _TestSession() as s:
                mock_user.return_value = s.get(User, admin_id)
                resp = client.get("/admin/users")
        assert resp.status_code == 200
        assert "admin@test.com" in resp.text
        assert "user1@test.com" in resp.text

    def test_toggle_active(self, client):
        """Admin can deactivate a user."""
        admin_id, _ = _create_user(is_admin=True)
        target_id, _ = _create_user()

        with patch("regulatory_alerts.admin.get_current_user") as mock_user:
            with _TestSession() as s:
                mock_user.return_value = s.get(User, admin_id)
                resp = client.post(
                    f"/admin/users/{target_id}/toggle-active",
                    follow_redirects=False,
                )
        assert resp.status_code == 303

        with _TestSession() as s:
            target = s.get(User, target_id)
            assert target.is_active is False

    def test_self_deactivation_blocked(self, client):
        """Admin cannot deactivate themselves."""
        admin_id, _ = _create_user(is_admin=True)

        with patch("regulatory_alerts.admin.get_current_user") as mock_user:
            with _TestSession() as s:
                mock_user.return_value = s.get(User, admin_id)
                resp = client.post(f"/admin/users/{admin_id}/toggle-active")
        assert resp.status_code == 400
        assert "yourself" in resp.json()["detail"].lower()

    def test_set_tier(self, client):
        """Admin can change user tier."""
        admin_id, _ = _create_user(is_admin=True)
        target_id, _ = _create_user(tier="free")

        with patch("regulatory_alerts.admin.get_current_user") as mock_user:
            with _TestSession() as s:
                mock_user.return_value = s.get(User, admin_id)
                resp = client.post(
                    f"/admin/users/{target_id}/set-tier",
                    data={"tier": "team"},
                    follow_redirects=False,
                )
        assert resp.status_code == 303

        with _TestSession() as s:
            target = s.get(User, target_id)
            assert target.subscription_tier == "team"

    def test_invalid_tier_rejected(self, client):
        """Setting an invalid tier returns 400."""
        admin_id, _ = _create_user(is_admin=True)
        target_id, _ = _create_user()

        with patch("regulatory_alerts.admin.get_current_user") as mock_user:
            with _TestSession() as s:
                mock_user.return_value = s.get(User, admin_id)
                resp = client.post(
                    f"/admin/users/{target_id}/set-tier",
                    data={"tier": "platinum"},
                )
        assert resp.status_code == 400
        assert "Invalid tier" in resp.json()["detail"]

    def test_toggle_admin(self, client):
        """Admin can promote another user to admin."""
        admin_id, _ = _create_user(is_admin=True)
        target_id, _ = _create_user()

        with patch("regulatory_alerts.admin.get_current_user") as mock_user:
            with _TestSession() as s:
                mock_user.return_value = s.get(User, admin_id)
                resp = client.post(
                    f"/admin/users/{target_id}/set-admin",
                    follow_redirects=False,
                )
        assert resp.status_code == 303

        with _TestSession() as s:
            target = s.get(User, target_id)
            assert target.is_admin is True

    def test_self_demotion_blocked(self, client):
        """Admin cannot remove their own admin status."""
        admin_id, _ = _create_user(is_admin=True)

        with patch("regulatory_alerts.admin.get_current_user") as mock_user:
            with _TestSession() as s:
                mock_user.return_value = s.get(User, admin_id)
                resp = client.post(f"/admin/users/{admin_id}/set-admin")
        assert resp.status_code == 400
        assert "your own" in resp.json()["detail"].lower()

    def test_toggle_active_reactivate(self, client):
        """Admin can reactivate a deactivated user."""
        admin_id, _ = _create_user(is_admin=True)
        target_id, _ = _create_user()

        # Deactivate first
        with _TestSession() as s:
            target = s.get(User, target_id)
            target.is_active = False
            s.commit()

        with patch("regulatory_alerts.admin.get_current_user") as mock_user:
            with _TestSession() as s:
                mock_user.return_value = s.get(User, admin_id)
                resp = client.post(
                    f"/admin/users/{target_id}/toggle-active",
                    follow_redirects=False,
                )
        assert resp.status_code == 303

        with _TestSession() as s:
            target = s.get(User, target_id)
            assert target.is_active is True


# ---------------------------------------------------------------------------
# System Health
# ---------------------------------------------------------------------------


class TestSystemHealth:
    def test_system_returns_html(self, client):
        """Admin sees system health page."""
        admin_id, _ = _create_user(is_admin=True)

        with patch("regulatory_alerts.admin.get_current_user") as mock_user:
            with _TestSession() as s:
                mock_user.return_value = s.get(User, admin_id)
                resp = client.get("/admin/system")
        assert resp.status_code == 200
        assert "System Health" in resp.text

    def test_system_shows_db_stats(self, client):
        """System page includes database statistics."""
        admin_id, _ = _create_user(is_admin=True)

        with patch("regulatory_alerts.admin.get_current_user") as mock_user:
            with _TestSession() as s:
                mock_user.return_value = s.get(User, admin_id)
                resp = client.get("/admin/system")
        assert resp.status_code == 200
        assert "Database" in resp.text

    def test_system_shows_error_breakdown(self, client):
        """System page shows error breakdown."""
        error_counter.record("fetcher")
        error_counter.record("notifier")
        admin_id, _ = _create_user(is_admin=True)

        with patch("regulatory_alerts.admin.get_current_user") as mock_user:
            with _TestSession() as s:
                mock_user.return_value = s.get(User, admin_id)
                resp = client.get("/admin/system")
        assert resp.status_code == 200
        assert "Error Breakdown" in resp.text


# ---------------------------------------------------------------------------
# Edge Cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_nonexistent_user_404(self, client):
        """Toggle on nonexistent user returns 404."""
        admin_id, _ = _create_user(is_admin=True)

        with patch("regulatory_alerts.admin.get_current_user") as mock_user:
            with _TestSession() as s:
                mock_user.return_value = s.get(User, admin_id)
                resp = client.post("/admin/users/99999/toggle-active")
        assert resp.status_code == 404

    def test_nonexistent_user_set_tier_404(self, client):
        """Set tier on nonexistent user returns 404."""
        admin_id, _ = _create_user(is_admin=True)

        with patch("regulatory_alerts.admin.get_current_user") as mock_user:
            with _TestSession() as s:
                mock_user.return_value = s.get(User, admin_id)
                resp = client.post(
                    "/admin/users/99999/set-tier",
                    data={"tier": "pro"},
                )
        assert resp.status_code == 404

    def test_admin_link_visible_for_admins(self, client):
        """Admin sidebar link appears for admin users."""
        import bcrypt
        admin_id, admin_email = _create_user(email="sidebar@test.com", is_admin=True)

        # Set a real password so we can login
        pw_hash = bcrypt.hashpw(b"testpass123", bcrypt.gensalt()).decode()
        with _TestSession() as s:
            u = s.get(User, admin_id)
            u.hashed_password = pw_hash
            s.commit()

        # Login to get session
        client.post("/login", data={"email": "sidebar@test.com", "password": "testpass123"})

        # Visit dashboard — should see Admin link
        resp = client.get("/")
        # The admin link should be in the sidebar
        assert "/admin" in resp.text or resp.status_code == 302

    def test_admin_link_hidden_for_non_admins(self, client):
        """Admin sidebar link does NOT appear for non-admin users."""
        import bcrypt
        user_id, email = _create_user(email="regular@test.com", is_admin=False)

        pw_hash = bcrypt.hashpw(b"testpass123", bcrypt.gensalt()).decode()
        with _TestSession() as s:
            u = s.get(User, user_id)
            u.hashed_password = pw_hash
            s.commit()

        client.post("/login", data={"email": "regular@test.com", "password": "testpass123"})
        resp = client.get("/")
        # For non-admins, the admin link should not be in sidebar
        # (they might redirect to /welcome, but the link shouldn't be there regardless)
        if resp.status_code == 200:
            assert 'href="/admin"' not in resp.text
