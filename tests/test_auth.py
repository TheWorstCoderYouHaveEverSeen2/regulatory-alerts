"""Tests for authentication routes and session management."""

import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select
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

from regulatory_alerts.models import Base, User, NotificationChannel


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
    """Unauthenticated client — no auto-login."""
    from regulatory_alerts.csrf import validate_csrf
    from tests.conftest import noop_csrf

    with patch("regulatory_alerts.api.get_sync_engine", _mock_sync_engine), \
         patch("regulatory_alerts.api.get_sync_session_factory", _mock_sync_session_factory), \
         patch("regulatory_alerts.rate_limit.get_sync_session_factory", _mock_sync_session_factory), \
         patch("regulatory_alerts.dashboard.get_sync_session_factory", _mock_sync_session_factory), \
         patch("regulatory_alerts.auth.get_sync_session_factory", _mock_sync_session_factory), \
         patch("regulatory_alerts.admin.get_sync_session_factory", _mock_sync_session_factory), \
         patch("regulatory_alerts.core.scheduler.start_scheduler", return_value=MagicMock()), \
         patch("regulatory_alerts.core.scheduler.stop_scheduler"):
        from regulatory_alerts.api import app
        app.dependency_overrides[validate_csrf] = noop_csrf
        with TestClient(app) as c:
            yield c
        app.dependency_overrides.pop(validate_csrf, None)


@pytest.fixture()
def logged_in_client(client):
    """Client that has registered and is logged in."""
    client.post("/register", data={
        "email": "user@example.com",
        "password": "testpass123",
        "password_confirm": "testpass123",
    })
    return client


# --- Registration ---

class TestRegistration:
    def test_register_page_returns_html(self, client):
        resp = client.get("/register")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "Create your account" in resp.text

    def test_register_creates_user(self, client):
        resp = client.post("/register", data={
            "email": "newuser@example.com",
            "password": "securepass1",
            "password_confirm": "securepass1",
        }, follow_redirects=False)
        # Should redirect to onboarding welcome page
        assert resp.status_code == 302
        assert resp.headers["location"] == "/welcome"

        # User should exist in DB
        with _TestSession() as session:
            user = session.scalars(
                select(User).where(User.email == "newuser@example.com")
            ).first()
            assert user is not None
            assert user.api_key  # auto-generated
            assert user.is_active is True

    def test_register_duplicate_email(self, client):
        # Register first time
        client.post("/register", data={
            "email": "dup@example.com",
            "password": "password123",
            "password_confirm": "password123",
        })
        # Register again with same email
        resp = client.post("/register", data={
            "email": "dup@example.com",
            "password": "password456",
            "password_confirm": "password456",
        })
        assert resp.status_code == 200
        assert "already exists" in resp.text

    def test_register_password_mismatch(self, client):
        resp = client.post("/register", data={
            "email": "user@example.com",
            "password": "password123",
            "password_confirm": "different456",
        })
        assert resp.status_code == 200
        assert "do not match" in resp.text

    def test_register_short_password(self, client):
        resp = client.post("/register", data={
            "email": "user@example.com",
            "password": "short",
            "password_confirm": "short",
        })
        assert resp.status_code == 200
        assert "at least 8" in resp.text


# --- Login ---

class TestLogin:
    def test_login_page_returns_html(self, client):
        resp = client.get("/login")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "Sign in" in resp.text

    def test_login_valid_credentials(self, client):
        # Register first
        client.post("/register", data={
            "email": "login@example.com",
            "password": "password123",
            "password_confirm": "password123",
        })
        # Logout
        client.post("/logout")
        # Login
        resp = client.post("/login", data={
            "email": "login@example.com",
            "password": "password123",
        }, follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["location"] == "/"

    def test_login_invalid_credentials(self, client):
        resp = client.post("/login", data={
            "email": "nobody@example.com",
            "password": "wrongpass",
        })
        assert resp.status_code == 200
        assert "Invalid email or password" in resp.text

    def test_login_redirects_to_dashboard(self, logged_in_client):
        # Already logged in, accessing /login should redirect to /
        resp = logged_in_client.get("/login", follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["location"] == "/"


# --- Logout ---

class TestLogout:
    def test_logout_clears_session(self, logged_in_client):
        # Verify logged in — dashboard accessible
        resp = logged_in_client.get("/", follow_redirects=False)
        assert resp.status_code == 200

        # Logout
        resp = logged_in_client.post("/logout", follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["location"] == "/login"

        # Dashboard should redirect to login now
        resp = logged_in_client.get("/", follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["location"] == "/login"


# --- Protected Routes ---

class TestProtectedRoutes:
    def test_dashboard_redirects_when_not_logged_in(self, client):
        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["location"] == "/login"

    def test_alerts_redirects_when_not_logged_in(self, client):
        resp = client.get("/alerts", follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["location"] == "/login"

    def test_channels_redirects_when_not_logged_in(self, client):
        resp = client.get("/channels", follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["location"] == "/login"

    def test_about_accessible_without_login(self, client):
        resp = client.get("/about")
        assert resp.status_code == 200
        assert "AI-Powered" in resp.text

    def test_health_accessible_without_login(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200


# --- Account ---

class TestAccount:
    def test_account_page_shows_info(self, logged_in_client):
        resp = logged_in_client.get("/account")
        assert resp.status_code == 200
        assert "user@example.com" in resp.text
        assert "API Key" in resp.text

    def test_account_redirects_when_not_logged_in(self, client):
        resp = client.get("/account", follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["location"] == "/login"

    def test_regenerate_api_key(self, logged_in_client):
        # Get current API key
        with _TestSession() as session:
            user = session.scalars(select(User)).first()
            old_key = user.api_key

        # Regenerate
        resp = logged_in_client.post("/account/regenerate-key", follow_redirects=False)
        # Should stay on account page (200 or redirect back)
        assert resp.status_code in (200, 302)

        # Verify key changed
        with _TestSession() as session:
            user = session.scalars(select(User)).first()
            assert user.api_key != old_key


# --- API Key Auth (DB-based) ---

class TestApiKeyAuth:
    def test_user_api_key_works(self, logged_in_client):
        # Get user's API key from DB
        with _TestSession() as session:
            user = session.scalars(select(User)).first()
            api_key = user.api_key

        # Enable API auth by setting API_KEYS
        from regulatory_alerts import api as api_mod
        original = api_mod.settings.API_KEYS
        api_mod.settings.API_KEYS = "admin-key-123"
        try:
            # User's DB-based key should work
            resp = logged_in_client.get(
                "/api/updates",
                headers={"X-API-Key": api_key},
            )
            assert resp.status_code == 200

            # Random key should fail
            resp = logged_in_client.get(
                "/api/updates",
                headers={"X-API-Key": "fake-key"},
            )
            assert resp.status_code == 401

            # Admin env key should still work
            resp = logged_in_client.get(
                "/api/updates",
                headers={"X-API-Key": "admin-key-123"},
            )
            assert resp.status_code == 200
        finally:
            api_mod.settings.API_KEYS = original
