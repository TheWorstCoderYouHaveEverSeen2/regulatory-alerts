"""Tests for security hardening: CSRF, CORS, SessionMiddleware, SECRET_KEY."""

import logging
import os
import sys
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

from regulatory_alerts.models import Base, User


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
def csrf_client():
    """Client with REAL CSRF enforcement — no dependency override."""
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
        with TestClient(app) as c:
            yield c


def _get_csrf_token(client) -> str:
    """Make a GET request and extract the CSRF token from the session cookie."""
    # GET /login populates the session with a CSRF token
    resp = client.get("/login")
    assert resp.status_code == 200
    # Extract token from the rendered HTML (hidden input)
    import re
    match = re.search(r'name="csrftoken"\s+value="([^"]+)"', resp.text)
    assert match, "CSRF token not found in login page HTML"
    return match.group(1)


def _register_with_csrf(client, email="sectest@example.com"):
    """Register a user using proper CSRF flow (upgraded to pro to avoid free-tier restrictions)."""
    # Get CSRF token from register page
    resp = client.get("/register")
    import re
    match = re.search(r'name="csrftoken"\s+value="([^"]+)"', resp.text)
    assert match, "CSRF token not found in register page HTML"
    token = match.group(1)

    resp = client.post("/register", data={
        "email": email,
        "password": "testpass123",
        "password_confirm": "testpass123",
        "csrftoken": token,
    }, follow_redirects=False)
    assert resp.status_code == 302

    # Upgrade to pro so free-tier restrictions don't interfere with CSRF tests
    from sqlalchemy import select
    with _TestSession() as session:
        user = session.scalars(select(User).where(User.email == email)).first()
        if user:
            user.subscription_tier = "pro"
            session.commit()

    return token


# --- CSRF Token Population ---

class TestCSRFTokenPopulation:
    def test_csrf_token_set_on_get(self, csrf_client):
        """GET request populates _csrf_token in session."""
        resp = csrf_client.get("/login")
        assert resp.status_code == 200
        assert 'name="csrftoken"' in resp.text

    def test_login_form_has_csrf_field(self, csrf_client):
        """Login HTML contains hidden csrftoken input."""
        resp = csrf_client.get("/login")
        assert 'name="csrftoken"' in resp.text
        assert 'type="hidden"' in resp.text

    def test_register_form_has_csrf_field(self, csrf_client):
        """Register HTML contains hidden csrftoken input."""
        resp = csrf_client.get("/register")
        assert 'name="csrftoken"' in resp.text

    def test_base_has_csrf_hx_headers(self, csrf_client):
        """Dashboard base.html body tag has X-CSRFToken in hx-headers."""
        _register_with_csrf(csrf_client)
        resp = csrf_client.get("/")
        assert resp.status_code == 200
        assert "X-CSRFToken" in resp.text


# --- CSRF Enforcement on POST Routes ---

class TestCSRFEnforcementLogin:
    def test_post_login_without_csrf_403(self, csrf_client):
        """POST /login without token returns 403."""
        resp = csrf_client.post("/login", data={
            "email": "test@example.com",
            "password": "testpass123",
        })
        assert resp.status_code == 403

    def test_post_login_with_csrf_works(self, csrf_client):
        """POST /login with valid form token succeeds (returns login error page since user doesn't exist)."""
        token = _get_csrf_token(csrf_client)
        resp = csrf_client.post("/login", data={
            "email": "test@example.com",
            "password": "testpass123",
            "csrftoken": token,
        })
        # Should get 200 with login error (user doesn't exist), not 403
        assert resp.status_code == 200
        assert "Invalid email or password" in resp.text


class TestCSRFEnforcementRegister:
    def test_post_register_without_csrf_403(self, csrf_client):
        """POST /register without token returns 403."""
        resp = csrf_client.post("/register", data={
            "email": "new@example.com",
            "password": "testpass123",
            "password_confirm": "testpass123",
        })
        assert resp.status_code == 403

    def test_post_register_with_csrf_works(self, csrf_client):
        """POST /register with valid token creates user."""
        _register_with_csrf(csrf_client, "newreg@example.com")
        # Verify user exists
        with _TestSession() as session:
            from sqlalchemy import select
            user = session.scalars(
                select(User).where(User.email == "newreg@example.com")
            ).first()
            assert user is not None


class TestCSRFEnforcementLogout:
    def test_logout_without_csrf_403(self, csrf_client):
        """POST /logout without token returns 403."""
        _register_with_csrf(csrf_client)
        resp = csrf_client.post("/logout")
        assert resp.status_code == 403


class TestCSRFEnforcementHTMX:
    def test_htmx_csrf_via_header(self, csrf_client):
        """POST /channels with X-CSRFToken header is accepted."""
        _register_with_csrf(csrf_client)
        token = _get_csrf_token(csrf_client)

        resp = csrf_client.post("/channels", data={
            "name": "Test Hook",
            "channel_type": "webhook",
            "webhook_url": "https://hooks.example.com/test",
            "webhook_secret": "",
            "email_address": "",
            "min_relevance_score": "",
            "agency_filter": "",
            "topic_filter": "",
        }, headers={
            "X-CSRFToken": token,
            "HX-Request": "true",
        })
        assert resp.status_code == 200

    def test_htmx_delete_via_header(self, csrf_client):
        """DELETE /channels/{id} with X-CSRFToken header is accepted."""
        _register_with_csrf(csrf_client)
        token = _get_csrf_token(csrf_client)

        # Create a channel first
        resp = csrf_client.post("/channels", data={
            "name": "Del Hook",
            "channel_type": "webhook",
            "webhook_url": "https://hooks.example.com/del",
            "webhook_secret": "",
            "email_address": "",
            "min_relevance_score": "",
            "agency_filter": "",
            "topic_filter": "",
        }, headers={"X-CSRFToken": token, "HX-Request": "true"})
        assert resp.status_code == 200

        # Find the channel ID
        from regulatory_alerts.models import NotificationChannel
        with _TestSession() as session:
            from sqlalchemy import select
            ch = session.scalars(select(NotificationChannel)).first()
            assert ch is not None
            ch_id = ch.id

        # Delete via HTMX header
        resp = csrf_client.delete(
            f"/channels/{ch_id}",
            headers={"X-CSRFToken": token, "HX-Request": "true"},
        )
        assert resp.status_code == 200


class TestCSRFWrongToken:
    def test_wrong_csrf_token_403(self, csrf_client):
        """POST with wrong token returns 403."""
        _get_csrf_token(csrf_client)  # populate session
        resp = csrf_client.post("/login", data={
            "email": "test@example.com",
            "password": "testpass123",
            "csrftoken": "completely-wrong-token",
        })
        assert resp.status_code == 403


class TestCSRFExemptions:
    def test_stripe_webhook_exempt(self, csrf_client):
        """POST /webhooks/stripe without CSRF does NOT get 403 (uses Stripe sig verification)."""
        resp = csrf_client.post("/webhooks/stripe", content=b"{}")
        # Should be 503 (webhook not configured) or 400, but NOT 403
        assert resp.status_code != 403

    def test_api_channels_exempt(self, csrf_client):
        """POST /api/channels without CSRF does NOT get 403 (API key auth, not session)."""
        resp = csrf_client.post("/api/channels", json={
            "name": "API Channel",
            "channel_type": "webhook",
            "webhook_url": "https://hooks.example.com/api",
        })
        # Should be 201 (auth disabled) or 401, but NOT 403
        assert resp.status_code != 403


class TestCSRFProtectedRoutes:
    def test_regenerate_key_needs_csrf(self, csrf_client):
        """POST /account/regenerate-key without token returns 403."""
        _register_with_csrf(csrf_client)
        resp = csrf_client.post("/account/regenerate-key")
        assert resp.status_code == 403

    def test_billing_checkout_needs_csrf(self, csrf_client):
        """POST /billing/checkout without token returns 403."""
        _register_with_csrf(csrf_client)
        resp = csrf_client.post("/billing/checkout")
        assert resp.status_code == 403


# --- CORS ---

class TestCORS:
    def test_cors_rejects_foreign_origin(self, csrf_client):
        """Preflight from evil.com gets no CORS headers."""
        resp = csrf_client.options("/api/updates", headers={
            "Origin": "https://evil.com",
            "Access-Control-Request-Method": "GET",
        })
        assert "access-control-allow-origin" not in resp.headers

    def test_cors_allows_base_url(self, csrf_client):
        """Preflight from BASE_URL gets CORS headers."""
        from regulatory_alerts.config import get_settings
        base = get_settings().BASE_URL
        resp = csrf_client.options("/api/updates", headers={
            "Origin": base,
            "Access-Control-Request-Method": "GET",
        })
        assert resp.headers.get("access-control-allow-origin") == base


# --- SECRET_KEY Warning ---

class TestSecretKeyWarning:
    def test_secret_key_warning(self, caplog):
        """Default SECRET_KEY logs warning on startup."""
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
            with caplog.at_level(logging.WARNING):
                with TestClient(app):
                    pass
            assert any("SECRET_KEY" in r.message for r in caplog.records)


# --- Session Cookie ---

class TestSessionCookie:
    def test_session_cookie_samesite(self, csrf_client):
        """Session cookie has SameSite=Lax."""
        resp = csrf_client.get("/login")
        cookies_header = resp.headers.get("set-cookie", "")
        # The session cookie should have SameSite=lax
        assert "samesite=lax" in cookies_header.lower()
