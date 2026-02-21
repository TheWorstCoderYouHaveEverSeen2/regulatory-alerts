"""Tests for password reset flow: token generation, validation, routes, email, security."""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

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
os.environ["SECRET_KEY"] = "test-secret-key-for-password-reset"

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
def client():
    """Unauthenticated test client with mocked DB and CSRF bypass."""
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


def _create_user(email="user@example.com", password="testpass123"):
    """Create a test user directly in the DB and return the User object."""
    from regulatory_alerts.auth import hash_password, generate_api_key

    with _TestSession() as session:
        user = User(
            email=email,
            hashed_password=hash_password(password),
            api_key=generate_api_key(),
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        return user


# ---------------------------------------------------------------------------
# Token generation and validation
# ---------------------------------------------------------------------------


class TestTokenGeneration:
    def test_generate_token_returns_string(self):
        user = _create_user()
        from regulatory_alerts.auth import generate_reset_token

        token = generate_reset_token(user)
        assert isinstance(token, str)
        assert len(token) > 20  # itsdangerous tokens are substantial

    def test_validate_valid_token(self):
        user = _create_user()
        from regulatory_alerts.auth import generate_reset_token, validate_reset_token

        token = generate_reset_token(user)
        data = validate_reset_token(token)
        assert data is not None
        assert data["uid"] == user.id
        assert data["hp"] == user.hashed_password[:16]

    def test_validate_expired_token(self):
        """Tokens older than max_age should be rejected."""
        import time as _time
        from itsdangerous.timed import TimestampSigner

        user = _create_user()
        from regulatory_alerts.auth import generate_reset_token, validate_reset_token

        # Generate token, then mock get_timestamp to simulate 2 hours later
        token = generate_reset_token(user)
        future_ts = int(_time.time()) + 7200

        with patch.object(TimestampSigner, "get_timestamp", return_value=future_ts):
            data = validate_reset_token(token)
        assert data is None

    def test_validate_tampered_token(self):
        user = _create_user()
        from regulatory_alerts.auth import generate_reset_token, validate_reset_token

        token = generate_reset_token(user)
        # Tamper with the token
        tampered = token[:-5] + "XXXXX"
        assert validate_reset_token(tampered) is None

    def test_validate_empty_token(self):
        from regulatory_alerts.auth import validate_reset_token
        assert validate_reset_token("") is None

    def test_validate_garbage_token(self):
        from regulatory_alerts.auth import validate_reset_token
        assert validate_reset_token("not-a-real-token-at-all") is None

    def test_token_single_use_enforcement(self):
        """After password change, old token should be invalid (hash prefix mismatch)."""
        user = _create_user()
        from regulatory_alerts.auth import generate_reset_token, validate_reset_token, hash_password

        token = generate_reset_token(user)

        # Verify token is valid
        data = validate_reset_token(token)
        assert data is not None

        # Change password (simulates successful reset)
        with _TestSession() as session:
            db_user = session.get(User, user.id)
            db_user.hashed_password = hash_password("newpassword1")
            session.commit()
            new_hash_prefix = db_user.hashed_password[:16]

        # Token still deserializes, but hp won't match
        data = validate_reset_token(token)
        assert data is not None  # itsdangerous doesn't know about hash
        assert data["hp"] != new_hash_prefix  # but the hp in token is stale


# ---------------------------------------------------------------------------
# Forgot password page
# ---------------------------------------------------------------------------


class TestForgotPasswordPage:
    def test_forgot_password_page_renders(self, client):
        resp = client.get("/forgot-password")
        assert resp.status_code == 200
        assert "Reset your password" in resp.text
        assert "Send Reset Link" in resp.text

    def test_forgot_password_submit_existing_email(self, client):
        """Should show success message (and send email) for existing user."""
        _create_user("existing@example.com")

        with patch("regulatory_alerts.core.notifier.send_raw_email", return_value=(True, "")) as mock_email:
            resp = client.post("/forgot-password", data={"email": "existing@example.com"})

        assert resp.status_code == 200
        assert "sent a password reset link" in resp.text
        mock_email.assert_called_once()
        # Verify email was sent to the correct address
        assert mock_email.call_args.kwargs["to"] == "existing@example.com"

    def test_forgot_password_submit_nonexistent_email(self, client):
        """Should show same success message for non-existent email (anti-enumeration)."""
        with patch("regulatory_alerts.core.notifier.send_raw_email") as mock_email:
            resp = client.post("/forgot-password", data={"email": "nobody@example.com"})

        assert resp.status_code == 200
        assert "sent a password reset link" in resp.text
        # Email should NOT have been sent
        mock_email.assert_not_called()

    def test_forgot_password_normalizes_email(self, client):
        """Email should be normalized to lowercase and stripped."""
        _create_user("user@example.com")

        with patch("regulatory_alerts.core.notifier.send_raw_email", return_value=(True, "")) as mock_email:
            resp = client.post("/forgot-password", data={"email": "  USER@Example.COM  "})

        assert resp.status_code == 200
        mock_email.assert_called_once()

    def test_forgot_password_inactive_user(self, client):
        """Inactive users should not receive reset emails."""
        user = _create_user("inactive@example.com")
        with _TestSession() as session:
            db_user = session.get(User, user.id)
            db_user.is_active = False
            session.commit()

        with patch("regulatory_alerts.core.notifier.send_raw_email") as mock_email:
            resp = client.post("/forgot-password", data={"email": "inactive@example.com"})

        assert resp.status_code == 200
        assert "sent a password reset link" in resp.text  # same message
        mock_email.assert_not_called()

    def test_forgot_password_email_failure_still_shows_success(self, client):
        """Even if SMTP fails, show success to user (don't reveal SMTP issues)."""
        _create_user("user@example.com")

        with patch("regulatory_alerts.core.notifier.send_raw_email", return_value=(False, "SMTP timeout")):
            resp = client.post("/forgot-password", data={"email": "user@example.com"})

        assert resp.status_code == 200
        assert "sent a password reset link" in resp.text


# ---------------------------------------------------------------------------
# Reset password page (GET)
# ---------------------------------------------------------------------------


class TestResetPasswordPage:
    def test_reset_page_with_valid_token(self, client):
        user = _create_user()
        from regulatory_alerts.auth import generate_reset_token
        token = generate_reset_token(user)

        resp = client.get(f"/reset-password?token={token}")
        assert resp.status_code == 200
        assert "New Password" in resp.text
        assert token in resp.text  # hidden field

    def test_reset_page_without_token(self, client):
        resp = client.get("/reset-password")
        assert resp.status_code == 200
        assert "invalid or has expired" in resp.text

    def test_reset_page_with_invalid_token(self, client):
        resp = client.get("/reset-password?token=bogus-token")
        assert resp.status_code == 200
        assert "invalid or has expired" in resp.text

    def test_reset_page_with_used_token(self, client):
        """Token should be invalid after password was already changed."""
        user = _create_user()
        from regulatory_alerts.auth import generate_reset_token, hash_password
        token = generate_reset_token(user)

        # Change password (simulate previous reset)
        with _TestSession() as session:
            db_user = session.get(User, user.id)
            db_user.hashed_password = hash_password("newpassword1")
            session.commit()

        resp = client.get(f"/reset-password?token={token}")
        assert resp.status_code == 200
        assert "invalid or has expired" in resp.text


# ---------------------------------------------------------------------------
# Reset password submission (POST)
# ---------------------------------------------------------------------------


class TestResetPasswordSubmit:
    def test_successful_reset(self, client):
        """Full happy path: token valid, passwords match, password updated."""
        user = _create_user("reset@example.com", "oldpassword1")
        from regulatory_alerts.auth import generate_reset_token
        token = generate_reset_token(user)

        resp = client.post("/reset-password", data={
            "token": token,
            "password": "newpassword1",
            "password_confirm": "newpassword1",
        })
        assert resp.status_code == 200
        assert "reset successfully" in resp.text

        # Verify can login with new password
        resp = client.post("/login", data={
            "email": "reset@example.com",
            "password": "newpassword1",
        }, follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["location"] == "/"

    def test_successful_reset_old_password_fails(self, client):
        """After reset, old password should not work."""
        user = _create_user("reset2@example.com", "oldpassword1")
        from regulatory_alerts.auth import generate_reset_token
        token = generate_reset_token(user)

        client.post("/reset-password", data={
            "token": token,
            "password": "newpassword1",
            "password_confirm": "newpassword1",
        })

        # Old password should fail
        resp = client.post("/login", data={
            "email": "reset2@example.com",
            "password": "oldpassword1",
        })
        assert resp.status_code == 200
        assert "Invalid email or password" in resp.text

    def test_reset_with_invalid_token(self, client):
        resp = client.post("/reset-password", data={
            "token": "bogus-token",
            "password": "newpassword1",
            "password_confirm": "newpassword1",
        })
        assert resp.status_code == 200
        assert "invalid or has expired" in resp.text

    def test_reset_password_too_short(self, client):
        user = _create_user()
        from regulatory_alerts.auth import generate_reset_token
        token = generate_reset_token(user)

        resp = client.post("/reset-password", data={
            "token": token,
            "password": "short",
            "password_confirm": "short",
        })
        assert resp.status_code == 200
        assert "at least 8" in resp.text

    def test_reset_password_mismatch(self, client):
        user = _create_user()
        from regulatory_alerts.auth import generate_reset_token
        token = generate_reset_token(user)

        resp = client.post("/reset-password", data={
            "token": token,
            "password": "newpassword1",
            "password_confirm": "different123",
        })
        assert resp.status_code == 200
        assert "do not match" in resp.text

    def test_reset_clears_session(self, client):
        """After successful reset, session should be cleared (security)."""
        # Register and login
        client.post("/register", data={
            "email": "session@example.com",
            "password": "testpass123",
            "password_confirm": "testpass123",
        })
        # Verify logged in
        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 200

        # Generate reset token
        with _TestSession() as session:
            user = session.scalars(select(User).where(User.email == "session@example.com")).first()
        from regulatory_alerts.auth import generate_reset_token
        token = generate_reset_token(user)

        # Reset password
        client.post("/reset-password", data={
            "token": token,
            "password": "newpassword1",
            "password_confirm": "newpassword1",
        })

        # Session should be cleared — dashboard should redirect to login
        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["location"] == "/login"

    def test_reset_token_becomes_single_use(self, client):
        """After successful reset, the same token should not work again."""
        user = _create_user()
        from regulatory_alerts.auth import generate_reset_token
        token = generate_reset_token(user)

        # First reset — success
        resp = client.post("/reset-password", data={
            "token": token,
            "password": "newpassword1",
            "password_confirm": "newpassword1",
        })
        assert "reset successfully" in resp.text

        # Second reset with same token — should fail (hash prefix changed)
        resp = client.post("/reset-password", data={
            "token": token,
            "password": "anotherpass1",
            "password_confirm": "anotherpass1",
        })
        assert "invalid or has expired" in resp.text


# ---------------------------------------------------------------------------
# Login page integration
# ---------------------------------------------------------------------------


class TestLoginPageIntegration:
    def test_login_page_has_forgot_password_link(self, client):
        resp = client.get("/login")
        assert resp.status_code == 200
        assert "forgot-password" in resp.text
        assert "Forgot password?" in resp.text


# ---------------------------------------------------------------------------
# Email content
# ---------------------------------------------------------------------------


class TestResetEmail:
    def test_reset_email_contains_link(self, client):
        """Reset email should contain a valid reset URL."""
        _create_user("emailtest@example.com")

        with patch("regulatory_alerts.core.notifier.send_raw_email", return_value=(True, "")) as mock_email:
            client.post("/forgot-password", data={"email": "emailtest@example.com"})

        mock_email.assert_called_once()
        html_body = mock_email.call_args.kwargs["html_body"]
        assert "/reset-password?token=" in html_body
        assert "Reset Password" in html_body
        assert "1 hour" in html_body

    def test_reset_email_subject(self, client):
        _create_user("subj@example.com")

        with patch("regulatory_alerts.core.notifier.send_raw_email", return_value=(True, "")) as mock_email:
            client.post("/forgot-password", data={"email": "subj@example.com"})

        assert mock_email.call_args.kwargs["subject"] == "Password Reset — Regulatory Alerts"


# ---------------------------------------------------------------------------
# send_raw_email unit tests
# ---------------------------------------------------------------------------


class TestSendRawEmail:
    def test_send_raw_email_no_smtp_host(self):
        """Should return failure if SMTP not configured."""
        from regulatory_alerts.core.notifier import send_raw_email

        with patch("regulatory_alerts.core.notifier.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(SMTP_HOST="")
            ok, err = send_raw_email("to@x.com", "Subject", "<p>Body</p>")

        assert not ok
        assert "SMTP not configured" in err

    def test_send_raw_email_success(self):
        """Should send email via SMTP when configured."""
        from regulatory_alerts.core.notifier import send_raw_email

        mock_smtp_instance = MagicMock()

        with patch("regulatory_alerts.core.notifier.get_settings") as mock_settings, \
             patch("smtplib.SMTP", return_value=mock_smtp_instance):
            mock_settings.return_value = MagicMock(
                SMTP_HOST="smtp.test.com",
                SMTP_PORT=587,
                SMTP_USE_TLS=True,
                SMTP_USER="user",
                SMTP_PASSWORD="pass",
                SMTP_FROM="from@test.com",
            )
            ok, err = send_raw_email("to@test.com", "Test Subject", "<p>Hello</p>")

        assert ok
        assert err == ""
        mock_smtp_instance.starttls.assert_called_once()
        mock_smtp_instance.login.assert_called_once_with("user", "pass")
        mock_smtp_instance.sendmail.assert_called_once()
        mock_smtp_instance.quit.assert_called_once()

    def test_send_raw_email_smtp_failure(self):
        """Should catch SMTP exceptions and return failure."""
        from regulatory_alerts.core.notifier import send_raw_email

        with patch("regulatory_alerts.core.notifier.get_settings") as mock_settings, \
             patch("smtplib.SMTP", side_effect=ConnectionRefusedError("Connection refused")):
            mock_settings.return_value = MagicMock(
                SMTP_HOST="smtp.test.com",
                SMTP_PORT=587,
                SMTP_USE_TLS=False,
                SMTP_USER="",
                SMTP_PASSWORD="",
                SMTP_FROM="from@test.com",
            )
            ok, err = send_raw_email("to@test.com", "Subject", "<p>Body</p>")

        assert not ok
        assert "Connection refused" in err


# ---------------------------------------------------------------------------
# Edge cases from LLM audit
# ---------------------------------------------------------------------------


class TestPasswordResetEdgeCases:
    def test_reset_token_for_deleted_user(self, client):
        """Token for a deleted user should be rejected."""
        user = _create_user("deleted@example.com")
        from regulatory_alerts.auth import generate_reset_token
        token = generate_reset_token(user)

        # Delete the user
        with _TestSession() as session:
            db_user = session.get(User, user.id)
            session.delete(db_user)
            session.commit()

        # GET should show error
        resp = client.get(f"/reset-password?token={token}")
        assert "invalid or has expired" in resp.text

        # POST should also show error
        resp = client.post("/reset-password", data={
            "token": token,
            "password": "newpassword1",
            "password_confirm": "newpassword1",
        })
        assert "invalid or has expired" in resp.text

    def test_reset_preserves_other_user_data(self, client):
        """Password reset should only change the password hash, nothing else."""
        user = _create_user("preserve@example.com")

        # Set some data on the user
        with _TestSession() as session:
            db_user = session.get(User, user.id)
            original_api_key = db_user.api_key
            original_email = db_user.email

        from regulatory_alerts.auth import generate_reset_token
        token = generate_reset_token(user)

        client.post("/reset-password", data={
            "token": token,
            "password": "newpassword1",
            "password_confirm": "newpassword1",
        })

        # Verify only password changed
        with _TestSession() as session:
            db_user = session.get(User, user.id)
            assert db_user.email == original_email
            assert db_user.api_key == original_api_key
            assert db_user.is_active is True

    def test_multiple_reset_tokens_only_latest_works(self, client):
        """Multiple tokens can be generated, but using one invalidates the rest."""
        user = _create_user("multi@example.com")
        from regulatory_alerts.auth import generate_reset_token

        token1 = generate_reset_token(user)
        token2 = generate_reset_token(user)

        # Both should be valid initially
        resp1 = client.get(f"/reset-password?token={token1}")
        assert "New Password" in resp1.text
        resp2 = client.get(f"/reset-password?token={token2}")
        assert "New Password" in resp2.text

        # Use token2 to reset
        client.post("/reset-password", data={
            "token": token2,
            "password": "newpassword1",
            "password_confirm": "newpassword1",
        })

        # token1 should now be invalid (hash prefix changed)
        resp = client.get(f"/reset-password?token={token1}")
        assert "invalid or has expired" in resp.text
