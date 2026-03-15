"""Tests for Sprint 11: Legal pages, disclaimer, landing page, founding member cap,
audit trail (AlertReview model), review routes, and review on alert detail."""

import os
import sys
from datetime import datetime, timezone
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

os.environ.setdefault("DATABASE_URL_SYNC", "sqlite:///:memory:")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("ANTHROPIC_API_KEY", "test-key-not-real")
os.environ.setdefault("API_KEYS", "")
os.environ.setdefault("STRIPE_SECRET_KEY", "")
os.environ.setdefault("STRIPE_WEBHOOK_SECRET", "")
os.environ.setdefault("STRIPE_PUBLISHABLE_KEY", "")
os.environ.setdefault("STRIPE_PRICE_ID_PRO", "")

from regulatory_alerts.config import get_settings
from regulatory_alerts.models import (
    AlertReview,
    Base,
    FeedDocument,
    FeedSource,
    ProcessedAlert,
    User,
)
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


def _patch_all():
    """Return a combined context manager patching all 7 session factories + scheduler + logging."""
    return (
        patch("regulatory_alerts.api.get_sync_engine", _mock_sync_engine),
        patch("regulatory_alerts.api.get_sync_session_factory", _mock_sync_session_factory),
        patch("regulatory_alerts.rate_limit.get_sync_session_factory", _mock_sync_session_factory),
        patch("regulatory_alerts.dashboard.get_sync_session_factory", _mock_sync_session_factory),
        patch("regulatory_alerts.auth.get_sync_session_factory", _mock_sync_session_factory),
        patch("regulatory_alerts.billing.get_sync_session_factory", _mock_sync_session_factory),
        patch("regulatory_alerts.admin.get_sync_session_factory", _mock_sync_session_factory),
        patch("regulatory_alerts.core.scheduler.start_scheduler", return_value=MagicMock()),
        patch("regulatory_alerts.core.scheduler.stop_scheduler"),
        patch("regulatory_alerts.observability.configure_logging"),
    )


@pytest.fixture()
def client():
    """Authenticated client (pro tier) for tests that need login."""
    from regulatory_alerts.csrf import validate_csrf
    from tests.conftest import noop_csrf

    patches = _patch_all()
    cm = patches[0]
    for p in patches[1:]:
        cm = cm.__class__.__enter__(cm) if False else p  # noqa — just collect
    # Use nested with for all patches
    with patches[0], patches[1], patches[2], patches[3], patches[4], \
         patches[5], patches[6], patches[7], patches[8], patches[9]:
        from regulatory_alerts.api import app
        app.dependency_overrides[validate_csrf] = noop_csrf
        with TestClient(app) as c:
            # Register a test user (auto-login via session cookie)
            c.post("/register", data={
                "email": "test@example.com",
                "password": "testpass123",
                "password_confirm": "testpass123",
            })
            # Upgrade to pro so free-tier restrictions don't interfere
            with _TestSession() as session:
                user = session.query(User).filter(User.email == "test@example.com").first()
                user.subscription_tier = "pro"
                session.commit()
            yield c
        app.dependency_overrides.pop(validate_csrf, None)


@pytest.fixture()
def anon_client():
    """Unauthenticated client for testing public pages."""
    from regulatory_alerts.csrf import validate_csrf
    from tests.conftest import noop_csrf

    patches = _patch_all()
    with patches[0], patches[1], patches[2], patches[3], patches[4], \
         patches[5], patches[6], patches[7], patches[8], patches[9]:
        from regulatory_alerts.api import app
        app.dependency_overrides[validate_csrf] = noop_csrf
        with TestClient(app) as c:
            yield c
        app.dependency_overrides.pop(validate_csrf, None)


def _seed_alert_data():
    """Create a FeedSource + FeedDocument + ProcessedAlert. Returns (doc_id, alert_id)."""
    with _TestSession() as session:
        source = FeedSource(
            name="SEC Press Releases",
            agency="SEC",
            feed_url="https://www.sec.gov/news/pressreleases.rss",
            feed_type="rss",
            enabled=True,
        )
        session.add(source)
        session.flush()

        doc = FeedDocument(
            feed_source_id=source.id,
            external_id="sprint11-doc-001",
            title="SEC Charges Widget Corp for Reporting Violations",
            url="https://www.sec.gov/litigation/test-sprint11",
            published_at=datetime(2026, 3, 10, 14, 0, 0, tzinfo=timezone.utc),
            agency="SEC",
            processing_status="completed",
        )
        session.add(doc)
        session.flush()

        alert = ProcessedAlert(
            feed_document_id=doc.id,
            summary="SEC filed charges against Widget Corp for misleading financial reports.",
            key_points=["Widget Corp charged", "Misleading reports", "Penalty TBD"],
            topics='["enforcement", "reporting"]',
            relevance_score=0.88,
            document_type="enforcement_action",
            ai_model="claude-haiku-4-5-20241022",
            ai_cost_usd=0.000100,
        )
        session.add(alert)
        session.commit()

        return doc.id, alert.id


def _get_user(email: str) -> User | None:
    with _TestSession() as session:
        return session.query(User).filter(User.email == email).first()


def _register(client_obj, email="beta@example.com"):
    return client_obj.post("/register", data={
        "email": email,
        "password": "testpass123",
        "password_confirm": "testpass123",
    })


# ======================================================================
# 1. LEGAL PAGES — /terms and /privacy (public, no login required)
# ======================================================================

class TestLegalPages:
    def test_terms_returns_200(self, anon_client):
        resp = anon_client.get("/terms")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    def test_terms_contains_tos_content(self, anon_client):
        resp = anon_client.get("/terms")
        assert "Terms of Service" in resp.text

    def test_terms_no_login_required(self, anon_client):
        """Terms page should be accessible without authentication."""
        resp = anon_client.get("/terms", follow_redirects=False)
        # Should NOT redirect to /login
        assert resp.status_code == 200

    def test_privacy_returns_200(self, anon_client):
        resp = anon_client.get("/privacy")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    def test_privacy_contains_policy_content(self, anon_client):
        resp = anon_client.get("/privacy")
        assert "Privacy Policy" in resp.text

    def test_privacy_no_login_required(self, anon_client):
        """Privacy page should be accessible without authentication."""
        resp = anon_client.get("/privacy", follow_redirects=False)
        assert resp.status_code == 200


# ======================================================================
# 2. DISCLAIMER — in base.html footer and email body
# ======================================================================

class TestDisclaimer:
    def test_base_footer_has_disclaimer(self, client):
        """The dashboard (which extends base.html) should contain the disclaimer text."""
        resp = client.get("/alerts")
        assert resp.status_code == 200
        assert "Not legal or compliance advice" in resp.text

    def test_landing_page_has_disclaimer(self, anon_client):
        """The landing page has an explicit disclaimer section."""
        resp = anon_client.get("/about")
        assert "NOT legal advice" in resp.text
        assert "information service" in resp.text

    def test_email_body_contains_disclaimer(self):
        """The notification email builder includes a disclaimer footer."""
        from regulatory_alerts.core.notifier import _build_email_body

        doc = FeedDocument(
            id=1,
            title="Test Filing",
            agency="SEC",
            url="https://sec.gov/test",
            published_at=datetime(2026, 3, 1, tzinfo=timezone.utc),
        )
        alert = ProcessedAlert(
            id=1,
            feed_document_id=1,
            summary="Test summary.",
            topics='["test"]',
            relevance_score=0.8,
            document_type="test",
            ai_model="test",
        )
        alert.feed_document = doc

        _subject, html = _build_email_body(alert, doc)
        assert "Not legal advice" in html
        assert "information service" in html


# ======================================================================
# 3. LANDING PAGE — /about
# ======================================================================

class TestLandingPage:
    def test_about_returns_200(self, anon_client):
        resp = anon_client.get("/about")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    def test_about_contains_market_positioning(self, anon_client):
        resp = anon_client.get("/about")
        assert "AI-Powered" in resp.text
        assert "SEC" in resp.text
        assert "Compliance" in resp.text

    def test_about_contains_founding_member_cap(self, anon_client):
        settings = get_settings()
        cap = settings.FOUNDING_MEMBER_CAP
        resp = anon_client.get("/about")
        assert str(cap) in resp.text


# ======================================================================
# 4. FOUNDING MEMBER CAP
# ======================================================================

class TestFoundingMemberCap:
    def test_cap_enforced_after_limit(self, anon_client):
        """When cap=2, first 2 registrations get founding member, 3rd gets free tier."""
        settings = get_settings()
        orig_mode = settings.BETA_MODE
        orig_cap = settings.FOUNDING_MEMBER_CAP
        settings.BETA_MODE = True
        settings.FOUNDING_MEMBER_CAP = 2
        try:
            # Register first user
            _register(anon_client, "fm1@example.com")
            user1 = _get_user("fm1@example.com")
            assert user1.is_founding_member is True
            assert user1.subscription_tier == "pro"

            # Logout and register second user
            anon_client.post("/logout")
            _register(anon_client, "fm2@example.com")
            user2 = _get_user("fm2@example.com")
            assert user2.is_founding_member is True
            assert user2.subscription_tier == "pro"

            # Logout and register third user — cap reached
            anon_client.post("/logout")
            _register(anon_client, "fm3@example.com")
            user3 = _get_user("fm3@example.com")
            assert user3.is_founding_member is False
            assert user3.subscription_tier == "free"
        finally:
            settings.BETA_MODE = orig_mode
            settings.FOUNDING_MEMBER_CAP = orig_cap

    def test_beta_off_no_founding_members(self, anon_client):
        """With beta mode off, registrations should not get founding member status."""
        settings = get_settings()
        assert settings.BETA_MODE is False  # conftest autouse disables it
        _register(anon_client, "nonfm@example.com")
        user = _get_user("nonfm@example.com")
        assert user.is_founding_member is False
        assert user.subscription_tier == "free"


# ======================================================================
# 5. AUDIT TRAIL MODEL — AlertReview CRUD
# ======================================================================

class TestAlertReviewModel:
    def test_create_alert_review(self):
        """AlertReview can be created and queried."""
        doc_id, alert_id = _seed_alert_data()
        with _TestSession() as session:
            user = User(
                email="reviewer@example.com",
                hashed_password="$2b$12$dummyhash",
                api_key="test-review-key",
            )
            session.add(user)
            session.commit()

            review = AlertReview(
                user_id=user.id,
                alert_id=alert_id,
                status="acknowledged",
                notes="Reviewed and noted.",
            )
            session.add(review)
            session.commit()
            session.refresh(review)

            assert review.id is not None
            assert review.user_id == user.id
            assert review.alert_id == alert_id
            assert review.status == "acknowledged"
            assert review.notes == "Reviewed and noted."
            assert review.reviewed_at is not None

    def test_alert_review_repr(self):
        doc_id, alert_id = _seed_alert_data()
        with _TestSession() as session:
            user = User(
                email="repr@example.com",
                hashed_password="$2b$12$dummyhash",
                api_key="test-repr-key",
            )
            session.add(user)
            session.commit()

            review = AlertReview(
                user_id=user.id,
                alert_id=alert_id,
                status="escalated",
            )
            session.add(review)
            session.commit()

            r = repr(review)
            assert "AlertReview" in r
            assert "escalated" in r


# ======================================================================
# 6. REVIEW ROUTES — POST /alerts/{id}/review, GET /reviews,
#    GET /reviews/export
# ======================================================================

class TestReviewRoutes:
    def test_post_review_creates_record(self, client):
        doc_id, alert_id = _seed_alert_data()
        resp = client.post(
            f"/alerts/{doc_id}/review",
            data={"status": "acknowledged", "notes": "Looks fine."},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert f"/alerts/{doc_id}" in resp.headers["location"]

        # Verify the review was persisted
        with _TestSession() as session:
            review = session.query(AlertReview).filter(
                AlertReview.alert_id == alert_id
            ).first()
            assert review is not None
            assert review.status == "acknowledged"
            assert review.notes == "Looks fine."

    def test_post_review_invalid_status(self, client):
        doc_id, _ = _seed_alert_data()
        resp = client.post(
            f"/alerts/{doc_id}/review",
            data={"status": "invalid_status", "notes": ""},
        )
        assert resp.status_code == 400

    def test_post_review_not_found(self, client):
        resp = client.post(
            "/alerts/9999/review",
            data={"status": "acknowledged", "notes": ""},
        )
        assert resp.status_code == 404

    def test_post_review_updates_existing(self, client):
        """Posting a review when one already exists should update it."""
        doc_id, alert_id = _seed_alert_data()

        # First review
        client.post(
            f"/alerts/{doc_id}/review",
            data={"status": "acknowledged", "notes": "First pass."},
        )
        # Second review (update)
        client.post(
            f"/alerts/{doc_id}/review",
            data={"status": "escalated", "notes": "Needs attention."},
        )

        with _TestSession() as session:
            reviews = session.query(AlertReview).filter(
                AlertReview.alert_id == alert_id
            ).all()
            # Should have exactly one review (updated, not duplicated)
            assert len(reviews) == 1
            assert reviews[0].status == "escalated"
            assert reviews[0].notes == "Needs attention."

    def test_reviews_page_returns_200(self, client):
        resp = client.get("/reviews")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "Compliance Reviews" in resp.text

    def test_reviews_page_shows_empty_state(self, client):
        resp = client.get("/reviews")
        assert "No reviews yet" in resp.text

    def test_reviews_page_shows_review(self, client):
        doc_id, _ = _seed_alert_data()
        client.post(
            f"/alerts/{doc_id}/review",
            data={"status": "action_taken", "notes": "Called counsel."},
        )
        resp = client.get("/reviews")
        assert resp.status_code == 200
        assert "Action Taken" in resp.text
        assert "SEC Charges Widget Corp" in resp.text

    def test_reviews_export_returns_csv(self, client):
        doc_id, _ = _seed_alert_data()
        client.post(
            f"/alerts/{doc_id}/review",
            data={"status": "no_action_required", "notes": "Low risk."},
        )
        resp = client.get("/reviews/export")
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]
        assert "attachment" in resp.headers.get("content-disposition", "")

        # CSV should have BOM + header + data row
        body = resp.text
        assert body.startswith("\ufeff")  # BOM
        assert "Review Date" in body
        assert "Status" in body
        assert "No Action Required" in body
        assert "Low risk." in body
        assert "SEC Charges Widget Corp" in body

    def test_reviews_export_empty(self, client):
        """Export with no reviews should still return a valid CSV with headers."""
        resp = client.get("/reviews/export")
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]
        body = resp.text
        assert "Review Date" in body


# ======================================================================
# 7. REVIEW ON ALERT DETAIL — form when not reviewed, status when reviewed
# ======================================================================

class TestReviewOnAlertDetail:
    def test_alert_detail_shows_review_form(self, client):
        """When alert is not yet reviewed, the detail page shows a review form."""
        doc_id, _ = _seed_alert_data()
        resp = client.get(f"/alerts/{doc_id}")
        assert resp.status_code == 200
        assert "Mark as Reviewed" in resp.text
        assert "Compliance Review" in resp.text
        # Should have the form action pointing to the review route
        assert f"/alerts/{doc_id}/review" in resp.text

    def test_alert_detail_shows_review_status(self, client):
        """After reviewing, the detail page shows the review status instead of the form."""
        doc_id, _ = _seed_alert_data()
        client.post(
            f"/alerts/{doc_id}/review",
            data={"status": "acknowledged", "notes": "Noted and filed."},
        )
        resp = client.get(f"/alerts/{doc_id}")
        assert resp.status_code == 200
        assert "Reviewed" in resp.text
        assert "acknowledged" in resp.text.lower()
        assert "Noted and filed." in resp.text
        # The submit button should no longer appear
        assert "Mark as Reviewed" not in resp.text
