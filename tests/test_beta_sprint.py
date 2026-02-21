"""Tests for Sprint 9: Beta Mode, Pricing, Free Tier Gating, Onboarding."""

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

os.environ.setdefault("DATABASE_URL_SYNC", "sqlite:///:memory:")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("ANTHROPIC_API_KEY", "test-key-not-real")
os.environ.setdefault("API_KEYS", "")
os.environ.setdefault("STRIPE_SECRET_KEY", "")
os.environ.setdefault("STRIPE_WEBHOOK_SECRET", "")
os.environ.setdefault("STRIPE_PUBLISHABLE_KEY", "")
os.environ.setdefault("STRIPE_PRICE_ID_PRO", "")

from regulatory_alerts.models import (
    Base,
    FeedDocument,
    FeedSource,
    NotificationChannel,
    ProcessedAlert,
    User,
)
from regulatory_alerts.billing import (
    TIER_FREE,
    TIER_PRO,
    TIER_LIMITS,
    get_tier_limits,
    check_channel_limit,
)
from regulatory_alerts.config import get_settings


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


def _make_client(beta_mode: bool = False):
    """Create a test client with optional beta mode."""
    from regulatory_alerts.csrf import validate_csrf
    from tests.conftest import noop_csrf

    settings = get_settings()
    settings.BETA_MODE = beta_mode

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


@pytest.fixture()
def client():
    """Standard client with beta mode disabled."""
    yield from _make_client(beta_mode=False)


@pytest.fixture()
def beta_client():
    """Client with beta mode enabled."""
    yield from _make_client(beta_mode=True)


def _get_user(email: str) -> User | None:
    with _TestSession() as session:
        return session.query(User).filter(User.email == email).first()


def _register(client, email="beta@example.com"):
    return client.post("/register", data={
        "email": email,
        "password": "testpass123",
        "password_confirm": "testpass123",
    })


# ======================================================================
# PHASE 1: New Pricing Tiers + Beta Mode Config
# ======================================================================

class TestBetaConfig:
    """Test that beta config settings have correct defaults."""

    def test_beta_mode_default(self):
        settings = get_settings()
        # Default is True (but tests set it to False via conftest autouse)
        # Verify the field exists and is a bool
        assert isinstance(settings.BETA_MODE, bool)

    def test_beta_end_date_default_empty(self):
        settings = get_settings()
        assert settings.BETA_END_DATE == ""

    def test_founding_member_discount_default(self):
        settings = get_settings()
        assert settings.FOUNDING_MEMBER_DISCOUNT_PCT == 40

    def test_pro_monthly_price(self):
        settings = get_settings()
        assert settings.PRO_MONTHLY_PRICE == 79

    def test_pro_annual_price(self):
        settings = get_settings()
        assert settings.PRO_ANNUAL_PRICE == 63

    def test_team_monthly_price(self):
        settings = get_settings()
        assert settings.TEAM_MONTHLY_PRICE == 199

    def test_team_annual_price(self):
        settings = get_settings()
        assert settings.TEAM_ANNUAL_PRICE == 159


class TestBetaRegistration:
    """Test that beta mode registration grants Pro tier + founding member."""

    def test_beta_mode_registration_gives_pro(self, beta_client):
        _register(beta_client, "betauser@example.com")
        user = _get_user("betauser@example.com")
        assert user is not None
        assert user.subscription_tier == "pro"

    def test_beta_mode_registration_sets_founding_member(self, beta_client):
        _register(beta_client, "founder@example.com")
        user = _get_user("founder@example.com")
        assert user.is_founding_member is True

    def test_beta_mode_registration_sets_enrolled_at(self, beta_client):
        _register(beta_client, "enrolled@example.com")
        user = _get_user("enrolled@example.com")
        assert user.beta_enrolled_at is not None
        # Should be recent (within the last minute)
        delta = datetime.now(timezone.utc) - user.beta_enrolled_at.replace(tzinfo=timezone.utc)
        assert delta.total_seconds() < 60

    def test_non_beta_registration_gives_free(self, client):
        _register(client, "normaluser@example.com")
        user = _get_user("normaluser@example.com")
        assert user is not None
        assert user.subscription_tier == "free"

    def test_non_beta_registration_not_founding_member(self, client):
        _register(client, "normal2@example.com")
        user = _get_user("normal2@example.com")
        assert user.is_founding_member is False
        assert user.beta_enrolled_at is None


class TestFreeTierLimits:
    """Test that free tier now has 1 channel limit."""

    def test_free_tier_max_channels_is_one(self):
        limits = get_tier_limits(TIER_FREE)
        assert limits["max_channels"] == 1

    def test_free_tier_rate_limit(self):
        limits = get_tier_limits(TIER_FREE)
        assert limits["rate_limit"] == "10/minute"

    def test_pro_tier_unlimited(self):
        limits = get_tier_limits(TIER_PRO)
        assert limits["max_channels"] is None

    def test_check_channel_limit_blocks_second_channel(self):
        """Free user with 1 channel should be blocked from creating a second."""
        with _TestSession() as session:
            user = User(
                email="limituser@example.com",
                hashed_password="$2b$12$dummy",
                api_key="test-key-limit",
                subscription_tier="free",
            )
            session.add(user)
            session.commit()
            session.refresh(user)

            # Create one channel
            ch = NotificationChannel(
                name="First",
                channel_type="email",
                email_address="test@example.com",
                user_id=user.id,
            )
            session.add(ch)
            session.commit()

            # Second should be blocked
            allowed, err = check_channel_limit(user, session)
            assert allowed is False
            assert "limited to 1 channels" in err


class TestUserModelBetaColumns:
    """Test that User model has new beta columns with correct defaults."""

    def test_is_founding_member_default_false(self):
        with _TestSession() as session:
            user = User(
                email="model@example.com",
                hashed_password="$2b$12$dummy",
                api_key="test-key-model",
            )
            session.add(user)
            session.commit()
            session.refresh(user)
            assert user.is_founding_member is False

    def test_beta_enrolled_at_default_none(self):
        with _TestSession() as session:
            user = User(
                email="model2@example.com",
                hashed_password="$2b$12$dummy",
                api_key="test-key-model2",
            )
            session.add(user)
            session.commit()
            session.refresh(user)
            assert user.beta_enrolled_at is None

    def test_founding_member_can_be_set(self):
        with _TestSession() as session:
            user = User(
                email="model3@example.com",
                hashed_password="$2b$12$dummy",
                api_key="test-key-model3",
                is_founding_member=True,
                beta_enrolled_at=datetime(2026, 2, 19, tzinfo=timezone.utc),
            )
            session.add(user)
            session.commit()
            session.refresh(user)
            assert user.is_founding_member is True
            assert user.beta_enrolled_at is not None


# ======================================================================
# PHASE 2: Pricing Page Redesign
# ======================================================================

class TestPricingPageBeta:
    """Test pricing page renders correctly in beta and non-beta mode."""

    def test_pricing_page_beta_banner(self, beta_client):
        resp = beta_client.get("/pricing")
        assert resp.status_code == 200
        assert "Founding Member Beta" in resp.text

    def test_pricing_page_no_banner_without_beta(self, client):
        resp = client.get("/pricing")
        assert resp.status_code == 200
        assert "Founding Member Beta" not in resp.text

    def test_pricing_page_beta_shows_free_during_beta(self, beta_client):
        resp = beta_client.get("/pricing")
        assert "FREE DURING BETA" in resp.text
        assert "Free during beta" in resp.text

    def test_pricing_page_shows_correct_prices(self, client):
        resp = client.get("/pricing")
        assert "$79" in resp.text
        assert "$199" in resp.text

    def test_pricing_page_shows_team_coming_soon(self, client):
        resp = client.get("/pricing")
        assert "Coming Soon" in resp.text

    def test_pricing_page_beta_shows_discount_percentage(self, beta_client):
        resp = beta_client.get("/pricing")
        assert "40%" in resp.text

    def test_pricing_page_beta_end_date_shown(self):
        """When BETA_END_DATE is set, it appears on the pricing page."""
        settings = get_settings()
        orig_end = settings.BETA_END_DATE
        settings.BETA_END_DATE = "2026-05-20"
        try:
            for c in _make_client(beta_mode=True):
                resp = c.get("/pricing")
                assert "2026-05-20" in resp.text
        finally:
            settings.BETA_END_DATE = orig_end


class TestBillingPageFoundingMember:
    """Test billing page shows founding member badge."""

    def test_billing_page_founding_member_badge(self, beta_client):
        # Register as founding member (beta mode is on)
        _register(beta_client, "billing_fm@example.com")
        resp = beta_client.get("/billing")
        assert resp.status_code == 200
        assert "Founding Member" in resp.text

    def test_billing_page_shows_discount(self, beta_client):
        _register(beta_client, "billing_disc@example.com")
        resp = beta_client.get("/billing")
        assert "40% off" in resp.text

    def test_billing_page_no_badge_non_beta(self, client):
        _register(client, "billing_nb@example.com")
        resp = client.get("/billing")
        assert resp.status_code == 200
        assert "Founding Member" not in resp.text


# ======================================================================
# PHASE 3: Free Tier Feature Gating
# ======================================================================

def _seed_sec_and_cftc_docs():
    """Create SEC and CFTC documents with alerts for testing agency filtering."""
    with _TestSession() as session:
        # SEC source + doc
        sec_src = FeedSource(name="SEC PR", agency="SEC", feed_url="https://sec.gov/rss", feed_type="rss", enabled=True)
        session.add(sec_src)
        session.flush()
        sec_doc = FeedDocument(
            feed_source_id=sec_src.id, external_id="sec-001", content_hash="hash1",
            title="SEC Enforcement Action", url="https://sec.gov/doc1",
            published_at=datetime(2026, 2, 15, tzinfo=timezone.utc),
            agency="SEC", processing_status="completed",
        )
        session.add(sec_doc)
        session.flush()
        sec_alert = ProcessedAlert(
            feed_document_id=sec_doc.id, summary="SEC enforcement summary",
            topics='["enforcement"]', relevance_score=0.8,
            document_type="enforcement_action", ai_model="claude-haiku-4-5-20241022",
        )
        session.add(sec_alert)

        # CFTC source + doc
        cftc_src = FeedSource(name="CFTC PR", agency="CFTC", feed_url="https://cftc.gov/rss", feed_type="html", enabled=True)
        session.add(cftc_src)
        session.flush()
        cftc_doc = FeedDocument(
            feed_source_id=cftc_src.id, external_id="cftc-001", content_hash="hash2",
            title="CFTC Market Notice", url="https://cftc.gov/doc1",
            published_at=datetime(2026, 2, 15, tzinfo=timezone.utc),
            agency="CFTC", processing_status="completed",
        )
        session.add(cftc_doc)
        session.flush()
        cftc_alert = ProcessedAlert(
            feed_document_id=cftc_doc.id, summary="CFTC market summary",
            topics='["markets"]', relevance_score=0.7,
            document_type="market_notice", ai_model="claude-haiku-4-5-20241022",
        )
        session.add(cftc_alert)
        session.commit()

        return sec_doc.id, cftc_doc.id


class TestFreeChannelTypeGating:
    """Test that free tier can only create email channels."""

    def test_free_user_cannot_create_webhook_channel(self, client):
        _register(client, "freegated@example.com")
        resp = client.post("/channels", data={
            "name": "My Webhook",
            "channel_type": "webhook",
            "webhook_url": "https://example.com/hook",
            "webhook_secret": "",
            "email_address": "",
            "min_relevance_score": "",
            "agency_filter": "",
            "topic_filter": "",
        })
        assert resp.status_code == 200
        assert "Webhook and Slack channels require a Pro plan" in resp.text

    def test_free_user_cannot_create_slack_channel(self, client):
        _register(client, "freeslack@example.com")
        resp = client.post("/channels", data={
            "name": "My Slack",
            "channel_type": "slack",
            "webhook_url": "https://hooks.slack.com/services/T/B/X",
            "webhook_secret": "",
            "email_address": "",
            "min_relevance_score": "",
            "agency_filter": "",
            "topic_filter": "",
        })
        assert resp.status_code == 200
        assert "Webhook and Slack channels require a Pro plan" in resp.text

    def test_free_user_can_create_email_channel(self, client):
        _register(client, "freeemail@example.com")
        resp = client.post("/channels", data={
            "name": "My Email",
            "channel_type": "email",
            "webhook_url": "",
            "webhook_secret": "",
            "email_address": "test@example.com",
            "min_relevance_score": "",
            "agency_filter": "",
            "topic_filter": "",
        })
        assert resp.status_code == 200
        assert "My Email" in resp.text
        assert "Webhook and Slack channels require a Pro plan" not in resp.text

    def test_pro_user_can_create_webhook_channel(self, beta_client):
        _register(beta_client, "prowebhook@example.com")
        resp = beta_client.post("/channels", data={
            "name": "Pro Webhook",
            "channel_type": "webhook",
            "webhook_url": "https://example.com/hook",
            "webhook_secret": "",
            "email_address": "",
            "min_relevance_score": "",
            "agency_filter": "",
            "topic_filter": "",
        })
        assert resp.status_code == 200
        assert "Pro Webhook" in resp.text
        assert "require a Pro plan" not in resp.text


class TestFreeAgencyGating:
    """Test that free tier only sees SEC alerts."""

    def test_free_user_dashboard_only_sec(self, client):
        _seed_sec_and_cftc_docs()
        _register(client, "freeagency@example.com")
        resp = client.get("/")
        assert resp.status_code == 200
        assert "SEC Enforcement Action" in resp.text
        assert "CFTC Market Notice" not in resp.text

    def test_pro_user_dashboard_sees_all(self, beta_client):
        _seed_sec_and_cftc_docs()
        _register(beta_client, "proagency@example.com")
        resp = beta_client.get("/")
        assert resp.status_code == 200
        assert "SEC Enforcement Action" in resp.text
        assert "CFTC Market Notice" in resp.text

    def test_free_user_alerts_only_sec(self, client):
        _seed_sec_and_cftc_docs()
        _register(client, "freeagency2@example.com")
        resp = client.get("/alerts")
        assert resp.status_code == 200
        assert "SEC Enforcement Action" in resp.text
        assert "CFTC Market Notice" not in resp.text

    def test_pro_user_alerts_sees_all(self, beta_client):
        _seed_sec_and_cftc_docs()
        _register(beta_client, "proagency2@example.com")
        resp = beta_client.get("/alerts")
        assert resp.status_code == 200
        assert "SEC Enforcement Action" in resp.text
        assert "CFTC Market Notice" in resp.text


class TestFreeAISummaryGating:
    """Test that free tier doesn't see AI summaries."""

    def test_free_user_alert_detail_shows_upgrade_prompt(self, client):
        sec_id, _ = _seed_sec_and_cftc_docs()
        _register(client, "freeai@example.com")
        resp = client.get(f"/alerts/{sec_id}")
        assert resp.status_code == 200
        assert "AI summary available on Pro plan" in resp.text
        assert "SEC enforcement summary" not in resp.text

    def test_pro_user_alert_detail_shows_summary(self, beta_client):
        sec_id, _ = _seed_sec_and_cftc_docs()
        _register(beta_client, "proai@example.com")
        resp = beta_client.get(f"/alerts/{sec_id}")
        assert resp.status_code == 200
        assert "SEC enforcement summary" in resp.text
        assert "AI summary available on Pro plan" not in resp.text


# ======================================================================
# PHASE 4: Onboarding Flow
# ======================================================================


class TestRegistrationRedirect:
    """Registration should redirect to /welcome."""

    def test_registration_redirects_to_welcome(self, client):
        resp = client.post("/register", data={
            "email": "onboard@example.com",
            "password": "testpass123",
            "password_confirm": "testpass123",
        }, follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["location"] == "/welcome"

    def test_beta_registration_redirects_to_welcome(self, beta_client):
        resp = beta_client.post("/register", data={
            "email": "onboard_beta@example.com",
            "password": "testpass123",
            "password_confirm": "testpass123",
        }, follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["location"] == "/welcome"


class TestWelcomePage:
    """Tests for the /welcome onboarding page."""

    def test_welcome_requires_login(self, client):
        resp = client.get("/welcome", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers.get("location", "")

    def test_welcome_page_renders(self, client):
        _register(client, "welcometest@example.com")
        resp = client.get("/welcome")
        assert resp.status_code == 200
        assert "Welcome to E3" in resp.text
        assert "welcometest" in resp.text  # Shows username portion of email

    def test_welcome_shows_checklist(self, client):
        _register(client, "checklist@example.com")
        resp = client.get("/welcome")
        assert "Create your account" in resp.text
        assert "Set up your first alert channel" in resp.text
        assert "Choose your topics" in resp.text

    def test_welcome_shows_founding_member_number(self, beta_client):
        _register(beta_client, "founder@example.com")
        resp = beta_client.get("/welcome")
        assert resp.status_code == 200
        assert "Founding Member #1" in resp.text

    def test_welcome_founding_member_numbering(self, beta_client):
        """Multiple founding members get sequential numbers."""
        # Register two users
        beta_client.post("/register", data={
            "email": "first@example.com",
            "password": "testpass123",
            "password_confirm": "testpass123",
        })
        beta_client.post("/logout")
        beta_client.post("/register", data={
            "email": "second@example.com",
            "password": "testpass123",
            "password_confirm": "testpass123",
        })
        resp = beta_client.get("/welcome")
        assert "Founding Member #2" in resp.text

    def test_welcome_channel_step_incomplete(self, client):
        """Step 2 shows setup buttons when no channels exist."""
        _register(client, "nochannel@example.com")
        resp = client.get("/welcome")
        assert "Email" in resp.text
        assert "Skip to Dashboard" in resp.text

    def test_welcome_channel_step_complete(self, client):
        """Step 2 shows checkmark when user has a channel."""
        _register(client, "haschannel@example.com")
        # Create a channel
        client.post("/channels", data={
            "name": "Test Email",
            "channel_type": "email",
            "webhook_url": "",
            "webhook_secret": "",
            "email_address": "notify@example.com",
            "min_relevance_score": "",
            "agency_filter": "",
            "topic_filter": "",
        })
        resp = client.get("/welcome")
        assert "you have a notification channel configured" in resp.text.lower()

    def test_welcome_topics_step_complete(self, client):
        """Step 3 shows checkmark when user has set topics."""
        _register(client, "hastopics@example.com")
        client.post("/topics", data={"topics": ["enforcement"]})
        resp = client.get("/welcome")
        assert "your topic preferences are set" in resp.text.lower()

    def test_welcome_all_complete_celebration(self, client):
        """All 3 steps done shows 'You're all set!' celebration."""
        _register(client, "allset@example.com")
        # Create channel
        client.post("/channels", data={
            "name": "Complete Email",
            "channel_type": "email",
            "webhook_url": "",
            "webhook_secret": "",
            "email_address": "done@example.com",
            "min_relevance_score": "",
            "agency_filter": "",
            "topic_filter": "",
        })
        # Set topics
        client.post("/topics", data={"topics": ["enforcement"]})
        resp = client.get("/welcome")
        assert "all set" in resp.text.lower()

    def test_skip_link_present(self, client):
        _register(client, "skip@example.com")
        resp = client.get("/welcome")
        assert "Skip to Dashboard" in resp.text


class TestDashboardChannelNudge:
    """Dashboard should show a setup nudge when user has 0 channels."""

    def test_nudge_shown_when_no_channels(self, client):
        _register(client, "nudge@example.com")
        resp = client.get("/")
        assert resp.status_code == 200
        assert "Set up your first notification channel" in resp.text

    def test_nudge_hidden_when_has_channels(self, client):
        _register(client, "hasch@example.com")
        client.post("/channels", data={
            "name": "Nudge Test",
            "channel_type": "email",
            "webhook_url": "",
            "webhook_secret": "",
            "email_address": "nudge@example.com",
            "min_relevance_score": "",
            "agency_filter": "",
            "topic_filter": "",
        })
        resp = client.get("/")
        assert resp.status_code == 200
        assert "Set up your first notification channel" not in resp.text
