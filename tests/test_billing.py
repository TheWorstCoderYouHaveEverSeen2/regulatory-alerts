"""Tests for Stripe billing integration: tier limits, channel gating, webhooks, pages."""

import json
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
os.environ["STRIPE_SECRET_KEY"] = ""
os.environ["STRIPE_WEBHOOK_SECRET"] = "whsec_test_secret"
os.environ["STRIPE_PUBLISHABLE_KEY"] = ""
os.environ["STRIPE_PRICE_ID_PRO"] = "price_test_pro"

from regulatory_alerts.models import (
    Base,
    NotificationChannel,
    StripeEvent,
    User,
)
from regulatory_alerts.billing import (
    TIER_FREE,
    TIER_PRO,
    TIER_ENTERPRISE,
    TIER_LIMITS,
    get_tier_limits,
    check_channel_limit,
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
                "email": "billing@example.com",
                "password": "testpass123",
                "password_confirm": "testpass123",
            })
            yield c
        app.dependency_overrides.pop(validate_csrf, None)


def _get_test_user():
    """Get the test user from the database."""
    with _TestSession() as session:
        user = session.query(User).filter(User.email == "billing@example.com").first()
        return user


def _set_user_tier(tier: str, status: str = None, stripe_customer_id: str = None,
                   stripe_subscription_id: str = None):
    """Update the test user's subscription fields."""
    with _TestSession() as session:
        user = session.query(User).filter(User.email == "billing@example.com").first()
        user.subscription_tier = tier
        if status is not None:
            user.subscription_status = status
        if stripe_customer_id is not None:
            user.stripe_customer_id = stripe_customer_id
        if stripe_subscription_id is not None:
            user.stripe_subscription_id = stripe_subscription_id
        session.commit()


def _create_channels_for_user(count: int):
    """Create N channels for the test user."""
    with _TestSession() as session:
        user = session.query(User).filter(User.email == "billing@example.com").first()
        for i in range(count):
            ch = NotificationChannel(
                name=f"Channel {i+1}",
                channel_type="webhook",
                webhook_url=f"https://example.com/hook{i+1}",
                user_id=user.id,
            )
            session.add(ch)
        session.commit()


# --- TestTierLimits ---

class TestTierLimits:
    def test_free_tier_limits(self):
        limits = get_tier_limits(TIER_FREE)
        assert limits["max_channels"] == 1
        assert limits["rate_limit"] == "10/minute"

    def test_pro_tier_limits(self):
        limits = get_tier_limits(TIER_PRO)
        assert limits["max_channels"] is None
        assert limits["rate_limit"] == "100/minute"

    def test_enterprise_tier_limits(self):
        limits = get_tier_limits(TIER_ENTERPRISE)
        assert limits["max_channels"] is None

    def test_unknown_tier_defaults_to_free(self):
        limits = get_tier_limits("nonexistent")
        assert limits["max_channels"] == 1

    def test_check_channel_limit_under(self, client):
        user = _get_test_user()
        with _TestSession() as session:
            db_user = session.get(User, user.id)
            allowed, err = check_channel_limit(db_user, session)
            assert allowed is True
            assert err is None


# --- TestChannelGating ---

class TestChannelGating:
    def test_free_user_blocked_at_second_channel_dashboard(self, client):
        _create_channels_for_user(1)
        resp = client.post("/channels", data={
            "name": "Second Channel",
            "channel_type": "email",
            "webhook_url": "",
            "webhook_secret": "",
            "email_address": "second@example.com",
            "min_relevance_score": "",
            "agency_filter": "",
            "topic_filter": "",
        })
        assert resp.status_code == 200
        assert "Free plan is limited to 1 channels" in resp.text

    def test_free_user_can_create_within_limit(self, client):
        resp = client.post("/channels", data={
            "name": "First Channel",
            "channel_type": "email",
            "webhook_url": "",
            "webhook_secret": "",
            "email_address": "first@example.com",
            "min_relevance_score": "",
            "agency_filter": "",
            "topic_filter": "",
        })
        assert resp.status_code == 200
        assert "First Channel" in resp.text
        assert "Free plan is limited" not in resp.text

    def test_pro_user_unlimited_channels(self, client):
        _set_user_tier(TIER_PRO, status="active")
        _create_channels_for_user(5)
        resp = client.post("/channels", data={
            "name": "Sixth Channel",
            "channel_type": "webhook",
            "webhook_url": "https://example.com/hook6",
            "webhook_secret": "",
            "email_address": "",
            "min_relevance_score": "",
            "agency_filter": "",
            "topic_filter": "",
        })
        assert resp.status_code == 200
        assert "Sixth Channel" in resp.text
        assert "Free plan is limited" not in resp.text

    def test_delete_then_create_within_limit(self, client):
        _create_channels_for_user(1)
        with _TestSession() as session:
            user = session.query(User).filter(User.email == "billing@example.com").first()
            ch = session.query(NotificationChannel).filter(
                NotificationChannel.user_id == user.id
            ).first()
            ch_id = ch.id

        client.delete(f"/channels/{ch_id}")

        resp = client.post("/channels", data={
            "name": "Replacement Channel",
            "channel_type": "email",
            "webhook_url": "",
            "webhook_secret": "",
            "email_address": "replacement@example.com",
            "min_relevance_score": "",
            "agency_filter": "",
            "topic_filter": "",
        })
        assert resp.status_code == 200
        assert "Replacement Channel" in resp.text

    def test_error_message_includes_upgrade(self, client):
        _create_channels_for_user(1)
        resp = client.post("/channels", data={
            "name": "Over Limit",
            "channel_type": "email",
            "webhook_url": "",
            "webhook_secret": "",
            "email_address": "over@example.com",
            "min_relevance_score": "",
            "agency_filter": "",
            "topic_filter": "",
        })
        assert "Upgrade to Pro" in resp.text


# --- TestBillingPage ---

class TestBillingPage:
    def test_billing_page_shows_free_tier(self, client):
        resp = client.get("/billing")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "Free" in resp.text
        assert "Upgrade to Pro" in resp.text

    def test_billing_page_shows_pro_tier(self, client):
        _set_user_tier(TIER_PRO, status="active", stripe_customer_id="cus_test123")
        resp = client.get("/billing")
        assert resp.status_code == 200
        assert "Pro" in resp.text
        assert "Manage Subscription" in resp.text

    def test_billing_page_redirects_when_not_logged_in(self):
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
            with TestClient(app, follow_redirects=False) as c:
                resp = c.get("/billing")
                assert resp.status_code == 302
                assert "/login" in resp.headers.get("location", "")


# --- TestPricingPage ---

class TestPricingPage:
    def test_pricing_public_access(self):
        """Pricing page accessible without login."""
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
                resp = c.get("/pricing")
                assert resp.status_code == 200
                assert "text/html" in resp.headers["content-type"]

    def test_pricing_shows_all_tiers(self, client):
        resp = client.get("/pricing")
        assert resp.status_code == 200
        assert "Free" in resp.text
        assert "Pro" in resp.text
        assert "Enterprise" in resp.text
        assert "$79" in resp.text


# --- TestStripeCheckout ---

class TestStripeCheckout:
    def test_checkout_creates_session(self, client):
        """Free user can initiate checkout (mocked Stripe)."""
        from regulatory_alerts import billing as billing_mod
        billing_mod.settings.STRIPE_SECRET_KEY = "sk_test_fake"
        billing_mod.settings.STRIPE_PRICE_ID_PRO = "price_test_pro"

        mock_session = MagicMock()
        mock_session.url = "https://checkout.stripe.com/test"

        try:
            with patch("stripe.Customer.create", return_value=MagicMock(id="cus_test")), \
                 patch("stripe.checkout.Session.create", return_value=mock_session) as mock_create:
                resp = client.post("/billing/checkout", follow_redirects=False)
                assert resp.status_code == 303
                assert "checkout.stripe.com" in resp.headers.get("location", "")
                mock_create.assert_called_once()
        finally:
            billing_mod.settings.STRIPE_SECRET_KEY = ""

    def test_checkout_requires_login(self):
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
            with TestClient(app, follow_redirects=False) as c:
                resp = c.post("/billing/checkout")
                assert resp.status_code == 302
                assert "/login" in resp.headers.get("location", "")
            app.dependency_overrides.pop(validate_csrf, None)

    def test_pro_user_redirected_to_billing(self, client):
        """Pro user trying to checkout gets redirected to billing page."""
        _set_user_tier(TIER_PRO, status="active", stripe_customer_id="cus_test")
        resp = client.post("/billing/checkout", follow_redirects=False)
        assert resp.status_code == 302
        assert "/billing" in resp.headers.get("location", "")

    def test_checkout_stripe_error(self, client):
        """Stripe API error returns friendly message."""
        import stripe
        from regulatory_alerts import billing as billing_mod
        billing_mod.settings.STRIPE_SECRET_KEY = "sk_test_fake"
        billing_mod.settings.STRIPE_PRICE_ID_PRO = "price_test_pro"

        try:
            with patch("stripe.Customer.create", return_value=MagicMock(id="cus_test")), \
                 patch("stripe.checkout.Session.create",
                       side_effect=stripe.error.StripeError("Test error")):
                resp = client.post("/billing/checkout")
                assert resp.status_code == 503
        finally:
            billing_mod.settings.STRIPE_SECRET_KEY = ""


# --- TestStripePortal ---

class TestStripePortal:
    def test_portal_creates_session(self, client):
        """Pro user can open portal."""
        _set_user_tier(TIER_PRO, status="active", stripe_customer_id="cus_test123")
        from regulatory_alerts import billing as billing_mod
        billing_mod.settings.STRIPE_SECRET_KEY = "sk_test_fake"

        mock_portal = MagicMock()
        mock_portal.url = "https://billing.stripe.com/test"

        try:
            with patch("stripe.billing_portal.Session.create", return_value=mock_portal):
                resp = client.post("/billing/portal", follow_redirects=False)
                assert resp.status_code == 303
                assert "billing.stripe.com" in resp.headers.get("location", "")
        finally:
            billing_mod.settings.STRIPE_SECRET_KEY = ""

    def test_portal_requires_stripe_customer(self, client):
        """User without stripe_customer_id gets error."""
        from regulatory_alerts import billing as billing_mod
        billing_mod.settings.STRIPE_SECRET_KEY = "sk_test_fake"
        try:
            resp = client.post("/billing/portal")
            assert resp.status_code == 400
        finally:
            billing_mod.settings.STRIPE_SECRET_KEY = ""


# --- TestStripeWebhook ---

class TestStripeWebhook:
    def _post_webhook(self, client, event_type, event_data, event_id="evt_test_001"):
        """Helper to post a webhook event with mocked signature verification."""
        from regulatory_alerts import billing as billing_mod
        billing_mod.settings.STRIPE_WEBHOOK_SECRET = "whsec_test"
        billing_mod.settings.STRIPE_SECRET_KEY = "sk_test"

        event = {
            "id": event_id,
            "type": event_type,
            "data": event_data,
        }

        with patch("stripe.Webhook.construct_event", return_value=event):
            resp = client.post(
                "/webhooks/stripe",
                content=json.dumps(event),
                headers={"stripe-signature": "t=123,v1=fakesig"},
            )
        return resp

    def test_checkout_completed_upgrades_user(self, client):
        user = _get_test_user()
        resp = self._post_webhook(client, "checkout.session.completed", {
            "object": {
                "client_reference_id": str(user.id),
                "subscription": "sub_test_123",
                "customer": "cus_test_456",
            }
        })
        assert resp.status_code == 200

        with _TestSession() as session:
            db_user = session.get(User, user.id)
            assert db_user.subscription_tier == TIER_PRO
            assert db_user.subscription_status == "active"
            assert db_user.stripe_subscription_id == "sub_test_123"
            assert db_user.stripe_customer_id == "cus_test_456"

    def test_subscription_deleted_downgrades_user(self, client):
        user = _get_test_user()
        _set_user_tier(TIER_PRO, "active", "cus_test", "sub_del_001")

        resp = self._post_webhook(client, "customer.subscription.deleted", {
            "object": {
                "id": "sub_del_001",
                "customer": "cus_test",
            }
        }, event_id="evt_del_001")
        assert resp.status_code == 200

        with _TestSession() as session:
            db_user = session.get(User, user.id)
            assert db_user.subscription_tier == TIER_FREE
            assert db_user.subscription_status == "canceled"
            assert db_user.stripe_subscription_id is None

    def test_payment_failed_sets_past_due(self, client):
        user = _get_test_user()
        _set_user_tier(TIER_PRO, "active", "cus_test", "sub_pf_001")

        resp = self._post_webhook(client, "invoice.payment_failed", {
            "object": {
                "subscription": "sub_pf_001",
            }
        }, event_id="evt_pf_001")
        assert resp.status_code == 200

        with _TestSession() as session:
            db_user = session.get(User, user.id)
            assert db_user.subscription_status == "past_due"
            assert db_user.subscription_tier == TIER_PRO  # Still pro

    def test_bad_signature_returns_400(self, client):
        from regulatory_alerts import billing as billing_mod
        billing_mod.settings.STRIPE_WEBHOOK_SECRET = "whsec_test"
        billing_mod.settings.STRIPE_SECRET_KEY = "sk_test"

        import stripe
        with patch("stripe.Webhook.construct_event",
                   side_effect=stripe.error.SignatureVerificationError("bad sig", "sig")):
            resp = client.post(
                "/webhooks/stripe",
                content=b'{"test": true}',
                headers={"stripe-signature": "t=123,v1=badsig"},
            )
        assert resp.status_code == 400

    def test_unknown_event_returns_200(self, client):
        resp = self._post_webhook(client, "some.unknown.event", {
            "object": {}
        }, event_id="evt_unknown_001")
        assert resp.status_code == 200

    def test_stale_subscription_id_ignored(self, client):
        """Webhook for a different subscription ID should not downgrade user."""
        user = _get_test_user()
        _set_user_tier(TIER_PRO, "active", "cus_test", "sub_current")

        resp = self._post_webhook(client, "customer.subscription.deleted", {
            "object": {
                "id": "sub_old_stale",
                "customer": "cus_test",
            }
        }, event_id="evt_stale_001")
        assert resp.status_code == 200

        with _TestSession() as session:
            db_user = session.get(User, user.id)
            assert db_user.subscription_tier == TIER_PRO  # Not downgraded

    def test_excess_channels_disabled_on_downgrade(self, client):
        user = _get_test_user()
        _set_user_tier(TIER_PRO, "active", "cus_test", "sub_down_001")
        _create_channels_for_user(4)

        resp = self._post_webhook(client, "customer.subscription.deleted", {
            "object": {
                "id": "sub_down_001",
                "customer": "cus_test",
            }
        }, event_id="evt_down_001")
        assert resp.status_code == 200

        with _TestSession() as session:
            channels = session.query(NotificationChannel).filter(
                NotificationChannel.user_id == user.id
            ).order_by(NotificationChannel.id).all()
            enabled = [ch for ch in channels if ch.enabled]
            disabled = [ch for ch in channels if not ch.enabled]
            assert len(enabled) == 1  # Free tier limit is now 1
            assert len(disabled) == 3


# --- TestWebhookIdempotency ---

class TestWebhookIdempotency:
    def test_event_recorded(self, client):
        """Processing an event records it in stripe_events."""
        from regulatory_alerts import billing as billing_mod
        billing_mod.settings.STRIPE_WEBHOOK_SECRET = "whsec_test"
        billing_mod.settings.STRIPE_SECRET_KEY = "sk_test"

        event = {
            "id": "evt_idempotent_001",
            "type": "some.test.event",
            "data": {"object": {}},
        }

        with patch("stripe.Webhook.construct_event", return_value=event):
            resp = client.post(
                "/webhooks/stripe",
                content=json.dumps(event),
                headers={"stripe-signature": "t=123,v1=sig"},
            )
        assert resp.status_code == 200

        with _TestSession() as session:
            se = session.get(StripeEvent, "evt_idempotent_001")
            assert se is not None
            assert se.event_type == "some.test.event"

    def test_duplicate_event_skipped(self, client):
        """Same event ID processed twice should be skipped on second call."""
        from regulatory_alerts import billing as billing_mod
        billing_mod.settings.STRIPE_WEBHOOK_SECRET = "whsec_test"
        billing_mod.settings.STRIPE_SECRET_KEY = "sk_test"

        user = _get_test_user()
        event = {
            "id": "evt_dup_001",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "client_reference_id": str(user.id),
                    "subscription": "sub_dup_001",
                    "customer": "cus_dup_001",
                }
            },
        }

        with patch("stripe.Webhook.construct_event", return_value=event):
            resp1 = client.post(
                "/webhooks/stripe",
                content=json.dumps(event),
                headers={"stripe-signature": "t=123,v1=sig"},
            )
            resp2 = client.post(
                "/webhooks/stripe",
                content=json.dumps(event),
                headers={"stripe-signature": "t=123,v1=sig"},
            )

        assert resp1.status_code == 200
        assert resp2.status_code == 200
        assert resp2.json()["status"] == "already_processed"

    def test_different_event_processed(self, client):
        """Different event IDs should both be processed."""
        from regulatory_alerts import billing as billing_mod
        billing_mod.settings.STRIPE_WEBHOOK_SECRET = "whsec_test"
        billing_mod.settings.STRIPE_SECRET_KEY = "sk_test"

        for i, eid in enumerate(["evt_diff_001", "evt_diff_002"]):
            event = {
                "id": eid,
                "type": "some.test.event",
                "data": {"object": {}},
            }
            with patch("stripe.Webhook.construct_event", return_value=event):
                resp = client.post(
                    "/webhooks/stripe",
                    content=json.dumps(event),
                    headers={"stripe-signature": "t=123,v1=sig"},
                )
            assert resp.status_code == 200
            assert resp.json()["status"] == "ok"

        with _TestSession() as session:
            count = session.query(StripeEvent).count()
            assert count == 2


# --- TestAccountBillingInfo ---

class TestAccountBillingInfo:
    def test_account_shows_subscription_info(self, client):
        resp = client.get("/account")
        assert resp.status_code == 200
        assert "Subscription" in resp.text
        assert "Free" in resp.text

    def test_account_shows_upgrade_link(self, client):
        resp = client.get("/account")
        assert resp.status_code == 200
        assert "Upgrade" in resp.text
        assert "/billing" in resp.text


# --- TestPerUserRateLimiting ---

class TestPerUserRateLimiting:
    def test_free_user_rate_limited(self, client):
        from regulatory_alerts import api as api_mod
        original = api_mod.settings.FREE_RATE_LIMIT
        api_mod.settings.FREE_RATE_LIMIT = "2/minute"
        api_mod.limiter.reset()
        try:
            resp1 = client.get("/api/updates")
            assert resp1.status_code == 200
            resp2 = client.get("/api/updates")
            assert resp2.status_code == 200
            resp3 = client.get("/api/updates")
            assert resp3.status_code == 429
        finally:
            api_mod.settings.FREE_RATE_LIMIT = original
            api_mod.limiter.reset()

    def test_health_exempt_from_rate_limit(self, client):
        from regulatory_alerts import api as api_mod
        original = api_mod.settings.FREE_RATE_LIMIT
        api_mod.settings.FREE_RATE_LIMIT = "2/minute"
        api_mod.limiter.reset()
        try:
            for _ in range(5):
                resp = client.get("/api/health")
                assert resp.status_code == 200
        finally:
            api_mod.settings.FREE_RATE_LIMIT = original
            api_mod.limiter.reset()
