"""Billing routes and helpers — Stripe integration for subscription tiers."""

import logging
from datetime import datetime, timezone

import stripe
from fastapi import APIRouter, Depends, HTTPException, Request

from regulatory_alerts.csrf import validate_csrf
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy import func, select

from regulatory_alerts.auth import get_current_user
from regulatory_alerts.config import get_settings
from regulatory_alerts.database.session import get_sync_session_factory
from regulatory_alerts.models import NotificationChannel, StripeEvent, User

logger = logging.getLogger(__name__)
settings = get_settings()
templates = Jinja2Templates(directory=str(settings.templates_dir))

router = APIRouter(tags=["billing"])

# --- Tier constants ---

TIER_FREE = "free"
TIER_PRO = "pro"
TIER_ENTERPRISE = "enterprise"

TIER_TEAM = "team"

TIER_LIMITS = {
    TIER_FREE: {"max_channels": 1, "rate_limit": "10/minute"},
    TIER_PRO: {"max_channels": None, "rate_limit": "100/minute"},
    TIER_TEAM: {"max_channels": None, "rate_limit": "100/minute"},
    TIER_ENTERPRISE: {"max_channels": None, "rate_limit": "100/minute"},
}

# Map Stripe price IDs to tier names
PRICE_TO_TIER = {}
if settings.STRIPE_PRICE_ID_PRO:
    PRICE_TO_TIER[settings.STRIPE_PRICE_ID_PRO] = TIER_PRO


# --- Helpers ---

def get_tier_limits(tier: str) -> dict:
    """Return limits dict for a subscription tier."""
    return TIER_LIMITS.get(tier, TIER_LIMITS[TIER_FREE])


def check_channel_limit(user: User, session) -> tuple[bool, str | None]:
    """Check if user can create another channel.

    Returns (allowed, error_message). If allowed is True, error_message is None.
    """
    limits = get_tier_limits(user.subscription_tier)
    max_channels = limits["max_channels"]
    if max_channels is None:
        return True, None

    count = session.scalar(
        select(func.count(NotificationChannel.id)).where(
            NotificationChannel.user_id == user.id
        )
    )
    if count >= max_channels:
        return False, (
            f"Free plan is limited to {max_channels} channels. "
            f"Upgrade to Pro for unlimited channels."
        )
    return True, None


def get_or_create_stripe_customer(user: User, session) -> str:
    """Get existing or create new Stripe customer. Returns customer ID."""
    if user.stripe_customer_id:
        return user.stripe_customer_id

    try:
        customer = stripe.Customer.create(
            email=user.email,
            metadata={"user_id": str(user.id)},
        )
    except stripe.error.StripeError as e:
        logger.error("Stripe customer creation failed: %s", e)
        raise HTTPException(status_code=503, detail="Billing service temporarily unavailable")

    user.stripe_customer_id = customer.id
    session.commit()
    return customer.id


def _disable_excess_channels(user: User, session) -> None:
    """Disable channels beyond the free tier limit on downgrade."""
    limits = get_tier_limits(TIER_FREE)
    max_channels = limits["max_channels"]
    if max_channels is None:
        return

    channels = session.scalars(
        select(NotificationChannel)
        .where(NotificationChannel.user_id == user.id, NotificationChannel.enabled == True)  # noqa: E712
        .order_by(NotificationChannel.id)
    ).all()

    if len(channels) > max_channels:
        for ch in channels[max_channels:]:
            ch.enabled = False


# --- Webhook event handlers (dispatch pattern) ---

def _handle_checkout_completed(event_data: dict, session) -> None:
    """Handle checkout.session.completed — upgrade user to pro."""
    checkout_session = event_data["object"]
    client_ref_id = checkout_session.get("client_reference_id")
    if not client_ref_id:
        logger.warning("checkout.session.completed missing client_reference_id")
        return

    try:
        user_id = int(client_ref_id)
    except (ValueError, TypeError):
        logger.error("checkout.session.completed invalid client_reference_id: %s", client_ref_id)
        return

    user = session.get(User, user_id)
    if not user:
        logger.warning("checkout.session.completed user not found: %s", client_ref_id)
        return

    subscription_id = checkout_session.get("subscription")
    user.stripe_subscription_id = subscription_id
    user.subscription_tier = TIER_PRO
    user.subscription_status = "active"
    user.tier_updated_at = datetime.now(timezone.utc)

    # Also store customer ID if not already set
    customer_id = checkout_session.get("customer")
    if customer_id and not user.stripe_customer_id:
        user.stripe_customer_id = customer_id


def _handle_subscription_updated(event_data: dict, session) -> None:
    """Handle customer.subscription.updated — sync status and tier."""
    subscription = event_data["object"]
    sub_id = subscription.get("id")

    user = session.scalars(
        select(User).where(User.stripe_subscription_id == sub_id)
    ).first()
    if not user:
        logger.warning("subscription.updated for unknown subscription: %s", sub_id)
        return

    user.subscription_status = subscription.get("status")
    user.tier_updated_at = datetime.now(timezone.utc)

    # Sync tier from price ID
    items = subscription.get("items", {}).get("data", [])
    if items:
        price_id = items[0].get("price", {}).get("id")
        if price_id and price_id in PRICE_TO_TIER:
            user.subscription_tier = PRICE_TO_TIER[price_id]


def _handle_subscription_deleted(event_data: dict, session) -> None:
    """Handle customer.subscription.deleted — downgrade to free."""
    subscription = event_data["object"]
    sub_id = subscription.get("id")

    user = session.scalars(
        select(User).where(User.stripe_subscription_id == sub_id)
    ).first()
    if not user:
        logger.warning("subscription.deleted for unknown subscription: %s", sub_id)
        return

    user.subscription_tier = TIER_FREE
    user.subscription_status = "canceled"
    user.stripe_subscription_id = None
    user.tier_updated_at = datetime.now(timezone.utc)

    # Disable excess channels
    _disable_excess_channels(user, session)


def _handle_payment_failed(event_data: dict, session) -> None:
    """Handle invoice.payment_failed — set past_due status."""
    invoice = event_data["object"]
    sub_id = invoice.get("subscription")
    if not sub_id:
        return

    user = session.scalars(
        select(User).where(User.stripe_subscription_id == sub_id)
    ).first()
    if not user:
        logger.warning("payment_failed for unknown subscription: %s", sub_id)
        return

    user.subscription_status = "past_due"
    user.tier_updated_at = datetime.now(timezone.utc)


WEBHOOK_HANDLERS = {
    "checkout.session.completed": _handle_checkout_completed,
    "customer.subscription.updated": _handle_subscription_updated,
    "customer.subscription.deleted": _handle_subscription_deleted,
    "invoice.payment_failed": _handle_payment_failed,
}


# --- Routes ---

@router.get("/pricing", response_class=HTMLResponse)
def pricing_page(request: Request):
    """Public pricing page — no login required."""
    user = get_current_user(request)
    return templates.TemplateResponse(request, "pages/pricing.html", {
        "active_page": "pricing",
        "user": user,
        "tier_limits": TIER_LIMITS,
        "beta_mode": settings.BETA_MODE,
        "beta_end_date": settings.BETA_END_DATE,
        "founding_member_discount": settings.FOUNDING_MEMBER_DISCOUNT_PCT,
        "pro_monthly_price": settings.PRO_MONTHLY_PRICE,
        "pro_annual_price": settings.PRO_ANNUAL_PRICE,
        "team_monthly_price": settings.TEAM_MONTHLY_PRICE,
        "team_annual_price": settings.TEAM_ANNUAL_PRICE,
    })


@router.get("/billing", response_class=HTMLResponse)
def billing_page(request: Request):
    """Billing dashboard — shows tier, usage, upgrade/manage buttons."""
    user = get_current_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)

    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        # Re-fetch user from DB to get fresh subscription_tier (may have been updated by webhook)
        db_user = session.get(User, user.id)
        if not db_user:
            return RedirectResponse(url="/login", status_code=302)

        channel_count = session.scalar(
            select(func.count(NotificationChannel.id)).where(
                NotificationChannel.user_id == db_user.id
            )
        )
        limits = get_tier_limits(db_user.subscription_tier)

        return templates.TemplateResponse(request, "pages/billing.html", {
            "active_page": "billing",
            "user": db_user,
            "channel_count": channel_count,
            "max_channels": limits["max_channels"],
            "tier_limits": TIER_LIMITS,
            "beta_mode": settings.BETA_MODE,
            "founding_member_discount": settings.FOUNDING_MEMBER_DISCOUNT_PCT,
        })


@router.post("/billing/checkout")
def create_checkout(request: Request, _csrf: None = Depends(validate_csrf)):
    """Create a Stripe Checkout Session and redirect to Stripe."""
    user = get_current_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)

    # Guard: already subscribed → redirect to portal
    if user.subscription_tier != TIER_FREE:
        return RedirectResponse(url="/billing", status_code=302)

    if not settings.STRIPE_SECRET_KEY or not settings.STRIPE_PRICE_ID_PRO:
        raise HTTPException(status_code=503, detail="Billing is not configured")

    stripe.api_key = settings.STRIPE_SECRET_KEY

    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        db_user = session.get(User, user.id)
        customer_id = get_or_create_stripe_customer(db_user, session)

        try:
            checkout_session = stripe.checkout.Session.create(
                customer=customer_id,
                mode="subscription",
                line_items=[{"price": settings.STRIPE_PRICE_ID_PRO, "quantity": 1}],
                success_url=f"{settings.BASE_URL}/billing?session_id={{CHECKOUT_SESSION_ID}}",
                cancel_url=f"{settings.BASE_URL}/pricing",
                client_reference_id=str(user.id),
            )
        except stripe.error.StripeError as e:
            logger.error("Stripe checkout session creation failed: %s", e)
            raise HTTPException(status_code=503, detail="Billing service temporarily unavailable")

        if not checkout_session.url:
            logger.error("Stripe checkout session created but URL is None")
            raise HTTPException(status_code=503, detail="Billing service temporarily unavailable")

        return RedirectResponse(url=checkout_session.url, status_code=303)


@router.post("/billing/portal")
def create_portal(request: Request, _csrf: None = Depends(validate_csrf)):
    """Create a Stripe Customer Portal session and redirect."""
    user = get_current_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)

    if not user.stripe_customer_id:
        raise HTTPException(status_code=400, detail="No billing account found")

    if not settings.STRIPE_SECRET_KEY:
        raise HTTPException(status_code=503, detail="Billing is not configured")

    stripe.api_key = settings.STRIPE_SECRET_KEY

    try:
        portal_session = stripe.billing_portal.Session.create(
            customer=user.stripe_customer_id,
            return_url=f"{settings.BASE_URL}/billing",
        )
    except stripe.error.StripeError as e:
        logger.error("Stripe portal session creation failed: %s", e)
        raise HTTPException(status_code=503, detail="Billing service temporarily unavailable")

    return RedirectResponse(url=portal_session.url, status_code=303)


@router.post("/webhooks/stripe")
async def stripe_webhook(request: Request):
    """Handle inbound Stripe webhook events with signature verification and idempotency."""
    if not settings.STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=503, detail="Webhook not configured")

    stripe.api_key = settings.STRIPE_SECRET_KEY
    payload = await request.body()
    sig = request.headers.get("stripe-signature")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig, settings.STRIPE_WEBHOOK_SECRET
        )
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid payload")

    event_id = event["id"]
    event_type = event["type"]

    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        # Idempotency check
        existing = session.get(StripeEvent, event_id)
        if existing:
            return {"status": "already_processed"}

        # Dispatch to handler
        handler = WEBHOOK_HANDLERS.get(event_type)
        if handler:
            try:
                handler(event["data"], session)
            except Exception:
                logger.exception("Error processing webhook event %s (%s)", event_id, event_type)
                session.rollback()
                # Do NOT record the event — let Stripe retry
                raise HTTPException(status_code=500, detail="Webhook processing failed")

        # Record the event (same transaction as business logic)
        session.add(StripeEvent(id=event_id, event_type=event_type))
        session.commit()

    return {"status": "ok"}
