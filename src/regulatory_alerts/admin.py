"""Admin dashboard routes — user management, system health, metrics.

All routes require ``is_admin=True`` on the logged-in user.
Non-admins get 403, unauthenticated users are redirected to /login.
"""

import logging

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select

from regulatory_alerts.auth import get_current_user
from regulatory_alerts.config import get_settings
from regulatory_alerts.csrf import validate_csrf
from regulatory_alerts.database.session import get_sync_session_factory
from regulatory_alerts.models import (
    FeedDocument,
    FeedSource,
    NotificationChannel,
    ProcessedAlert,
    User,
)

logger = logging.getLogger(__name__)
settings = get_settings()
templates = Jinja2Templates(directory=str(settings.templates_dir))

router = APIRouter(prefix="/admin", tags=["admin"])


def _require_admin(request: Request):
    """Check session for admin user. Returns User or None."""
    user = get_current_user(request)
    return user if user and user.is_admin else None


# ---------------------------------------------------------------------------
# Admin Dashboard Home
# ---------------------------------------------------------------------------


@router.get("", response_class=HTMLResponse)
def admin_home(request: Request):
    """Admin dashboard with stats overview."""
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")

    from regulatory_alerts.observability import error_counter, get_uptime_seconds, scheduler_metrics

    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        # Users by tier
        tier_rows = session.execute(
            select(User.subscription_tier, func.count(User.id)).group_by(User.subscription_tier)
        ).all()
        users_by_tier = {tier: count for tier, count in tier_rows}

        total_users = sum(users_by_tier.values())
        total_docs = session.scalar(select(func.count(FeedDocument.id))) or 0
        total_alerts = session.scalar(select(func.count(ProcessedAlert.id))) or 0
        total_channels = session.scalar(select(func.count(NotificationChannel.id))) or 0
        total_sources = session.scalar(select(func.count(FeedSource.id))) or 0
        founding_members = session.scalar(
            select(func.count(User.id)).where(User.is_founding_member == True)  # noqa: E712
        ) or 0

    sched = scheduler_metrics.to_dict()
    errors = error_counter.to_dict()
    uptime = get_uptime_seconds()

    return templates.TemplateResponse(
        request,
        "pages/admin_dashboard.html",
        {
            "user": user,
            "active_page": "admin",
            "users_by_tier": users_by_tier,
            "total_users": total_users,
            "total_docs": total_docs,
            "total_alerts": total_alerts,
            "total_channels": total_channels,
            "total_sources": total_sources,
            "founding_members": founding_members,
            "scheduler": sched,
            "errors": errors,
            "uptime": uptime,
        },
    )


# ---------------------------------------------------------------------------
# User Management
# ---------------------------------------------------------------------------


@router.get("/users", response_class=HTMLResponse)
def admin_users(request: Request):
    """List all users with management actions."""
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")

    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        users = session.scalars(select(User).order_by(User.id)).all()
        # Count channels per user
        channel_counts = dict(
            session.execute(
                select(NotificationChannel.user_id, func.count(NotificationChannel.id))
                .group_by(NotificationChannel.user_id)
            ).all()
        )

    return templates.TemplateResponse(
        request,
        "pages/admin_users.html",
        {
            "user": user,
            "active_page": "admin",
            "users_list": users,
            "channel_counts": channel_counts,
        },
    )


@router.post("/users/{user_id}/toggle-active", dependencies=[Depends(validate_csrf)])
def toggle_user_active(request: Request, user_id: int):
    """Toggle a user's is_active status."""
    admin = get_current_user(request)
    if not admin:
        return RedirectResponse(url="/login", status_code=302)
    if not admin.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")

    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot deactivate yourself")

    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        target = session.get(User, user_id)
        if not target:
            raise HTTPException(status_code=404, detail="User not found")
        target.is_active = not target.is_active
        session.commit()

    return RedirectResponse(url="/admin/users", status_code=303)


@router.post("/users/{user_id}/set-tier", dependencies=[Depends(validate_csrf)])
def set_user_tier(request: Request, user_id: int, tier: str = Form(...)):
    """Change a user's subscription tier."""
    admin = get_current_user(request)
    if not admin:
        return RedirectResponse(url="/login", status_code=302)
    if not admin.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")

    allowed_tiers = ("free", "pro", "team", "enterprise")
    if tier not in allowed_tiers:
        raise HTTPException(status_code=400, detail=f"Invalid tier. Must be one of: {', '.join(allowed_tiers)}")

    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        target = session.get(User, user_id)
        if not target:
            raise HTTPException(status_code=404, detail="User not found")
        old_tier = target.subscription_tier
        target.subscription_tier = tier

        # If downgrading to free, disable excess channels
        if tier == "free" and old_tier != "free":
            from regulatory_alerts.billing import _disable_excess_channels
            _disable_excess_channels(target, session)

        session.commit()

    return RedirectResponse(url="/admin/users", status_code=303)


@router.post("/users/{user_id}/set-admin", dependencies=[Depends(validate_csrf)])
def set_user_admin(request: Request, user_id: int):
    """Toggle a user's admin flag."""
    admin = get_current_user(request)
    if not admin:
        return RedirectResponse(url="/login", status_code=302)
    if not admin.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")

    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot change your own admin status")

    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        target = session.get(User, user_id)
        if not target:
            raise HTTPException(status_code=404, detail="User not found")
        target.is_admin = not target.is_admin
        session.commit()

    return RedirectResponse(url="/admin/users", status_code=303)


# ---------------------------------------------------------------------------
# System Health
# ---------------------------------------------------------------------------


@router.get("/system", response_class=HTMLResponse)
def admin_system(request: Request):
    """System health: scheduler, errors, DB stats."""
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")

    from regulatory_alerts.observability import error_counter, get_uptime_seconds, scheduler_metrics

    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        db_stats = {
            "feed_sources": session.scalar(select(func.count(FeedSource.id))) or 0,
            "documents": session.scalar(select(func.count(FeedDocument.id))) or 0,
            "alerts": session.scalar(select(func.count(ProcessedAlert.id))) or 0,
            "channels": session.scalar(select(func.count(NotificationChannel.id))) or 0,
            "users": session.scalar(select(func.count(User.id))) or 0,
        }

    return templates.TemplateResponse(
        request,
        "pages/admin_system.html",
        {
            "user": user,
            "active_page": "admin",
            "scheduler": scheduler_metrics.to_dict(),
            "errors": error_counter.to_dict(),
            "uptime": get_uptime_seconds(),
            "db_stats": db_stats,
        },
    )
