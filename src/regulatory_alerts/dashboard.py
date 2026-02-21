"""Dashboard routes — HTML frontend served via Jinja2 + HTMX."""

import json

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request

from regulatory_alerts.csrf import validate_csrf
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import delete, desc, func, select
from sqlalchemy.orm import joinedload

from regulatory_alerts.auth import get_current_user
from regulatory_alerts.config import get_settings
from regulatory_alerts.database.session import get_sync_session_factory
from regulatory_alerts.models import (
    FeedDocument,
    FeedSource,
    NotificationChannel,
    NotificationLog,
    ProcessedAlert,
    User,
)

settings = get_settings()
templates = Jinja2Templates(directory=str(settings.templates_dir))

router = APIRouter(tags=["dashboard"])


def _is_htmx(request: Request) -> bool:
    return request.headers.get("HX-Request") == "true"


def _require_login(request: Request):
    """Check session for logged-in user; return User or None (caller redirects)."""
    user = get_current_user(request)
    return user


def _parse_topics(alert: ProcessedAlert | None) -> list[str]:
    """Parse topics JSON from an alert into a list."""
    if not alert or not alert.topics:
        return []
    try:
        parsed = json.loads(alert.topics) if isinstance(alert.topics, str) else alert.topics
        return parsed if isinstance(parsed, list) else []
    except (json.JSONDecodeError, TypeError):
        return []


def _score_class(score: float | None) -> str:
    """Return CSS class for relevance score badge."""
    if score is None:
        return "score-none"
    if score >= 0.7:
        return "score-high"
    if score >= 0.5:
        return "score-medium"
    return "score-low"


def get_known_topics(session) -> list[str]:
    """Return a sorted, deduplicated list of all topics across processed alerts."""
    # Select only the topics column — avoids loading summary/key_points TEXT blobs
    topic_strings = session.scalars(
        select(ProcessedAlert.topics).where(ProcessedAlert.topics.isnot(None))
    ).all()
    topics_set: set[str] = set()
    for raw in topic_strings:
        try:
            parsed = json.loads(raw) if isinstance(raw, str) else raw
            if isinstance(parsed, list):
                topics_set.update(parsed)
        except (json.JSONDecodeError, TypeError):
            pass
    return sorted(topics_set)


def query_updates(
    session,
    agency: str | None = None,
    topic: str | None = None,
    min_score: float | None = None,
    limit: int = 20,
    offset: int = 0,
    subscribed_topics: list[str] | None = None,
    restrict_agency: str | None = None,
) -> tuple[list[FeedDocument], int]:
    """Query FeedDocuments with alerts, applying filters. Returns (page, total_count).

    Args:
        subscribed_topics: If provided, only include alerts matching these topics.
            Empty list = nothing matches. None = no topic subscription filter.
        restrict_agency: If set, force-filter to this agency (e.g. "SEC" for free tier).
            Overrides the user-specified agency filter.
    """
    query = (
        select(FeedDocument)
        .options(joinedload(FeedDocument.alert))
        .order_by(desc(FeedDocument.published_at))
    )

    # Free tier agency restriction takes precedence
    effective_agency = restrict_agency or agency
    if effective_agency:
        query = query.where(FeedDocument.agency == effective_agency.upper())

    docs = session.scalars(query).unique().all()

    # Post-query filtering for topic, score, and subscriptions (matches API behavior)
    filtered = []
    for doc in docs:
        alert = doc.alert

        # Subscription filter: if user has subscribed topics, only show matching alerts
        if subscribed_topics is not None:
            if not subscribed_topics:
                continue  # empty list = nothing matches
            if alert:
                alert_topics = alert.topics_list
                if not any(t in subscribed_topics for t in alert_topics):
                    continue
            else:
                continue  # no alert = no topics = skip

        if topic and alert:
            if topic not in alert.topics_list:
                continue
        elif topic and not alert:
            continue
        if min_score is not None and alert:
            if (alert.relevance_score or 0) < min_score:
                continue
        elif min_score is not None and not alert:
            continue
        filtered.append(doc)

    total = len(filtered)
    page = filtered[offset : offset + limit]
    return page, total


# --- Onboarding ---

@router.get("/welcome", response_class=HTMLResponse)
def welcome_page(request: Request):
    """Post-registration onboarding page."""
    user = _require_login(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)

    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        db_user = session.get(User, user.id)

        has_channel = (session.scalar(
            select(func.count(NotificationChannel.id)).where(NotificationChannel.user_id == user.id)
        ) or 0) > 0
        has_topics = db_user.subscribed_topics_list is not None

        # Founding member number: count of founding members with id <= this user
        founding_member_number = 0
        if db_user.is_founding_member:
            founding_member_number = session.scalar(
                select(func.count(User.id)).where(
                    User.is_founding_member == True,  # noqa: E712
                    User.id <= user.id,
                )
            ) or 0

        # Track onboarding state in session
        if has_channel and has_topics:
            request.session["onboarding_complete"] = True

        return templates.TemplateResponse(request, "pages/welcome.html", {
            "active_page": "welcome",
            "user": user,
            "has_channel": has_channel,
            "has_topics": has_topics,
            "founding_member_number": founding_member_number,
        })


# --- Dashboard Home ---

@router.get("/", response_class=HTMLResponse)
def dashboard_home(request: Request):
    user = _require_login(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)

    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        # Refresh user from this session for topic subscriptions
        db_user = session.get(User, user.id)

        channel_count = session.scalar(
            select(func.count(NotificationChannel.id)).where(NotificationChannel.user_id == user.id)
        ) or 0
        stats = {
            "feed_sources": session.scalar(select(func.count(FeedSource.id))) or 0,
            "total_documents": session.scalar(select(func.count(FeedDocument.id))) or 0,
            "total_alerts": session.scalar(select(func.count(ProcessedAlert.id))) or 0,
            "notification_channels": channel_count,
        }

        # Filter by user's subscribed topics (None = show all)
        user_topics = db_user.subscribed_topics_list if db_user else None

        # Free tier: SEC only
        agency_restrict = "SEC" if user.subscription_tier == "free" else None
        docs, _ = query_updates(session, limit=10, subscribed_topics=user_topics, restrict_agency=agency_restrict)

        return templates.TemplateResponse(request, "pages/dashboard.html", {
            "active_page": "dashboard",
            "stats": stats,
            "docs": docs,
            "parse_topics": _parse_topics,
            "score_class": _score_class,
            "user": user,
            "is_free_tier": user.subscription_tier == "free",
            "show_channel_nudge": channel_count == 0,
        })


# --- Alerts ---

@router.get("/alerts", response_class=HTMLResponse)
def alerts_list(
    request: Request,
    agency: str | None = Query(None),
    topic: str | None = Query(None),
    min_score: float | None = Query(None),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    user = _require_login(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)

    # Free tier: SEC only
    agency_restrict = "SEC" if user.subscription_tier == "free" else None

    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        docs, total = query_updates(session, agency=agency, topic=topic,
                                    min_score=min_score, limit=limit, offset=offset,
                                    restrict_agency=agency_restrict)

        total_pages = max(1, (total + limit - 1) // limit)
        current_page = (offset // limit) + 1

        context = {
            "request": request,
            "active_page": "alerts",
            "docs": docs,
            "total": total,
            "total_pages": total_pages,
            "current_page": current_page,
            "limit": limit,
            "offset": offset,
            "agency": agency or "",
            "topic": topic or "",
            "min_score": min_score,
            "parse_topics": _parse_topics,
            "score_class": _score_class,
            "user": user,
            "is_free_tier": user.subscription_tier == "free",
        }

        if _is_htmx(request):
            return templates.TemplateResponse(request, "partials/_alerts_table_body.html", context)

        return templates.TemplateResponse(request, "pages/alerts_list.html", context)


@router.get("/alerts/{alert_id}", response_class=HTMLResponse)
def alert_detail(request: Request, alert_id: int):
    user = _require_login(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)

    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        doc = session.get(
            FeedDocument, alert_id,
            options=[joinedload(FeedDocument.alert)],
        )
        if not doc:
            raise HTTPException(status_code=404, detail="Alert not found")

        is_free = user.subscription_tier == "free"
        return templates.TemplateResponse(request, "pages/alert_detail.html", {
            "active_page": "alerts",
            "doc": doc,
            "alert": None if is_free else doc.alert,
            "topics": [] if is_free else _parse_topics(doc.alert),
            "score_class": _score_class,
            "key_points": [] if is_free else (doc.alert.key_points if doc.alert and doc.alert.key_points else []),
            "user": user,
            "is_free_tier": is_free,
        })


# --- Channels (user-scoped) ---


def _get_user_channels(session, user_id: int) -> list:
    """Query all channels for a user. Single source of truth for channel list queries."""
    return session.scalars(
        select(NotificationChannel).where(NotificationChannel.user_id == user_id)
    ).all()


def _render_channels(
    request, session, user,
    *,
    flash_message: str | None = None,
    flash_type: str = "green",
    errors: list[str] | None = None,
    form_data: dict | None = None,
    is_htmx: bool = False,
):
    """Render the channels page or HTMX partial. DRYs up repeated render logic."""
    channels = _get_user_channels(session, user.id)

    if is_htmx:
        ctx = {"channels": channels}
        if flash_message:
            ctx["flash_message"] = flash_message
            ctx["flash_type"] = flash_type
        return templates.TemplateResponse(request, "partials/_channels_list.html", ctx)

    ctx = {
        "active_page": "channels",
        "channels": channels,
        "user": user,
    }
    if flash_message:
        ctx["flash_message"] = flash_message
        ctx["flash_type"] = flash_type
    if errors:
        ctx["errors"] = errors
    if form_data:
        ctx["form_data"] = form_data
    return templates.TemplateResponse(request, "pages/channels.html", ctx)


@router.get("/channels", response_class=HTMLResponse)
def channels_page(request: Request):
    user = _require_login(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)

    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        return _render_channels(request, session, user)


@router.post("/channels", response_class=HTMLResponse)
def channels_create(
    request: Request,
    name: str = Form(...),
    channel_type: str = Form(...),
    webhook_url: str = Form(""),
    webhook_secret: str = Form(""),
    email_address: str = Form(""),
    min_relevance_score: str = Form(""),
    agency_filter: str = Form(""),
    topic_filter: str = Form(""),
    _csrf: None = Depends(validate_csrf),
):
    user = _require_login(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)

    # Validation
    errors = []
    if channel_type not in ("webhook", "email", "slack"):
        errors.append("Channel type must be 'webhook', 'email', or 'slack'.")
    if channel_type == "webhook" and not webhook_url.strip():
        errors.append("Webhook URL is required for webhook channels.")
    elif channel_type == "webhook" and webhook_url.strip():
        from regulatory_alerts.validation import validate_webhook_url
        url_valid, url_error = validate_webhook_url(webhook_url.strip())
        if not url_valid:
            errors.append(url_error)
    if channel_type == "slack" and not webhook_url.strip():
        errors.append("Webhook URL is required for Slack channels.")
    elif channel_type == "slack" and webhook_url.strip():
        if not webhook_url.strip().startswith("https://hooks.slack.com/"):
            errors.append("Slack webhook URL must start with https://hooks.slack.com/")
        else:
            from regulatory_alerts.validation import validate_webhook_url
            url_valid, url_error = validate_webhook_url(webhook_url.strip())
            if not url_valid:
                errors.append(url_error)
    if channel_type == "email" and not email_address.strip():
        errors.append("Email address is required for email channels.")
    if not name.strip():
        errors.append("Channel name is required.")

    from regulatory_alerts.billing import check_channel_limit

    # Free tier: only email channels allowed
    if user.subscription_tier == "free" and channel_type in ("webhook", "slack"):
        errors.append("Webhook and Slack channels require a Pro plan.")

    # Shared form data for error re-renders
    fdata = {
        "name": name, "channel_type": channel_type,
        "webhook_url": webhook_url, "webhook_secret": webhook_secret,
        "email_address": email_address, "min_relevance_score": min_relevance_score,
        "agency_filter": agency_filter, "topic_filter": topic_filter,
    }

    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        if errors:
            return _render_channels(request, session, user, errors=errors, form_data=fdata)

        # Channel limit gating
        db_user = session.get(User, user.id)
        allowed, err_msg = check_channel_limit(db_user, session)
        if not allowed:
            return _render_channels(request, session, user, errors=[err_msg], form_data=fdata)

        # Parse optional fields
        min_score = None
        if min_relevance_score.strip():
            try:
                min_score = float(min_relevance_score)
                if not (0 <= min_score <= 1):
                    errors.append("Minimum relevance score must be between 0 and 1.")
                    min_score = None
            except ValueError:
                errors.append("Minimum relevance score must be a number.")

        if errors:
            return _render_channels(request, session, user, errors=errors, form_data=fdata)

        agency = agency_filter.upper() if agency_filter.strip() else None
        topics_json = None
        if topic_filter.strip():
            topics_json = json.dumps([t.strip() for t in topic_filter.split(",") if t.strip()])

        channel = NotificationChannel(
            name=name.strip(),
            channel_type=channel_type,
            webhook_url=webhook_url.strip() or None,
            webhook_secret=webhook_secret.strip() or None,
            email_address=email_address.strip() or None,
            min_relevance_score=min_score,
            agency_filter=agency,
            topic_filter=topics_json,
            user_id=user.id,
        )
        session.add(channel)
        session.commit()

        return _render_channels(
            request, session, user,
            flash_message=f'Channel "{name}" created successfully.',
            is_htmx=_is_htmx(request),
        )


@router.delete("/channels/{channel_id}", response_class=HTMLResponse)
def channels_delete(request: Request, channel_id: int, _csrf: None = Depends(validate_csrf)):
    user = _require_login(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)

    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        channel = session.get(NotificationChannel, channel_id)
        if not channel:
            raise HTTPException(status_code=404, detail="Channel not found")

        # Only allow deleting own channels (404 to prevent ID enumeration)
        if channel.user_id != user.id:
            raise HTTPException(status_code=404, detail="Channel not found")

        channel_name = channel.name
        session.execute(
            delete(NotificationLog).where(NotificationLog.channel_id == channel_id)
        )
        session.delete(channel)
        session.commit()

        return _render_channels(
            request, session, user,
            flash_message=f'Channel "{channel_name}" deleted.',
            is_htmx=_is_htmx(request),
        )


@router.post("/channels/{channel_id}/toggle", response_class=HTMLResponse)
def channels_toggle(request: Request, channel_id: int, _csrf: None = Depends(validate_csrf)):
    """Toggle a channel's enabled/disabled state."""
    user = _require_login(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)

    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        channel = session.get(NotificationChannel, channel_id)
        if not channel or channel.user_id != user.id:
            raise HTTPException(status_code=404, detail="Channel not found")

        channel.enabled = not channel.enabled
        status_text = "enabled" if channel.enabled else "disabled"
        session.commit()

        return _render_channels(
            request, session, user,
            flash_message=f'Channel "{channel.name}" {status_text}.',
            is_htmx=_is_htmx(request),
        )


# --- Channel Test ---

@router.post("/channels/{channel_id}/test", response_class=HTMLResponse)
def channels_test(request: Request, channel_id: int, _csrf: None = Depends(validate_csrf)):
    """Send a test notification to verify channel configuration."""
    user = _require_login(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)

    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        channel = session.get(NotificationChannel, channel_id)
        if not channel or channel.user_id != user.id:
            raise HTTPException(status_code=404, detail="Channel not found")

        if not channel.enabled:
            return _render_channels(
                request, session, user,
                flash_message="Cannot test a disabled channel. Enable it first.",
                flash_type="red",
                is_htmx=True,
            )

        # Build transient test objects (NOT added to session)
        from datetime import datetime, timezone
        test_doc = FeedDocument(
            id=0,
            title="[TEST] Regulatory Alert Test Notification",
            agency="SEC",
            url="https://www.sec.gov/test",
            published_at=datetime.now(timezone.utc),
        )
        test_alert = ProcessedAlert(
            id=0,
            feed_document_id=0,
            summary="This is a test notification to verify your channel configuration is working correctly.",
            topics='["test"]',
            relevance_score=1.0,
            document_type="test",
            ai_model="test",
            key_points=["Test notification sent successfully"],
        )
        # Wire up the relationship manually for payload builders
        test_alert.feed_document = test_doc

        from regulatory_alerts.core.notifier import send_test_notification
        success, error = send_test_notification(channel, test_alert, test_doc)

        if success:
            flash_msg = f'Test notification sent to "{channel.name}" successfully!'
            flash_type = "green"
        else:
            flash_msg = f'Test failed for "{channel.name}": {error[:200]}'
            flash_type = "red"

        return _render_channels(
            request, session, user,
            flash_message=flash_msg,
            flash_type=flash_type,
            is_htmx=_is_htmx(request),
        )


# --- Notification History ---

@router.get("/notifications", response_class=HTMLResponse)
def notifications_page(
    request: Request,
    channel_id: int | None = Query(None),
    status: str | None = Query(None),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    """Show paginated notification delivery history."""
    user = _require_login(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)

    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        # Get user's channel IDs for scoping
        user_channels = session.scalars(
            select(NotificationChannel).where(NotificationChannel.user_id == user.id)
        ).all()
        user_channel_ids = [ch.id for ch in user_channels]

        # Build shared filter conditions (applied to both count and data queries)
        conditions = [NotificationLog.channel_id.in_(user_channel_ids)]
        if channel_id is not None:
            if channel_id not in user_channel_ids:
                raise HTTPException(status_code=404, detail="Channel not found")
            conditions.append(NotificationLog.channel_id == channel_id)
        if status and status in ("sent", "failed", "pending"):
            conditions.append(NotificationLog.status == status)

        total = session.scalar(
            select(func.count(NotificationLog.id)).where(*conditions)
        ) or 0

        # Paginate
        logs = session.scalars(
            select(NotificationLog)
            .options(
                joinedload(NotificationLog.channel),
                joinedload(NotificationLog.alert).joinedload(ProcessedAlert.feed_document),
            )
            .where(*conditions)
            .order_by(desc(NotificationLog.created_at))
            .offset(offset)
            .limit(limit)
        ).unique().all()

        total_pages = max(1, (total + limit - 1) // limit)
        current_page = (offset // limit) + 1

        context = {
            "active_page": "notifications",
            "logs": logs,
            "channels": user_channels,
            "total": total,
            "total_pages": total_pages,
            "current_page": current_page,
            "limit": limit,
            "offset": offset,
            "channel_id": channel_id,
            "status_filter": status or "",
            "user": user,
        }

        if _is_htmx(request):
            return templates.TemplateResponse(request, "partials/_notifications_table.html", context)

        return templates.TemplateResponse(request, "pages/notifications.html", context)


# --- Topic Subscriptions ---

@router.get("/topics", response_class=HTMLResponse)
def topics_page(request: Request):
    """Show the topic subscription management page."""
    user = _require_login(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)

    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        db_user = session.get(User, user.id)
        known_topics = get_known_topics(session)
        user_topics = db_user.subscribed_topics_list  # None = all

        return templates.TemplateResponse(request, "pages/topics.html", {
            "active_page": "topics",
            "known_topics": known_topics,
            "user_topics": user_topics,
            "user": user,
        })


@router.post("/topics", response_class=HTMLResponse)
def topics_update(
    request: Request,
    topics: list[str] = Form(default=[]),
    show_all: str = Form(default=""),
    _csrf: None = Depends(validate_csrf),
):
    """Update the user's topic subscriptions."""
    user = _require_login(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)

    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        db_user = session.get(User, user.id)

        if show_all:
            # "Show all" checkbox checked — remove subscription filter
            db_user.subscribed_topics_list = None
        else:
            # Store selected topics (empty list = show nothing)
            clean_topics = sorted(set(t.strip() for t in topics if t.strip()))
            db_user.subscribed_topics_list = clean_topics

        session.commit()

        known_topics = get_known_topics(session)
        user_topics = db_user.subscribed_topics_list

        return templates.TemplateResponse(request, "pages/topics.html", {
            "active_page": "topics",
            "known_topics": known_topics,
            "user_topics": user_topics,
            "user": user,
            "flash_message": "Topic subscriptions updated.",
            "flash_type": "green",
        })


# --- About ---

@router.get("/about", response_class=HTMLResponse)
def about_page(request: Request):
    return templates.TemplateResponse(request, "pages/landing.html", {
        "active_page": "about",
    })
