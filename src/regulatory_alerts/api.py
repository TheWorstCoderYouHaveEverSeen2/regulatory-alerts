"""FastAPI REST API for Regulatory Alerts.

Endpoints:
    GET  /api/updates              Latest regulatory updates (with filters)
    GET  /api/updates/export       Export updates as CSV download
    GET  /api/updates/{id}         Single update by ID
    GET  /api/health               Health check (backward compat, same as /ready)
    GET  /api/health/live          Liveness probe (no DB, sub-1ms)
    GET  /api/health/ready         Readiness probe (full health check)
    GET  /api/channels             List notification channels
    POST /api/channels             Create a notification channel
    DELETE /api/channels/{id}      Delete a notification channel
    PATCH  /api/channels/{id}      Toggle channel enabled/disabled
    GET  /api/notifications         List notification delivery logs
"""

import csv
import io
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from sqlalchemy import delete, desc, func, select
from sqlalchemy.orm import joinedload

from regulatory_alerts.config import get_settings
from regulatory_alerts.database.session import get_sync_engine, get_sync_session_factory
from starlette.middleware.sessions import SessionMiddleware

from regulatory_alerts.models import (
    Base,
    FeedDocument,
    FeedSource,
    NotificationChannel,
    NotificationLog,
    ProcessedAlert,
    User,
)

logger = logging.getLogger(__name__)
settings = get_settings()

# --- Rate Limiting (shared module) ---

from regulatory_alerts.rate_limit import limiter, _dynamic_rate_limit  # noqa: E402


# --- Auth ---

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def verify_api_key(request: Request, api_key: str | None = Security(api_key_header)) -> str | None:
    """Validate the API key if authentication is enabled.

    Checks in order:
    1. If API_KEYS env var is empty, auth is disabled (all requests pass).
    2. Check against env-based API_KEYS (admin/service keys).
    3. Check against user API keys in the database.

    Also stashes the resolved User on request.state.api_user for rate limiting.
    """
    valid_keys = settings.api_keys_list
    if not valid_keys:
        return None  # Auth disabled
    if not api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    # Check env-based keys first
    if api_key in valid_keys:
        return api_key
    # Check DB-based user keys
    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        user = session.scalars(
            select(User).where(User.api_key == api_key, User.is_active == True)  # noqa: E712
        ).first()
        if user:
            request.state.api_user = user
            return api_key
    raise HTTPException(status_code=401, detail="Invalid or missing API key")


# --- Lifespan ---

@asynccontextmanager
async def lifespan(app: FastAPI):
    from regulatory_alerts.core.scheduler import start_scheduler, stop_scheduler
    from regulatory_alerts.observability import configure_logging, record_app_start

    configure_logging(settings.LOG_LEVEL, settings.LOG_FORMAT)
    record_app_start()

    if settings.SECRET_KEY == "change-me-in-production":
        if settings.is_sqlite:
            logger.warning(
                "SECRET_KEY is set to the default value. "
                "Set a strong random key: python -c 'import secrets; print(secrets.token_urlsafe(32))'"
            )
        else:
            raise RuntimeError(
                "FATAL: SECRET_KEY is set to the default value. "
                "Generate a strong key: python -c 'import secrets; print(secrets.token_urlsafe(32))' "
                "and set the SECRET_KEY environment variable."
            )

    engine = get_sync_engine()
    Base.metadata.create_all(engine)

    # Start background fetch scheduler
    start_scheduler()

    yield

    # Shutdown scheduler on app exit
    stop_scheduler()


# --- App ---

app = FastAPI(
    title="Regulatory Alerts API",
    description="AI-powered regulatory monitoring for SEC and CFTC filings",
    version="0.10.0-beta",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.BASE_URL],
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-CSRFToken", "X-API-Key", "X-Requested-With"],
    allow_credentials=True,
    max_age=600,
)

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SECRET_KEY,
    session_cookie="session",
    max_age=14 * 24 * 60 * 60,  # 14 days
    same_site="lax",
    https_only=not settings.is_sqlite,  # HTTPS in prod (Postgres), HTTP for local dev (SQLite)
)

# Request logging — outermost middleware (last added = outermost in Starlette LIFO)
from regulatory_alerts.observability import RequestLoggingMiddleware  # noqa: E402

app.add_middleware(RequestLoggingMiddleware)


# CSRF token injection — register get_csrf_token as a Jinja2 global
# so templates can use {{ get_csrf_token(request) }}
from regulatory_alerts.csrf import get_csrf_token as _csrf_fn  # noqa: E402

# We need to register this on all Jinja2 environments used across modules.
# Import them after routers are included (at the bottom of this file).
_csrf_globals_installed = False


def _install_csrf_globals():
    """Register get_csrf_token on all Jinja2 template environments."""
    global _csrf_globals_installed
    if _csrf_globals_installed:
        return
    from regulatory_alerts.admin import templates as admin_tmpl
    from regulatory_alerts.auth import templates as auth_tmpl
    from regulatory_alerts.dashboard import templates as dash_tmpl
    from regulatory_alerts.billing import templates as bill_tmpl
    for tmpl in (auth_tmpl, dash_tmpl, bill_tmpl, admin_tmpl):
        tmpl.env.globals["get_csrf_token"] = _csrf_fn
    _csrf_globals_installed = True


# Static files
if settings.static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(settings.static_dir)), name="static")


# --- Response schemas ---

class UpdateResponse(BaseModel):
    id: int
    title: str
    agency: str
    url: str
    published_at: str
    document_type: Optional[str] = None
    summary: Optional[str] = None
    topics: list[str] = []
    relevance_score: Optional[float] = None
    ai_model: Optional[str] = None

    model_config = {"from_attributes": True}


class UpdatesListResponse(BaseModel):
    count: int
    updates: list[UpdateResponse]


class SchedulerHealthResponse(BaseModel):
    status: str
    total_cycles: int
    successful_cycles: int = 0
    partial_cycles: int = 0
    failed_cycles: int = 0
    last_run_at: Optional[str] = None
    last_duration_seconds: Optional[float] = None


class ErrorsResponse(BaseModel):
    total: int
    by_module: dict[str, int] = {}


class HealthResponse(BaseModel):
    status: str
    feed_sources: int
    total_documents: int
    total_alerts: int
    notification_channels: int
    uptime_seconds: float = 0.0
    database_connected: bool = True
    scheduler: Optional[SchedulerHealthResponse] = None
    errors: Optional[ErrorsResponse] = None


class LivenessResponse(BaseModel):
    status: str
    uptime_seconds: float


class ChannelResponse(BaseModel):
    id: int
    name: str
    channel_type: str
    enabled: bool
    webhook_url: Optional[str] = None
    email_address: Optional[str] = None
    min_relevance_score: Optional[float] = None
    agency_filter: Optional[str] = None
    topic_filter: list[str] = []

    model_config = {"from_attributes": True}


class ChannelCreateRequest(BaseModel):
    name: str
    channel_type: str  # "webhook", "email", or "slack"
    webhook_url: Optional[str] = None
    webhook_secret: Optional[str] = None
    email_address: Optional[str] = None
    min_relevance_score: Optional[float] = None
    agency_filter: Optional[str] = None
    topic_filter: list[str] = []


class ChannelToggleRequest(BaseModel):
    enabled: bool


# --- Helpers ---

def _build_update(doc: FeedDocument, alert: Optional[ProcessedAlert] = None, hide_ai: bool = False) -> UpdateResponse:
    """Convert a FeedDocument + optional ProcessedAlert into an API response.

    Args:
        hide_ai: If True, omit AI-generated fields (summary, topics, relevance_score)
                 for free tier users.
    """
    topics: list[str] = []
    if alert and alert.topics and not hide_ai:
        try:
            parsed = json.loads(alert.topics) if isinstance(alert.topics, str) else alert.topics
            if isinstance(parsed, list):
                topics = parsed
        except (json.JSONDecodeError, TypeError):
            pass

    return UpdateResponse(
        id=doc.id,
        title=doc.title,
        agency=doc.agency,
        url=doc.url,
        published_at=doc.published_at.isoformat() if doc.published_at else "",
        document_type=alert.document_type if alert and not hide_ai else doc.document_type,
        summary=None if hide_ai else (alert.summary if alert else doc.raw_summary),
        topics=topics,
        relevance_score=None if hide_ai else (alert.relevance_score if alert else None),
        ai_model=None if hide_ai else (alert.ai_model if alert else None),
    )


def _build_channel_response(ch: NotificationChannel) -> ChannelResponse:
    return ChannelResponse(
        id=ch.id,
        name=ch.name,
        channel_type=ch.channel_type,
        enabled=ch.enabled,
        webhook_url=ch.webhook_url,
        email_address=ch.email_address,
        min_relevance_score=ch.min_relevance_score,
        agency_filter=ch.agency_filter,
        topic_filter=ch.topic_filter_list,
    )


# --- Update endpoints ---

@app.get("/api/updates", response_model=UpdatesListResponse)
@limiter.limit(_dynamic_rate_limit)
def list_updates(
    request: Request,
    limit: int = Query(20, ge=1, le=100, description="Number of updates to return"),
    agency: Optional[str] = Query(None, description="Filter by agency (SEC, CFTC)"),
    topic: Optional[str] = Query(None, description="Filter by topic"),
    min_score: Optional[float] = Query(None, ge=0, le=1, description="Minimum relevance score"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    _key: str | None = Depends(verify_api_key),
):
    """Return the latest regulatory updates as JSON."""
    from regulatory_alerts.dashboard import query_updates

    # Determine user tier for gating
    api_user = getattr(request.state, "api_user", None)
    is_free = api_user.subscription_tier == "free" if api_user else False
    agency_restrict = "SEC" if is_free else None

    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        docs, total = query_updates(
            session, agency=agency, topic=topic, min_score=min_score,
            limit=limit, offset=offset, restrict_agency=agency_restrict,
        )
        updates = [_build_update(doc, doc.alert, hide_ai=is_free) for doc in docs]
        return UpdatesListResponse(count=total, updates=updates)


@app.get("/api/updates/export")
@limiter.limit(_dynamic_rate_limit)
def export_updates(
    request: Request,
    agency: Optional[str] = Query(None, description="Filter by agency (SEC, CFTC)"),
    topic: Optional[str] = Query(None, description="Filter by topic"),
    min_score: Optional[float] = Query(None, ge=0, le=1, description="Minimum relevance score"),
    limit: int = Query(1000, ge=1, le=10000, description="Maximum rows to export"),
    _key: str | None = Depends(verify_api_key),
):
    """Export regulatory updates as a CSV file download.

    Supports the same filters as /api/updates. Default limit is 1000 rows.
    """
    from regulatory_alerts.dashboard import query_updates
    from starlette.responses import StreamingResponse

    # Determine user tier for gating
    api_user = getattr(request.state, "api_user", None)
    is_free = api_user.subscription_tier == "free" if api_user else False
    agency_restrict = "SEC" if is_free else None

    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        docs, _ = query_updates(
            session, agency=agency, topic=topic, min_score=min_score, limit=limit,
            restrict_agency=agency_restrict,
        )
        rows = [_build_update(doc, doc.alert, hide_ai=is_free) for doc in docs]

    # Build CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Title", "Agency", "URL", "Published At",
        "Document Type", "Topics", "Relevance Score", "Summary",
    ])
    for u in rows:
        writer.writerow([
            u.id,
            u.title,
            u.agency,
            u.url,
            u.published_at,
            u.document_type or "",
            "; ".join(u.topics),
            f"{u.relevance_score:.2f}" if u.relevance_score is not None else "",
            u.summary or "",
        ])

    csv_bytes = output.getvalue().encode("utf-8-sig")  # BOM for Excel compat
    return StreamingResponse(
        io.BytesIO(csv_bytes),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=regulatory_alerts_export.csv"},
    )


@app.get("/api/updates/{update_id}", response_model=UpdateResponse)
@limiter.limit(_dynamic_rate_limit)
def get_update(request: Request, update_id: int, _key: str | None = Depends(verify_api_key)):
    """Get a single regulatory update by ID."""
    api_user = getattr(request.state, "api_user", None)
    is_free = api_user.subscription_tier == "free" if api_user else False

    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        doc = session.get(
            FeedDocument,
            update_id,
            options=[joinedload(FeedDocument.alert)],
        )
        if not doc:
            raise HTTPException(status_code=404, detail="Update not found")

        return _build_update(doc, doc.alert, hide_ai=is_free)


# --- Notification channel endpoints ---

@app.get("/api/channels", response_model=list[ChannelResponse])
@limiter.limit(_dynamic_rate_limit)
def list_channels(request: Request, _key: str | None = Depends(verify_api_key)):
    """List notification channels owned by the authenticated user."""
    api_user = getattr(request.state, "api_user", None)
    session_user_id = request.session.get("user_id") if hasattr(request, "session") else None
    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        query = select(NotificationChannel)
        if api_user:
            query = query.where(NotificationChannel.user_id == api_user.id)
        elif session_user_id:
            query = query.where(NotificationChannel.user_id == session_user_id)
        elif settings.api_keys_list:
            # Auth is enabled but no user identified — return empty
            return []
        channels = session.scalars(query).all()
        return [_build_channel_response(ch) for ch in channels]


@app.post("/api/channels", response_model=ChannelResponse, status_code=201)
@limiter.limit(_dynamic_rate_limit)
def create_channel(request: Request, req: ChannelCreateRequest, _key: str | None = Depends(verify_api_key)):
    """Create a new notification channel."""
    from regulatory_alerts.billing import check_channel_limit

    if req.channel_type not in ("webhook", "email", "slack"):
        raise HTTPException(status_code=400, detail="channel_type must be 'webhook', 'email', or 'slack'")

    if req.channel_type == "webhook" and not req.webhook_url:
        raise HTTPException(status_code=400, detail="webhook_url required for webhook channels")

    if req.channel_type == "webhook" and req.webhook_url:
        from regulatory_alerts.validation import validate_webhook_url
        url_valid, url_error = validate_webhook_url(req.webhook_url)
        if not url_valid:
            raise HTTPException(status_code=400, detail=url_error)

    if req.channel_type == "slack" and not req.webhook_url:
        raise HTTPException(status_code=400, detail="webhook_url required for Slack channels")
    if req.channel_type == "slack" and req.webhook_url:
        if not req.webhook_url.startswith("https://hooks.slack.com/"):
            raise HTTPException(status_code=400, detail="Slack webhook URL must start with https://hooks.slack.com/")

    if req.channel_type == "email" and not req.email_address:
        raise HTTPException(status_code=400, detail="email_address required for email channels")

    # Resolve user for channel ownership and limit check
    api_user = getattr(request.state, "api_user", None)

    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        # Free tier: only email channels allowed
        if api_user:
            db_user = session.get(User, api_user.id)
            if db_user and db_user.subscription_tier == "free" and req.channel_type in ("webhook", "slack"):
                raise HTTPException(status_code=403, detail="Webhook and Slack channels require a Pro plan")

        # Channel limit gating (if user is known)
        if api_user:
            db_user = session.get(User, api_user.id)
            if db_user:
                allowed, err_msg = check_channel_limit(db_user, session)
                if not allowed:
                    raise HTTPException(status_code=403, detail=err_msg)

        channel = NotificationChannel(
            name=req.name,
            channel_type=req.channel_type,
            webhook_url=req.webhook_url,
            webhook_secret=req.webhook_secret,
            email_address=req.email_address,
            min_relevance_score=req.min_relevance_score,
            agency_filter=req.agency_filter.upper() if req.agency_filter else None,
            topic_filter=json.dumps(req.topic_filter) if req.topic_filter else None,
            user_id=api_user.id if api_user else None,
        )
        session.add(channel)
        session.commit()
        session.refresh(channel)
        return _build_channel_response(channel)


@app.delete("/api/channels/{channel_id}", status_code=204)
@limiter.limit(_dynamic_rate_limit)
def delete_channel(request: Request, channel_id: int, _key: str | None = Depends(verify_api_key)):
    """Delete a notification channel and its logs. Users can only delete their own channels."""
    api_user = getattr(request.state, "api_user", None)
    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        channel = session.get(NotificationChannel, channel_id)
        if not channel:
            raise HTTPException(status_code=404, detail="Channel not found")

        # Ownership check: users can only delete their own channels (404 to prevent enumeration)
        session_user_id = request.session.get("user_id") if hasattr(request, "session") else None
        if api_user and channel.user_id != api_user.id:
            raise HTTPException(status_code=404, detail="Channel not found")
        elif session_user_id and channel.user_id != session_user_id:
            raise HTTPException(status_code=404, detail="Channel not found")
        elif settings.api_keys_list and not api_user and not session_user_id:
            raise HTTPException(status_code=404, detail="Channel not found")

        # Delete associated logs first
        session.execute(
            delete(NotificationLog).where(NotificationLog.channel_id == channel_id)
        )
        session.delete(channel)
        session.commit()


@app.patch("/api/channels/{channel_id}", response_model=ChannelResponse)
@limiter.limit(_dynamic_rate_limit)
def toggle_channel(
    request: Request,
    channel_id: int,
    req: ChannelToggleRequest,
    _key: str | None = Depends(verify_api_key),
):
    """Toggle a notification channel's enabled state."""
    api_user = getattr(request.state, "api_user", None)
    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        channel = session.get(NotificationChannel, channel_id)
        if not channel:
            raise HTTPException(status_code=404, detail="Channel not found")

        # Ownership check (same pattern as delete)
        session_user_id = request.session.get("user_id") if hasattr(request, "session") else None
        if api_user and channel.user_id != api_user.id:
            raise HTTPException(status_code=404, detail="Channel not found")
        elif session_user_id and channel.user_id != session_user_id:
            raise HTTPException(status_code=404, detail="Channel not found")
        elif settings.api_keys_list and not api_user and not session_user_id:
            raise HTTPException(status_code=404, detail="Channel not found")

        channel.enabled = req.enabled
        session.commit()
        return _build_channel_response(channel)


# --- Notification Logs ---

class NotificationLogResponse(BaseModel):
    id: int
    channel_id: int
    channel_name: str
    channel_type: str
    alert_id: int
    alert_title: Optional[str] = None
    status: str
    error_message: Optional[str] = None
    sent_at: Optional[str] = None
    retry_count: int = 0
    created_at: Optional[str] = None


class NotificationLogsListResponse(BaseModel):
    count: int
    logs: list[NotificationLogResponse]


@app.get("/api/notifications", response_model=NotificationLogsListResponse)
@limiter.limit(_dynamic_rate_limit)
def list_notifications(
    request: Request,
    channel_id: Optional[int] = Query(None, description="Filter by channel ID"),
    status: Optional[str] = Query(None, description="Filter by status (sent, failed, pending)"),
    limit: int = Query(20, ge=1, le=100, description="Number of logs to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    _key: str | None = Depends(verify_api_key),
):
    """List notification delivery logs scoped to the authenticated user's channels."""
    api_user = getattr(request.state, "api_user", None)
    session_user_id = request.session.get("user_id") if hasattr(request, "session") else None

    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        # Get user's channel IDs for scoping
        ch_query = select(NotificationChannel.id)
        if api_user:
            ch_query = ch_query.where(NotificationChannel.user_id == api_user.id)
        elif session_user_id:
            ch_query = ch_query.where(NotificationChannel.user_id == session_user_id)
        elif settings.api_keys_list:
            return NotificationLogsListResponse(count=0, logs=[])

        user_channel_ids = list(session.scalars(ch_query).all())

        if not user_channel_ids:
            return NotificationLogsListResponse(count=0, logs=[])

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

        result_logs = []
        for log in logs:
            alert_title = None
            if log.alert and log.alert.feed_document:
                alert_title = log.alert.feed_document.title
            result_logs.append(NotificationLogResponse(
                id=log.id,
                channel_id=log.channel_id,
                channel_name=log.channel.name if log.channel else "Deleted",
                channel_type=log.channel.channel_type if log.channel else "unknown",
                alert_id=log.alert_id,
                alert_title=alert_title,
                status=log.status,
                error_message=log.error_message,
                sent_at=log.sent_at.isoformat() if log.sent_at else None,
                retry_count=log.retry_count,
                created_at=log.created_at.isoformat() if log.created_at else None,
            ))

        return NotificationLogsListResponse(count=total, logs=result_logs)


# --- Prometheus Metrics ---

@app.get("/metrics")
def prometheus_metrics_endpoint():
    """Expose Prometheus metrics. No auth, no rate limit."""
    from prometheus_client import generate_latest

    from regulatory_alerts.observability import prometheus_metrics

    prometheus_metrics.collect_from_singletons()

    try:
        SessionFactory = get_sync_session_factory()
        with SessionFactory() as session:
            prometheus_metrics.collect_from_db(session)
    except Exception:
        pass  # Serve whatever we have if DB is down

    from starlette.responses import Response

    return Response(
        content=generate_latest(prometheus_metrics.registry),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


# --- Health ---

def _full_health_check() -> HealthResponse:
    """Shared logic for readiness probe and backward-compatible health endpoint."""
    from regulatory_alerts.core.scheduler import get_scheduler_status
    from regulatory_alerts.observability import error_counter, get_uptime_seconds

    db_connected = True
    feed_sources = 0
    total_documents = 0
    total_alerts_count = 0
    notification_channels = 0

    try:
        SessionFactory = get_sync_session_factory()
        with SessionFactory() as session:
            feed_sources = session.scalar(select(func.count(FeedSource.id))) or 0
            total_documents = session.scalar(select(func.count(FeedDocument.id))) or 0
            total_alerts_count = session.scalar(select(func.count(ProcessedAlert.id))) or 0
            notification_channels = session.scalar(select(func.count(NotificationChannel.id))) or 0
    except Exception:
        db_connected = False
        logger.exception("Health check: database unreachable")

    sched = get_scheduler_status()
    errors = error_counter.to_dict()

    health_status = "ok"
    if not db_connected or sched.get("status") == "error":
        health_status = "degraded"

    return HealthResponse(
        status=health_status,
        feed_sources=feed_sources,
        total_documents=total_documents,
        total_alerts=total_alerts_count,
        notification_channels=notification_channels,
        uptime_seconds=get_uptime_seconds(),
        database_connected=db_connected,
        scheduler=SchedulerHealthResponse(**sched),
        errors=ErrorsResponse(**errors),
    )


@app.get("/api/health/live", response_model=LivenessResponse)
def liveness():
    """Liveness probe: confirms the process is running. No DB, no scheduler check."""
    from regulatory_alerts.observability import get_uptime_seconds

    return LivenessResponse(status="ok", uptime_seconds=get_uptime_seconds())


@app.get("/api/health/ready", response_model=HealthResponse)
def readiness():
    """Readiness probe: full health check including DB, scheduler, errors."""
    return _full_health_check()


@app.get("/api/health", response_model=HealthResponse)
def health_check():
    """Health check (backward-compatible). Same as /api/health/ready."""
    return _full_health_check()


# --- Auth (session-based login/registration) ---

from regulatory_alerts.auth import router as auth_router  # noqa: E402

app.include_router(auth_router)

# --- Billing ---

from regulatory_alerts.billing import router as billing_router  # noqa: E402

app.include_router(billing_router)

# --- Dashboard (HTML frontend) ---

from regulatory_alerts.dashboard import router as dashboard_router  # noqa: E402

app.include_router(dashboard_router)

# --- Admin ---

from regulatory_alerts.admin import router as admin_router  # noqa: E402

app.include_router(admin_router)

# Install CSRF token as Jinja2 global (must happen after router imports)
_install_csrf_globals()
