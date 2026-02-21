"""Shared rate limiting — used by api.py and auth.py.

Extracts the Limiter, key function, and dynamic rate limit helper
to avoid circular imports (api.py imports auth.py's router).
"""

import contextvars

from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy import select

from regulatory_alerts.config import get_settings
from regulatory_alerts.database.session import get_sync_session_factory
from regulatory_alerts.models import User

settings = get_settings()

_current_rate_limit: contextvars.ContextVar[str] = contextvars.ContextVar(
    "_current_rate_limit", default=""
)


def _rate_limit_key(request: Request) -> str:
    """Rate limit key: user ID for session users, API key for API users, IP fallback."""
    tier_limit = settings.FREE_RATE_LIMIT

    user_id = request.session.get("user_id") if hasattr(request, "session") else None
    if user_id:
        SessionFactory = get_sync_session_factory()
        with SessionFactory() as session:
            user = session.get(User, user_id)
            if user and user.subscription_tier != "free":
                tier_limit = settings.PRO_RATE_LIMIT
        _current_rate_limit.set(tier_limit)
        return f"user:{user_id}"

    api_key = request.headers.get("X-API-Key")
    if api_key:
        SessionFactory = get_sync_session_factory()
        with SessionFactory() as session:
            api_user = session.scalars(
                select(User).where(User.api_key == api_key, User.is_active == True)  # noqa: E712
            ).first()
            if api_user and api_user.subscription_tier != "free":
                tier_limit = settings.PRO_RATE_LIMIT
        _current_rate_limit.set(tier_limit)
        return f"key:{api_key}"

    _current_rate_limit.set(tier_limit)
    return get_remote_address(request)


limiter = Limiter(key_func=_rate_limit_key)


def _dynamic_rate_limit() -> str:
    """Return tier-based rate limit (set by _rate_limit_key during key resolution)."""
    val = _current_rate_limit.get("")
    return val if val else settings.FREE_RATE_LIMIT
