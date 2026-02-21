"""CSRF protection — session-stored token with dual validation (form + header)."""

import secrets

from fastapi import Form, HTTPException, Request


def get_csrf_token(request: Request) -> str:
    """Read or create a CSRF token in the session."""
    token = request.session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["_csrf_token"] = token
    return token


async def validate_csrf(
    request: Request,
    csrftoken: str | None = Form(None),
) -> None:
    """Validate CSRF token from header (HTMX) or form field (standard forms).

    Raises HTTP 403 if the token is missing or does not match.
    """
    expected = request.session.get("_csrf_token")
    if not expected:
        raise HTTPException(status_code=403, detail="CSRF token missing from session")

    # Check header first (HTMX sends via hx-headers on body)
    submitted = request.headers.get("X-CSRFToken")
    if not submitted:
        submitted = csrftoken  # Fall back to form hidden input

    if not submitted or not secrets.compare_digest(submitted, expected):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
