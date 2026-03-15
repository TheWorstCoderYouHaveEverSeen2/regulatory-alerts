"""Authentication routes and helpers — session-based login/registration/password reset.

Password reset uses stateless signed tokens (itsdangerous.URLSafeTimedSerializer).
Token payload: {uid: int, hp: str} where hp = first 16 chars of hashed_password.
This makes tokens single-use: changing the password invalidates all outstanding tokens.
"""

import logging
import secrets

import bcrypt as _bcrypt
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from fastapi import APIRouter, Depends, Form, Request

from regulatory_alerts.csrf import validate_csrf
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from regulatory_alerts.config import get_settings
from regulatory_alerts.database.session import get_sync_session_factory
from regulatory_alerts.models import User
from regulatory_alerts.rate_limit import limiter

logger = logging.getLogger(__name__)

settings = get_settings()
templates = Jinja2Templates(directory=str(settings.templates_dir))

router = APIRouter(tags=["auth"])

# --- Password reset token helpers ---

_RESET_SALT = "password-reset"
_RESET_MAX_AGE = 3600  # 1 hour


def _get_serializer() -> URLSafeTimedSerializer:
    """Create a token serializer using the app's SECRET_KEY."""
    return URLSafeTimedSerializer(get_settings().SECRET_KEY)


def generate_reset_token(user: User) -> str:
    """Generate a password reset token embedding user ID + password hash prefix.

    The hash prefix (first 16 chars) ensures the token becomes invalid
    once the user changes their password (single-use enforcement).
    """
    s = _get_serializer()
    return s.dumps({"uid": user.id, "hp": user.hashed_password[:16]}, salt=_RESET_SALT)


def validate_reset_token(token: str) -> dict | None:
    """Validate and decode a password reset token.

    Returns:
        {"uid": int, "hp": str} if valid, None if invalid/expired.
    """
    s = _get_serializer()
    try:
        data = s.loads(token, salt=_RESET_SALT, max_age=_RESET_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None
    # Ensure payload structure is correct
    if not isinstance(data, dict) or "uid" not in data or "hp" not in data:
        return None
    return data


# --- Password helpers ---

def hash_password(plain: str) -> str:
    salt = _bcrypt.gensalt()
    return _bcrypt.hashpw(plain.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    return _bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def generate_api_key() -> str:
    return secrets.token_urlsafe(32)


# --- Session helpers ---

def get_current_user(request: Request):
    """Read user_id from session, return User or None."""
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        user = session.get(User, user_id)
        if user and user.is_active:
            return user
    return None


def require_login(request: Request):
    """Dependency: redirect to /login if not authenticated."""
    user = get_current_user(request)
    if user is None:
        return None  # Caller checks and redirects
    return user


# --- Auth routes ---

@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    # If already logged in, redirect to dashboard
    if request.session.get("user_id"):
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse(request, "pages/login.html", {
        "active_page": "login",
    })


@router.post("/login", response_class=HTMLResponse)
@limiter.limit("5/minute")
def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    _csrf: None = Depends(validate_csrf),
):
    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        user = session.scalars(
            select(User).where(User.email == email.strip().lower())
        ).first()

        if not user or not verify_password(password, user.hashed_password):
            return templates.TemplateResponse(request, "pages/login.html", {
                "active_page": "login",
                "error": "Invalid email or password.",
                "email": email,
            })

        if not user.is_active:
            return templates.TemplateResponse(request, "pages/login.html", {
                "active_page": "login",
                "error": "Account is disabled.",
                "email": email,
            })

        # Set session + rotate CSRF token (prevents session fixation)
        request.session.pop("_csrf_token", None)
        request.session["user_id"] = user.id
        return RedirectResponse(url="/", status_code=302)


@router.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse(request, "pages/register.html", {
        "active_page": "register",
    })


@router.post("/register", response_class=HTMLResponse)
@limiter.limit("3/minute")
def register_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
    _csrf: None = Depends(validate_csrf),
):
    errors = []
    clean_email = email.strip().lower()

    if not clean_email:
        errors.append("Email is required.")
    elif "@" not in clean_email or "." not in clean_email.split("@")[-1]:
        errors.append("Please enter a valid email address.")
    elif len(clean_email) > 254:
        errors.append("Email address is too long.")
    if len(password) < 8:
        errors.append("Password must be at least 8 characters.")
    if len(password) > 128:
        errors.append("Password must be 128 characters or fewer.")
    if password != password_confirm:
        errors.append("Passwords do not match.")

    if errors:
        return templates.TemplateResponse(request, "pages/register.html", {
            "active_page": "register",
            "errors": errors,
            "email": email,
        })

    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        # Check for duplicate email
        existing = session.scalars(
            select(User).where(User.email == clean_email)
        ).first()
        if existing:
            return templates.TemplateResponse(request, "pages/register.html", {
                "active_page": "register",
                "errors": ["An account with that email already exists."],
                "email": email,
            })

        user = User(
            email=clean_email,
            hashed_password=hash_password(password),
            api_key=generate_api_key(),
        )

        # Beta mode: grant Pro tier + founding member status to new signups
        if settings.BETA_MODE:
            from datetime import datetime, timezone

            # Check founding member cap before granting status
            founding_count = session.scalar(
                select(func.count(User.id)).where(User.is_founding_member == True)  # noqa: E712
            ) or 0
            cap = settings.FOUNDING_MEMBER_CAP

            if cap <= 0 or founding_count < cap:
                # Spots available — grant founding member status + Pro tier
                user.subscription_tier = "pro"
                user.is_founding_member = True
                user.beta_enrolled_at = datetime.now(timezone.utc)
            else:
                # Cap reached — still register but as free tier (beta full)
                user.subscription_tier = "free"
                user.is_founding_member = False

        session.add(user)
        try:
            session.commit()
        except IntegrityError:
            session.rollback()
            return templates.TemplateResponse(request, "pages/register.html", {
                "active_page": "register",
                "errors": ["An account with that email already exists."],
                "email": email,
            })
        session.refresh(user)

        # Auto-login after registration
        request.session["user_id"] = user.id
        return RedirectResponse(url="/welcome", status_code=302)


@router.post("/logout")
def logout(request: Request, _csrf: None = Depends(validate_csrf)):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)


@router.get("/account", response_class=HTMLResponse)
def account_page(request: Request):
    user = get_current_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse(request, "pages/account.html", {
        "active_page": "account",
        "user": user,
    })


@router.post("/account/regenerate-key", response_class=HTMLResponse)
def regenerate_api_key(request: Request, _csrf: None = Depends(validate_csrf)):
    user = get_current_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)

    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        db_user = session.get(User, user.id)
        if not db_user:
            request.session.clear()
            return RedirectResponse(url="/login", status_code=302)
        db_user.api_key = generate_api_key()
        session.commit()
        session.refresh(db_user)

        return templates.TemplateResponse(request, "pages/account.html", {
            "active_page": "account",
            "user": db_user,
            "flash_message": "API key regenerated successfully.",
            "flash_type": "green",
        })


# --- Password Reset ---

def _build_reset_email(reset_url: str) -> str:
    """Build HTML body for the password reset email."""
    return f"""\
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
  <div style="background: #1a1a2e; color: white; padding: 16px 20px; border-radius: 8px 8px 0 0;">
    <h2 style="margin: 0;">Password Reset</h2>
    <p style="margin: 4px 0 0; opacity: 0.8;">Regulatory Alerts</p>
  </div>
  <div style="padding: 20px; border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 8px 8px;">
    <p>You requested a password reset. Click the button below to set a new password:</p>
    <div style="text-align: center; margin: 24px 0;">
      <a href="{reset_url}"
         style="display: inline-block; background: #1a1a2e; color: white; padding: 12px 32px;
                border-radius: 6px; text-decoration: none; font-weight: bold;">
        Reset Password
      </a>
    </div>
    <p style="font-size: 13px; color: #666;">
      This link expires in 1 hour. If you didn't request this, you can safely ignore this email.
    </p>
    <p style="font-size: 12px; color: #999; word-break: break-all;">
      Or copy this link: {reset_url}
    </p>
  </div>
  <p style="font-size: 11px; color: #999; text-align: center; margin-top: 12px;">
    Sent by Regulatory Alerts SaaS
  </p>
</body>
</html>"""


@router.get("/forgot-password", response_class=HTMLResponse)
def forgot_password_page(request: Request):
    """Show the forgot-password form."""
    return templates.TemplateResponse(request, "pages/forgot_password.html", {
        "active_page": "login",
    })


@router.post("/forgot-password", response_class=HTMLResponse)
@limiter.limit("3/minute")
def forgot_password_submit(
    request: Request,
    email: str = Form(...),
    _csrf: None = Depends(validate_csrf),
):
    """Process forgot-password request: generate token, send email.

    SECURITY: Always shows the same success message regardless of whether
    the email exists — prevents user enumeration.
    """
    clean_email = email.strip().lower()
    success_ctx = {
        "active_page": "login",
        "success": True,
    }

    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        user = session.scalars(
            select(User).where(User.email == clean_email)
        ).first()

        if user and user.is_active:
            token = generate_reset_token(user)
            base_url = get_settings().BASE_URL.rstrip("/")
            reset_url = f"{base_url}/reset-password?token={token}"

            html_body = _build_reset_email(reset_url)

            # Lazy import to avoid circular dependency (notifier → models → auth)
            from regulatory_alerts.core.notifier import send_raw_email
            ok, err = send_raw_email(
                to=user.email,
                subject="Password Reset — Regulatory Alerts",
                html_body=html_body,
            )
            if not ok:
                logger.warning("Password reset email failed for %s: %s", clean_email, err)
        else:
            # Log for audit but don't reveal to user
            logger.info("Password reset requested for non-existent/inactive email: %s", clean_email)

    return templates.TemplateResponse(request, "pages/forgot_password.html", success_ctx)


@router.get("/reset-password", response_class=HTMLResponse)
def reset_password_page(request: Request, token: str = ""):
    """Validate the reset token and show the new-password form."""
    if not token:
        return templates.TemplateResponse(request, "pages/reset_password.html", {
            "active_page": "login",
            "error": "This reset link is invalid or has expired.",
        })

    data = validate_reset_token(token)
    if not data:
        return templates.TemplateResponse(request, "pages/reset_password.html", {
            "active_page": "login",
            "error": "This reset link is invalid or has expired.",
        })

    # Verify hash prefix still matches (single-use check on GET too)
    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        user = session.get(User, data["uid"])
        if not user or not user.is_active or user.hashed_password[:16] != data["hp"]:
            return templates.TemplateResponse(request, "pages/reset_password.html", {
                "active_page": "login",
                "error": "This reset link is invalid or has expired.",
            })

    return templates.TemplateResponse(request, "pages/reset_password.html", {
        "active_page": "login",
        "token": token,
    })


@router.post("/reset-password", response_class=HTMLResponse)
def reset_password_submit(
    request: Request,
    token: str = Form(""),
    password: str = Form(...),
    password_confirm: str = Form(...),
    _csrf: None = Depends(validate_csrf),
):
    """Validate token, validate new password, update password hash.

    SECURITY: Invalidates session after reset (prevents session fixation).
    Rotates CSRF token. Token becomes single-use because hash prefix changes.
    """
    # Validate token
    data = validate_reset_token(token)
    if not data:
        return templates.TemplateResponse(request, "pages/reset_password.html", {
            "active_page": "login",
            "error": "This reset link is invalid or has expired.",
        })

    # Validate password
    errors = []
    if len(password) < 8:
        errors.append("Password must be at least 8 characters.")
    if len(password) > 128:
        errors.append("Password must be 128 characters or fewer.")
    if password != password_confirm:
        errors.append("Passwords do not match.")

    if errors:
        return templates.TemplateResponse(request, "pages/reset_password.html", {
            "active_page": "login",
            "token": token,
            "errors": errors,
        })

    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        user = session.get(User, data["uid"])

        # Re-verify hash prefix (race condition prevention)
        if not user or not user.is_active or user.hashed_password[:16] != data["hp"]:
            return templates.TemplateResponse(request, "pages/reset_password.html", {
                "active_page": "login",
                "error": "This reset link is invalid or has expired.",
            })

        # Update password — this invalidates all outstanding reset tokens
        user.hashed_password = hash_password(password)
        session.commit()

        logger.info("Password reset completed for user %d", user.id)

    # Invalidate session + rotate CSRF (security: prevent session fixation)
    request.session.clear()

    return templates.TemplateResponse(request, "pages/reset_password.html", {
        "active_page": "login",
        "reset_success": True,
    })
