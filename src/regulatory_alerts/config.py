from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings

# Project root is 3 levels up: src/regulatory_alerts/config.py -> project root
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_DB_PATH = _PROJECT_ROOT / "data" / "regulatory_alerts.db"


class Settings(BaseSettings):
    # Database — defaults to SQLite; set to postgresql+asyncpg://... for Postgres
    # Railway auto-provides DATABASE_URL as plain postgresql:// — we auto-convert below
    DATABASE_URL: str = f"sqlite+aiosqlite:///{_DEFAULT_DB_PATH}"
    DATABASE_URL_SYNC: str = f"sqlite:///{_DEFAULT_DB_PATH}"

    def model_post_init(self, __context) -> None:
        """Auto-convert plain postgresql:// URLs to driver-specific formats.

        Railway and other PaaS providers give you a plain postgresql:// URL.
        Our app needs asyncpg for async and psycopg2 for sync.
        """
        url = self.DATABASE_URL
        # If DATABASE_URL is plain postgresql:// (no driver specified),
        # auto-generate both async and sync variants
        if url.startswith("postgresql://") and "+asyncpg" not in url:
            object.__setattr__(
                self, "DATABASE_URL",
                url.replace("postgresql://", "postgresql+asyncpg://", 1),
            )
            object.__setattr__(
                self, "DATABASE_URL_SYNC",
                url.replace("postgresql://", "postgresql+psycopg2://", 1),
            )
        # If DATABASE_URL already has a driver but SYNC is still SQLite default,
        # derive SYNC from async URL
        elif "+asyncpg" in url and self.DATABASE_URL_SYNC.startswith("sqlite"):
            object.__setattr__(
                self, "DATABASE_URL_SYNC",
                url.replace("postgresql+asyncpg://", "postgresql+psycopg2://", 1),
            )

    # Anthropic API
    ANTHROPIC_API_KEY: str = ""
    CLAUDE_MODEL: str = "claude-haiku-4-5-20241022"
    CLAUDE_MAX_TOKENS: int = 500

    # Feed scraping
    USER_AGENT: str = "RegulatoryAlerts/1.0 (contact@example.com)"
    REQUEST_TIMEOUT: int = 30
    SEC_RATE_LIMIT_PER_SECOND: int = 8  # SEC allows 10, we use 8 for safety margin

    # API
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    API_KEYS: str = ""  # Comma-separated valid API keys; empty = no auth required

    # Email / SMTP (for email notifications)
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "alerts@regulatory-alerts.local"
    SMTP_USE_TLS: bool = True

    # Scheduler
    FETCH_INTERVAL_MINUTES: int = 30

    # Rate limiting
    RATE_LIMIT_DEFAULT: str = "100/minute"

    # Session / Auth
    SECRET_KEY: str = "change-me-in-production"

    # Stripe Billing
    STRIPE_SECRET_KEY: str = ""
    STRIPE_PUBLISHABLE_KEY: str = ""
    STRIPE_WEBHOOK_SECRET: str = ""
    STRIPE_PRICE_ID_PRO: str = ""
    BASE_URL: str = "http://localhost:8000"

    # Tier limits
    FREE_MAX_CHANNELS: int = 1
    FREE_RATE_LIMIT: str = "10/minute"
    PRO_RATE_LIMIT: str = "100/minute"

    # Beta mode
    BETA_MODE: bool = True  # When True, all new signups get Pro tier free
    BETA_END_DATE: str = ""  # ISO date string, e.g. "2026-05-20". Empty = no end date set yet
    FOUNDING_MEMBER_DISCOUNT_PCT: int = 40  # Percentage off GA price for beta users

    # Updated pricing (display only — Stripe Price IDs control actual billing)
    PRO_MONTHLY_PRICE: int = 79
    PRO_ANNUAL_PRICE: int = 63  # per month, billed annually
    TEAM_MONTHLY_PRICE: int = 199
    TEAM_ANNUAL_PRICE: int = 159  # per month, billed annually

    # System alerting
    ALERTING_ENABLED: bool = False
    ALERT_EMAIL: str = ""  # Admin email for system alerts
    ALERT_COOLDOWN_MINUTES: int = 60  # Minimum minutes between alert emails

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"  # "json" (production) or "text" (dev)

    @property
    def api_keys_list(self) -> list[str]:
        """Parse comma-separated API keys into a list."""
        if not self.API_KEYS:
            return []
        return [k.strip() for k in self.API_KEYS.split(",") if k.strip()]

    @property
    def is_sqlite(self) -> bool:
        return self.DATABASE_URL_SYNC.startswith("sqlite")

    @property
    def templates_dir(self) -> Path:
        return Path(__file__).resolve().parent / "templates"

    @property
    def static_dir(self) -> Path:
        return Path(__file__).resolve().parent / "static"

    model_config = {
        "env_file": str(_PROJECT_ROOT / ".env"),
        "case_sensitive": True,
    }


@lru_cache()
def get_settings() -> Settings:
    return Settings()
