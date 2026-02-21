"""Shared test fixtures: in-memory SQLite database, session, seeded data."""

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

# Ensure src is on path for imports
_src = str(Path(__file__).resolve().parents[1] / "src")
if _src not in sys.path:
    sys.path.insert(0, _src)

# Set test env vars before importing config
os.environ.setdefault("ANTHROPIC_API_KEY", "test-key-not-real")
os.environ.setdefault("DATABASE_URL_SYNC", "sqlite:///:memory:")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("STRIPE_SECRET_KEY", "")
os.environ.setdefault("STRIPE_WEBHOOK_SECRET", "")
os.environ.setdefault("STRIPE_PUBLISHABLE_KEY", "")
os.environ.setdefault("STRIPE_PRICE_ID_PRO", "")

from regulatory_alerts.csrf import validate_csrf
from regulatory_alerts.models import (
    Base,
    FeedDocument,
    FeedSource,
    NotificationChannel,
    ProcessedAlert,
)


async def noop_csrf():
    """No-op CSRF validator for business logic tests."""
    return None


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Reset slowapi rate limiter storage before and after each test to prevent 429 leaks."""
    from regulatory_alerts.rate_limit import limiter

    limiter.reset()
    yield
    limiter.reset()


@pytest.fixture(autouse=True)
def _disable_beta_mode():
    """Disable beta mode by default in all tests to preserve existing behavior.

    Tests that specifically want to test beta mode should re-enable it:
        settings.BETA_MODE = True
    """
    from regulatory_alerts.config import get_settings
    _settings = get_settings()
    _orig = _settings.BETA_MODE
    _settings.BETA_MODE = False
    yield
    _settings.BETA_MODE = _orig


def _enable_sqlite_fk(dbapi_conn, connection_record):
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


@pytest.fixture()
def db_engine():
    """Create a fresh in-memory SQLite engine with all tables."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    event.listen(engine, "connect", _enable_sqlite_fk)
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture()
def db_session(db_engine):
    """Provide a transactional session that rolls back after each test."""
    SessionFactory = sessionmaker(db_engine, expire_on_commit=False)
    session = SessionFactory()
    yield session
    session.rollback()
    session.close()


@pytest.fixture()
def seed_feed_source(db_session: Session) -> FeedSource:
    """Insert a single SEC feed source and return it."""
    source = FeedSource(
        name="SEC Press Releases",
        agency="SEC",
        feed_url="https://www.sec.gov/news/pressreleases.rss",
        feed_type="rss",
        enabled=True,
    )
    db_session.add(source)
    db_session.commit()
    return source


@pytest.fixture()
def seed_document(db_session: Session, seed_feed_source: FeedSource) -> FeedDocument:
    """Insert a single FeedDocument and return it."""
    doc = FeedDocument(
        feed_source_id=seed_feed_source.id,
        external_id="test-doc-001",
        content_hash="abc123",
        title="SEC Charges Acme Corp for Securities Fraud",
        url="https://www.sec.gov/litigation/litreleases/test-001",
        published_at=datetime(2026, 2, 7, 12, 0, 0, tzinfo=timezone.utc),
        discovered_at=datetime(2026, 2, 7, 12, 5, 0, tzinfo=timezone.utc),
        agency="SEC",
        raw_summary="The SEC filed charges against Acme Corp.",
        processing_status="pending",
    )
    db_session.add(doc)
    db_session.commit()
    return doc


@pytest.fixture()
def seed_alert(db_session: Session, seed_document: FeedDocument) -> ProcessedAlert:
    """Insert a ProcessedAlert for the seed document."""
    alert = ProcessedAlert(
        feed_document_id=seed_document.id,
        summary="The SEC charged Acme Corp with securities fraud related to misleading disclosures.",
        key_points=["Acme Corp charged", "Misleading disclosures", "Penalty pending"],
        topics='["enforcement", "fraud", "securities"]',
        relevance_score=0.95,
        document_type="enforcement_action",
        ai_model="claude-haiku-4-5-20241022",
        ai_cost_usd=0.000123,
    )
    db_session.add(alert)
    seed_document.processing_status = "completed"
    db_session.commit()
    return alert


@pytest.fixture()
def seed_webhook_channel(db_session: Session) -> NotificationChannel:
    """Insert a webhook notification channel."""
    channel = NotificationChannel(
        name="Test Webhook",
        channel_type="webhook",
        webhook_url="https://hooks.example.com/test",
        webhook_secret="test-secret-123",
        enabled=True,
        min_relevance_score=0.5,
    )
    db_session.add(channel)
    db_session.commit()
    return channel
