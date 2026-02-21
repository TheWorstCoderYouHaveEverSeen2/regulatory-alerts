"""Tests for hardening improvements: CFTC scraper fallback, CSV export,
API channel ownership, session factory caching.

Covers:
    - CFTC scraper: 3 parsing strategies + fallback cascade + retry + date parsing
    - CSV export: endpoint, filters, format, empty results
    - API channel ownership: list/delete scoping
    - Session factory: lru_cache prevents duplicate engines
"""

import csv
import io
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

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
os.environ["API_KEYS"] = ""  # Auth disabled for most tests

from regulatory_alerts.models import (
    Base,
    FeedDocument,
    FeedSource,
    NotificationChannel,
    ProcessedAlert,
    User,
)
from regulatory_alerts.csrf import validate_csrf


async def noop_csrf():
    return None


def _enable_sqlite_fk(dbapi_conn, connection_record):
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


# Shared test engine
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


@pytest.fixture(autouse=True)
def _reset_observability_singletons():
    from regulatory_alerts.observability import scheduler_metrics, error_counter, reset_uptime
    scheduler_metrics.reset()
    error_counter.reset()
    reset_uptime()
    yield


def _seed_data():
    """Create feed source, documents, and alerts for testing."""
    with _TestSession() as session:
        source = FeedSource(
            name="SEC Press Releases",
            agency="SEC",
            feed_url="https://www.sec.gov/rss",
            feed_type="rss",
            enabled=True,
        )
        session.add(source)
        session.flush()

        doc1 = FeedDocument(
            feed_source_id=source.id,
            external_id="sec-001",
            content_hash="hash1",
            title="SEC Charges Acme Corp",
            url="https://sec.gov/lit/001",
            published_at=datetime(2026, 2, 10, 12, 0, tzinfo=timezone.utc),
            discovered_at=datetime(2026, 2, 10, 12, 0, tzinfo=timezone.utc),
            agency="SEC",
            raw_summary="SEC charged Acme Corp",
            processing_status="completed",
        )
        doc2 = FeedDocument(
            feed_source_id=source.id,
            external_id="sec-002",
            content_hash="hash2",
            title="SEC Proposes New Rule",
            url="https://sec.gov/rules/002",
            published_at=datetime(2026, 2, 11, 12, 0, tzinfo=timezone.utc),
            discovered_at=datetime(2026, 2, 11, 12, 0, tzinfo=timezone.utc),
            agency="SEC",
            raw_summary="SEC proposes new rule",
            processing_status="completed",
        )
        session.add_all([doc1, doc2])
        session.flush()

        alert1 = ProcessedAlert(
            feed_document_id=doc1.id,
            summary="Acme Corp enforcement action",
            key_points=["Fraud charges", "Penalty"],
            topics='["enforcement", "fraud"]',
            relevance_score=0.9,
            document_type="enforcement_action",
            ai_model="claude-haiku-4-5",
            ai_cost_usd=0.0001,
        )
        alert2 = ProcessedAlert(
            feed_document_id=doc2.id,
            summary="New SEC rule proposal",
            key_points=["Market structure", "Disclosure"],
            topics='["rulemaking"]',
            relevance_score=0.6,
            document_type="proposed_rule",
            ai_model="claude-haiku-4-5",
            ai_cost_usd=0.0001,
        )
        session.add_all([alert1, alert2])
        session.commit()
        return source, doc1, doc2, alert1, alert2


def _create_user(email="user@test.com", api_key="test-api-key-123"):
    """Create a user in the test DB."""
    import bcrypt as _bcrypt
    import secrets

    with _TestSession() as session:
        user = User(
            email=email,
            hashed_password=_bcrypt.hashpw(b"password123", _bcrypt.gensalt()).decode(),
            api_key=api_key,
            is_active=True,
            subscription_tier="free",
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        return user.id, user.api_key


@pytest.fixture()
def client():
    with patch("regulatory_alerts.api.get_sync_engine", _mock_sync_engine), \
         patch("regulatory_alerts.api.get_sync_session_factory", _mock_sync_session_factory), \
         patch("regulatory_alerts.rate_limit.get_sync_session_factory", _mock_sync_session_factory), \
         patch("regulatory_alerts.dashboard.get_sync_session_factory", _mock_sync_session_factory), \
         patch("regulatory_alerts.auth.get_sync_session_factory", _mock_sync_session_factory), \
         patch("regulatory_alerts.billing.get_sync_session_factory", _mock_sync_session_factory), \
         patch("regulatory_alerts.admin.get_sync_session_factory", _mock_sync_session_factory), \
         patch("regulatory_alerts.core.scheduler.start_scheduler", return_value=MagicMock()), \
         patch("regulatory_alerts.core.scheduler.stop_scheduler"), \
         patch("regulatory_alerts.observability.configure_logging"):
        from regulatory_alerts.api import app
        app.dependency_overrides[validate_csrf] = noop_csrf
        with TestClient(app) as c:
            yield c
        app.dependency_overrides.pop(validate_csrf, None)


# =============================================================================
# CFTC Scraper Tests — Fallback Strategies
# =============================================================================

class TestCFTCParserStrategies:
    """Test each parsing strategy in isolation and the fallback cascade."""

    def test_drupal_table_strategy(self):
        """Strategy 1: Drupal table layout parses dates, links, and titles."""
        from regulatory_alerts.core.cftc_scraper import _parse_drupal_table

        html = '''
        <td headers="view-field-date-table-column">
        01/15/2026
        </td><td><a href="/PressRoom/PressReleases/9180-26" class="link">CFTC Orders Firm to Pay</a></td>
        '''
        entries = _parse_drupal_table(html)
        assert len(entries) == 1
        assert entries[0].title == "CFTC Orders Firm to Pay"
        assert entries[0].external_id == "/PressRoom/PressReleases/9180-26"
        assert entries[0].published_at.year == 2026
        assert entries[0].published_at.month == 1
        assert entries[0].published_at.day == 15

    def test_generic_table_strategy(self):
        """Strategy 2: Generic table with date cells and PressRoom links."""
        from regulatory_alerts.core.cftc_scraper import _parse_generic_table

        html = '''
        <tr>
            <td class="date">02/20/2026</td>
            <td><a href="/PressRoom/SpeechesTestimony/speech-001">Chairman's Remarks</a></td>
        </tr>
        '''
        entries = _parse_generic_table(html)
        assert len(entries) == 1
        assert entries[0].title == "Chairman's Remarks"
        assert entries[0].published_at.month == 2
        assert entries[0].published_at.day == 20

    def test_link_context_strategy(self):
        """Strategy 3: Find PressRoom links with dates from nearby context."""
        from regulatory_alerts.core.cftc_scraper import _parse_links_with_context

        html = '''
        <div>
            <span>03/10/2026</span>
            <a href="/PressRoom/PressReleases/pr-999">New Enforcement Action</a>
        </div>
        '''
        entries = _parse_links_with_context(html)
        assert len(entries) == 1
        assert entries[0].title == "New Enforcement Action"
        assert entries[0].published_at.month == 3

    def test_link_context_no_date_uses_now(self):
        """Strategy 3: Falls back to now() when no date is found nearby."""
        from regulatory_alerts.core.cftc_scraper import _parse_links_with_context

        html = '<a href="/PressRoom/PressReleases/pr-100">No Date Press Release</a>'
        entries = _parse_links_with_context(html)
        assert len(entries) == 1
        assert entries[0].published_at.year >= 2026

    def test_fallback_cascade(self):
        """parse_cftc_html tries strategies in order, using first that works."""
        from regulatory_alerts.core.cftc_scraper import parse_cftc_html

        # This HTML only matches strategy 3 (no Drupal headers, no table cells)
        html = '''
        <div>04/01/2026 <a href="/PressRoom/PressReleases/fallback-1">Fallback Entry</a></div>
        '''
        entries = parse_cftc_html(html)
        assert len(entries) == 1
        assert entries[0].title == "Fallback Entry"

    def test_all_strategies_fail_empty_html(self):
        """Empty HTML produces empty list with warning log."""
        from regulatory_alerts.core.cftc_scraper import parse_cftc_html

        entries = parse_cftc_html("<html><body>No press releases here</body></html>")
        assert entries == []

    def test_drupal_multiple_entries_sorted(self):
        """Multiple entries are sorted newest first."""
        from regulatory_alerts.core.cftc_scraper import parse_cftc_html

        html = '''
        <td headers="view-field-date-table-column">01/01/2026</td>
        <td><a href="/PressRoom/PressReleases/old">Old Entry</a></td>
        <td headers="view-field-date-table-column">06/15/2026</td>
        <td><a href="/PressRoom/PressReleases/new">New Entry</a></td>
        '''
        entries = parse_cftc_html(html)
        assert len(entries) == 2
        assert entries[0].title == "New Entry"  # newer first
        assert entries[1].title == "Old Entry"

    def test_deduplication_in_generic_strategy(self):
        """Strategy 2 deduplicates entries with the same path."""
        from regulatory_alerts.core.cftc_scraper import _parse_generic_table

        html = '''
        <td>01/01/2026</td><td><a href="/PressRoom/PressReleases/dup1">Same Entry</a></td>
        <td>01/02/2026</td><td><a href="/PressRoom/PressReleases/dup1">Same Entry Again</a></td>
        '''
        entries = _parse_generic_table(html)
        assert len(entries) == 1


class TestCFTCDateParsing:
    """Test _parse_date with various formats."""

    def test_us_date_format(self):
        from regulatory_alerts.core.cftc_scraper import _parse_date

        result = _parse_date("01/15/2026")
        assert result is not None
        assert result.month == 1
        assert result.day == 15
        assert result.year == 2026

    def test_short_year_format(self):
        from regulatory_alerts.core.cftc_scraper import _parse_date

        result = _parse_date("01/15/26")
        assert result is not None
        assert result.month == 1

    def test_long_month_format(self):
        from regulatory_alerts.core.cftc_scraper import _parse_date

        result = _parse_date("January 15, 2026")
        assert result is not None
        assert result.month == 1

    def test_short_month_format(self):
        from regulatory_alerts.core.cftc_scraper import _parse_date

        result = _parse_date("Jan 15, 2026")
        assert result is not None
        assert result.month == 1

    def test_invalid_date_returns_none(self):
        from regulatory_alerts.core.cftc_scraper import _parse_date

        assert _parse_date("not-a-date") is None
        assert _parse_date("") is None


class TestCFTCScrapeFunction:
    """Test the async scrape_cftc_page function."""

    @pytest.mark.asyncio
    async def test_scrape_success(self):
        from regulatory_alerts.core.cftc_scraper import scrape_cftc_page

        html = '''
        <td headers="view-field-date-table-column">01/01/2026</td>
        <td><a href="/PressRoom/PressReleases/test-1">Test Press Release</a></td>
        '''
        with patch("regulatory_alerts.core.cftc_scraper._fetch_cftc_html", new_callable=AsyncMock, return_value=html):
            entries = await scrape_cftc_page("https://www.cftc.gov/test")
            assert len(entries) == 1
            assert entries[0].title == "Test Press Release"

    @pytest.mark.asyncio
    async def test_scrape_http_error_returns_empty(self):
        import httpx
        from regulatory_alerts.core.cftc_scraper import scrape_cftc_page

        mock_response = MagicMock()
        mock_response.status_code = 500
        error = httpx.HTTPStatusError("Server Error", request=MagicMock(), response=mock_response)

        with patch("regulatory_alerts.core.cftc_scraper._fetch_cftc_html", new_callable=AsyncMock, side_effect=error):
            entries = await scrape_cftc_page("https://www.cftc.gov/test")
            assert entries == []

    @pytest.mark.asyncio
    async def test_scrape_network_error_returns_empty(self):
        from regulatory_alerts.core.cftc_scraper import scrape_cftc_page

        with patch("regulatory_alerts.core.cftc_scraper._fetch_cftc_html", new_callable=AsyncMock, side_effect=Exception("Network down")):
            entries = await scrape_cftc_page("https://www.cftc.gov/test")
            assert entries == []


# =============================================================================
# CSV Export Tests
# =============================================================================

class TestCSVExport:
    """Test the /api/updates/export endpoint."""

    def test_export_csv_returns_file(self, client):
        """Export endpoint returns a CSV file with correct headers."""
        _seed_data()
        resp = client.get("/api/updates/export")
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]
        assert "attachment" in resp.headers["content-disposition"]
        assert "regulatory_alerts_export.csv" in resp.headers["content-disposition"]

    def test_export_csv_content(self, client):
        """CSV contains header row and data rows with correct columns."""
        _seed_data()
        resp = client.get("/api/updates/export")

        # Decode with BOM handling
        content = resp.content.decode("utf-8-sig")
        reader = csv.reader(io.StringIO(content))
        rows = list(reader)

        # Header row
        assert rows[0] == [
            "ID", "Title", "Agency", "URL", "Published At",
            "Document Type", "Topics", "Relevance Score", "Summary",
        ]
        # At least 2 data rows
        assert len(rows) >= 3

    def test_export_csv_agency_filter(self, client):
        """Agency filter limits exported data."""
        _seed_data()
        # Add a CFTC source + doc to test filtering
        with _TestSession() as session:
            cftc_source = FeedSource(
                name="CFTC Press", agency="CFTC",
                feed_url="https://cftc.gov/rss", feed_type="html", enabled=True,
            )
            session.add(cftc_source)
            session.flush()
            cftc_doc = FeedDocument(
                feed_source_id=cftc_source.id,
                external_id="cftc-001", content_hash="hash-cftc",
                title="CFTC Action", url="https://cftc.gov/001",
                published_at=datetime(2026, 2, 12, tzinfo=timezone.utc),
                discovered_at=datetime(2026, 2, 12, tzinfo=timezone.utc),
                agency="CFTC", processing_status="pending",
            )
            session.add(cftc_doc)
            session.commit()

        resp = client.get("/api/updates/export?agency=SEC")
        content = resp.content.decode("utf-8-sig")
        reader = csv.reader(io.StringIO(content))
        rows = list(reader)
        # All data rows should be SEC
        for row in rows[1:]:
            assert row[2] == "SEC"

    def test_export_csv_topic_filter(self, client):
        """Topic filter limits exported rows to matching alerts."""
        _seed_data()
        resp = client.get("/api/updates/export?topic=enforcement")
        content = resp.content.decode("utf-8-sig")
        reader = csv.reader(io.StringIO(content))
        rows = list(reader)
        # Should only include the enforcement alert
        assert len(rows) == 2  # header + 1 data row
        assert "enforcement" in rows[1][6]  # Topics column

    def test_export_csv_min_score_filter(self, client):
        """Min score filter excludes low-scoring alerts."""
        _seed_data()
        resp = client.get("/api/updates/export?min_score=0.8")
        content = resp.content.decode("utf-8-sig")
        reader = csv.reader(io.StringIO(content))
        rows = list(reader)
        # Only the 0.9 score alert should be included
        assert len(rows) == 2  # header + 1 row
        assert float(rows[1][7]) >= 0.8

    def test_export_csv_empty_results(self, client):
        """Empty DB returns CSV with only header row."""
        resp = client.get("/api/updates/export")
        content = resp.content.decode("utf-8-sig")
        reader = csv.reader(io.StringIO(content))
        rows = list(reader)
        assert len(rows) == 1  # just the header

    def test_export_csv_limit(self, client):
        """Limit parameter caps the number of exported rows."""
        _seed_data()
        resp = client.get("/api/updates/export?limit=1")
        content = resp.content.decode("utf-8-sig")
        reader = csv.reader(io.StringIO(content))
        rows = list(reader)
        assert len(rows) == 2  # header + 1 row

    def test_export_csv_topics_semicolon_separated(self, client):
        """Topics in CSV are semicolon-separated."""
        _seed_data()
        resp = client.get("/api/updates/export")
        content = resp.content.decode("utf-8-sig")
        reader = csv.reader(io.StringIO(content))
        rows = list(reader)
        # Find the row with enforcement topics
        enforcement_rows = [r for r in rows[1:] if "enforcement" in r[6]]
        assert len(enforcement_rows) >= 1
        assert "; " in enforcement_rows[0][6]  # multiple topics separated by "; "


# =============================================================================
# API Channel Ownership Tests
# =============================================================================

@pytest.fixture()
def auth_client():
    """Client with API key auth enabled."""
    from regulatory_alerts.config import get_settings
    settings = get_settings()
    old_keys = settings.API_KEYS
    settings.API_KEYS = "admin-key-999"  # Enable auth

    with patch("regulatory_alerts.api.get_sync_engine", _mock_sync_engine), \
         patch("regulatory_alerts.api.get_sync_session_factory", _mock_sync_session_factory), \
         patch("regulatory_alerts.rate_limit.get_sync_session_factory", _mock_sync_session_factory), \
         patch("regulatory_alerts.dashboard.get_sync_session_factory", _mock_sync_session_factory), \
         patch("regulatory_alerts.auth.get_sync_session_factory", _mock_sync_session_factory), \
         patch("regulatory_alerts.billing.get_sync_session_factory", _mock_sync_session_factory), \
         patch("regulatory_alerts.admin.get_sync_session_factory", _mock_sync_session_factory), \
         patch("regulatory_alerts.core.scheduler.start_scheduler", return_value=MagicMock()), \
         patch("regulatory_alerts.core.scheduler.stop_scheduler"), \
         patch("regulatory_alerts.observability.configure_logging"):
        from regulatory_alerts.api import app
        app.dependency_overrides[validate_csrf] = noop_csrf
        with TestClient(app) as c:
            yield c
        app.dependency_overrides.pop(validate_csrf, None)

    settings.API_KEYS = old_keys


class TestChannelOwnership:
    """Test that API channel endpoints are scoped to the authenticated user."""

    def test_list_channels_scoped_to_user(self, auth_client):
        """API user only sees their own channels."""
        user_id, api_key = _create_user("alice@test.com", "alice-key-111")
        user2_id, api_key2 = _create_user("bob@test.com", "bob-key-222")

        # Create channels for both users
        with _TestSession() as session:
            ch1 = NotificationChannel(
                name="Alice Channel", channel_type="webhook",
                webhook_url="https://alice.example.com/hook",
                user_id=user_id, enabled=True,
            )
            ch2 = NotificationChannel(
                name="Bob Channel", channel_type="webhook",
                webhook_url="https://bob.example.com/hook",
                user_id=user2_id, enabled=True,
            )
            session.add_all([ch1, ch2])
            session.commit()

        # Alice should only see her channel
        resp = auth_client.get("/api/channels", headers={"X-API-Key": "alice-key-111"})
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["name"] == "Alice Channel"

    def test_delete_channel_blocks_other_user(self, auth_client):
        """User cannot delete another user's channel (returns 404)."""
        user_id, _ = _create_user("alice@test.com", "alice-key-111")
        user2_id, _ = _create_user("bob@test.com", "bob-key-222")

        with _TestSession() as session:
            ch = NotificationChannel(
                name="Bob Channel", channel_type="email",
                email_address="bob@test.com",
                user_id=user2_id, enabled=True,
            )
            session.add(ch)
            session.commit()
            channel_id = ch.id

        # Alice tries to delete Bob's channel
        resp = auth_client.delete(
            f"/api/channels/{channel_id}",
            headers={"X-API-Key": "alice-key-111"},
        )
        assert resp.status_code == 404

        # Channel should still exist
        with _TestSession() as session:
            ch = session.get(NotificationChannel, channel_id)
            assert ch is not None

    def test_delete_own_channel_succeeds(self, auth_client):
        """User can delete their own channel."""
        user_id, api_key = _create_user("alice@test.com", "alice-key-111")

        with _TestSession() as session:
            ch = NotificationChannel(
                name="Alice Channel", channel_type="webhook",
                webhook_url="https://alice.example.com/hook",
                user_id=user_id, enabled=True,
            )
            session.add(ch)
            session.commit()
            channel_id = ch.id

        resp = auth_client.delete(
            f"/api/channels/{channel_id}",
            headers={"X-API-Key": "alice-key-111"},
        )
        assert resp.status_code == 204

        with _TestSession() as session:
            ch = session.get(NotificationChannel, channel_id)
            assert ch is None


# =============================================================================
# Session Factory Caching Tests
# =============================================================================

class TestSessionCaching:
    """Test that session factory caching (lru_cache) works correctly."""

    def test_sync_engine_cached(self):
        """get_sync_engine returns the same instance on repeated calls."""
        # We need to clear lru_cache first to test fresh
        from regulatory_alerts.database.session import get_sync_engine
        get_sync_engine.cache_clear()
        try:
            engine1 = get_sync_engine()
            engine2 = get_sync_engine()
            assert engine1 is engine2
        finally:
            get_sync_engine.cache_clear()

    def test_sync_session_factory_cached(self):
        """get_sync_session_factory returns the same factory on repeated calls."""
        from regulatory_alerts.database.session import get_sync_session_factory
        get_sync_session_factory.cache_clear()
        try:
            factory1 = get_sync_session_factory()
            factory2 = get_sync_session_factory()
            assert factory1 is factory2
        finally:
            get_sync_session_factory.cache_clear()

    def test_async_engine_cached(self):
        """get_async_engine returns the same instance on repeated calls."""
        from regulatory_alerts.database.session import get_async_engine
        get_async_engine.cache_clear()
        try:
            engine1 = get_async_engine()
            engine2 = get_async_engine()
            assert engine1 is engine2
        finally:
            get_async_engine.cache_clear()


# =============================================================================
# Alembic Migration Tests
# =============================================================================

class TestAlembicEnv:
    """Test that alembic/env.py imports all models."""

    def test_all_models_in_metadata(self):
        """All 7 tables are reflected in Base.metadata (env.py imports them)."""
        table_names = set(Base.metadata.tables.keys())
        expected = {
            "feed_sources", "feed_documents", "processed_alerts",
            "notification_channels", "notification_logs",
            "users", "stripe_events",
        }
        assert expected.issubset(table_names), f"Missing: {expected - table_names}"


# =============================================================================
# Dashboard Export Button Test
# =============================================================================

class TestDashboardExportButton:
    """Test the alerts page has an export button."""

    def test_alerts_page_has_export_link(self, client):
        """Alerts page HTML contains an export CSV link."""
        # Register + login (creates session cookie)
        resp = client.post("/register", data={
            "email": "export@test.com",
            "password": "password123",
            "password_confirm": "password123",
        }, follow_redirects=False)
        # Should redirect to / after registration
        assert resp.status_code in (302, 303)

        resp = client.get("/alerts")
        assert resp.status_code == 200
        assert "/api/updates/export" in resp.text
        assert "Export" in resp.text
