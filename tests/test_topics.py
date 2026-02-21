"""Tests for topic subscriptions: model property, dashboard filtering, routes."""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Ensure src is on path
_src = str(Path(__file__).resolve().parents[1] / "src")
if _src not in sys.path:
    sys.path.insert(0, _src)

os.environ["DATABASE_URL_SYNC"] = "sqlite:///:memory:"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["ANTHROPIC_API_KEY"] = "test-key-not-real"
os.environ["API_KEYS"] = ""

from regulatory_alerts.models import Base, FeedDocument, FeedSource, ProcessedAlert, User


def _enable_sqlite_fk(dbapi_conn, connection_record):
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


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


@pytest.fixture()
def client():
    from regulatory_alerts.csrf import validate_csrf
    from tests.conftest import noop_csrf

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


@pytest.fixture()
def logged_in_client(client):
    """Register and login a user (pro tier to avoid free restrictions)."""
    client.post("/register", data={
        "email": "topics@example.com",
        "password": "testpass123",
        "password_confirm": "testpass123",
    })
    # Upgrade to pro so free-tier restrictions don't interfere
    with _TestSession() as session:
        user = session.scalars(select(User).where(User.email == "topics@example.com")).first()
        user.subscription_tier = "pro"
        session.commit()
    return client


def _seed_alerts():
    """Seed feed source + documents + alerts with various topics."""
    with _TestSession() as session:
        source = FeedSource(
            name="SEC RSS",
            agency="SEC",
            feed_url="https://sec.gov/rss",
            feed_type="rss",
            enabled=True,
        )
        session.add(source)
        session.flush()

        # Doc 1: enforcement, fraud
        doc1 = FeedDocument(
            feed_source_id=source.id,
            external_id="doc-001",
            content_hash="h1",
            title="SEC Enforcement Action",
            url="https://sec.gov/1",
            published_at=datetime(2026, 2, 1, tzinfo=timezone.utc),
            discovered_at=datetime(2026, 2, 1, tzinfo=timezone.utc),
            agency="SEC",
            processing_status="completed",
        )
        session.add(doc1)
        session.flush()

        alert1 = ProcessedAlert(
            feed_document_id=doc1.id,
            summary="Enforcement action.",
            topics=json.dumps(["enforcement", "fraud"]),
            relevance_score=0.9,
            document_type="enforcement_action",
            ai_model="test",
        )
        session.add(alert1)

        # Doc 2: rulemaking, derivatives
        doc2 = FeedDocument(
            feed_source_id=source.id,
            external_id="doc-002",
            content_hash="h2",
            title="CFTC Rule Proposal",
            url="https://cftc.gov/2",
            published_at=datetime(2026, 2, 2, tzinfo=timezone.utc),
            discovered_at=datetime(2026, 2, 2, tzinfo=timezone.utc),
            agency="CFTC",
            processing_status="completed",
        )
        session.add(doc2)
        session.flush()

        alert2 = ProcessedAlert(
            feed_document_id=doc2.id,
            summary="Rule proposal.",
            topics=json.dumps(["rulemaking", "derivatives"]),
            relevance_score=0.8,
            document_type="proposed_rule",
            ai_model="test",
        )
        session.add(alert2)

        # Doc 3: enforcement, securities
        doc3 = FeedDocument(
            feed_source_id=source.id,
            external_id="doc-003",
            content_hash="h3",
            title="SEC Securities Case",
            url="https://sec.gov/3",
            published_at=datetime(2026, 2, 3, tzinfo=timezone.utc),
            discovered_at=datetime(2026, 2, 3, tzinfo=timezone.utc),
            agency="SEC",
            processing_status="completed",
        )
        session.add(doc3)
        session.flush()

        alert3 = ProcessedAlert(
            feed_document_id=doc3.id,
            summary="Securities case.",
            topics=json.dumps(["enforcement", "securities"]),
            relevance_score=0.85,
            document_type="enforcement_action",
            ai_model="test",
        )
        session.add(alert3)

        session.commit()


# ---------------------------------------------------------------------------
# User model property tests
# ---------------------------------------------------------------------------


class TestUserTopicsProperty:
    def test_default_is_none(self):
        """New users have NULL subscribed_topics (show all)."""
        with _TestSession() as session:
            from regulatory_alerts.auth import hash_password, generate_api_key
            user = User(
                email="prop@test.com",
                hashed_password=hash_password("pass1234"),
                api_key=generate_api_key(),
            )
            session.add(user)
            session.commit()
            session.refresh(user)
            assert user.subscribed_topics is None
            assert user.subscribed_topics_list is None

    def test_set_topics_list(self):
        with _TestSession() as session:
            from regulatory_alerts.auth import hash_password, generate_api_key
            user = User(
                email="set@test.com",
                hashed_password=hash_password("pass1234"),
                api_key=generate_api_key(),
            )
            session.add(user)
            session.flush()

            user.subscribed_topics_list = ["enforcement", "fraud"]
            session.commit()
            session.refresh(user)

            assert user.subscribed_topics_list == ["enforcement", "fraud"]
            assert json.loads(user.subscribed_topics) == ["enforcement", "fraud"]

    def test_set_empty_list(self):
        """Empty list means 'explicitly subscribed to nothing'."""
        with _TestSession() as session:
            from regulatory_alerts.auth import hash_password, generate_api_key
            user = User(
                email="empty@test.com",
                hashed_password=hash_password("pass1234"),
                api_key=generate_api_key(),
            )
            session.add(user)
            session.flush()

            user.subscribed_topics_list = []
            session.commit()
            session.refresh(user)

            assert user.subscribed_topics_list == []
            assert user.subscribed_topics == "[]"

    def test_set_none_clears(self):
        with _TestSession() as session:
            from regulatory_alerts.auth import hash_password, generate_api_key
            user = User(
                email="none@test.com",
                hashed_password=hash_password("pass1234"),
                api_key=generate_api_key(),
            )
            session.add(user)
            session.flush()

            user.subscribed_topics_list = ["test"]
            session.commit()
            user.subscribed_topics_list = None
            session.commit()
            session.refresh(user)

            assert user.subscribed_topics is None
            assert user.subscribed_topics_list is None

    def test_invalid_json_returns_none(self):
        with _TestSession() as session:
            from regulatory_alerts.auth import hash_password, generate_api_key
            user = User(
                email="bad@test.com",
                hashed_password=hash_password("pass1234"),
                api_key=generate_api_key(),
                subscribed_topics="not-valid-json",
            )
            session.add(user)
            session.commit()
            session.refresh(user)

            assert user.subscribed_topics_list is None


# ---------------------------------------------------------------------------
# query_updates with subscription filter
# ---------------------------------------------------------------------------


class TestQueryUpdatesSubscriptionFilter:
    def test_no_filter_returns_all(self):
        """subscribed_topics=None should return all docs."""
        _seed_alerts()
        from regulatory_alerts.dashboard import query_updates
        with _TestSession() as session:
            docs, total = query_updates(session, subscribed_topics=None)
        assert total == 3

    def test_filter_by_enforcement(self):
        """Only docs with 'enforcement' topic should appear."""
        _seed_alerts()
        from regulatory_alerts.dashboard import query_updates
        with _TestSession() as session:
            docs, total = query_updates(session, subscribed_topics=["enforcement"])
        assert total == 2
        titles = {d.title for d in docs}
        assert "SEC Enforcement Action" in titles
        assert "SEC Securities Case" in titles

    def test_filter_by_rulemaking(self):
        _seed_alerts()
        from regulatory_alerts.dashboard import query_updates
        with _TestSession() as session:
            docs, total = query_updates(session, subscribed_topics=["rulemaking"])
        assert total == 1
        assert docs[0].title == "CFTC Rule Proposal"

    def test_filter_by_multiple_topics(self):
        """Multiple subscribed topics: union (any match)."""
        _seed_alerts()
        from regulatory_alerts.dashboard import query_updates
        with _TestSession() as session:
            docs, total = query_updates(session, subscribed_topics=["rulemaking", "fraud"])
        assert total == 2  # doc1 (fraud) + doc2 (rulemaking)

    def test_empty_list_returns_nothing(self):
        """Empty subscribed list = show nothing."""
        _seed_alerts()
        from regulatory_alerts.dashboard import query_updates
        with _TestSession() as session:
            docs, total = query_updates(session, subscribed_topics=[])
        assert total == 0

    def test_filter_nonexistent_topic(self):
        _seed_alerts()
        from regulatory_alerts.dashboard import query_updates
        with _TestSession() as session:
            docs, total = query_updates(session, subscribed_topics=["nonexistent"])
        assert total == 0


# ---------------------------------------------------------------------------
# get_known_topics
# ---------------------------------------------------------------------------


class TestGetKnownTopics:
    def test_returns_sorted_unique(self):
        _seed_alerts()
        from regulatory_alerts.dashboard import get_known_topics
        with _TestSession() as session:
            topics = get_known_topics(session)
        assert topics == ["derivatives", "enforcement", "fraud", "rulemaking", "securities"]

    def test_empty_db(self):
        from regulatory_alerts.dashboard import get_known_topics
        with _TestSession() as session:
            topics = get_known_topics(session)
        assert topics == []


# ---------------------------------------------------------------------------
# Topics page routes
# ---------------------------------------------------------------------------


class TestTopicsPage:
    def test_topics_page_renders(self, logged_in_client):
        resp = logged_in_client.get("/topics")
        assert resp.status_code == 200
        assert "Topic Subscriptions" in resp.text

    def test_topics_page_requires_login(self, client):
        resp = client.get("/topics", follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["location"] == "/login"

    def test_topics_page_shows_known_topics(self, logged_in_client):
        _seed_alerts()
        resp = logged_in_client.get("/topics")
        assert "enforcement" in resp.text
        assert "fraud" in resp.text
        assert "rulemaking" in resp.text

    def test_topics_page_show_all_checked_by_default(self, logged_in_client):
        resp = logged_in_client.get("/topics")
        assert resp.status_code == 200
        assert "Showing all topics" in resp.text

    def test_topics_update_subscribe_to_topics(self, logged_in_client):
        _seed_alerts()
        resp = logged_in_client.post("/topics", data={
            "topics": ["enforcement", "fraud"],
        })
        assert resp.status_code == 200
        assert "updated" in resp.text
        assert "2 topics selected" in resp.text

        # Verify in DB
        with _TestSession() as session:
            user = session.scalars(select(User).where(User.email == "topics@example.com")).first()
            assert user.subscribed_topics_list == ["enforcement", "fraud"]

    def test_topics_update_show_all(self, logged_in_client):
        """Setting show_all should clear subscriptions (NULL)."""
        # First set some topics
        logged_in_client.post("/topics", data={"topics": ["enforcement"]})
        # Then set show_all
        resp = logged_in_client.post("/topics", data={"show_all": "1"})
        assert resp.status_code == 200
        assert "Showing all topics" in resp.text

        with _TestSession() as session:
            user = session.scalars(select(User).where(User.email == "topics@example.com")).first()
            assert user.subscribed_topics is None

    def test_topics_update_empty_clears_all(self, logged_in_client):
        """Submitting with no topics selected and no show_all sets empty list."""
        resp = logged_in_client.post("/topics", data={})
        assert resp.status_code == 200
        assert "No topics selected" in resp.text

        with _TestSession() as session:
            user = session.scalars(select(User).where(User.email == "topics@example.com")).first()
            assert user.subscribed_topics_list == []


# ---------------------------------------------------------------------------
# Dashboard filtering by subscriptions
# ---------------------------------------------------------------------------


class TestDashboardTopicFiltering:
    def test_dashboard_shows_all_when_no_subscriptions(self, logged_in_client):
        """Default (NULL) = show all alerts on dashboard."""
        _seed_alerts()
        resp = logged_in_client.get("/")
        assert resp.status_code == 200
        assert "SEC Enforcement Action" in resp.text
        assert "CFTC Rule Proposal" in resp.text
        assert "SEC Securities Case" in resp.text

    def test_dashboard_filters_by_subscribed_topics(self, logged_in_client):
        """After subscribing to 'rulemaking', only that doc appears on dashboard."""
        _seed_alerts()

        # Subscribe to rulemaking only
        logged_in_client.post("/topics", data={"topics": ["rulemaking"]})

        resp = logged_in_client.get("/")
        assert resp.status_code == 200
        assert "CFTC Rule Proposal" in resp.text
        # Others should NOT appear
        assert "SEC Enforcement Action" not in resp.text
        assert "SEC Securities Case" not in resp.text

    def test_dashboard_empty_subscriptions_shows_nothing(self, logged_in_client):
        """Empty subscription list = no alerts on dashboard."""
        _seed_alerts()
        logged_in_client.post("/topics", data={})

        resp = logged_in_client.get("/")
        assert resp.status_code == 200
        assert "SEC Enforcement Action" not in resp.text
        assert "CFTC Rule Proposal" not in resp.text


# ---------------------------------------------------------------------------
# Sidebar nav link
# ---------------------------------------------------------------------------


class TestSidebarNav:
    def test_topics_link_in_sidebar(self, logged_in_client):
        resp = logged_in_client.get("/")
        assert resp.status_code == 200
        assert 'href="/topics"' in resp.text
        assert "Topics" in resp.text


# ---------------------------------------------------------------------------
# Edge cases from LLM audit
# ---------------------------------------------------------------------------


class TestTopicEdgeCases:
    def test_doc_without_alert_filtered_out_by_subscription(self):
        """Docs without alerts (no topics) should be filtered out when subscriptions are set."""
        with _TestSession() as session:
            source = FeedSource(
                name="SEC RSS", agency="SEC", feed_url="https://sec.gov/rss",
                feed_type="rss", enabled=True,
            )
            session.add(source)
            session.flush()
            doc = FeedDocument(
                feed_source_id=source.id, external_id="no-alert",
                content_hash="ha", title="Doc Without Alert",
                url="https://sec.gov/x",
                published_at=datetime(2026, 2, 1, tzinfo=timezone.utc),
                discovered_at=datetime(2026, 2, 1, tzinfo=timezone.utc),
                agency="SEC", processing_status="pending",
            )
            session.add(doc)
            session.commit()

        from regulatory_alerts.dashboard import query_updates
        with _TestSession() as session:
            docs, total = query_updates(session, subscribed_topics=["enforcement"])
        assert total == 0

    def test_subscriptions_persist_across_login(self, client):
        """Topic subscriptions survive logout/login."""
        # Register and set topics
        client.post("/register", data={
            "email": "persist@example.com",
            "password": "testpass123",
            "password_confirm": "testpass123",
        })
        _seed_alerts()
        client.post("/topics", data={"topics": ["enforcement"]})

        # Logout
        client.post("/logout")

        # Login again
        client.post("/login", data={
            "email": "persist@example.com",
            "password": "testpass123",
        })

        # Verify subscriptions still set
        with _TestSession() as session:
            user = session.scalars(select(User).where(User.email == "persist@example.com")).first()
            assert user.subscribed_topics_list == ["enforcement"]

    def test_case_sensitive_topic_filtering(self):
        """Topic filtering should be case-sensitive (topics are lowercase by convention)."""
        _seed_alerts()
        from regulatory_alerts.dashboard import query_updates
        with _TestSession() as session:
            docs, total = query_updates(session, subscribed_topics=["ENFORCEMENT"])
        assert total == 0  # Case mismatch = no match

    def test_subscription_combined_with_agency_filter(self):
        """Subscription filter works together with agency filter."""
        _seed_alerts()
        from regulatory_alerts.dashboard import query_updates
        with _TestSession() as session:
            # Subscribe to enforcement, filter by SEC only
            docs, total = query_updates(
                session, agency="SEC", subscribed_topics=["enforcement"]
            )
        assert total == 2  # Both SEC enforcement docs match
        titles = {d.title for d in docs}
        assert "SEC Enforcement Action" in titles
        assert "SEC Securities Case" in titles
