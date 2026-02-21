"""Tests for the document deduplication and persistence module."""

from datetime import datetime, timezone

from regulatory_alerts.core.document_processor import process_entries, _compute_content_hash
from regulatory_alerts.core.feed_fetcher import FeedEntry
from regulatory_alerts.models import FeedDocument


def _make_entry(external_id="entry-1", title="Test Entry", url="https://example.com/1"):
    return FeedEntry(
        external_id=external_id,
        title=title,
        url=url,
        published_at=datetime(2026, 2, 7, tzinfo=timezone.utc),
        summary="Test summary",
    )


class TestComputeContentHash:
    def test_deterministic(self):
        h1 = _compute_content_hash("title", "summary", "url")
        h2 = _compute_content_hash("title", "summary", "url")
        assert h1 == h2

    def test_different_inputs(self):
        h1 = _compute_content_hash("title1", "summary", "url")
        h2 = _compute_content_hash("title2", "summary", "url")
        assert h1 != h2

    def test_returns_hex_string(self):
        h = _compute_content_hash("t", "s", "u")
        assert len(h) == 64  # SHA-256 hex


class TestProcessEntries:
    def test_inserts_new_entries(self, db_session, seed_feed_source):
        entries = [_make_entry("new-1"), _make_entry("new-2", title="Second")]
        new_docs = process_entries(db_session, entries, seed_feed_source.id, "SEC")

        assert len(new_docs) == 2
        assert all(isinstance(d, FeedDocument) for d in new_docs)
        assert new_docs[0].processing_status == "pending"
        assert new_docs[0].agency == "SEC"

    def test_deduplicates_existing(self, db_session, seed_feed_source, seed_document):
        # seed_document has external_id="test-doc-001"
        entries = [
            _make_entry("test-doc-001", title="Duplicate"),
            _make_entry("genuinely-new"),
        ]
        new_docs = process_entries(db_session, entries, seed_feed_source.id, "SEC")

        assert len(new_docs) == 1
        assert new_docs[0].external_id == "genuinely-new"

    def test_empty_entries(self, db_session, seed_feed_source):
        new_docs = process_entries(db_session, [], seed_feed_source.id, "SEC")
        assert new_docs == []

    def test_assigns_content_hash(self, db_session, seed_feed_source):
        entries = [_make_entry("hash-test")]
        new_docs = process_entries(db_session, entries, seed_feed_source.id, "SEC")

        assert new_docs[0].content_hash is not None
        assert len(new_docs[0].content_hash) == 64
