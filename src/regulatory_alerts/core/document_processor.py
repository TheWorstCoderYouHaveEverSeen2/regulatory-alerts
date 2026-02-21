"""Deduplication and persistence of feed entries.

Checks each entry against the database to avoid re-processing.
Uses external_id (GUID/URL) as the primary dedup key, with
content_hash as a secondary check.
"""

import hashlib
import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from regulatory_alerts.core.feed_fetcher import FeedEntry
from regulatory_alerts.models.document import FeedDocument

logger = logging.getLogger(__name__)


def _compute_content_hash(title: str, summary: str, url: str) -> str:
    """SHA-256 hash for secondary deduplication."""
    raw = f"{title}|{summary}|{url}"
    return hashlib.sha256(raw.encode()).hexdigest()


def process_entries(
    session: Session,
    entries: list[FeedEntry],
    feed_source_id: int,
    agency: str,
) -> list[FeedDocument]:
    """Check entries against DB and insert new ones.

    Args:
        session: SQLAlchemy sync session
        entries: Normalized feed entries from FeedFetcher
        feed_source_id: ID of the FeedSource these came from
        agency: Agency name (e.g. "SEC")

    Returns:
        List of newly inserted FeedDocument objects (status=pending)
    """
    if not entries:
        return []

    # Get existing external_ids in one query
    external_ids = [e.external_id for e in entries]
    existing = set(
        session.scalars(
            select(FeedDocument.external_id).where(
                FeedDocument.external_id.in_(external_ids)
            )
        ).all()
    )

    new_docs = []
    skipped = 0

    for entry in entries:
        if entry.external_id in existing:
            skipped += 1
            continue

        # Track within-batch duplicates to prevent IntegrityError
        existing.add(entry.external_id)

        content_hash = _compute_content_hash(entry.title, entry.summary, entry.url)

        doc = FeedDocument(
            feed_source_id=feed_source_id,
            external_id=entry.external_id,
            content_hash=content_hash,
            title=entry.title,
            url=entry.url,
            published_at=entry.published_at,
            discovered_at=datetime.now(timezone.utc),
            agency=agency,
            raw_summary=entry.summary if entry.summary else None,
            processing_status="pending",
        )
        session.add(doc)
        new_docs.append(doc)

    if new_docs:
        session.flush()  # Assign IDs without committing

    logger.info(
        "Processed %d entries: %d new, %d duplicates",
        len(entries),
        len(new_docs),
        skipped,
    )

    return new_docs
