"""Fetch and parse RSS/Atom feeds from regulatory agencies.

Handles rate limiting (SEC max 10 req/sec), retries on transient errors,
and normalizes RSS 2.0 / Atom differences into a common FeedEntry dataclass.
"""

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import feedparser
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from regulatory_alerts.config import get_settings

logger = logging.getLogger(__name__)


@dataclass
class FeedEntry:
    """Normalized entry from any RSS/Atom feed."""
    external_id: str
    title: str
    url: str
    published_at: datetime
    summary: str = ""
    categories: list[str] = field(default_factory=list)


class RateLimiter:
    """Token bucket rate limiter for SEC compliance (max 10 req/sec)."""

    def __init__(self, max_per_second: int = 8):
        self.max_per_second = max_per_second
        self.min_interval = 1.0 / max_per_second
        self._last_request_time = 0.0

    async def acquire(self):
        now = time.monotonic()
        elapsed = now - self._last_request_time
        if elapsed < self.min_interval:
            await asyncio.sleep(self.min_interval - elapsed)
        self._last_request_time = time.monotonic()


class FeedFetcher:
    """Fetches and parses regulatory RSS/Atom feeds."""

    def __init__(self):
        settings = get_settings()
        self.user_agent = settings.USER_AGENT
        self.timeout = settings.REQUEST_TIMEOUT
        self.rate_limiter = RateLimiter(settings.SEC_RATE_LIMIT_PER_SECOND)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=2, max=30),
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.HTTPStatusError, httpx.ConnectError)),
    )
    async def _fetch_feed_xml(self, url: str) -> str:
        """Fetch raw feed XML with rate limiting and retries."""
        await self.rate_limiter.acquire()
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(
                url,
                headers={"User-Agent": self.user_agent},
                follow_redirects=True,
            )
            response.raise_for_status()
            return response.text

    def _parse_published_date(self, entry: dict) -> datetime:
        """Extract publication date from feed entry, handling various formats."""
        # Try standard feedparser parsed time
        for field_name in ("published_parsed", "updated_parsed"):
            parsed = entry.get(field_name)
            if parsed:
                try:
                    from calendar import timegm
                    ts = timegm(parsed)
                    return datetime.fromtimestamp(ts, tz=timezone.utc)
                except (ValueError, OverflowError):
                    continue

        # Try raw date strings
        for field_name in ("published", "updated"):
            raw = entry.get(field_name, "")
            if raw:
                try:
                    return parsedate_to_datetime(raw)
                except (ValueError, TypeError):
                    continue

        # Fallback to now
        logger.warning("No date found for entry: %s", entry.get("title", "unknown"))
        return datetime.now(timezone.utc)

    def _generate_external_id(self, entry: dict, feed_url: str) -> str:
        """Generate a unique ID for deduplication.

        Priority: feed GUID > entry link > hash(title + feed_url)
        """
        # feedparser normalizes 'id' from both RSS guid and Atom id
        if entry.get("id"):
            return entry["id"]

        if entry.get("link"):
            return entry["link"]

        # Fallback: hash of title + feed URL
        raw = f"{entry.get('title', '')}|{feed_url}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def _parse_entries(self, feed_data: feedparser.FeedParserDict, feed_url: str) -> list[FeedEntry]:
        """Convert feedparser entries to normalized FeedEntry objects."""
        entries = []
        for entry in feed_data.entries:
            title = entry.get("title", "").strip()
            if not title:
                logger.warning("Skipping entry with no title from %s", feed_url)
                continue

            url = entry.get("link", "").strip()
            if not url:
                logger.warning("Skipping entry with no URL from %s: %s", feed_url, title)
                continue
            summary = entry.get("summary", entry.get("description", ""))
            categories = [
                tag.get("term", tag.get("label", ""))
                for tag in entry.get("tags", [])
                if tag.get("term") or tag.get("label")
            ]

            entries.append(
                FeedEntry(
                    external_id=self._generate_external_id(entry, feed_url),
                    title=title,
                    url=url,
                    published_at=self._parse_published_date(entry),
                    summary=summary,
                    categories=categories,
                )
            )

        return entries

    async def fetch(self, feed_url: str) -> list[FeedEntry]:
        """Fetch a feed URL and return normalized entries.

        Args:
            feed_url: RSS or Atom feed URL

        Returns:
            List of FeedEntry objects, newest first
        """
        logger.info("Fetching feed: %s", feed_url)

        try:
            xml = await self._fetch_feed_xml(feed_url)
        except Exception:
            logger.exception("Failed to fetch feed: %s", feed_url)
            return []

        feed_data = feedparser.parse(xml)

        if feed_data.bozo:
            logger.warning(
                "Feed parse warning for %s: %s",
                feed_url,
                feed_data.get("bozo_exception", "unknown"),
            )

        entries = self._parse_entries(feed_data, feed_url)

        # Sort newest first
        entries.sort(key=lambda e: e.published_at, reverse=True)

        logger.info("Parsed %d entries from %s", len(entries), feed_url)
        return entries
