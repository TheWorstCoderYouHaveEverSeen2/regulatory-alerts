"""Scraper for CFTC press releases from HTML pages.

CFTC's RSS feeds no longer work, so we scrape the HTML listing pages
at https://www.cftc.gov/PressRoom/PressReleases and
https://www.cftc.gov/PressRoom/SpeechesTestimony.

The scraper uses multiple parsing strategies with automatic fallback:
1. Primary: Drupal table pattern (headers="view-field-date-table-column")
2. Fallback A: Generic anchor + date pattern in any table/list context
3. Fallback B: Simple /PressRoom/ link extraction with sibling date text
"""

import html as html_module
import logging
import re
from datetime import datetime, timezone

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from regulatory_alerts.core.feed_fetcher import FeedEntry, RateLimiter

logger = logging.getLogger(__name__)

CFTC_BASE = "https://www.cftc.gov"

# --- Parsing Strategy 1: Drupal table (current CFTC layout) ---
_DRUPAL_TABLE_PATTERN = re.compile(
    r'headers="view-field-date-table-column">\s*'
    r'(\d{2}/\d{2}/\d{4})\s*'           # date: MM/DD/YYYY
    r'</td>.*?'                           # skip to link
    r'<a href="(/PressRoom/[^"]+)"[^>]*>' # href
    r'([^<]+)'                            # title
    r'</a>',
    re.DOTALL,
)

# --- Parsing Strategy 2: Generic table row with date + link ---
_GENERIC_TABLE_PATTERN = re.compile(
    r'<td[^>]*>\s*(\d{1,2}/\d{1,2}/\d{4})\s*</td>'   # date cell
    r'.*?'                                               # content between
    r'<a\s+href="(/PressRoom/[^"]+)"[^>]*>'             # link to PressRoom
    r'\s*([^<]+?)\s*</a>',                               # title
    re.DOTALL,
)

# --- Parsing Strategy 3: Any /PressRoom/ link with nearby date text ---
_LINK_PATTERN = re.compile(
    r'<a\s+href="(/PressRoom/(?:PressReleases|SpeechesTestimony)/[^"]+)"[^>]*>'
    r'\s*([^<]+?)\s*</a>',
    re.DOTALL,
)
_NEARBY_DATE_PATTERN = re.compile(r'(\d{1,2}/\d{1,2}/\d{4})')

# Common date formats found on CFTC pages
_DATE_FORMATS = [
    "%m/%d/%Y",    # 01/15/2026
    "%m/%d/%y",    # 01/15/26
    "%B %d, %Y",   # January 15, 2026
    "%b %d, %Y",   # Jan 15, 2026
]


def _parse_date(date_str: str) -> datetime | None:
    """Try multiple date formats, return UTC datetime or None."""
    date_str = date_str.strip()
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _parse_drupal_table(html: str) -> list[FeedEntry]:
    """Strategy 1: Parse CFTC's Drupal-rendered table layout."""
    entries = []
    for match in _DRUPAL_TABLE_PATTERN.finditer(html):
        date_str, path, title = match.groups()
        title = html_module.unescape(title.strip())
        if not title:
            continue
        published = _parse_date(date_str)
        if published is None:
            logger.warning("Strategy 1: Could not parse date '%s' for '%s'", date_str, title)
            published = datetime.now(timezone.utc)
        entries.append(FeedEntry(
            external_id=path,
            title=title,
            url=f"{CFTC_BASE}{path}",
            published_at=published,
            summary="",
        ))
    return entries


def _parse_generic_table(html: str) -> list[FeedEntry]:
    """Strategy 2: Parse any table with date cell + PressRoom link."""
    entries = []
    seen_paths = set()
    for match in _GENERIC_TABLE_PATTERN.finditer(html):
        date_str, path, title = match.groups()
        title = html_module.unescape(title.strip())
        if not title or path in seen_paths:
            continue
        seen_paths.add(path)
        published = _parse_date(date_str)
        if published is None:
            logger.warning("Strategy 2: Could not parse date '%s' for '%s'", date_str, title)
            published = datetime.now(timezone.utc)
        entries.append(FeedEntry(
            external_id=path,
            title=title,
            url=f"{CFTC_BASE}{path}",
            published_at=published,
            summary="",
        ))
    return entries


def _parse_links_with_context(html: str) -> list[FeedEntry]:
    """Strategy 3: Find all /PressRoom/ links and extract nearby dates."""
    entries = []
    seen_paths = set()
    for match in _LINK_PATTERN.finditer(html):
        path, title = match.groups()
        title = html_module.unescape(title.strip())
        if not title or path in seen_paths:
            continue
        seen_paths.add(path)

        # Look for a date within 200 chars before the link
        context_start = max(0, match.start() - 200)
        context = html[context_start:match.end() + 200]
        date_match = _NEARBY_DATE_PATTERN.search(context)

        published = _parse_date(date_match.group(1)) if date_match else None
        if published is None:
            published = datetime.now(timezone.utc)

        entries.append(FeedEntry(
            external_id=path,
            title=title,
            url=f"{CFTC_BASE}{path}",
            published_at=published,
            summary="",
        ))
    return entries


def parse_cftc_html(html: str) -> list[FeedEntry]:
    """Parse CFTC HTML using cascading strategies with automatic fallback.

    Tries strategies in order, using the first one that returns results.
    Logs which strategy succeeded for debugging.

    Args:
        html: Raw HTML from a CFTC listing page

    Returns:
        List of FeedEntry objects, newest first
    """
    strategies = [
        ("drupal_table", _parse_drupal_table),
        ("generic_table", _parse_generic_table),
        ("link_context", _parse_links_with_context),
    ]

    for name, parser in strategies:
        entries = parser(html)
        if entries:
            logger.info("CFTC parser strategy '%s' matched %d entries", name, len(entries))
            entries.sort(key=lambda e: e.published_at, reverse=True)
            return entries
        logger.debug("CFTC parser strategy '%s' found no entries, trying next", name)

    logger.warning("All CFTC parser strategies failed — HTML structure may have changed")
    return []


@retry(
    retry=retry_if_exception_type((httpx.TransportError, httpx.TimeoutException, httpx.HTTPStatusError)),
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=30),
    reraise=True,
)
async def _fetch_cftc_html(
    page_url: str,
    user_agent: str,
    timeout: int,
) -> str:
    """Fetch CFTC page HTML with retry on transient errors."""
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.get(
            page_url,
            headers={"User-Agent": user_agent},
            follow_redirects=True,
        )
        response.raise_for_status()
        return response.text


async def scrape_cftc_page(
    page_url: str,
    user_agent: str = "RegulatoryAlerts/1.0",
    timeout: int = 30,
) -> list[FeedEntry]:
    """Scrape a CFTC press release listing page and return FeedEntry objects.

    Features:
    - Automatic retry on transient HTTP errors (3 attempts with exponential backoff)
    - Multiple parsing strategies with automatic fallback
    - Detailed logging for debugging parser failures

    Args:
        page_url: Full URL to the CFTC listing page
        user_agent: User-Agent header for requests
        timeout: HTTP request timeout in seconds

    Returns:
        List of FeedEntry objects, newest first
    """
    logger.info("Scraping CFTC page: %s", page_url)

    try:
        html = await _fetch_cftc_html(page_url, user_agent, timeout)
    except httpx.HTTPStatusError as e:
        logger.error(
            "CFTC page returned HTTP %d: %s",
            e.response.status_code,
            page_url,
        )
        return []
    except Exception:
        logger.exception("Failed to fetch CFTC page after retries: %s", page_url)
        return []

    entries = parse_cftc_html(html)
    logger.info("Scraped %d entries from %s", len(entries), page_url)
    return entries
