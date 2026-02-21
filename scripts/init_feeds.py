"""Standalone script to seed SEC + CFTC feed sources.

Usage: python scripts/init_feeds.py

This is an alternative to `python -m regulatory_alerts.cli init-db`
for cases where you want to seed feeds without the CLI dependencies.
"""

import sys
from pathlib import Path

# Add project root and src to path
root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
sys.path.insert(0, str(root / "src"))

from config import get_settings
from regulatory_alerts.database.session import get_sync_engine, get_sync_session_factory
from regulatory_alerts.models import Base, FeedSource

SEED_FEEDS = [
    # SEC
    ("SEC Press Releases", "SEC", "https://www.sec.gov/news/pressreleases.rss", "rss"),
    ("SEC Litigation Releases", "SEC", "https://www.sec.gov/rss/litigation/litreleases.xml", "rss"),
    ("SEC Admin Proceedings", "SEC", "https://www.sec.gov/rss/litigation/admin.xml", "rss"),
    ("SEC Proposed Rules", "SEC", "https://www.sec.gov/rss/rulemaking/proposed.xml", "rss"),
    ("SEC Final Rules", "SEC", "https://www.sec.gov/rss/rulemaking/final.xml", "rss"),
    ("SEC Speeches", "SEC", "https://www.sec.gov/news/speeches.rss", "rss"),
    # CFTC (HTML scraping — RSS feeds are defunct)
    ("CFTC Press Releases", "CFTC", "https://www.cftc.gov/PressRoom/PressReleases", "html"),
    ("CFTC Speeches & Testimony", "CFTC", "https://www.cftc.gov/PressRoom/SpeechesTestimony", "html"),
]


def main():
    engine = get_sync_engine()
    Base.metadata.create_all(engine)

    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        existing = session.query(FeedSource).count()
        if existing > 0:
            print(f"Found {existing} existing feed sources. Skipping seed.")
            return

        for name, agency, url, feed_type in SEED_FEEDS:
            session.add(FeedSource(name=name, agency=agency, feed_url=url, feed_type=feed_type))

        session.commit()
        print(f"Seeded {len(SEED_FEEDS)} feed sources (SEC + CFTC).")


if __name__ == "__main__":
    main()
