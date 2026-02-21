"""Background scheduler for periodic feed fetching.

Uses APScheduler to run the fetch pipeline on a configurable interval.
Integrates with the FastAPI lifespan so the scheduler starts/stops with the server.
"""

import asyncio
import logging
import time
from datetime import datetime, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from regulatory_alerts.config import get_settings
from regulatory_alerts.core.ai_summarizer import summarize_document
from regulatory_alerts.core.cftc_scraper import scrape_cftc_page
from regulatory_alerts.core.document_processor import process_entries
from regulatory_alerts.core.feed_fetcher import FeedFetcher
from regulatory_alerts.core.notifier import notify_new_alerts, retry_failed_notifications
from sqlalchemy import select

from regulatory_alerts.database.session import get_sync_session_factory
from regulatory_alerts.models import FeedSource

logger = logging.getLogger(__name__)

_scheduler: BackgroundScheduler | None = None


def _run_fetch_cycle():
    """Execute one full fetch cycle: fetch → dedup → summarize → notify.

    This runs synchronously in a background thread (APScheduler default).
    Async feed fetching is handled via asyncio.run().
    """
    from regulatory_alerts.observability import error_counter, scheduler_metrics

    scheduler_metrics.record_start()
    start = time.perf_counter()
    any_source_failed = False

    settings = get_settings()
    logger.info("Scheduled fetch cycle starting...")

    try:
        fetcher = FeedFetcher()
        SessionFactory = get_sync_session_factory()

        total_new = 0
        total_alerts = 0
        total_notifications = 0

        with SessionFactory() as session:
            sources = session.scalars(
                select(FeedSource).where(FeedSource.enabled == True)  # noqa: E712
            ).all()

            if not sources:
                logger.warning("No enabled feed sources for scheduled fetch")
                duration = time.perf_counter() - start
                scheduler_metrics.record_success(duration, any_failures=False)
                return

            # Single event loop for all async fetches (avoids per-source loop overhead)
            loop = asyncio.new_event_loop()
            try:
                for source in sources:
                    try:
                        if source.feed_type == "html":
                            entries = loop.run_until_complete(
                                scrape_cftc_page(source.feed_url, settings.USER_AGENT, settings.REQUEST_TIMEOUT)
                            )
                        else:
                            entries = loop.run_until_complete(fetcher.fetch(source.feed_url))
                    except Exception:
                        logger.exception("Scheduled fetch failed for %s", source.name)
                        any_source_failed = True
                        error_counter.record("scheduler")
                        continue

                    new_docs = process_entries(session, entries, source.id, source.agency)
                    new_alerts = []

                    for doc in new_docs:
                        alert = summarize_document(session, doc)
                        if alert:
                            total_alerts += 1
                            new_alerts.append(alert)

                    source.last_checked_at = datetime.now(timezone.utc)

                    # Send notifications in the SAME transaction as document/alert creation
                    # so a crash doesn't permanently lose notification attempts.
                    if new_alerts:
                        notif_count = notify_new_alerts(session, new_alerts)
                        total_notifications += notif_count

                    session.commit()

                    total_new += len(new_docs)
            finally:
                loop.close()

        # Retry failed notifications from previous cycles
        with SessionFactory() as session:
            retried = retry_failed_notifications(session)
            if retried:
                session.commit()
                total_notifications += retried
                logger.info("Retried %d failed notifications", retried)

        logger.info(
            "Scheduled fetch complete: %d new docs, %d alerts, %d notifications",
            total_new,
            total_alerts,
            total_notifications,
        )

        duration = time.perf_counter() - start
        scheduler_metrics.record_success(duration, any_failures=any_source_failed)

        # System alerting check (after success — checks for prior failures)
        try:
            from regulatory_alerts.alerting import check_and_send_alerts
            check_and_send_alerts()
        except Exception:
            logger.debug("Alerting check failed", exc_info=True)

    except Exception as e:
        duration = time.perf_counter() - start
        scheduler_metrics.record_failure(e, duration)
        error_counter.record("scheduler")

        # System alerting check (after failure)
        try:
            from regulatory_alerts.alerting import check_and_send_alerts
            check_and_send_alerts()
        except Exception:
            logger.debug("Alerting check failed", exc_info=True)

        raise


def start_scheduler() -> BackgroundScheduler:
    """Create and start the background fetch scheduler."""
    global _scheduler

    settings = get_settings()
    interval_minutes = settings.FETCH_INTERVAL_MINUTES

    _scheduler = BackgroundScheduler()
    _scheduler.add_job(
        _run_fetch_cycle,
        trigger=IntervalTrigger(minutes=interval_minutes),
        id="fetch_cycle",
        name=f"Fetch regulatory feeds every {interval_minutes}m",
        replace_existing=True,
    )
    _scheduler.start()
    logger.info("Scheduler started: fetching every %d minutes", interval_minutes)
    return _scheduler


def stop_scheduler():
    """Gracefully shut down the scheduler, waiting for running jobs to finish."""
    global _scheduler
    if _scheduler:
        _scheduler.shutdown(wait=True)
        logger.info("Scheduler stopped (waited for running jobs)")
        _scheduler = None


def get_scheduler_status() -> dict:
    """Return scheduler metrics for the health endpoint."""
    from regulatory_alerts.observability import scheduler_metrics

    return scheduler_metrics.to_dict()
