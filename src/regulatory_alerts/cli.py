"""CLI tool for Regulatory Alerts.

Commands:
    init-db     Create database tables and seed SEC + CFTC feed sources
    list-feeds  Show all configured feed sources
    fetch       Fetch feeds, detect new documents, generate AI summaries
    serve       Start the FastAPI server
"""

import asyncio
import logging
from datetime import datetime, timezone

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table

from regulatory_alerts.config import get_settings
from regulatory_alerts.core.ai_summarizer import summarize_document
from regulatory_alerts.core.document_processor import process_entries
from regulatory_alerts.core.cftc_scraper import scrape_cftc_page
from regulatory_alerts.core.feed_fetcher import FeedFetcher
from regulatory_alerts.core.notifier import notify_new_alerts
from regulatory_alerts.database.session import get_sync_engine, get_sync_session_factory
from regulatory_alerts.models import Base, FeedDocument, FeedSource, ProcessedAlert, NotificationChannel

console = Console()

# Feed sources to seed on init
SEED_FEEDS = [
    # --- SEC ---
    {
        "name": "SEC Press Releases",
        "agency": "SEC",
        "feed_url": "https://www.sec.gov/news/pressreleases.rss",
        "feed_type": "rss",
    },
    {
        "name": "SEC Litigation Releases",
        "agency": "SEC",
        "feed_url": "https://www.sec.gov/rss/litigation/litreleases.xml",
        "feed_type": "rss",
    },
    {
        "name": "SEC Admin Proceedings",
        "agency": "SEC",
        "feed_url": "https://www.sec.gov/rss/litigation/admin.xml",
        "feed_type": "rss",
    },
    {
        "name": "SEC Proposed Rules",
        "agency": "SEC",
        "feed_url": "https://www.sec.gov/rss/rulemaking/proposed.xml",
        "feed_type": "rss",
    },
    {
        "name": "SEC Final Rules",
        "agency": "SEC",
        "feed_url": "https://www.sec.gov/rss/rulemaking/final.xml",
        "feed_type": "rss",
    },
    {
        "name": "SEC Speeches",
        "agency": "SEC",
        "feed_url": "https://www.sec.gov/news/speeches.rss",
        "feed_type": "rss",
    },
    # --- CFTC (HTML scraping — RSS feeds are defunct) ---
    {
        "name": "CFTC Press Releases",
        "agency": "CFTC",
        "feed_url": "https://www.cftc.gov/PressRoom/PressReleases",
        "feed_type": "html",
    },
    {
        "name": "CFTC Speeches & Testimony",
        "agency": "CFTC",
        "feed_url": "https://www.cftc.gov/PressRoom/SpeechesTestimony",
        "feed_type": "html",
    },
]


def setup_logging(level: str = "INFO"):
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )


@click.group()
@click.option("--log-level", default=None, help="Override log level (DEBUG, INFO, WARNING, ERROR)")
def cli(log_level: str | None):
    """Regulatory Alerts - AI-powered regulatory monitoring."""
    settings = get_settings()
    setup_logging(log_level or settings.LOG_LEVEL)


@cli.command()
def init_db():
    """Create database tables and seed SEC + CFTC feed sources."""
    engine = get_sync_engine()

    console.print("[bold]Creating database tables...[/bold]")
    Base.metadata.create_all(engine)
    console.print("[green]Tables created successfully.[/green]")

    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        existing = session.query(FeedSource).count()
        if existing > 0:
            console.print(f"[yellow]Found {existing} existing feed sources. Skipping seed.[/yellow]")
            return

        for feed_data in SEED_FEEDS:
            source = FeedSource(**feed_data)
            session.add(source)

        session.commit()
        sec_count = sum(1 for f in SEED_FEEDS if f["agency"] == "SEC")
        cftc_count = sum(1 for f in SEED_FEEDS if f["agency"] == "CFTC")
        console.print(f"[green]Seeded {sec_count} SEC + {cftc_count} CFTC feed sources ({len(SEED_FEEDS)} total).[/green]")


@cli.command("list-feeds")
def list_feeds():
    """Show all configured feed sources."""
    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        sources = session.query(FeedSource).all()

        if not sources:
            console.print("[yellow]No feed sources found. Run 'init-db' first.[/yellow]")
            return

        table = Table(title="Feed Sources")
        table.add_column("ID", style="dim")
        table.add_column("Agency", style="cyan")
        table.add_column("Name", style="bold")
        table.add_column("Type")
        table.add_column("Enabled")
        table.add_column("Last Checked")

        for s in sources:
            table.add_row(
                str(s.id),
                s.agency,
                s.name,
                s.feed_type,
                "[green]Yes[/green]" if s.enabled else "[red]No[/red]",
                s.last_checked_at.strftime("%Y-%m-%d %H:%M") if s.last_checked_at else "Never",
            )

        console.print(table)


@cli.command()
@click.option("--no-ai", is_flag=True, help="Skip AI summarization (just fetch and dedup)")
@click.option("--limit", default=None, type=int, help="Max entries to process per feed")
def fetch(no_ai: bool, limit: int | None):
    """Fetch feeds, detect new documents, and generate AI summaries."""
    asyncio.run(_fetch_async(no_ai, limit))


async def _fetch_async(no_ai: bool, limit: int | None):
    settings = get_settings()
    fetcher = FeedFetcher()
    SessionFactory = get_sync_session_factory()

    total_new = 0
    total_alerts = 0
    total_cost = 0.0
    total_notifications = 0
    feed_results = []

    with SessionFactory() as session:
        sources = session.query(FeedSource).filter(FeedSource.enabled == True).all()

        if not sources:
            console.print("[yellow]No enabled feed sources. Run 'init-db' first.[/yellow]")
            return

        console.print(f"\n[bold]Fetching {len(sources)} feed sources...[/bold]\n")

        for source in sources:
            try:
                if source.feed_type == "html":
                    entries = await scrape_cftc_page(source.feed_url, settings.USER_AGENT, settings.REQUEST_TIMEOUT)
                else:
                    entries = await fetcher.fetch(source.feed_url)
            except Exception as e:
                console.print(f"[red]Error fetching {source.name}: {e}[/red]")
                feed_results.append((source.name, 0, 0, "ERROR"))
                continue

            if limit:
                entries = entries[:limit]

            new_docs = process_entries(session, entries, source.id, source.agency)

            alerts_generated = 0
            feed_cost = 0.0
            new_alerts = []

            if not no_ai and new_docs:
                for doc in new_docs:
                    alert = summarize_document(session, doc)
                    if alert:
                        alerts_generated += 1
                        feed_cost += float(alert.ai_cost_usd or 0)
                        new_alerts.append(alert)

            # Update last checked
            source.last_checked_at = datetime.now(timezone.utc)
            session.commit()

            # Send notifications for new alerts
            if new_alerts:
                notif_count = notify_new_alerts(session, new_alerts)
                session.commit()
                total_notifications += notif_count

            total_new += len(new_docs)
            total_alerts += alerts_generated
            total_cost += feed_cost

            feed_results.append((source.name, len(entries), len(new_docs), "OK"))

        # --- Print results ---

        # Feed summary table
        feed_table = Table(title="Feed Results")
        feed_table.add_column("Feed", style="bold")
        feed_table.add_column("Entries", justify="right")
        feed_table.add_column("New", justify="right", style="green")
        feed_table.add_column("Status")

        for name, total, new, status in feed_results:
            status_str = f"[green]{status}[/green]" if status == "OK" else f"[red]{status}[/red]"
            feed_table.add_row(name, str(total), str(new), status_str)

        console.print(feed_table)

        # Summary panel
        summary_text = (
            f"Feeds Checked: {len(sources)}\n"
            f"New Documents: {total_new}\n"
            f"Alerts Generated: {total_alerts}\n"
            f"Notifications Sent: {total_notifications}\n"
            f"AI Cost: ${total_cost:.4f}"
        )
        console.print(Panel(summary_text, title="Fetch Complete", border_style="green"))

        # Print new alerts
        if total_alerts > 0:
            console.print("\n[bold]New Alerts:[/bold]\n")

            new_alerts = (
                session.query(ProcessedAlert)
                .join(FeedDocument)
                .filter(FeedDocument.processing_status == "completed")
                .order_by(ProcessedAlert.relevance_score.desc())
                .limit(total_alerts)
                .all()
            )

            for alert in new_alerts:
                doc = alert.feed_document
                score_color = "green" if alert.relevance_score >= 0.7 else "yellow" if alert.relevance_score >= 0.5 else "dim"
                topics = alert.topics_list

                console.print(f"[bold cyan]{doc.agency}[/bold cyan] - [bold]{doc.title}[/bold]")
                console.print(f"  [{score_color}]Relevance: {alert.relevance_score:.0%}[/{score_color}] | Type: {alert.document_type}")
                console.print(f"  Published: {doc.published_at.strftime('%Y-%m-%d %H:%M UTC')}")
                console.print(f"  [italic]{alert.summary}[/italic]")
                if topics:
                    console.print(f"  Topics: {', '.join(topics)}")
                console.print(f"  URL: {doc.url}")
                console.print()


@cli.command()
@click.option("--host", default=None, help="Host to bind to")
@click.option("--port", default=None, type=int, help="Port to bind to")
def serve(host: str | None, port: int | None):
    """Start the FastAPI API server."""
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "regulatory_alerts.api:app",
        host=host or settings.API_HOST,
        port=port or settings.API_PORT,
        reload=True,
    )


# --- Notification channel management ---

@cli.command("add-webhook")
@click.argument("name")
@click.argument("url")
@click.option("--secret", default=None, help="HMAC secret for payload signing")
@click.option("--min-score", default=None, type=float, help="Minimum relevance score (0.0-1.0)")
@click.option("--agency", default=None, help="Filter by agency (SEC, CFTC)")
def add_webhook(name: str, url: str, secret: str | None, min_score: float | None, agency: str | None):
    """Add a webhook notification channel."""
    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        channel = NotificationChannel(
            name=name,
            channel_type="webhook",
            webhook_url=url,
            webhook_secret=secret,
            min_relevance_score=min_score,
            agency_filter=agency.upper() if agency else None,
        )
        session.add(channel)
        session.commit()
        console.print(f"[green]Added webhook channel '{name}' (ID: {channel.id})[/green]")


@cli.command("add-email")
@click.argument("name")
@click.argument("email")
@click.option("--min-score", default=None, type=float, help="Minimum relevance score (0.0-1.0)")
@click.option("--agency", default=None, help="Filter by agency (SEC, CFTC)")
def add_email(name: str, email: str, min_score: float | None, agency: str | None):
    """Add an email notification channel."""
    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        channel = NotificationChannel(
            name=name,
            channel_type="email",
            email_address=email,
            min_relevance_score=min_score,
            agency_filter=agency.upper() if agency else None,
        )
        session.add(channel)
        session.commit()
        console.print(f"[green]Added email channel '{name}' (ID: {channel.id})[/green]")


@cli.command("list-channels")
def list_channels():
    """Show all notification channels."""
    SessionFactory = get_sync_session_factory()
    with SessionFactory() as session:
        channels = session.query(NotificationChannel).all()

        if not channels:
            console.print("[yellow]No notification channels configured. Use 'add-webhook' or 'add-email'.[/yellow]")
            return

        table = Table(title="Notification Channels")
        table.add_column("ID", style="dim")
        table.add_column("Name", style="bold")
        table.add_column("Type", style="cyan")
        table.add_column("Target")
        table.add_column("Filters")
        table.add_column("Enabled")

        for ch in channels:
            target = ch.webhook_url[:50] + "..." if ch.webhook_url and len(ch.webhook_url) > 50 else (ch.webhook_url or ch.email_address or "N/A")
            filters = []
            if ch.min_relevance_score is not None:
                filters.append(f"score>={ch.min_relevance_score:.0%}")
            if ch.agency_filter:
                filters.append(ch.agency_filter)
            filter_str = ", ".join(filters) if filters else "None"

            table.add_row(
                str(ch.id),
                ch.name,
                ch.channel_type,
                target,
                filter_str,
                "[green]Yes[/green]" if ch.enabled else "[red]No[/red]",
            )

        console.print(table)


if __name__ == "__main__":
    cli()
