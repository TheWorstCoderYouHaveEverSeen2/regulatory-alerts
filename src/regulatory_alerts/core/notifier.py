"""Notification delivery for webhook, Slack, and email channels.

After new alerts are generated, this module checks all enabled notification
channels, applies filters, and delivers via HTTP POST (webhooks/Slack) or SMTP (email).
"""

import hashlib
import hmac
import html as html_module
import json
import logging
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from regulatory_alerts.config import get_settings
from regulatory_alerts.models.alert import ProcessedAlert
from regulatory_alerts.models.document import FeedDocument
from regulatory_alerts.models.notification import NotificationChannel, NotificationLog

logger = logging.getLogger(__name__)

# Module-level HTTP client for connection pooling across webhook/Slack deliveries.
# Avoids TCP+TLS handshake per notification — connections are reused when multiple
# notifications target the same host within a batch cycle.
_http_client = httpx.Client(timeout=15)


def _alert_matches_channel(
    alert: ProcessedAlert,
    doc: FeedDocument,
    channel: NotificationChannel,
) -> bool:
    """Check whether an alert passes the channel's filters."""
    # Relevance score filter
    if channel.min_relevance_score is not None:
        if (alert.relevance_score or 0) < channel.min_relevance_score:
            return False

    # Agency filter
    if channel.agency_filter:
        if doc.agency.upper() != channel.agency_filter.upper():
            return False

    # Topic filter
    topic_filter = channel.topic_filter_list
    if topic_filter:
        alert_topics = alert.topics_list
        if not any(t in topic_filter for t in alert_topics):
            return False

    return True


def _build_webhook_payload(alert: ProcessedAlert, doc: FeedDocument) -> dict:
    """Build the JSON payload for webhook delivery."""
    return {
        "event": "new_alert",
        "alert": {
            "id": alert.id,
            "summary": alert.summary,
            "key_points": alert.key_points if isinstance(alert.key_points, list) else [],
            "topics": alert.topics_list,
            "relevance_score": alert.relevance_score,
            "document_type": alert.document_type,
            "ai_model": alert.ai_model,
        },
        "document": {
            "id": doc.id,
            "title": doc.title,
            "agency": doc.agency,
            "url": doc.url,
            "published_at": doc.published_at.isoformat() if doc.published_at else None,
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _sign_payload(payload_bytes: bytes, secret: str) -> str:
    """Create HMAC-SHA256 signature for webhook verification."""
    return hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()


def _send_webhook(
    channel: NotificationChannel,
    alert: ProcessedAlert,
    doc: FeedDocument,
) -> tuple[bool, str]:
    """Send a webhook notification via HTTP POST.

    Returns:
        (success, error_message)
    """
    payload = _build_webhook_payload(alert, doc)
    payload_bytes = json.dumps(payload, default=str).encode()

    headers = {"Content-Type": "application/json"}
    if channel.webhook_secret:
        sig = _sign_payload(payload_bytes, channel.webhook_secret)
        headers["X-Signature-256"] = f"sha256={sig}"

    try:
        resp = _http_client.post(
            channel.webhook_url,
            content=payload_bytes,
            headers=headers,
        )
        resp.raise_for_status()
        return True, ""
    except httpx.HTTPStatusError as e:
        msg = f"HTTP {e.response.status_code}: {e.response.text[:200]}"
        logger.error("Webhook failed for channel %d: %s", channel.id, msg)
        return False, msg
    except Exception as e:
        msg = str(e)[:500]
        logger.error("Webhook error for channel %d: %s", channel.id, msg)
        return False, msg


# --- Slack ---

def _build_slack_payload(alert: ProcessedAlert, doc: FeedDocument) -> dict:
    """Build Slack Block Kit payload for incoming webhook delivery."""
    score_pct = f"{alert.relevance_score:.0%}" if alert.relevance_score else "N/A"
    topics = ", ".join(alert.topics_list) if alert.topics_list else "General"

    # Slack header block has a 150-char limit for plain_text
    header_text = f"[{doc.agency}] {doc.title[:140]}"

    return {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": header_text, "emoji": True},
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": alert.summary or "No summary available.",
                },
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Score:* {score_pct} | *Type:* {alert.document_type or 'N/A'} | *Topics:* {topics}",
                    }
                ],
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "View Document"},
                        "url": doc.url,
                        "style": "primary",
                    }
                ],
            },
            {"type": "divider"},
        ]
    }


def _send_slack(
    channel: NotificationChannel,
    alert: ProcessedAlert,
    doc: FeedDocument,
) -> tuple[bool, str]:
    """Send a Slack notification via incoming webhook.

    Slack incoming webhooks return "ok" as plain text (not JSON) on success.

    Returns:
        (success, error_message)
    """
    payload = _build_slack_payload(alert, doc)
    try:
        resp = _http_client.post(channel.webhook_url, json=payload)
        resp.raise_for_status()
        # Slack returns "ok" as plain text on success
        if resp.text != "ok":
            return False, f"Slack API error: {resp.text[:200]}"
        return True, ""
    except httpx.HTTPStatusError as e:
        msg = f"HTTP {e.response.status_code}: {e.response.text[:200]}"
        logger.error("Slack webhook failed for channel %d: %s", channel.id, msg)
        return False, msg
    except Exception as e:
        msg = str(e)[:500]
        logger.error("Slack webhook error for channel %d: %s", channel.id, msg)
        return False, msg


# --- Email ---

def _build_email_body(alert: ProcessedAlert, doc: FeedDocument) -> tuple[str, str]:
    """Build email subject and HTML body for an alert notification."""
    esc = html_module.escape  # Prevent XSS via malicious document titles/summaries

    score_pct = f"{alert.relevance_score:.0%}" if alert.relevance_score else "N/A"
    topics = esc(", ".join(alert.topics_list) if alert.topics_list else "General")

    # Sanitize subject: strip CR/LF to prevent email header injection
    raw_title = (doc.title or "")[:80].replace("\r", "").replace("\n", "")
    subject = f"[{doc.agency}] {raw_title}"

    safe_agency = esc(doc.agency or "")
    safe_title = esc(doc.title or "")
    safe_doc_type = esc(alert.document_type or "N/A")
    safe_summary = esc(alert.summary or "")
    safe_url = esc(doc.url or "")
    safe_published = esc(doc.published_at.strftime('%Y-%m-%d %H:%M UTC') if doc.published_at else 'N/A')

    html = f"""\
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
  <div style="background: #1a1a2e; color: white; padding: 16px 20px; border-radius: 8px 8px 0 0;">
    <h2 style="margin: 0;">Regulatory Alert</h2>
    <p style="margin: 4px 0 0; opacity: 0.8;">{safe_agency} &bull; Relevance: {score_pct}</p>
  </div>
  <div style="padding: 20px; border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 8px 8px;">
    <h3 style="margin-top: 0;">{safe_title}</h3>
    <p><strong>Type:</strong> {safe_doc_type}<br>
       <strong>Topics:</strong> {topics}<br>
       <strong>Published:</strong> {safe_published}</p>
    <div style="background: #f5f5f5; padding: 12px; border-radius: 6px; margin: 12px 0;">
      <p style="margin: 0;">{safe_summary}</p>
    </div>
    <p><a href="{safe_url}" style="color: #0066cc;">View Original Document</a></p>
  </div>
  <p style="font-size: 11px; color: #999; text-align: center; margin-top: 12px;">
    Sent by E3 Regulatory Alert SaaS
  </p>
  <p style="font-size: 10px; color: #bbb; text-align: center; margin-top: 4px; line-height: 1.4;">
    This is an information service. AI summaries may be incomplete or inaccurate.
    Not legal advice, compliance advice, or an official interpretation of any regulatory filing.
    Verify all information with original sources.
  </p>
</body>
</html>"""

    return subject, html


def send_raw_email(to: str, subject: str, html_body: str) -> tuple[bool, str]:
    """Send a raw email via SMTP. Reusable by any module (notifications, password reset, etc.).

    Args:
        to: Recipient email address.
        subject: Email subject line.
        html_body: HTML email body.

    Returns:
        (success, error_message)
    """
    settings = get_settings()

    if not settings.SMTP_HOST:
        return False, "SMTP not configured (SMTP_HOST is empty)"

    # Validate email address to prevent SMTP header injection
    if "\r" in to or "\n" in to:
        return False, "Invalid recipient email address"

    # Sanitize subject line
    subject = subject.replace("\r", "").replace("\n", "")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = settings.SMTP_FROM
    msg["To"] = to
    msg.attach(MIMEText(html_body, "html"))

    try:
        if settings.SMTP_USE_TLS:
            server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15)
            server.starttls()
            # Re-set socket timeout after TLS upgrade (starttls replaces the socket)
            if server.sock:
                server.sock.settimeout(15)
        else:
            server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15)

        if settings.SMTP_USER and settings.SMTP_PASSWORD:
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)

        server.sendmail(settings.SMTP_FROM, [to], msg.as_string())
        server.quit()
        return True, ""
    except Exception as e:
        msg_err = str(e)[:500]
        logger.error("Email send failed to %s: %s", to, msg_err)
        return False, msg_err


def _send_email(
    channel: NotificationChannel,
    alert: ProcessedAlert,
    doc: FeedDocument,
) -> tuple[bool, str]:
    """Send an email notification via SMTP.

    Returns:
        (success, error_message)
    """
    subject, html_body = _build_email_body(alert, doc)
    success, error = send_raw_email(channel.email_address, subject, html_body)
    if not success:
        logger.error("Email failed for channel %d: %s", channel.id, error)
    return success, error


# --- Dispatch ---

def _dispatch_notification(
    channel: NotificationChannel,
    alert: ProcessedAlert,
    doc: FeedDocument,
) -> tuple[bool, str]:
    """Route a notification to the appropriate delivery function.

    Single source of truth for dispatch logic — used by notify_new_alerts,
    retry_failed_notifications, and send_test_notification.
    """
    if channel.channel_type == "webhook" and channel.webhook_url:
        return _send_webhook(channel, alert, doc)
    elif channel.channel_type == "slack" and channel.webhook_url:
        return _send_slack(channel, alert, doc)
    elif channel.channel_type == "email" and channel.email_address:
        return _send_email(channel, alert, doc)
    return False, f"Invalid channel config: {channel.channel_type}"


def send_test_notification(
    channel: NotificationChannel,
    alert: ProcessedAlert,
    doc: FeedDocument,
) -> tuple[bool, str]:
    """Send a test notification to verify channel configuration.

    Public API for dashboard test button. Uses the same dispatch logic
    as real notifications.
    """
    return _dispatch_notification(channel, alert, doc)


def notify_new_alerts(
    session: Session,
    alerts: list[ProcessedAlert],
) -> int:
    """Send notifications for a batch of newly created alerts.

    Args:
        session: SQLAlchemy sync session
        alerts: List of ProcessedAlert objects (must have feed_document loaded)

    Returns:
        Number of notifications successfully sent
    """
    if not alerts:
        return 0

    channels = session.scalars(
        select(NotificationChannel).where(NotificationChannel.enabled == True)
    ).all()

    if not channels:
        logger.debug("No enabled notification channels")
        return 0

    sent_count = 0

    # Pre-fetch all existing (channel_id, alert_id) pairs for idempotency check
    # This replaces N*M individual SELECT queries with a single batch query
    alert_ids = [a.id for a in alerts]
    channel_ids = [c.id for c in channels]
    existing_pairs = set(
        session.execute(
            select(NotificationLog.channel_id, NotificationLog.alert_id).where(
                NotificationLog.channel_id.in_(channel_ids),
                NotificationLog.alert_id.in_(alert_ids),
            )
        ).all()
    )

    for alert in alerts:
        doc = alert.feed_document

        for channel in channels:
            if not _alert_matches_channel(alert, doc, channel):
                continue

            # Idempotency: skip if already notified (O(1) set lookup)
            if (channel.id, alert.id) in existing_pairs:
                continue

            # Dispatch based on channel type
            success, error = _dispatch_notification(channel, alert, doc)

            now = datetime.now(timezone.utc)
            log = NotificationLog(
                channel_id=channel.id,
                alert_id=alert.id,
                status="sent" if success else "failed",
                error_message=error if error else None,
                sent_at=now if success else None,
                retry_count=0,
                next_retry_at=_next_retry_time(now, 0) if not success else None,
            )
            session.add(log)

            if success:
                sent_count += 1
                logger.info(
                    "Notified channel %d (%s) for alert %d",
                    channel.id,
                    channel.channel_type,
                    alert.id,
                )
            else:
                logger.warning(
                    "Notification failed for channel %d, alert %d: %s",
                    channel.id,
                    alert.id,
                    error,
                )

    session.flush()
    return sent_count


# --- Retry logic ---

MAX_RETRIES = 3  # After 3 retries, give up (total: 1 initial + 3 retries = 4 attempts)
_RETRY_BACKOFF_MINUTES = [5, 30, 120]  # Exponential-ish: 5min, 30min, 2hr


def _next_retry_time(now: datetime, retry_count: int) -> datetime | None:
    """Calculate next retry time using exponential backoff. None if max retries exceeded."""
    if retry_count >= MAX_RETRIES:
        return None
    backoff = _RETRY_BACKOFF_MINUTES[min(retry_count, len(_RETRY_BACKOFF_MINUTES) - 1)]
    return now + timedelta(minutes=backoff)


def retry_failed_notifications(session: Session) -> int:
    """Retry failed notifications that are due for retry.

    Selects NotificationLogs with status='failed', retry_count < MAX_RETRIES,
    and next_retry_at <= now. Re-attempts delivery and updates the log entry.

    Returns:
        Number of notifications successfully retried.
    """
    now = datetime.now(timezone.utc)

    # Eagerly load channel and alert+document to avoid N+1 queries in the loop
    failed_logs = session.scalars(
        select(NotificationLog)
        .options(
            joinedload(NotificationLog.channel),
            joinedload(NotificationLog.alert).joinedload(ProcessedAlert.feed_document),
        )
        .where(
            NotificationLog.status == "failed",
            NotificationLog.retry_count < MAX_RETRIES,
            NotificationLog.next_retry_at <= now,
        )
    ).unique().all()

    if not failed_logs:
        return 0

    retried_count = 0

    for log in failed_logs:
        channel = log.channel
        alert = log.alert

        if not channel or not alert or not channel.enabled:
            # Channel deleted/disabled or alert gone — mark as permanently failed
            log.status = "failed"
            log.next_retry_at = None
            continue

        doc = alert.feed_document
        if not doc:
            # FeedDocument was deleted — can't rebuild payload, give up
            log.status = "failed"
            log.error_message = "Associated document was deleted"
            log.next_retry_at = None
            continue

        # Re-attempt delivery
        success, error = _dispatch_notification(channel, alert, doc)

        log.retry_count += 1

        if success:
            log.status = "sent"
            log.error_message = None
            log.sent_at = now
            log.next_retry_at = None
            retried_count += 1
            logger.info(
                "Retry succeeded for channel %d, alert %d (attempt %d)",
                channel.id, alert.id, log.retry_count,
            )
        else:
            log.error_message = error if error else None
            log.next_retry_at = _next_retry_time(now, log.retry_count)
            if log.retry_count >= MAX_RETRIES:
                logger.warning(
                    "Giving up on channel %d, alert %d after %d retries: %s",
                    channel.id, alert.id, log.retry_count, error,
                )
            else:
                logger.info(
                    "Retry %d failed for channel %d, alert %d, next at %s: %s",
                    log.retry_count, channel.id, alert.id, log.next_retry_at, error,
                )

    session.flush()
    return retried_count
