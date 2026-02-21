"""System alerting: email admin when scheduler fails.

Sends alert emails to ALERT_EMAIL when:
- Scheduler status is "error"
- Failed cycles >= 2

Cooldown: at most one alert per ALERT_COOLDOWN_MINUTES.
Thread-safe via threading.Lock (called from APScheduler background thread).
"""

import logging
import threading
from datetime import datetime, timezone

from regulatory_alerts.config import get_settings

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_last_alert_sent_at: datetime | None = None


def check_and_send_alerts() -> bool:
    """Check scheduler state and send an alert email if warranted.

    Returns True if an alert was sent, False otherwise.
    Called after each scheduler cycle (both success and failure).
    """
    global _last_alert_sent_at

    settings = get_settings()

    if not settings.ALERTING_ENABLED:
        return False

    if not settings.ALERT_EMAIL:
        logger.warning("ALERTING_ENABLED=True but ALERT_EMAIL is empty — cannot send alerts")
        return False

    from regulatory_alerts.observability import scheduler_metrics

    with scheduler_metrics._lock:
        status = scheduler_metrics.last_status
        failed = scheduler_metrics.failed_cycles

    # Trigger conditions: status is error OR 2+ failed cycles
    should_alert = status == "error" or failed >= 2
    if not should_alert:
        return False

    # Cooldown check
    with _lock:
        now = datetime.now(timezone.utc)
        if _last_alert_sent_at is not None:
            cooldown_seconds = settings.ALERT_COOLDOWN_MINUTES * 60
            elapsed = (now - _last_alert_sent_at).total_seconds()
            if elapsed < cooldown_seconds:
                logger.debug(
                    "Alert cooldown active (%.0fs remaining)",
                    cooldown_seconds - elapsed,
                )
                return False

        # Send the alert
        reason = f"Scheduler status: {status}, failed cycles: {failed}"
        sent = _send_alert_email(settings.ALERT_EMAIL, reason)

        if sent:
            _last_alert_sent_at = now

        return sent


def _send_alert_email(to: str, reason: str) -> bool:
    """Build and send an alert email with scheduler stats.

    Returns True if sent successfully, False otherwise.
    """
    from regulatory_alerts.observability import get_uptime_seconds, scheduler_metrics

    stats = scheduler_metrics.to_dict()
    uptime = get_uptime_seconds()

    subject = "[Regulatory Alerts] System Alert"
    body = f"""\
<html><body>
<h2>System Alert</h2>
<p><strong>Reason:</strong> {reason}</p>
<h3>Scheduler Status</h3>
<ul>
<li>Status: {stats.get('status', 'unknown')}</li>
<li>Total cycles: {stats.get('total_cycles', 0)}</li>
<li>Successful: {stats.get('successful_cycles', 0)}</li>
<li>Failed: {stats.get('failed_cycles', 0)}</li>
<li>Last run: {stats.get('last_run_at', 'never')}</li>
<li>Last duration: {stats.get('last_duration_seconds', 'N/A')}s</li>
</ul>
<p>Uptime: {uptime:.0f}s</p>
<p><em>This is an automated alert from the Regulatory Alerts system.</em></p>
</body></html>"""

    try:
        from regulatory_alerts.core.notifier import send_raw_email
        success, error = send_raw_email(to, subject, body)
        if not success:
            logger.error("Failed to send system alert: %s", error)
        return success
    except Exception:
        logger.exception("Exception sending system alert email")
        return False


def reset_alerting_state() -> None:
    """Clear cooldown state (for tests)."""
    global _last_alert_sent_at
    with _lock:
        _last_alert_sent_at = None
