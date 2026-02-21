"""Tests for system alerting: email alerts on scheduler failures."""

import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure src is on path
_src = str(Path(__file__).resolve().parents[1] / "src")
if _src not in sys.path:
    sys.path.insert(0, _src)

os.environ["DATABASE_URL_SYNC"] = "sqlite:///:memory:"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["ANTHROPIC_API_KEY"] = "test-key-not-real"

from regulatory_alerts.alerting import (
    _send_alert_email,
    check_and_send_alerts,
    reset_alerting_state,
)
from regulatory_alerts.config import get_settings
from regulatory_alerts.observability import (
    error_counter,
    reset_uptime,
    scheduler_metrics,
)


@pytest.fixture(autouse=True)
def _reset_all():
    """Reset singletons and alerting state between tests."""
    scheduler_metrics.reset()
    error_counter.reset()
    reset_uptime()
    reset_alerting_state()
    yield


@pytest.fixture(autouse=True)
def _default_settings():
    """Reset alerting settings to disabled by default."""
    settings = get_settings()
    orig_enabled = settings.ALERTING_ENABLED
    orig_email = settings.ALERT_EMAIL
    orig_cooldown = settings.ALERT_COOLDOWN_MINUTES
    settings.ALERTING_ENABLED = False
    settings.ALERT_EMAIL = ""
    settings.ALERT_COOLDOWN_MINUTES = 60
    yield settings
    settings.ALERTING_ENABLED = orig_enabled
    settings.ALERT_EMAIL = orig_email
    settings.ALERT_COOLDOWN_MINUTES = orig_cooldown


class TestCheckAndSendAlerts:
    def test_disabled_by_default(self):
        """No alert sent when ALERTING_ENABLED=False."""
        result = check_and_send_alerts()
        assert result is False

    def test_no_email_configured(self, _default_settings):
        """Warning logged when enabled but no email configured."""
        _default_settings.ALERTING_ENABLED = True
        _default_settings.ALERT_EMAIL = ""
        result = check_and_send_alerts()
        assert result is False

    @patch("regulatory_alerts.alerting._send_alert_email", return_value=True)
    def test_triggers_on_error_status(self, mock_send, _default_settings):
        """Alert sent when scheduler status is 'error'."""
        _default_settings.ALERTING_ENABLED = True
        _default_settings.ALERT_EMAIL = "admin@example.com"

        scheduler_metrics.record_start()
        scheduler_metrics.record_failure(RuntimeError("boom"), 1.0)

        result = check_and_send_alerts()
        assert result is True
        mock_send.assert_called_once()
        assert "admin@example.com" in mock_send.call_args[0]

    @patch("regulatory_alerts.alerting._send_alert_email", return_value=True)
    def test_triggers_on_two_failures(self, mock_send, _default_settings):
        """Alert sent when failed_cycles >= 2."""
        _default_settings.ALERTING_ENABLED = True
        _default_settings.ALERT_EMAIL = "admin@example.com"

        # Two failed cycles, but status might be partial now (after a success)
        scheduler_metrics.record_start()
        scheduler_metrics.record_failure(RuntimeError("fail 1"), 1.0)
        scheduler_metrics.record_start()
        scheduler_metrics.record_failure(RuntimeError("fail 2"), 1.0)

        result = check_and_send_alerts()
        assert result is True

    @patch("regulatory_alerts.alerting._send_alert_email", return_value=True)
    def test_no_trigger_on_success(self, mock_send, _default_settings):
        """No alert sent when scheduler is healthy."""
        _default_settings.ALERTING_ENABLED = True
        _default_settings.ALERT_EMAIL = "admin@example.com"

        scheduler_metrics.record_start()
        scheduler_metrics.record_success(1.0)

        result = check_and_send_alerts()
        assert result is False
        mock_send.assert_not_called()

    @patch("regulatory_alerts.alerting._send_alert_email", return_value=True)
    def test_cooldown_enforcement(self, mock_send, _default_settings):
        """Second alert within cooldown window is suppressed."""
        _default_settings.ALERTING_ENABLED = True
        _default_settings.ALERT_EMAIL = "admin@example.com"
        _default_settings.ALERT_COOLDOWN_MINUTES = 60

        scheduler_metrics.record_start()
        scheduler_metrics.record_failure(RuntimeError("boom"), 1.0)

        # First alert sends
        result1 = check_and_send_alerts()
        assert result1 is True

        # Second alert within cooldown — suppressed
        result2 = check_and_send_alerts()
        assert result2 is False
        assert mock_send.call_count == 1

    @patch("regulatory_alerts.alerting._send_alert_email", return_value=True)
    def test_cooldown_expiry(self, mock_send, _default_settings):
        """Alert sends again after cooldown expires."""
        import regulatory_alerts.alerting as alerting_mod

        _default_settings.ALERTING_ENABLED = True
        _default_settings.ALERT_EMAIL = "admin@example.com"
        _default_settings.ALERT_COOLDOWN_MINUTES = 1  # 1 minute

        scheduler_metrics.record_start()
        scheduler_metrics.record_failure(RuntimeError("boom"), 1.0)

        # First alert sends
        check_and_send_alerts()

        # Simulate cooldown expiry by backdating _last_alert_sent_at
        with alerting_mod._lock:
            alerting_mod._last_alert_sent_at = datetime.now(timezone.utc) - timedelta(minutes=2)

        # Second alert should now send
        result = check_and_send_alerts()
        assert result is True
        assert mock_send.call_count == 2


class TestSendAlertEmail:
    @patch("regulatory_alerts.core.notifier.send_raw_email", return_value=(True, ""))
    def test_email_content(self, mock_send):
        """Alert email contains reason and scheduler stats."""
        result = _send_alert_email("admin@example.com", "Test reason")
        assert result is True
        mock_send.assert_called_once()
        args = mock_send.call_args[0]
        assert args[0] == "admin@example.com"
        assert "System Alert" in args[1]  # subject
        assert "Test reason" in args[2]  # body

    @patch("regulatory_alerts.core.notifier.send_raw_email", return_value=(False, "SMTP error"))
    def test_email_failure_returns_false(self, mock_send):
        """Returns False when send_raw_email fails."""
        result = _send_alert_email("admin@example.com", "Test reason")
        assert result is False

    @patch("regulatory_alerts.core.notifier.send_raw_email", side_effect=Exception("crash"))
    def test_email_exception_returns_false(self, mock_send):
        """Returns False when send_raw_email throws."""
        result = _send_alert_email("admin@example.com", "Test reason")
        assert result is False


class TestResetAlertingState:
    @patch("regulatory_alerts.alerting._send_alert_email", return_value=True)
    def test_reset_clears_cooldown(self, mock_send, _default_settings):
        """reset_alerting_state() clears cooldown so alerts can send again."""
        _default_settings.ALERTING_ENABLED = True
        _default_settings.ALERT_EMAIL = "admin@example.com"

        scheduler_metrics.record_start()
        scheduler_metrics.record_failure(RuntimeError("boom"), 1.0)

        check_and_send_alerts()
        assert mock_send.call_count == 1

        # Without reset, cooldown blocks
        result = check_and_send_alerts()
        assert result is False

        # After reset, alert sends again
        reset_alerting_state()
        result = check_and_send_alerts()
        assert result is True
        assert mock_send.call_count == 2
