"""Tests for the notification system."""

from unittest.mock import patch, MagicMock

from regulatory_alerts.core.notifier import (
    _alert_matches_channel,
    _build_webhook_payload,
    _sign_payload,
    notify_new_alerts,
)
from regulatory_alerts.models import NotificationChannel, NotificationLog


class TestAlertMatchesChannel:
    def test_matches_when_no_filters(self, seed_alert, seed_document):
        channel = NotificationChannel(
            name="All", channel_type="webhook", webhook_url="http://example.com"
        )
        assert _alert_matches_channel(seed_alert, seed_document, channel) is True

    def test_filters_by_min_score(self, seed_alert, seed_document):
        channel = NotificationChannel(
            name="High", channel_type="webhook", webhook_url="http://example.com",
            min_relevance_score=0.99,
        )
        # seed_alert has score 0.95
        assert _alert_matches_channel(seed_alert, seed_document, channel) is False

    def test_passes_min_score(self, seed_alert, seed_document):
        channel = NotificationChannel(
            name="Med", channel_type="webhook", webhook_url="http://example.com",
            min_relevance_score=0.5,
        )
        assert _alert_matches_channel(seed_alert, seed_document, channel) is True

    def test_filters_by_agency(self, seed_alert, seed_document):
        channel = NotificationChannel(
            name="CFTC Only", channel_type="webhook", webhook_url="http://example.com",
            agency_filter="CFTC",
        )
        # seed_document is SEC
        assert _alert_matches_channel(seed_alert, seed_document, channel) is False

    def test_passes_agency_filter(self, seed_alert, seed_document):
        channel = NotificationChannel(
            name="SEC Only", channel_type="webhook", webhook_url="http://example.com",
            agency_filter="SEC",
        )
        assert _alert_matches_channel(seed_alert, seed_document, channel) is True

    def test_filters_by_topic(self, seed_alert, seed_document):
        channel = NotificationChannel(
            name="Crypto Only", channel_type="webhook", webhook_url="http://example.com",
            topic_filter='["crypto"]',
        )
        # seed_alert topics are enforcement, fraud, securities
        assert _alert_matches_channel(seed_alert, seed_document, channel) is False

    def test_passes_topic_filter(self, seed_alert, seed_document):
        channel = NotificationChannel(
            name="Enforcement", channel_type="webhook", webhook_url="http://example.com",
            topic_filter='["enforcement"]',
        )
        assert _alert_matches_channel(seed_alert, seed_document, channel) is True


class TestBuildWebhookPayload:
    def test_payload_structure(self, seed_alert, seed_document):
        payload = _build_webhook_payload(seed_alert, seed_document)

        assert payload["event"] == "new_alert"
        assert "alert" in payload
        assert "document" in payload
        assert "timestamp" in payload
        assert payload["document"]["agency"] == "SEC"
        assert payload["alert"]["relevance_score"] == 0.95


class TestSignPayload:
    def test_produces_hex(self):
        sig = _sign_payload(b'{"test": true}', "secret")
        assert len(sig) == 64  # SHA-256 hex

    def test_deterministic(self):
        s1 = _sign_payload(b"data", "key")
        s2 = _sign_payload(b"data", "key")
        assert s1 == s2

    def test_different_keys_differ(self):
        s1 = _sign_payload(b"data", "key1")
        s2 = _sign_payload(b"data", "key2")
        assert s1 != s2


class TestNotifyNewAlerts:
    @patch("regulatory_alerts.core.notifier._send_webhook")
    def test_sends_to_matching_channel(
        self, mock_send, db_session, seed_alert, seed_webhook_channel
    ):
        mock_send.return_value = (True, "")

        count = notify_new_alerts(db_session, [seed_alert])
        db_session.commit()

        assert count == 1
        mock_send.assert_called_once()

        # Check log was created
        logs = db_session.query(NotificationLog).all()
        assert len(logs) == 1
        assert logs[0].status == "sent"

    @patch("regulatory_alerts.core.notifier._send_webhook")
    def test_skips_disabled_channels(
        self, mock_send, db_session, seed_alert, seed_webhook_channel
    ):
        seed_webhook_channel.enabled = False
        db_session.commit()

        count = notify_new_alerts(db_session, [seed_alert])
        assert count == 0
        mock_send.assert_not_called()

    @patch("regulatory_alerts.core.notifier._send_webhook")
    def test_logs_failure(
        self, mock_send, db_session, seed_alert, seed_webhook_channel
    ):
        mock_send.return_value = (False, "Connection refused")

        count = notify_new_alerts(db_session, [seed_alert])
        db_session.commit()

        assert count == 0
        logs = db_session.query(NotificationLog).all()
        assert len(logs) == 1
        assert logs[0].status == "failed"
        assert "Connection refused" in logs[0].error_message

    @patch("regulatory_alerts.core.notifier._send_webhook")
    def test_idempotent(
        self, mock_send, db_session, seed_alert, seed_webhook_channel
    ):
        mock_send.return_value = (True, "")

        # Send once
        notify_new_alerts(db_session, [seed_alert])
        db_session.commit()

        # Send again — should be skipped
        count = notify_new_alerts(db_session, [seed_alert])
        assert count == 0
        assert mock_send.call_count == 1  # Only called once total

    def test_no_channels_returns_zero(self, db_session, seed_alert):
        count = notify_new_alerts(db_session, [seed_alert])
        assert count == 0
