"""Notification channel configuration and delivery log.

Supports webhook (HTTP POST), Slack (incoming webhook), and email notification channels.
Each channel can filter by agency, minimum relevance score, and topics.
"""

import json
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from regulatory_alerts.models.base import Base, TimestampMixin


class NotificationChannel(Base, TimestampMixin):
    __tablename__ = "notification_channels"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    channel_type: Mapped[str] = mapped_column(
        String(20), nullable=False
    )  # "webhook", "slack", or "email"
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # Webhook config
    webhook_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    webhook_secret: Mapped[Optional[str]] = mapped_column(
        String(200), nullable=True
    )  # HMAC signing key

    # Email config
    email_address: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Owner (nullable for backward compat with pre-user channels)
    user_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )

    # Filters — if null/empty, no filtering (send everything)
    min_relevance_score: Mapped[Optional[float]] = mapped_column(
        Float, nullable=True
    )  # e.g. 0.7 = only high-relevance
    agency_filter: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )  # "SEC", "CFTC", or null for all
    topic_filter: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON list of topics, null = all

    user: Mapped[Optional["User"]] = relationship(back_populates="channels")  # noqa: F821
    logs: Mapped[list["NotificationLog"]] = relationship(back_populates="channel")

    @property
    def topic_filter_list(self) -> list[str]:
        if not self.topic_filter:
            return []
        try:
            return json.loads(self.topic_filter)
        except (json.JSONDecodeError, TypeError):
            return []

    @topic_filter_list.setter
    def topic_filter_list(self, value: list[str]):
        self.topic_filter = json.dumps(value) if value else None

    def __repr__(self) -> str:
        return f"<NotificationChannel {self.channel_type}: {self.name}>"


class NotificationLog(Base):
    __tablename__ = "notification_logs"
    __table_args__ = (
        Index("idx_notif_logs_channel", "channel_id"),
        Index("idx_notif_logs_alert", "alert_id"),
        Index("idx_notif_logs_status", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    channel_id: Mapped[int] = mapped_column(
        ForeignKey("notification_channels.id"), nullable=False
    )
    alert_id: Mapped[int] = mapped_column(
        ForeignKey("processed_alerts.id"), nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="pending"
    )  # pending, sent, failed
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    sent_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_retry_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    channel: Mapped["NotificationChannel"] = relationship(back_populates="logs")
    alert: Mapped["ProcessedAlert"] = relationship()
