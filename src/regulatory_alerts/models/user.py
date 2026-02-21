"""User model for session-based authentication, billing, and topic subscriptions."""

import json
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from regulatory_alerts.models.base import Base, TimestampMixin


class User(Base, TimestampMixin):
    __tablename__ = "users"
    __table_args__ = (
        Index("idx_users_email", "email"),
        Index("idx_users_api_key", "api_key"),
        Index("idx_users_stripe_customer_id", "stripe_customer_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    api_key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)

    # Stripe billing
    stripe_customer_id: Mapped[Optional[str]] = mapped_column(String(255), unique=True, nullable=True)
    stripe_subscription_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    subscription_tier: Mapped[str] = mapped_column(String(50), nullable=False, default="free")
    subscription_status: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    tier_updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Topic subscriptions: JSON list of topic strings.
    # NULL = "show all" (backward compat), "[]" = "explicitly subscribed to nothing".
    subscribed_topics: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default=None)

    # Beta / founding member tracking
    is_founding_member: Mapped[bool] = mapped_column(Boolean, default=False)
    beta_enrolled_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    channels: Mapped[list["NotificationChannel"]] = relationship(  # noqa: F821
        back_populates="user"
    )

    @property
    def subscribed_topics_list(self) -> list[str] | None:
        """Parse subscribed_topics JSON into a list. Returns None if unset (show all)."""
        if self.subscribed_topics is None:
            return None
        try:
            result = json.loads(self.subscribed_topics)
            return result if isinstance(result, list) else None
        except (json.JSONDecodeError, TypeError):
            return None

    @subscribed_topics_list.setter
    def subscribed_topics_list(self, value: list[str] | None) -> None:
        """Set subscribed_topics from a list. None = show all."""
        if value is None:
            self.subscribed_topics = None
        else:
            self.subscribed_topics = json.dumps(value)

    def __repr__(self) -> str:
        return f"<User {self.email}>"
