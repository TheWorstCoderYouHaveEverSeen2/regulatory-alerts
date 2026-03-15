"""Audit trail model — tracks when a user reviews a regulatory alert.

Compliance officers need to document that they saw a filing and took action.
This model provides that audit trail: who reviewed what, when, what action
they took, and any notes for the compliance record.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from regulatory_alerts.models.base import Base


class AlertReview(Base):
    __tablename__ = "alert_reviews"
    __table_args__ = (
        Index("idx_reviews_user_alert", "user_id", "alert_id"),
        Index("idx_reviews_user_date", "user_id", "reviewed_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"), nullable=False
    )
    alert_id: Mapped[int] = mapped_column(
        ForeignKey("processed_alerts.id"), nullable=False
    )

    # Review metadata
    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default="acknowledged"
    )  # acknowledged, escalated, no_action_required, action_taken
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    reviewed_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    # Relationships
    user: Mapped["User"] = relationship()
    alert: Mapped["ProcessedAlert"] = relationship()

    def __repr__(self) -> str:
        return f"<AlertReview user={self.user_id} alert={self.alert_id} status={self.status}>"
