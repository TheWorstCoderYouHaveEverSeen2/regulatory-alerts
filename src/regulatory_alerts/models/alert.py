import json
from datetime import datetime
from decimal import Decimal
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Index, JSON, Numeric, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from regulatory_alerts.models.base import Base


class ProcessedAlert(Base):
    __tablename__ = "processed_alerts"
    __table_args__ = (
        Index("idx_alerts_relevance", "relevance_score"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    feed_document_id: Mapped[int] = mapped_column(
        ForeignKey("feed_documents.id"), unique=True, nullable=False
    )

    # AI-generated content
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    key_points: Mapped[Optional[str]] = mapped_column(JSON, nullable=True)
    topics: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON-encoded list
    relevance_score: Mapped[Optional[float]] = mapped_column(nullable=True)
    document_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # AI metadata
    ai_model: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    ai_cost_usd: Mapped[Optional[Decimal]] = mapped_column(
        Numeric(10, 6), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    feed_document: Mapped["FeedDocument"] = relationship(back_populates="alert")

    @property
    def topics_list(self) -> list[str]:
        """Deserialize topics from JSON string."""
        if not self.topics:
            return []
        if isinstance(self.topics, list):
            return self.topics
        try:
            return json.loads(self.topics)
        except (json.JSONDecodeError, TypeError):
            return []

    @topics_list.setter
    def topics_list(self, value: list[str]):
        self.topics = json.dumps(value) if value else None

    def __repr__(self) -> str:
        return f"<ProcessedAlert doc={self.feed_document_id} score={self.relevance_score}>"
