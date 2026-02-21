from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from regulatory_alerts.models.base import Base, TimestampMixin


class FeedSource(Base, TimestampMixin):
    __tablename__ = "feed_sources"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    agency: Mapped[str] = mapped_column(String(50), nullable=False)
    feed_url: Mapped[str] = mapped_column(Text, nullable=False)
    feed_type: Mapped[str] = mapped_column(String(20), nullable=False, default="rss")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_checked_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    documents: Mapped[list["FeedDocument"]] = relationship(back_populates="feed_source")

    def __repr__(self) -> str:
        return f"<FeedSource {self.agency}: {self.name}>"


class FeedDocument(Base, TimestampMixin):
    __tablename__ = "feed_documents"
    __table_args__ = (
        Index("idx_feed_documents_status", "processing_status"),
        Index("idx_feed_documents_published", "published_at"),
        Index("idx_feed_documents_agency", "agency"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    feed_source_id: Mapped[int] = mapped_column(ForeignKey("feed_sources.id"), nullable=False)
    external_id: Mapped[str] = mapped_column(String(500), unique=True, nullable=False)
    content_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    published_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    agency: Mapped[str] = mapped_column(String(50), nullable=False)
    document_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    raw_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    processing_status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="pending"
    )
    processed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    feed_source: Mapped["FeedSource"] = relationship(back_populates="documents")
    alert: Mapped[Optional["ProcessedAlert"]] = relationship(back_populates="feed_document")

    def __repr__(self) -> str:
        return f"<FeedDocument {self.agency}: {self.title[:50]}>"
