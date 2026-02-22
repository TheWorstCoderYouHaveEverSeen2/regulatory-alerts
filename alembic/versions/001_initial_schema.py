"""Initial schema: feed_sources, feed_documents, processed_alerts

Revision ID: 001
Revises:
Create Date: 2026-02-08
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "feed_sources",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("agency", sa.String(50), nullable=False),
        sa.Column("feed_url", sa.Text(), nullable=False),
        sa.Column("feed_type", sa.String(20), nullable=False, server_default="rss"),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true")),
        sa.Column("last_checked_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now()),
    )

    op.create_table(
        "feed_documents",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "feed_source_id",
            sa.Integer(),
            sa.ForeignKey("feed_sources.id"),
            nullable=False,
        ),
        sa.Column("external_id", sa.String(500), unique=True, nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=True),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("published_at", sa.DateTime(), nullable=False),
        sa.Column("discovered_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("agency", sa.String(50), nullable=False),
        sa.Column("document_type", sa.String(50), nullable=True),
        sa.Column("raw_summary", sa.Text(), nullable=True),
        sa.Column(
            "processing_status",
            sa.String(20),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("processed_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now()),
    )
    op.create_index("idx_feed_documents_status", "feed_documents", ["processing_status"])
    op.create_index("idx_feed_documents_published", "feed_documents", ["published_at"])
    op.create_index("idx_feed_documents_agency", "feed_documents", ["agency"])

    op.create_table(
        "processed_alerts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "feed_document_id",
            sa.Integer(),
            sa.ForeignKey("feed_documents.id"),
            unique=True,
            nullable=False,
        ),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("key_points", sa.JSON(), nullable=True),
        sa.Column("topics", sa.Text(), nullable=True),  # JSON-encoded list
        sa.Column("relevance_score", sa.Float(), nullable=True),
        sa.Column("document_type", sa.String(50), nullable=True),
        sa.Column("ai_model", sa.String(50), nullable=True),
        sa.Column("ai_cost_usd", sa.Numeric(10, 6), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
    )
    op.create_index("idx_alerts_relevance", "processed_alerts", ["relevance_score"])


def downgrade() -> None:
    op.drop_table("processed_alerts")
    op.drop_table("feed_documents")
    op.drop_table("feed_sources")
