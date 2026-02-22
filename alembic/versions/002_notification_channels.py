"""Add notification_channels and notification_logs tables

Revision ID: 002
Revises: 001
Create Date: 2026-02-08
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "notification_channels",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("channel_type", sa.String(20), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true")),
        sa.Column("webhook_url", sa.Text(), nullable=True),
        sa.Column("webhook_secret", sa.String(200), nullable=True),
        sa.Column("email_address", sa.String(255), nullable=True),
        sa.Column("min_relevance_score", sa.Float(), nullable=True),
        sa.Column("agency_filter", sa.String(50), nullable=True),
        sa.Column("topic_filter", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now()),
    )

    op.create_table(
        "notification_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "channel_id",
            sa.Integer(),
            sa.ForeignKey("notification_channels.id"),
            nullable=False,
        ),
        sa.Column(
            "alert_id",
            sa.Integer(),
            sa.ForeignKey("processed_alerts.id"),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.String(20),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("sent_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
    )
    op.create_index("idx_notif_logs_channel", "notification_logs", ["channel_id"])
    op.create_index("idx_notif_logs_alert", "notification_logs", ["alert_id"])
    op.create_index("idx_notif_logs_status", "notification_logs", ["status"])


def downgrade() -> None:
    op.drop_table("notification_logs")
    op.drop_table("notification_channels")
