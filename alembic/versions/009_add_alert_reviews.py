"""Add alert_reviews table for compliance audit trail

Revision ID: 009
Revises: 008
Create Date: 2026-03-14
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "009"
down_revision: Union[str, None] = "008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "alert_reviews",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("alert_id", sa.Integer(), sa.ForeignKey("processed_alerts.id"), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="acknowledged"),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("idx_reviews_user_alert", "alert_reviews", ["user_id", "alert_id"])
    op.create_index("idx_reviews_user_date", "alert_reviews", ["user_id", "reviewed_at"])


def downgrade() -> None:
    op.drop_index("idx_reviews_user_date", table_name="alert_reviews")
    op.drop_index("idx_reviews_user_alert", table_name="alert_reviews")
    op.drop_table("alert_reviews")
