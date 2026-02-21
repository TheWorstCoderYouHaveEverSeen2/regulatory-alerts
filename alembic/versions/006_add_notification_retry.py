"""Add retry_count and next_retry_at columns to notification_logs

Revision ID: 006
Revises: 005
Create Date: 2026-02-15
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "006"
down_revision: Union[str, None] = "005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("notification_logs", sa.Column("retry_count", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("notification_logs", sa.Column("next_retry_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column("notification_logs", "next_retry_at")
    op.drop_column("notification_logs", "retry_count")
