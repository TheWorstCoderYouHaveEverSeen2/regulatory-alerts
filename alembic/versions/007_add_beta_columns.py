"""Add enabled column to notification_channels, is_founding_member and beta_enrolled_at to users

Revision ID: 007
Revises: 006
Create Date: 2026-02-19
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "007"
down_revision: Union[str, None] = "006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Sprint 8 feature: enabled column on notification_channels (was missing migration)
    op.add_column("notification_channels", sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"))

    # Sprint 9: Beta / founding member columns on users
    op.add_column("users", sa.Column("is_founding_member", sa.Boolean(), nullable=False, server_default="false"))
    op.add_column("users", sa.Column("beta_enrolled_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "beta_enrolled_at")
    op.drop_column("users", "is_founding_member")
    op.drop_column("notification_channels", "enabled")
