"""Add subscribed_topics column to users table

Revision ID: 005
Revises: 004
Create Date: 2026-02-14
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "005"
down_revision: Union[str, None] = "004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Topic subscriptions: JSON list of topic strings.
    # NULL = "show all" (backward compat), "[]" = "explicitly subscribed to nothing".
    op.add_column("users", sa.Column("subscribed_topics", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "subscribed_topics")
