"""Add Stripe billing columns to users and stripe_events table

Revision ID: 004
Revises: 003
Create Date: 2026-02-14
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Stripe billing columns on users
    op.add_column("users", sa.Column("stripe_customer_id", sa.String(255), nullable=True, unique=True))
    op.add_column("users", sa.Column("stripe_subscription_id", sa.String(255), nullable=True))
    op.add_column("users", sa.Column("subscription_tier", sa.String(50), nullable=False, server_default="free"))
    op.add_column("users", sa.Column("subscription_status", sa.String(50), nullable=True))
    op.add_column("users", sa.Column("tier_updated_at", sa.DateTime(), nullable=True))
    op.create_index("idx_users_stripe_customer_id", "users", ["stripe_customer_id"])

    # Stripe webhook idempotency table
    op.create_table(
        "stripe_events",
        sa.Column("id", sa.String(255), primary_key=True),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("processed_at", sa.DateTime(), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("stripe_events")
    op.drop_index("idx_users_stripe_customer_id", table_name="users")
    op.drop_column("users", "tier_updated_at")
    op.drop_column("users", "subscription_status")
    op.drop_column("users", "subscription_tier")
    op.drop_column("users", "stripe_subscription_id")
    op.drop_column("users", "stripe_customer_id")
