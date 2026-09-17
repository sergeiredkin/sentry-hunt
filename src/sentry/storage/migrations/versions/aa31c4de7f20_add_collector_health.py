"""add collector health

Revision ID: aa31c4de7f20
Revises: 8f2b7c1d9e41
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sentry.storage.models import UTCDateTime

revision: str = "aa31c4de7f20"
down_revision: Union[str, Sequence[str], None] = "8f2b7c1d9e41"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "collector_health",
        sa.Column("collector_name", sa.String(length=64), nullable=False),
        sa.Column("last_started", UTCDateTime(), nullable=False),
        sa.Column("last_completed", UTCDateTime(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("observation_count", sa.Integer(), nullable=False, server_default="0"),
        sa.PrimaryKeyConstraint("collector_name"),
    )


def downgrade() -> None:
    op.drop_table("collector_health")
