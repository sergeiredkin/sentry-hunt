"""add persistent application state

Revision ID: 8f2b7c1d9e41
Revises: 6cd7079d4a5c
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "8f2b7c1d9e41"
down_revision: Union[str, Sequence[str], None] = "6cd7079d4a5c"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "app_state",
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("key"),
    )


def downgrade() -> None:
    op.drop_table("app_state")
