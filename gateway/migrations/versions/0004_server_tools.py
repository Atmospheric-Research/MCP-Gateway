"""server tools cache

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-11 12:00:00
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0004'
down_revision: str | None = '0003'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table('servers') as batch_op:
        batch_op.add_column(sa.Column('tools', sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('servers') as batch_op:
        batch_op.drop_column('tools')
