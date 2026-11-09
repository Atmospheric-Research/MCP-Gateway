"""server kind and url

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-03 12:00:00
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0002'
down_revision: str | None = '0001'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table('servers') as batch_op:
        batch_op.add_column(sa.Column('kind', sa.String(length=16), server_default='uv', nullable=False))
        batch_op.add_column(sa.Column('url', sa.String(length=2048), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('servers') as batch_op:
        batch_op.drop_column('url')
        batch_op.drop_column('kind')
