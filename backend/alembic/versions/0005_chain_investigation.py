"""Blockchain investigation: looked-up addresses and the flows between them.

Additive and idempotent, like the revisions before it.

Revision ID: 0005
Revises: 0004
"""
from alembic import op

from app.models import Base, ChainAddress, ChainEdge

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    Base.metadata.create_all(bind=op.get_bind(), tables=[ChainAddress.__table__, ChainEdge.__table__], checkfirst=True)


def downgrade() -> None:
    for table in ("chain_edges", "chain_addresses"):
        op.execute(f"DROP TABLE IF EXISTS {table}")
