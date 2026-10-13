"""Baseline schema.

Creates every table from the models as they stood at release 1.0. Later schema
changes are ordinary incremental revisions:

    docker compose exec api alembic revision --autogenerate -m "describe the change"

Revision ID: 0001
Revises:
"""
from alembic import op

from app.models import Base

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)
    # Prefix lookups for indicator type-ahead.
    op.execute("CREATE INDEX IF NOT EXISTS ix_iocs_value_prefix ON iocs (value text_pattern_ops)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_documents_meta_tracker ON documents ((meta->>'tracker'))")


def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind())
