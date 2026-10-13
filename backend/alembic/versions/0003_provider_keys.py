"""Provider API keys managed from the console, with their last connection test.

Additive and idempotent, like 0002.

Revision ID: 0003
Revises: 0002
"""
from alembic import op

from app.models import Base, ProviderKey

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    Base.metadata.create_all(bind=op.get_bind(), tables=[ProviderKey.__table__], checkfirst=True)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS provider_keys")
