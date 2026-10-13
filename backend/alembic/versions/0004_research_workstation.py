"""Dark-web research workstation: research crawls, source link map, console-managed
collection settings, and what a source calls itself.

Additive and idempotent, like the revisions before it.

Revision ID: 0004
Revises: 0003
"""
from alembic import op

from app.models import AppSetting, Base, CrawlJob, SourceLink

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

_COLUMNS = {
    "sources": ["title text NOT NULL DEFAULT ''", "language varchar(8) NOT NULL DEFAULT ''", "relevance integer NOT NULL DEFAULT 0", "last_changed_at timestamptz"],
    "crawl_log": ["parent_url varchar(2048) NOT NULL DEFAULT ''"],
}


def upgrade() -> None:
    Base.metadata.create_all(bind=op.get_bind(), tables=[AppSetting.__table__, CrawlJob.__table__, SourceLink.__table__], checkfirst=True)
    for table, columns in _COLUMNS.items():
        for column in columns:
            op.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column}")
    op.execute("CREATE INDEX IF NOT EXISTS ix_crawl_log_url ON crawl_log (md5(url))")


def downgrade() -> None:
    for table in ("source_links", "crawl_jobs", "app_settings"):
        op.execute(f"DROP TABLE IF EXISTS {table}")
