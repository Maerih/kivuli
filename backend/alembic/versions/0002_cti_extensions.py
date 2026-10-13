"""Release 1.1: exposure, vulnerability, attack-surface, enrichment, rules,
integrations, API keys, typed relationships, verification state and MFA.

Additive only. Every statement is idempotent, because the baseline revision
creates tables from the current models: on a fresh database the new tables and
columns already exist by the time this runs.

Revision ID: 0002
Revises: 0001
"""
from alembic import op

from app.models import ApiKey, Asset, Base, Delivery, Enrichment, Exposure, Integration, Relationship, Rule, Vulnerability

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

_COLUMNS = {
    "users": ["mfa_enabled boolean NOT NULL DEFAULT false", "mfa_secret text NOT NULL DEFAULT ''", "recovery_codes varchar(64)[] NOT NULL DEFAULT '{}'"],
    "sources": ["reliability varchar(1) NOT NULL DEFAULT ''"],
    "documents": ["verification varchar(16) NOT NULL DEFAULT 'unverified'", "corroboration integer NOT NULL DEFAULT 0",
                  "techniques varchar(12)[] NOT NULL DEFAULT '{}'", "ai_summary text NOT NULL DEFAULT ''"],
    "iocs": ["tags varchar(32)[] NOT NULL DEFAULT '{}'", "feeds varchar(80)[] NOT NULL DEFAULT '{}'", "benign boolean NOT NULL DEFAULT false"],
    "watchlists": ["is_asset boolean NOT NULL DEFAULT false", "criticality integer NOT NULL DEFAULT 3", "org varchar(120) NOT NULL DEFAULT ''",
                   "last_scanned_at timestamptz"],
    "alerts": ["rule_id integer", "title text NOT NULL DEFAULT ''", "priority integer NOT NULL DEFAULT 0", "factors jsonb NOT NULL DEFAULT '[]'",
               "dedupe_key varchar(80)", "detail jsonb NOT NULL DEFAULT '{}'"],
}


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind, tables=[t.__table__ for t in (
        Rule, Relationship, Exposure, Vulnerability, Asset, Enrichment, Integration, Delivery, ApiKey)], checkfirst=True)
    for table, columns in _COLUMNS.items():
        for column in columns:
            op.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column}")

    # Alerts can now come from a rule or from the attack surface, with no watchlist or finding behind them.
    op.execute("ALTER TABLE alerts ALTER COLUMN watchlist_id DROP NOT NULL")
    op.execute("ALTER TABLE alerts ALTER COLUMN document_id DROP NOT NULL")
    op.execute("""
        DO $$ BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'alerts_rule_id_fkey') THEN
                ALTER TABLE alerts ADD CONSTRAINT alerts_rule_id_fkey FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE;
            END IF;
            IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_alerts_dedupe_key') THEN
                ALTER TABLE alerts ADD CONSTRAINT uq_alerts_dedupe_key UNIQUE (dedupe_key);
            END IF;
        END $$;
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_alerts_rule_id ON alerts (rule_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_alerts_priority ON alerts (priority)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_documents_techniques ON documents USING gin (techniques)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_iocs_feeds ON iocs USING gin (feeds)")

    # Existing findings from established sources were "reported", not "unverified".
    op.execute("""
        UPDATE documents d SET verification = 'reported'
        FROM sources s WHERE s.id = d.source_id AND s.trust >= 60 AND d.verification = 'unverified'
    """)
    # Existing alerts get a priority so the queue sorts sensibly before they are re-scored.
    op.execute("UPDATE alerts SET priority = risk_score WHERE priority = 0")


def downgrade() -> None:
    for table in ("deliveries", "integrations", "api_keys", "enrichments", "assets", "vulnerabilities", "exposures", "relationships"):
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
    op.execute("ALTER TABLE alerts DROP COLUMN IF EXISTS rule_id")
    op.execute("DROP TABLE IF EXISTS rules CASCADE")
    for table, columns in _COLUMNS.items():
        for column in columns:
            name = column.split()[0]
            if name != "rule_id":
                op.execute(f"ALTER TABLE {table} DROP COLUMN IF EXISTS {name}")
