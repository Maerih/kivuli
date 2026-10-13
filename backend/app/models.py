"""Relational schema. PostgreSQL is the system of record; OpenSearch is a derived index."""
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


TS = DateTime(timezone=True)

ROLES = ("viewer", "analyst", "admin")
SOURCE_STATUSES = ("candidate", "approved", "paused", "blocked")
SEVERITIES = ("info", "low", "medium", "high", "critical")
ALERT_STATUSES = ("open", "acknowledged", "resolved", "false_positive")
FINDING_STATUSES = ("new", "triaged", "escalated", "dismissed")
WATCH_KINDS = ("keyword", "domain", "email", "ip", "organization", "actor", "cve", "hash", "crypto", "username",
               "brand", "technology", "vendor", "executive")
ENTITY_TYPES = ("actor", "organization", "malware", "campaign", "incident", "technique")
VERIFICATION = ("unverified", "reported", "corroborated", "confirmed")
RELATIONSHIP_KINDS = ("uses", "targets", "attributed_to", "exploits", "delivers", "related_to")
EXPOSURE_KINDS = ("credential", "stealer_log", "api_key", "token", "private_key", "cloud_secret", "card")
EXPOSURE_STATUSES = ("open", "remediated", "ignored", "false_positive")
RULE_KINDS = ("query", "threshold", "spike")
INTEGRATION_KINDS = ("webhook", "slack", "teams", "splunk_hec", "jira", "servicenow")


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True)
    name: Mapped[str] = mapped_column(String(120), default="")
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="analyst")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    created_at: Mapped[datetime] = mapped_column(TS, default=utcnow)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    mfa_secret: Mapped[str] = mapped_column(Text, default="", server_default="")  # encrypted
    recovery_codes: Mapped[list[str]] = mapped_column(ARRAY(String(64)), default=list, server_default="{}")  # hashed


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    ts: Mapped[datetime] = mapped_column(TS, default=utcnow, index=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    user_email: Mapped[str] = mapped_column(String(254), default="")
    action: Mapped[str] = mapped_column(String(64), index=True)
    object_type: Mapped[str] = mapped_column(String(32), default="")
    object_id: Mapped[str] = mapped_column(String(64), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    detail: Mapped[dict] = mapped_column(JSONB, default=dict)


class Source(Base):
    __tablename__ = "sources"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    url: Mapped[str] = mapped_column(String(1024), unique=True)
    host: Mapped[str] = mapped_column(String(255), index=True)
    network: Mapped[str] = mapped_column(String(16))  # onion | surface
    connector: Mapped[str] = mapped_column(String(32), default="html")
    route: Mapped[str] = mapped_column(String(16), default="tor")  # tor | direct
    category: Mapped[str] = mapped_column(String(32), default="other")
    status: Mapped[str] = mapped_column(String(16), default="candidate", index=True)
    trust: Mapped[int] = mapped_column(Integer, default=50)
    reliability: Mapped[str] = mapped_column(String(1), default="", server_default="")  # Admiralty A-F; empty = derive from trust
    crawl_interval_minutes: Mapped[int] = mapped_column(Integer, default=360)
    max_depth: Mapped[int] = mapped_column(Integer, default=1)
    max_pages: Mapped[int] = mapped_column(Integer, default=25)
    config: Mapped[dict] = mapped_column(JSONB, default=dict)
    is_live: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    last_live_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    last_crawled_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    last_http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_error: Mapped[str] = mapped_column(Text, default="")
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    doc_count: Mapped[int] = mapped_column(Integer, default=0)
    discovered_from_id: Mapped[int | None] = mapped_column(ForeignKey("sources.id", ondelete="SET NULL"), nullable=True)
    discovery_context: Mapped[str] = mapped_column(Text, default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    title: Mapped[str] = mapped_column(Text, default="", server_default="")  # what the site calls itself, read when it was first checked
    language: Mapped[str] = mapped_column(String(8), default="", server_default="")
    relevance: Mapped[int] = mapped_column(Integer, default=0, server_default="0")  # security-research relevance of the landing page, 0-10
    last_changed_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)  # last time a crawl found new or changed pages
    created_by: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(TS, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(TS, default=utcnow, onupdate=utcnow)


class CrawlLog(Base):
    __tablename__ = "crawl_log"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id", ondelete="CASCADE"), index=True)
    url: Mapped[str] = mapped_column(String(2048))
    depth: Mapped[int] = mapped_column(Integer, default=0)
    probe: Mapped[bool] = mapped_column(Boolean, default=False)
    fetched_at: Mapped[datetime] = mapped_column(TS, default=utcnow, index=True)
    ok: Mapped[bool] = mapped_column(Boolean, default=False)
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    bytes: Mapped[int] = mapped_column(Integer, default=0)
    elapsed_ms: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default="")
    new_docs: Mapped[int] = mapped_column(Integer, default=0)
    changed_docs: Mapped[int] = mapped_column(Integer, default=0)
    unchanged_docs: Mapped[int] = mapped_column(Integer, default=0)
    dropped_docs: Mapped[int] = mapped_column(Integer, default=0)
    parent_url: Mapped[str] = mapped_column(String(2048), default="", server_default="")  # the page whose link led here


class Document(Base):
    """A finding: one page, post or feed item, tracked across every capture."""

    __tablename__ = "documents"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    doc_key: Mapped[str] = mapped_column(String(64), unique=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id", ondelete="CASCADE"), index=True)
    url: Mapped[str] = mapped_column(String(2048))
    host: Mapped[str] = mapped_column(String(255), default="")
    network: Mapped[str] = mapped_column(String(16), default="surface")
    title: Mapped[str] = mapped_column(Text, default="")
    summary: Mapped[str] = mapped_column(Text, default="")
    content: Mapped[str] = mapped_column(Text, default="")
    content_sha256: Mapped[str] = mapped_column(String(64), index=True)
    raw_sha256: Mapped[str] = mapped_column(String(64), default="")
    simhash: Mapped[int] = mapped_column(BigInteger, default=0)
    sh0: Mapped[int] = mapped_column(Integer, default=0)
    sh1: Mapped[int] = mapped_column(Integer, default=0)
    sh2: Mapped[int] = mapped_column(Integer, default=0)
    sh3: Mapped[int] = mapped_column(Integer, default=0)
    lang: Mapped[str] = mapped_column(String(8), default="")
    threat_type: Mapped[str] = mapped_column(String(32), default="other", index=True)
    threat_types: Mapped[list[str]] = mapped_column(ARRAY(String(32)), default=list)
    severity: Mapped[str] = mapped_column(String(16), default="info", index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    risk_factors: Mapped[list] = mapped_column(JSONB, default=list)
    confidence: Mapped[int] = mapped_column(Integer, default=0)
    countries: Mapped[list[str]] = mapped_column(ARRAY(String(2)), default=list)
    sectors: Mapped[list[str]] = mapped_column(ARRAY(String(64)), default=list)
    has_credentials: Mapped[bool] = mapped_column(Boolean, default=False)
    exposure: Mapped[dict] = mapped_column(JSONB, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="new", index=True)
    duplicate_of: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    first_seen_at: Mapped[datetime] = mapped_column(TS, default=utcnow, index=True)
    last_seen_at: Mapped[datetime] = mapped_column(TS, default=utcnow)
    last_changed_at: Mapped[datetime] = mapped_column(TS, default=utcnow)
    published_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    version_count: Mapped[int] = mapped_column(Integer, default=1)
    meta: Mapped[dict] = mapped_column(JSONB, default=dict)
    verification: Mapped[str] = mapped_column(String(16), default="unverified", server_default="unverified")
    corroboration: Mapped[int] = mapped_column(Integer, default=0, server_default="0")  # other independent sources
    techniques: Mapped[list[str]] = mapped_column(ARRAY(String(12)), default=list, server_default="{}")  # ATT&CK ids
    ai_summary: Mapped[str] = mapped_column(Text, default="", server_default="")

    source: Mapped[Source] = relationship(lazy="joined", innerjoin=True)

    __table_args__ = (
        Index("ix_documents_sh0", "sh0"),
        Index("ix_documents_sh1", "sh1"),
        Index("ix_documents_sh2", "sh2"),
        Index("ix_documents_sh3", "sh3"),
    )


class DocumentVersion(Base):
    """Immutable capture of a finding. Rows form a per-document hash chain."""

    __tablename__ = "document_versions"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    document_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("documents.id", ondelete="CASCADE"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    captured_at: Mapped[datetime] = mapped_column(TS, default=utcnow)
    url: Mapped[str] = mapped_column(String(2048), default="")
    title: Mapped[str] = mapped_column(Text, default="")
    content: Mapped[str] = mapped_column(Text, default="")
    content_sha256: Mapped[str] = mapped_column(String(64))
    raw_sha256: Mapped[str] = mapped_column(String(64), default="")
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    headers: Mapped[dict] = mapped_column(JSONB, default=dict)
    bytes: Mapped[int] = mapped_column(Integer, default=0)
    prev_chain_hash: Mapped[str] = mapped_column(String(64), default="")
    chain_hash: Mapped[str] = mapped_column(String(64), default="")
    signature: Mapped[str] = mapped_column(String(64), default="")
    change: Mapped[dict] = mapped_column(JSONB, default=dict)

    __table_args__ = (UniqueConstraint("document_id", "version"),)


class Ioc(Base):
    __tablename__ = "iocs"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    type: Mapped[str] = mapped_column(String(16), index=True)
    value: Mapped[str] = mapped_column(String(1024))
    first_seen_at: Mapped[datetime] = mapped_column(TS, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(TS, default=utcnow)
    doc_count: Mapped[int] = mapped_column(Integer, default=0)
    tags: Mapped[list[str]] = mapped_column(ARRAY(String(32)), default=list, server_default="{}")
    feeds: Mapped[list[str]] = mapped_column(ARRAY(String(80)), default=list, server_default="{}")  # threat feeds listing it
    benign: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")  # excluded from correlation

    __table_args__ = (UniqueConstraint("type", "value"),)


class DocumentIoc(Base):
    __tablename__ = "document_iocs"
    document_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("documents.id", ondelete="CASCADE"), primary_key=True)
    ioc_id: Mapped[int] = mapped_column(ForeignKey("iocs.id", ondelete="CASCADE"), primary_key=True, index=True)
    count: Mapped[int] = mapped_column(Integer, default=1)
    context: Mapped[str] = mapped_column(Text, default="")


class Entity(Base):
    __tablename__ = "entities"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    type: Mapped[str] = mapped_column(String(16), index=True)
    name: Mapped[str] = mapped_column(String(300))
    slug: Mapped[str] = mapped_column(String(300))
    aliases: Mapped[list[str]] = mapped_column(ARRAY(String(300)), default=list)
    description: Mapped[str] = mapped_column(Text, default="")
    curated: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    doc_count: Mapped[int] = mapped_column(Integer, default=0)
    meta: Mapped[dict] = mapped_column(JSONB, default=dict)

    __table_args__ = (UniqueConstraint("type", "slug"),)


class DocumentEntity(Base):
    __tablename__ = "document_entities"
    document_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("documents.id", ondelete="CASCADE"), primary_key=True)
    entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"), primary_key=True, index=True)
    role: Mapped[str] = mapped_column(String(16), default="mention")  # mention | actor | victim
    confidence: Mapped[int] = mapped_column(Integer, default=60)


class Watchlist(Base):
    __tablename__ = "watchlists"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text, default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    min_severity: Mapped[str] = mapped_column(String(16), default="info")
    notify_mode: Mapped[str] = mapped_column(String(16), default="immediate")  # immediate | digest | none
    recipients: Mapped[list[str]] = mapped_column(ARRAY(String(254)), default=list)
    match_count: Mapped[int] = mapped_column(Integer, default=0)
    last_matched_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    created_by: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(TS, default=utcnow)
    # Asset inventory: an entry the organisation owns, and how much it matters (1 low - 5 crown jewel).
    is_asset: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    criticality: Mapped[int] = mapped_column(Integer, default=3, server_default="3")
    org: Mapped[str] = mapped_column(String(120), default="", server_default="")
    last_scanned_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    watchlist_id: Mapped[int | None] = mapped_column(ForeignKey("watchlists.id", ondelete="CASCADE"), index=True, nullable=True)
    document_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("documents.id", ondelete="CASCADE"), index=True, nullable=True)
    rule_id: Mapped[int | None] = mapped_column(ForeignKey("rules.id", ondelete="CASCADE"), index=True, nullable=True)
    title: Mapped[str] = mapped_column(Text, default="", server_default="")
    priority: Mapped[int] = mapped_column(Integer, default=0, server_default="0", index=True)
    factors: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    dedupe_key: Mapped[str | None] = mapped_column(String(80), nullable=True)
    detail: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    # compromise | mention | rule | attack_surface | exposure | vulnerability | lookalike
    category: Mapped[str] = mapped_column(String(16), default="mention")
    reason: Mapped[str] = mapped_column(String(16), default="new")  # new | changed | retro
    matched: Mapped[str] = mapped_column(Text, default="")
    snippet: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), default="medium", index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    assigned_to: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(TS, default=utcnow, index=True)
    notified_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)

    watchlist: Mapped[Watchlist | None] = relationship(lazy="joined")
    document: Mapped[Document | None] = relationship(lazy="joined")
    rule: Mapped["Rule | None"] = relationship(lazy="joined")

    __table_args__ = (UniqueConstraint("watchlist_id", "document_id"), UniqueConstraint("dedupe_key", name="uq_alerts_dedupe_key"))


class Case(Base):
    __tablename__ = "cases"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(16), default="open")  # open | in_progress | closed
    priority: Mapped[str] = mapped_column(String(16), default="medium")
    tlp: Mapped[str] = mapped_column(String(16), default="amber")
    owner_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_by: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(TS, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(TS, default=utcnow, onupdate=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)


class CaseItem(Base):
    __tablename__ = "case_items"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    object_type: Mapped[str] = mapped_column(String(16))  # finding | ioc | entity
    object_id: Mapped[str] = mapped_column(String(64))
    note: Mapped[str] = mapped_column(Text, default="")
    added_by: Mapped[int | None] = mapped_column(Integer, nullable=True)
    added_at: Mapped[datetime] = mapped_column(TS, default=utcnow)

    __table_args__ = (UniqueConstraint("case_id", "object_type", "object_id"),)


class Note(Base):
    __tablename__ = "notes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    object_type: Mapped[str] = mapped_column(String(16))  # finding | case | entity | ioc | source
    object_id: Mapped[str] = mapped_column(String(64))
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    user_name: Mapped[str] = mapped_column(String(120), default="")
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(TS, default=utcnow)

    __table_args__ = (Index("ix_notes_object", "object_type", "object_id"),)


class Tag(Base):
    __tablename__ = "tags"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)


class DocumentTag(Base):
    __tablename__ = "document_tags"
    document_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("documents.id", ondelete="CASCADE"), primary_key=True)
    tag_id: Mapped[int] = mapped_column(ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True, index=True)


class SavedSearch(Base):
    __tablename__ = "saved_searches"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    query: Mapped[str] = mapped_column(Text, default="")
    params: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(TS, default=utcnow)


class EmailLog(Base):
    __tablename__ = "email_log"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    ts: Mapped[datetime] = mapped_column(TS, default=utcnow, index=True)
    kind: Mapped[str] = mapped_column(String(16), default="alert")  # alert | digest | test
    recipients: Mapped[list[str]] = mapped_column(ARRAY(String(254)), default=list)
    subject: Mapped[str] = mapped_column(Text, default="")
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    ok: Mapped[bool] = mapped_column(Boolean, default=True)
    error: Mapped[str] = mapped_column(Text, default="")


# ── Release 1.1 ─────────────────────────────────────────────────────────────


class Relationship(Base):
    """A typed, sourced edge between two entities (actor uses technique, ...)."""

    __tablename__ = "relationships"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    src_id: Mapped[int] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"), index=True)
    dst_id: Mapped[int] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(24))
    confidence: Mapped[int] = mapped_column(Integer, default=70)
    source: Mapped[str] = mapped_column(String(120), default="")  # provenance: "MITRE ATT&CK", "analyst:<email>", ...
    first_seen_at: Mapped[datetime] = mapped_column(TS, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(TS, default=utcnow)
    meta: Mapped[dict] = mapped_column(JSONB, default=dict)

    __table_args__ = (UniqueConstraint("src_id", "dst_id", "kind"),)


class Exposure(Base):
    """One exposed identity or secret seen in a finding. The secret itself is never stored."""

    __tablename__ = "exposures"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    document_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("documents.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(16), index=True)
    identity: Mapped[str] = mapped_column(String(320), default="")  # mailbox or username
    domain: Mapped[str] = mapped_column(String(255), default="", index=True)  # mailbox domain or service host
    service: Mapped[str] = mapped_column(String(255), default="")  # where the credential is used
    secret_type: Mapped[str] = mapped_column(String(40), default="")
    fingerprint: Mapped[str] = mapped_column(String(24), default="")  # SHA-256 prefix: lets an owner confirm a match
    password_exposed: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    first_seen_at: Mapped[datetime] = mapped_column(TS, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(TS, default=utcnow)

    document: Mapped[Document] = relationship(lazy="joined")

    __table_args__ = (UniqueConstraint("document_id", "kind", "identity", "service", "fingerprint"),)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    cve: Mapped[str] = mapped_column(String(24), primary_key=True)
    title: Mapped[str] = mapped_column(Text, default="")
    vendor: Mapped[str] = mapped_column(String(200), default="")
    product: Mapped[str] = mapped_column(String(200), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str] = mapped_column(String(120), default="")
    epss: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    kev: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    kev_added: Mapped[datetime | None] = mapped_column(Date, nullable=True)
    kev_due: Mapped[datetime | None] = mapped_column(Date, nullable=True)
    ransomware_use: Mapped[bool] = mapped_column(Boolean, default=False)
    mention_count: Mapped[int] = mapped_column(Integer, default=0)
    last_mentioned_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    exposed_assets: Mapped[int] = mapped_column(Integer, default=0)
    priority: Mapped[int] = mapped_column(Integer, default=0, index=True)
    priority_factors: Mapped[list] = mapped_column(JSONB, default=list)
    enriched_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(TS, default=utcnow, onupdate=utcnow)


class Asset(Base):
    """An internet-facing host discovered passively for an owned domain or range."""

    __tablename__ = "assets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    watchlist_id: Mapped[int] = mapped_column(ForeignKey("watchlists.id", ondelete="CASCADE"), index=True)
    host: Mapped[str] = mapped_column(String(255))
    ips: Mapped[list[str]] = mapped_column(ARRAY(String(45)), default=list)
    ports: Mapped[list[int]] = mapped_column(ARRAY(Integer), default=list)
    cpes: Mapped[list[str]] = mapped_column(ARRAY(String(200)), default=list)
    tags: Mapped[list[str]] = mapped_column(ARRAY(String(40)), default=list)
    vulns: Mapped[list[str]] = mapped_column(ARRAY(String(24)), default=list)
    asn: Mapped[str] = mapped_column(String(160), default="")
    discovered_via: Mapped[str] = mapped_column(String(40), default="")
    risk: Mapped[int] = mapped_column(Integer, default=0, index=True)
    risk_factors: Mapped[list] = mapped_column(JSONB, default=list)
    first_seen_at: Mapped[datetime] = mapped_column(TS, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(TS, default=utcnow)
    last_scanned_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    meta: Mapped[dict] = mapped_column(JSONB, default=dict)

    watchlist: Mapped[Watchlist] = relationship(lazy="joined")

    __table_args__ = (UniqueConstraint("watchlist_id", "host"),)


class Enrichment(Base):
    """What a third-party provider said about an indicator. The indicator itself is never contacted."""

    __tablename__ = "enrichments"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    subject_type: Mapped[str] = mapped_column(String(16))
    subject: Mapped[str] = mapped_column(String(1024))
    provider: Mapped[str] = mapped_column(String(32))
    fetched_at: Mapped[datetime] = mapped_column(TS, default=utcnow)
    ok: Mapped[bool] = mapped_column(Boolean, default=True)
    verdict: Mapped[str] = mapped_column(String(16), default="unknown")  # malicious | suspicious | clean | unknown
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    summary: Mapped[dict] = mapped_column(JSONB, default=dict)
    error: Mapped[str] = mapped_column(Text, default="")

    __table_args__ = (UniqueConstraint("subject_type", "subject", "provider"),)


class Rule(Base):
    """A detection rule over the intelligence stream: any search can become an alert."""

    __tablename__ = "rules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(16), default="query")
    query: Mapped[str] = mapped_column(Text, default="")
    threshold: Mapped[int] = mapped_column(Integer, default=5)
    window_hours: Mapped[int] = mapped_column(Integer, default=24)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    notify_mode: Mapped[str] = mapped_column(String(16), default="immediate")
    recipients: Mapped[list[str]] = mapped_column(ARRAY(String(254)), default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    match_count: Mapped[int] = mapped_column(Integer, default=0)
    last_run_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    last_triggered_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    created_by: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(TS, default=utcnow)


class Integration(Base):
    """An outbound destination for alerts: webhook, chat, SIEM or ticketing."""

    __tablename__ = "integrations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    kind: Mapped[str] = mapped_column(String(24))
    url: Mapped[str] = mapped_column(String(1024), default="")
    config: Mapped[dict] = mapped_column(JSONB, default=dict)  # non-secret settings
    secret: Mapped[str] = mapped_column(Text, default="")  # encrypted; never returned by the API
    min_severity: Mapped[str] = mapped_column(String(16), default="high")
    categories: Mapped[list[str]] = mapped_column(ARRAY(String(16)), default=list)  # empty = all
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_delivery_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    last_error: Mapped[str] = mapped_column(Text, default="")
    failures: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(TS, default=utcnow)


class AppSetting(Base):
    """A setting an administrator changes in the console (collection policy and limits)."""

    __tablename__ = "app_settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(JSONB, default=dict)
    updated_by: Mapped[int | None] = mapped_column(Integer, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(TS, default=utcnow)


CRAWL_JOB_STATUSES = ("running", "done", "stopped", "failed")


class CrawlJob(Base):
    """A research crawl a researcher started from one URL: its limits, who asked, and how it ended."""

    __tablename__ = "crawl_jobs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id", ondelete="CASCADE"), index=True)
    url: Mapped[str] = mapped_column(String(2048))
    run_id: Mapped[str] = mapped_column(String(36), unique=True)
    depth: Mapped[int] = mapped_column(Integer, default=1)
    max_pages: Mapped[int] = mapped_column(Integer, default=50)
    status: Mapped[str] = mapped_column(String(16), default="running", index=True)
    note: Mapped[str] = mapped_column(Text, default="")
    case_id: Mapped[int | None] = mapped_column(Integer, nullable=True)  # the investigation it was started for
    created_by: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(TS, default=utcnow, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)

    source: Mapped["Source"] = relationship(lazy="joined", innerjoin=True)


class SourceLink(Base):
    """Source A links to host B: the map of which dark-web sites reference which."""

    __tablename__ = "source_links"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    src_source_id: Mapped[int] = mapped_column(ForeignKey("sources.id", ondelete="CASCADE"), index=True)
    dst_host: Mapped[str] = mapped_column(String(255), index=True)
    first_seen_at: Mapped[datetime] = mapped_column(TS, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(TS, default=utcnow)
    count: Mapped[int] = mapped_column(Integer, default=1)

    __table_args__ = (UniqueConstraint("src_source_id", "dst_host", name="uq_source_links_pair"),)


class ProviderKey(Base):
    """An enrichment or AI provider configured from the console: its API key (encrypted), settings and last connection test."""

    __tablename__ = "provider_keys"
    name: Mapped[str] = mapped_column(String(32), primary_key=True)
    secret: Mapped[str] = mapped_column(Text, default="")  # encrypted with PROVIDER_KEYS_KEY; never returned by the API
    hint: Mapped[str] = mapped_column(String(8), default="")  # last characters, to recognise which key is in use
    config: Mapped[dict] = mapped_column(JSONB, default=dict)  # non-secret settings, e.g. the AI model
    updated_by: Mapped[int | None] = mapped_column(Integer, nullable=True)
    updated_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    last_test_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    last_test_ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    last_test_message: Mapped[str] = mapped_column(Text, default="")
    last_test_detail: Mapped[dict] = mapped_column(JSONB, default=dict)


class Delivery(Base):
    __tablename__ = "deliveries"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    integration_id: Mapped[int] = mapped_column(ForeignKey("integrations.id", ondelete="CASCADE"), index=True)
    alert_id: Mapped[int | None] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), nullable=True)
    ts: Mapped[datetime] = mapped_column(TS, default=utcnow, index=True)
    ok: Mapped[bool] = mapped_column(Boolean, default=False)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str] = mapped_column(Text, default="")

    __table_args__ = (UniqueConstraint("integration_id", "alert_id"),)


class ApiKey(Base):
    __tablename__ = "api_keys"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    prefix: Mapped[str] = mapped_column(String(16), index=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    scopes: Mapped[list[str]] = mapped_column(ARRAY(String(16)), default=list)  # read | write
    created_at: Mapped[datetime] = mapped_column(TS, default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
