"""Shared helpers for API routers."""
import uuid
from datetime import datetime

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.extract.classify import THREAT_TYPES
from app.models import Document


def iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def parse_uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError:
        raise HTTPException(404, "Not found") from None


def get_document(db: Session, doc_id: str) -> Document:
    doc = db.get(Document, parse_uuid(doc_id))
    if doc is None:
        raise HTTPException(404, "Finding not found")
    return doc


def paginate(db: Session, stmt, page: int, size: int) -> tuple[list, int]:
    size = max(1, min(size, 200))
    page = max(1, page)
    total = db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery())) or 0
    rows = db.execute(stmt.limit(size).offset((page - 1) * size)).all()
    return rows, total


def finding_summary(doc: Document) -> dict:
    return {
        "id": str(doc.id), "title": doc.title, "summary": doc.summary, "url": doc.url, "host": doc.host,
        "network": doc.network, "source_id": doc.source_id, "source_name": doc.source.name,
        "threat_type": doc.threat_type, "threat_label": THREAT_TYPES.get(doc.threat_type, doc.threat_type),
        "severity": doc.severity, "risk_score": doc.risk_score, "confidence": doc.confidence, "countries": doc.countries,
        "has_credentials": doc.has_credentials, "status": doc.status, "first_seen": iso(doc.first_seen_at),
        "last_seen": iso(doc.last_seen_at), "published_at": iso(doc.published_at), "version_count": doc.version_count,
    }


def csv_safe(value):
    """Stop a spreadsheet from running a cell that begins like a formula. Empty cells stay empty."""
    return "'" + value if isinstance(value, str) and value[:1] in ("=", "+", "-", "@") else value
