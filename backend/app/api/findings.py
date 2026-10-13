import difflib
import hashlib
import hmac
import json

from fastapi import APIRouter, Depends, HTTPException, Request
from opensearchpy.exceptions import OpenSearchException
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.api.common import finding_summary, get_document, iso, parse_uuid
from app.config import get_settings
from app.db import get_db
from app.extract.geo import country_name
from app.intel import attack, quality
from app.models import Exposure as ExposureRow
from app.extract.iocs import defang
from app.extract.lang import LANGUAGE_NAMES
from app.models import (FINDING_STATUSES, Alert, Case, CaseItem, Document, DocumentEntity, DocumentIoc, DocumentTag, DocumentVersion,
                        Entity, Ioc, Note, Rule, Tag, User, Watchlist)
from app.search import index as search_index
from app.search import service
from app.security import analyst, audit, viewer
from app.worker.ingest import evidence_chain, reindex_document

router = APIRouter(tags=["findings"])
settings = get_settings()


def _related(db: Session, doc: Document, limit: int = 8) -> list[dict]:
    """Findings connected to this one, most meaningful link first: the same victim
    or incident, then a shared uncommon indicator, then similar wording."""
    out: list[dict] = []
    seen = {doc.id}

    def add(other: Document, reason: str) -> None:
        if other.id not in seen and len(out) < limit:
            seen.add(other.id)
            out.append({**finding_summary(other), "reason": reason})

    labels = {"organization": "Same organisation", "incident": "Same incident", "campaign": "Same campaign"}
    mine = select(DocumentEntity.entity_id).join(Entity, Entity.id == DocumentEntity.entity_id).where(
        DocumentEntity.document_id == doc.id, Entity.type.in_(labels), Entity.doc_count <= 60)
    rows = db.execute(
        select(Document, Entity.type, Entity.name).join(DocumentEntity, DocumentEntity.document_id == Document.id)
        .join(Entity, Entity.id == DocumentEntity.entity_id)
        .where(DocumentEntity.entity_id.in_(mine), Document.id != doc.id)
        .order_by((Entity.type == "incident").desc(), Document.first_seen_at.desc()).limit(30)
    ).unique().all()
    for other, kind, name in rows:
        add(other, labels[kind] if kind == "incident" else f"{labels[kind]}: {name}")

    rare = select(DocumentIoc.ioc_id).join(Ioc, Ioc.id == DocumentIoc.ioc_id).where(
        DocumentIoc.document_id == doc.id, Ioc.doc_count.between(2, 25), Ioc.type != "username")
    rows = db.execute(
        select(Document, Ioc.type, Ioc.value).join(DocumentIoc, DocumentIoc.document_id == Document.id).join(Ioc, Ioc.id == DocumentIoc.ioc_id)
        .where(DocumentIoc.ioc_id.in_(rare), Document.id != doc.id).order_by(Ioc.doc_count, Document.first_seen_at.desc()).limit(30)
    ).unique().all()
    for other, kind, value in rows:
        add(other, f"Shares {kind}: {defang(value)}")

    if len(out) < limit and len(doc.content) > 800:
        try:
            ids = [parse_uuid(r["id"]) for r in service.related(str(doc.id), size=limit)]
        except OpenSearchException:
            ids = []
        for other in db.scalars(select(Document).where(Document.id.in_(ids))).unique() if ids else []:
            add(other, "Similar wording")
    return out


def _tags(db: Session, doc_id) -> list[str]:
    return list(db.scalars(select(Tag.name).join(DocumentTag, DocumentTag.tag_id == Tag.id).where(DocumentTag.document_id == doc_id).order_by(Tag.name)))


@router.get("/findings/{doc_id}")
def finding_detail(doc_id: str, db: Session = Depends(get_db), user: User = Depends(viewer)):
    doc = get_document(db, doc_id)
    iocs = db.execute(
        select(Ioc.id, Ioc.type, Ioc.value, Ioc.doc_count, DocumentIoc.count, DocumentIoc.context)
        .join(DocumentIoc, DocumentIoc.ioc_id == Ioc.id).where(DocumentIoc.document_id == doc.id).order_by(Ioc.type, DocumentIoc.count.desc()).limit(1000)
    ).all()
    entities = db.execute(
        select(Entity.id, Entity.type, Entity.name, Entity.doc_count, DocumentEntity.role, DocumentEntity.confidence)
        .join(DocumentEntity, DocumentEntity.entity_id == Entity.id).where(DocumentEntity.document_id == doc.id).order_by(Entity.type, Entity.name)
    ).all()
    versions = db.execute(
        select(DocumentVersion.version, DocumentVersion.captured_at, DocumentVersion.content_sha256, DocumentVersion.raw_sha256,
               DocumentVersion.chain_hash, DocumentVersion.http_status, DocumentVersion.bytes, DocumentVersion.change)
        .where(DocumentVersion.document_id == doc.id).order_by(DocumentVersion.version.desc())
    ).all()
    alerts = db.execute(
        select(Alert.id, Alert.category, Alert.severity, Alert.status, Alert.matched, Alert.created_at, func.coalesce(Watchlist.name, Rule.name, "Platform").label("name"))
        .outerjoin(Watchlist, Watchlist.id == Alert.watchlist_id).outerjoin(Rule, Rule.id == Alert.rule_id)
        .where(Alert.document_id == doc.id).order_by(Alert.created_at.desc())
    ).all()
    cases = db.execute(select(Case.id, Case.title, Case.status).join(CaseItem, CaseItem.case_id == Case.id)
                       .where(CaseItem.object_type == "finding", CaseItem.object_id == str(doc.id))).all()
    duplicates = db.scalars(select(Document).where(Document.duplicate_of == doc.id).limit(20)).unique().all()
    original = db.get(Document, doc.duplicate_of) if doc.duplicate_of else None
    related = _related(db, doc)

    return {
        **finding_summary(doc),
        "content": doc.content,
        "threat_types": doc.threat_types,
        "sectors": doc.sectors,
        "country_names": {c: country_name(c) for c in doc.countries},
        "risk_factors": doc.risk_factors,
        "exposure": doc.exposure,
        "meta": doc.meta,
        "last_changed": iso(doc.last_changed_at),
        "content_sha256": doc.content_sha256,
        "lang": doc.lang, "language": LANGUAGE_NAMES.get(doc.lang, ""),
        "verification": doc.verification,
        "verification_label": quality.VERIFICATION_LABELS.get(doc.verification, doc.verification),
        "corroboration": doc.corroboration,
        "admiralty": quality.admiralty(doc.source, doc.verification),
        "reliability_label": quality.RELIABILITY[quality.reliability(doc.source)],
        "techniques": [{"id": t, "name": attack.techniques().get(t, {}).get("name", t), "tactics": attack.techniques().get(t, {}).get("tactics", [])} for t in doc.techniques or []],
        "exposures": [{"id": x.id, "kind": x.kind, "identity": x.identity, "domain": x.domain, "service": x.service, "secret_type": x.secret_type,
                       "fingerprint": x.fingerprint, "password_exposed": x.password_exposed, "status": x.status}
                      for x in db.scalars(select(ExposureRow).where(ExposureRow.document_id == doc.id).order_by(ExposureRow.kind, ExposureRow.identity).limit(500))],
        "ai_summary": json.loads(doc.ai_summary) if doc.ai_summary else None,
        "raw_sha256": doc.raw_sha256,
        "source": {"id": doc.source.id, "name": doc.source.name, "category": doc.source.category, "trust": doc.source.trust,
                   "network": doc.source.network, "connector": doc.source.connector},
        "tags": _tags(db, doc.id),
        "iocs": [{"id": r.id, "type": r.type, "value": r.value, "doc_count": r.doc_count, "count": r.count, "context": r.context} for r in iocs],
        "entities": [{"id": r.id, "type": r.type, "name": r.name, "doc_count": r.doc_count, "role": r.role, "confidence": r.confidence} for r in entities],
        "versions": [{"version": r.version, "captured_at": iso(r.captured_at), "content_sha256": r.content_sha256, "raw_sha256": r.raw_sha256,
                      "chain_hash": r.chain_hash, "http_status": r.http_status, "bytes": r.bytes, "change": r.change} for r in versions],
        "alerts": [{"id": r.id, "category": r.category, "severity": r.severity, "status": r.status, "matched": r.matched,
                    "created_at": iso(r.created_at), "watchlist": r.name} for r in alerts],
        "cases": [{"id": r.id, "title": r.title, "status": r.status} for r in cases],
        "duplicate_of": finding_summary(original) if original else None,
        "duplicates": [finding_summary(d) for d in duplicates],
        "related": related,
    }


@router.get("/findings/{doc_id}/versions/{version}")
def finding_version(doc_id: str, version: int, db: Session = Depends(get_db), user: User = Depends(viewer)):
    doc = get_document(db, doc_id)
    row = db.scalar(select(DocumentVersion).where(DocumentVersion.document_id == doc.id, DocumentVersion.version == version))
    if row is None:
        raise HTTPException(404, "Version not found")
    return {"version": row.version, "captured_at": iso(row.captured_at), "title": row.title, "content": row.content, "url": row.url,
            "content_sha256": row.content_sha256, "raw_sha256": row.raw_sha256, "headers": row.headers, "change": row.change}


@router.get("/findings/{doc_id}/diff")
def finding_diff(doc_id: str, a: int, b: int, db: Session = Depends(get_db), user: User = Depends(viewer)):
    """Line diff between two captures of the same finding."""
    doc = get_document(db, doc_id)
    rows = {r.version: r for r in db.scalars(select(DocumentVersion).where(DocumentVersion.document_id == doc.id, DocumentVersion.version.in_((a, b))))}
    if a not in rows or b not in rows:
        raise HTTPException(404, "Version not found")
    old, new = rows[a].content.split("\n")[:6000], rows[b].content.split("\n")[:6000]
    lines = []
    for line in difflib.unified_diff(old, new, lineterm="", n=2):
        if line.startswith(("---", "+++")):
            continue
        kind = "hunk" if line.startswith("@@") else "add" if line.startswith("+") else "del" if line.startswith("-") else "ctx"
        lines.append({"kind": kind, "text": line if kind == "hunk" else line[1:]})
        if len(lines) >= 2000:
            break
    return {"a": {"version": a, "captured_at": iso(rows[a].captured_at)}, "b": {"version": b, "captured_at": iso(rows[b].captured_at)}, "lines": lines}


@router.get("/findings/{doc_id}/evidence")
def finding_evidence(doc_id: str, request: Request, db: Session = Depends(get_db), user: User = Depends(viewer)):
    """Evidence record for a finding, with the hash chain re-verified on every request."""
    doc = get_document(db, doc_id)
    versions = db.scalars(select(DocumentVersion).where(DocumentVersion.document_id == doc.id).order_by(DocumentVersion.version)).all()
    prev, intact, records = "", True, []
    for v in versions:
        expected_hash, expected_sig = evidence_chain(prev, doc.id, v.version, v.url, v.captured_at, v.raw_sha256, v.content_sha256)
        content_ok = hashlib.sha256(f"{v.title}\n{v.content}".encode("utf-8", "replace")).hexdigest() == v.content_sha256
        ok = v.prev_chain_hash == prev and hmac.compare_digest(expected_hash, v.chain_hash) and hmac.compare_digest(expected_sig, v.signature) and content_ok
        intact = intact and ok
        records.append({
            "version": v.version, "captured_at": iso(v.captured_at), "url": v.url, "http_status": v.http_status, "response_headers": v.headers,
            "bytes": v.bytes, "raw_sha256": v.raw_sha256, "content_sha256": v.content_sha256, "prev_chain_hash": v.prev_chain_hash,
            "chain_hash": v.chain_hash, "hmac_sha256": v.signature, "verified": ok,
        })
        prev = v.chain_hash
    audit(db, request, user, "evidence.view", "finding", doc.id)
    db.commit()
    return {
        "finding_id": str(doc.id), "title": doc.title, "source": doc.source.name, "source_url": doc.source.url, "network": doc.network,
        "first_seen": iso(doc.first_seen_at), "last_seen": iso(doc.last_seen_at), "intact": intact, "captures": records,
        "method": "Each capture is chained: chain_hash = SHA-256(prev_chain_hash | finding | version | url | captured_at | raw_sha256 | content_sha256), "
                  "then signed with HMAC-SHA-256 using a key held outside the database. raw_sha256 covers the bytes as fetched; "
                  "content_sha256 covers the stored text" + (" after secrets were redacted." if settings.redact_secrets else "."),
    }


class FindingPatch(BaseModel):
    status: str | None = None
    tags: list[str] | None = Field(None, max_length=20)
    confirmed: bool | None = None  # analyst validation: True confirms, False withdraws it


@router.patch("/findings/{doc_id}")
def update_finding(doc_id: str, body: FindingPatch, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    doc = get_document(db, doc_id)
    if body.status is not None:
        if body.status not in FINDING_STATUSES:
            raise HTTPException(400, "Unknown status")
        doc.status = body.status
    if body.confirmed is not None:
        doc.verification = "confirmed" if body.confirmed else quality.verification_for(doc.source.trust, doc.corroboration)
    if body.tags is not None:
        names = sorted({t.strip().lower()[:64] for t in body.tags if t.strip()})
        db.execute(delete(DocumentTag).where(DocumentTag.document_id == doc.id))
        for name in names:
            db.execute(pg_insert(Tag).values(name=name).on_conflict_do_nothing(index_elements=["name"]))
            tag_id = db.scalar(select(Tag.id).where(Tag.name == name))
            db.execute(pg_insert(DocumentTag).values(document_id=doc.id, tag_id=tag_id).on_conflict_do_nothing())
    audit(db, request, user, "finding.update", "finding", doc.id, **body.model_dump(exclude_none=True))
    db.commit()
    try:
        search_index.update_fields(str(doc.id), {"status": doc.status, "tags": _tags(db, doc.id), "verification": doc.verification,
                                                 "admiralty": quality.admiralty(doc.source, doc.verification)}, refresh=True)
    except OpenSearchException:
        pass
    return {"ok": True, "status": doc.status, "tags": _tags(db, doc.id)}


class EntityLink(BaseModel):
    entity_id: int


@router.post("/findings/{doc_id}/entities")
def link_entity(doc_id: str, body: EntityLink, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    """Attach a finding to an entity by hand, e.g. to a campaign an analyst is tracking."""
    doc = get_document(db, doc_id)
    entity = db.get(Entity, body.entity_id)
    if entity is None:
        raise HTTPException(404, "Entity not found")
    inserted = db.execute(pg_insert(DocumentEntity).values(document_id=doc.id, entity_id=entity.id, role="mention", confidence=100)
                          .on_conflict_do_nothing().returning(DocumentEntity.entity_id)).first()
    if inserted:
        entity.doc_count += 1
        entity.first_seen_at = min(entity.first_seen_at or doc.first_seen_at, doc.first_seen_at)
        entity.last_seen_at = max(entity.last_seen_at or doc.first_seen_at, doc.first_seen_at)
    audit(db, request, user, "finding.link_entity", "finding", doc.id, entity_id=entity.id)
    db.commit()
    reindex_document(db, doc, refresh=True)
    return {"ok": True}


@router.delete("/findings/{doc_id}/entities/{entity_id}")
def unlink_entity(doc_id: str, entity_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    doc = get_document(db, doc_id)
    removed = db.execute(delete(DocumentEntity).where(DocumentEntity.document_id == doc.id, DocumentEntity.entity_id == entity_id)).rowcount
    if removed and (entity := db.get(Entity, entity_id)):
        entity.doc_count = max(0, entity.doc_count - 1)
    audit(db, request, user, "finding.unlink_entity", "finding", doc.id, entity_id=entity_id)
    db.commit()
    reindex_document(db, doc, refresh=True)
    return {"ok": True}


class NoteIn(BaseModel):
    object_type: str
    object_id: str = Field(max_length=64)
    body: str = Field(min_length=1, max_length=10000)


@router.get("/notes")
def list_notes(object_type: str, object_id: str, db: Session = Depends(get_db), user: User = Depends(viewer)):
    rows = db.scalars(select(Note).where(Note.object_type == object_type, Note.object_id == object_id).order_by(Note.created_at.desc())).all()
    return [{"id": n.id, "body": n.body, "user_id": n.user_id, "user_name": n.user_name, "created_at": iso(n.created_at)} for n in rows]


@router.post("/notes")
def add_note(body: NoteIn, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    if body.object_type not in ("finding", "case", "entity", "ioc", "source"):
        raise HTTPException(400, "Unknown object type")
    note = Note(object_type=body.object_type, object_id=body.object_id, user_id=user.id, user_name=user.name or user.email, body=body.body.strip())
    db.add(note)
    audit(db, request, user, "note.add", body.object_type, body.object_id)
    db.commit()
    return {"id": note.id}


@router.delete("/notes/{note_id}")
def delete_note(note_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    note = db.get(Note, note_id)
    if note is None:
        raise HTTPException(404, "Not found")
    if note.user_id != user.id and user.role != "admin":
        raise HTTPException(403, "Only the author or an admin can delete a note")
    audit(db, request, user, "note.delete", note.object_type, note.object_id)
    db.delete(note)
    db.commit()
    return {"ok": True}
