"""MITRE ATT&CK views, typed relationships and entity resolution."""
from fastapi import APIRouter, Depends, HTTPException, Request
from opensearchpy.exceptions import OpenSearchException
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, aliased

from app.api.common import finding_summary, iso
from app.db import get_db
from app.intel import attack
from app.intel.relationships import merge_entities, upsert_relationship
from app.models import RELATIONSHIP_KINDS, Document, DocumentEntity, Entity, Relationship, User
from app.search import service
from app.security import analyst, audit, viewer
from app.worker.ingest import reindex_document

router = APIRouter(tags=["attack"])


@router.get("/attack/matrix")
def matrix(days: int = 90, db: Session = Depends(get_db), user: User = Depends(viewer)):
    """ATT&CK techniques by tactic, with how often each appears in collected intelligence."""
    data = attack.catalog()
    try:
        counts = service.technique_counts(days)
    except OpenSearchException:
        counts = {}
    # A technique's slug is its ATT&CK id in lower case. Count the tracked groups (not software) known to use it.
    user = aliased(Entity)
    actors = {slug.upper(): n for slug, n in db.execute(
        select(Entity.slug, func.count()).join(Relationship, Relationship.dst_id == Entity.id).join(user, user.id == Relationship.src_id)
        .where(Entity.type == "technique", Relationship.kind == "uses", user.type == "actor").group_by(Entity.slug)).all()}
    by_tactic: dict[str, list] = {t["shortname"]: [] for t in data["tactics"]}
    for technique in data["techniques"]:
        if "." in technique["id"]:
            continue  # sub-techniques roll up into their parent
        observed = counts.get(technique["id"], 0) + sum(n for key, n in counts.items() if key.startswith(technique["id"] + "."))
        row = {"id": technique["id"], "name": technique["name"], "count": observed, "actors": actors.get(technique["id"], 0)}
        for tactic in technique["tactics"]:
            by_tactic.setdefault(tactic, []).append(row)
    return {"version": data["version"], "days": days, "observed": sum(1 for v in counts.values() if v),
            "tactics": [{"id": t["id"], "shortname": t["shortname"], "name": t["name"],
                         "techniques": sorted(by_tactic.get(t["shortname"], []), key=lambda r: (-r["count"], r["id"]))} for t in data["tactics"]]}


@router.get("/attack/techniques/{technique_id}")
def technique_detail(technique_id: str, db: Session = Depends(get_db), user: User = Depends(viewer)):
    technique = attack.techniques().get(technique_id.upper())
    if technique is None:
        raise HTTPException(404, "Unknown technique")
    entity = db.scalar(select(Entity).where(Entity.type == "technique", Entity.slug == technique["id"].lower()))
    findings, users = [], []
    if entity is not None:
        docs = db.scalars(select(Document).join(DocumentEntity, DocumentEntity.document_id == Document.id).where(DocumentEntity.entity_id == entity.id)
                          .order_by(Document.first_seen_at.desc()).limit(30)).unique().all()
        findings = [finding_summary(d) for d in docs]
        users = [{"id": r.id, "type": r.type, "name": r.name, "confidence": r.confidence, "source": r.source, "doc_count": r.doc_count}
                 for r in db.execute(select(Entity.id, Entity.type, Entity.name, Entity.doc_count, Relationship.confidence, Relationship.source)
                                     .join(Relationship, Relationship.src_id == Entity.id).where(Relationship.dst_id == entity.id, Relationship.kind == "uses")
                                     .order_by(Entity.doc_count.desc(), Entity.name).limit(80))]
    subs = [t for t in attack.catalog()["techniques"] if t["id"].startswith(technique["id"] + ".")]
    return {**technique, "entity_id": entity.id if entity else None, "url": f"https://attack.mitre.org/techniques/{technique['id'].replace('.', '/')}/",
            "sub_techniques": [{"id": t["id"], "name": t["name"]} for t in subs], "findings": findings, "used_by": users}


@router.get("/entities/{entity_id}/relationships")
def entity_relationships(entity_id: int, db: Session = Depends(get_db), user: User = Depends(viewer)):
    """Typed, sourced relationships of an entity, in both directions."""
    other = aliased(Entity)
    out = []
    for direction, own, far in (("out", Relationship.src_id, Relationship.dst_id), ("in", Relationship.dst_id, Relationship.src_id)):
        rows = db.execute(select(Relationship, other.id, other.type, other.name).join(other, other.id == far).where(own == entity_id)
                          .order_by(Relationship.kind, other.type, other.name).limit(400)).all()
        out += [{"id": rel.id, "direction": direction, "kind": rel.kind, "confidence": rel.confidence, "source": rel.source,
                 "first_seen": iso(rel.first_seen_at), "last_seen": iso(rel.last_seen_at), "entity": {"id": oid, "type": otype, "name": oname}}
                for rel, oid, otype, oname in rows]
    return out


class RelationshipIn(BaseModel):
    src_id: int
    dst_id: int
    kind: str
    confidence: int = Field(70, ge=0, le=100)


@router.post("/relationships")
def create_relationship(body: RelationshipIn, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    if body.kind not in RELATIONSHIP_KINDS or body.src_id == body.dst_id:
        raise HTTPException(400, "Unknown relationship kind, or an entity related to itself")
    if db.get(Entity, body.src_id) is None or db.get(Entity, body.dst_id) is None:
        raise HTTPException(404, "Entity not found")
    upsert_relationship(db, body.src_id, body.dst_id, body.kind, confidence=body.confidence, source=f"analyst:{user.email}")
    audit(db, request, user, "relationship.create", "entity", body.src_id, dst=body.dst_id, kind=body.kind)
    db.commit()
    return {"ok": True}


@router.delete("/relationships/{relationship_id}")
def delete_relationship(relationship_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    rel = db.get(Relationship, relationship_id)
    if rel is None:
        raise HTTPException(404, "Not found")
    audit(db, request, user, "relationship.delete", "entity", rel.src_id, dst=rel.dst_id, kind=rel.kind)
    db.delete(rel)
    db.commit()
    return {"ok": True}


class MergeIn(BaseModel):
    into_id: int


@router.post("/entities/{entity_id}/merge")
def merge(entity_id: int, body: MergeIn, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    """Resolve two records of the same real-world entity into one. The merged name becomes an alias."""
    drop, keep = db.get(Entity, entity_id), db.get(Entity, body.into_id)
    if drop is None or keep is None:
        raise HTTPException(404, "Entity not found")
    if drop.type in ("technique", "incident"):
        raise HTTPException(400, "Techniques and incidents cannot be merged")
    try:
        affected = merge_entities(db, keep, drop)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    audit(db, request, user, "entity.merge", "entity", keep.id, merged=drop.name, into=keep.name, findings=len(affected))
    db.commit()
    for doc in db.scalars(select(Document).where(Document.id.in_(affected[:2000]))).unique() if affected else []:
        reindex_document(db, doc)
    return {"ok": True, "id": keep.id, "findings": len(affected)}


@router.get("/entities/{entity_id}/duplicates")
def possible_duplicates(entity_id: int, db: Session = Depends(get_db), user: User = Depends(viewer)):
    """Other entities of the same type whose name is very close: candidates for a merge."""
    entity = db.get(Entity, entity_id)
    if entity is None:
        raise HTTPException(404, "Entity not found")
    stem = entity.name.lower().split()[0][:8]
    if len(stem) < 4:
        return []
    rows = db.execute(select(Entity.id, Entity.name, Entity.doc_count).where(
        Entity.type == entity.type, Entity.id != entity.id, or_(func.lower(Entity.name).like(f"{stem}%"), func.lower(Entity.name).like(f"% {stem}%")))
        .order_by(Entity.doc_count.desc()).limit(8)).all()
    return [{"id": r.id, "name": r.name, "doc_count": r.doc_count} for r in rows]
