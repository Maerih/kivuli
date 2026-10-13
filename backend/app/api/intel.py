"""Indicators, entities and the relationship graph."""
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from opensearchpy.exceptions import OpenSearchException
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, aliased

from app.api.common import finding_summary, iso, paginate, parse_uuid
from app.db import get_db
from app.extract.iocs import IOC_TYPES, defang, refang
from app.extract.textutil import slugify
from app.models import ENTITY_TYPES, Document, DocumentEntity, DocumentIoc, Entity, Ioc, Relationship, User
from app.search import service
from app.security import analyst, audit, viewer

router = APIRouter(tags=["intel"])

_INDEX_FIELD = {"actor": "actors", "organization": "organizations", "malware": "malware", "campaign": "campaigns"}


def _docs_for(db: Session, link, column, value, limit: int = 50) -> list[dict]:
    docs = db.scalars(select(Document).join(link, link.document_id == Document.id).where(column == value)
                      .order_by(Document.first_seen_at.desc()).limit(limit)).unique().all()
    return [finding_summary(d) for d in docs]


@router.get("/iocs")
def list_iocs(type: str | None = None, q: str = Query("", max_length=300), sort: str = "recent", page: int = 1, size: int = 50,
              db: Session = Depends(get_db), user: User = Depends(viewer)):
    stmt = select(Ioc.id, Ioc.type, Ioc.value, Ioc.doc_count, Ioc.first_seen_at, Ioc.last_seen_at).where(Ioc.doc_count > 0)
    if type:
        if type not in IOC_TYPES:
            raise HTTPException(400, "Unknown indicator type")
        stmt = stmt.where(Ioc.type == type)
    if q.strip():
        needle = refang(q.strip()).lower().replace("%", "").replace("_", r"\_")
        stmt = stmt.where(func.lower(Ioc.value).like(f"%{needle}%"))
    stmt = stmt.order_by(Ioc.doc_count.desc(), Ioc.last_seen_at.desc()) if sort == "frequent" else stmt.order_by(Ioc.last_seen_at.desc(), Ioc.id.desc())
    rows, total = paginate(db, stmt, page, size)
    counts = dict(db.execute(select(Ioc.type, func.count()).where(Ioc.doc_count > 0).group_by(Ioc.type)).all())
    return {"total": total, "counts": counts, "items": [
        {"id": r.id, "type": r.type, "value": r.value, "defanged": defang(r.value), "doc_count": r.doc_count,
         "first_seen": iso(r.first_seen_at), "last_seen": iso(r.last_seen_at)} for r in rows]}


@router.get("/iocs/{ioc_id}")
def ioc_detail(ioc_id: int, db: Session = Depends(get_db), user: User = Depends(viewer)):
    ioc = db.get(Ioc, ioc_id)
    if ioc is None:
        raise HTTPException(404, "Indicator not found")
    doc_ids = select(DocumentIoc.document_id).where(DocumentIoc.ioc_id == ioc.id).limit(500).subquery()
    entities = db.execute(
        select(Entity.id, Entity.type, Entity.name, func.count().label("shared"))
        .join(DocumentEntity, DocumentEntity.entity_id == Entity.id).where(DocumentEntity.document_id.in_(select(doc_ids.c.document_id)))
        .group_by(Entity.id).order_by(func.count().desc()).limit(20)
    ).all()
    siblings = db.execute(
        select(Ioc.id, Ioc.type, Ioc.value, func.count().label("shared"))
        .join(DocumentIoc, DocumentIoc.ioc_id == Ioc.id).where(DocumentIoc.document_id.in_(select(doc_ids.c.document_id)), Ioc.id != ioc.id)
        .group_by(Ioc.id).order_by(func.count().desc()).limit(25)
    ).all()
    contexts = db.execute(select(DocumentIoc.document_id, DocumentIoc.context).where(DocumentIoc.ioc_id == ioc.id).limit(50)).all()
    context_by_doc = {str(r.document_id): r.context for r in contexts}
    findings = _docs_for(db, DocumentIoc, DocumentIoc.ioc_id, ioc.id)
    for f in findings:
        f["context"] = context_by_doc.get(f["id"], "")
    return {
        "id": ioc.id, "type": ioc.type, "value": ioc.value, "defanged": defang(ioc.value), "doc_count": ioc.doc_count,
        "first_seen": iso(ioc.first_seen_at), "last_seen": iso(ioc.last_seen_at), "findings": findings,
        "entities": [{"id": r.id, "type": r.type, "name": r.name, "shared": r.shared} for r in entities],
        "related_iocs": [{"id": r.id, "type": r.type, "value": r.value, "shared": r.shared} for r in siblings],
    }


@router.get("/entities")
def list_entities(type: str | None = None, q: str = Query("", max_length=200), sort: str = "recent", page: int = 1, size: int = 50,
                  db: Session = Depends(get_db), user: User = Depends(viewer)):
    stmt = select(Entity.id, Entity.type, Entity.name, Entity.aliases, Entity.doc_count, Entity.first_seen_at, Entity.last_seen_at,
                  Entity.curated, Entity.description, Entity.meta)
    if type:
        if type not in ENTITY_TYPES:
            raise HTTPException(400, "Unknown entity type")
        stmt = stmt.where(Entity.type == type)
    if type != "campaign":
        stmt = stmt.where(or_(Entity.doc_count > 0, Entity.type == "campaign"))
    if q.strip():
        needle = q.strip().replace("%", "").replace("_", r"\_")
        stmt = stmt.where(or_(Entity.name.ilike(f"%{needle}%"), func.array_to_string(Entity.aliases, " ").ilike(f"%{needle}%")))
    order = {"frequent": (Entity.doc_count.desc(), Entity.name), "name": (Entity.name,), "first": (Entity.first_seen_at.desc().nulls_last(),)}
    stmt = stmt.order_by(*order.get(sort, (Entity.last_seen_at.desc().nulls_last(), Entity.doc_count.desc())))
    rows, total = paginate(db, stmt, page, size)
    counts = dict(db.execute(select(Entity.type, func.count()).where(or_(Entity.doc_count > 0, Entity.type == "campaign")).group_by(Entity.type)).all())
    return {"total": total, "counts": counts, "items": [
        {"id": r.id, "type": r.type, "name": r.name, "aliases": r.aliases, "doc_count": r.doc_count, "curated": r.curated,
         "first_seen": iso(r.first_seen_at), "last_seen": iso(r.last_seen_at), "description": (r.description or "")[:240],
         "countries": (r.meta or {}).get("countries", [])} for r in rows]}


class EntityIn(BaseModel):
    type: str
    name: str = Field(min_length=2, max_length=300)
    description: str = Field("", max_length=20000)
    aliases: list[str] = Field(default=[], max_length=30)


class EntityPatch(BaseModel):
    name: str | None = Field(None, min_length=2, max_length=300)
    description: str | None = Field(None, max_length=20000)
    aliases: list[str] | None = Field(None, max_length=30)


@router.post("/entities")
def create_entity(body: EntityIn, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    if body.type not in ("actor", "organization", "malware", "campaign"):
        raise HTTPException(400, "Entities of this type are created automatically")
    slug = slugify(body.name)
    if db.scalar(select(Entity.id).where(Entity.type == body.type, Entity.slug == slug)):
        raise HTTPException(409, "An entity with this name already exists")
    entity = Entity(type=body.type, name=" ".join(body.name.split()), slug=slug, description=body.description,
                    aliases=[a.strip() for a in body.aliases if a.strip()], curated=True, meta={"created_by": user.email})
    db.add(entity)
    db.flush()
    audit(db, request, user, "entity.create", "entity", entity.id, type=body.type, name=entity.name)
    db.commit()
    return {"id": entity.id}


@router.patch("/entities/{entity_id}")
def update_entity(entity_id: int, body: EntityPatch, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    entity = db.get(Entity, entity_id)
    if entity is None:
        raise HTTPException(404, "Entity not found")
    if body.name is not None:
        entity.name = " ".join(body.name.split())
    if body.description is not None:
        entity.description = body.description
    if body.aliases is not None:
        entity.aliases = [a.strip() for a in body.aliases if a.strip()]
    audit(db, request, user, "entity.update", "entity", entity.id)
    db.commit()
    return {"ok": True}


@router.get("/entities/{entity_id}")
def entity_detail(entity_id: int, db: Session = Depends(get_db), user: User = Depends(viewer)):
    entity = db.get(Entity, entity_id)
    if entity is None:
        raise HTTPException(404, "Entity not found")
    doc_ids = select(DocumentEntity.document_id).where(DocumentEntity.entity_id == entity.id).limit(2000).subquery()
    related = db.execute(
        select(Entity.id, Entity.type, Entity.name, func.count().label("shared"))
        .join(DocumentEntity, DocumentEntity.entity_id == Entity.id)
        .where(DocumentEntity.document_id.in_(select(doc_ids.c.document_id)), Entity.id != entity.id)
        .group_by(Entity.id).order_by(func.count().desc()).limit(40)
    ).all()
    iocs = db.execute(
        select(Ioc.id, Ioc.type, Ioc.value, func.count().label("shared"))
        .join(DocumentIoc, DocumentIoc.ioc_id == Ioc.id).where(DocumentIoc.document_id.in_(select(doc_ids.c.document_id)))
        .group_by(Ioc.id).order_by(func.count().desc(), Ioc.last_seen_at.desc()).limit(40)
    ).all()
    stats = db.execute(
        select(func.unnest(Document.countries).label("c"), func.count()).join(DocumentEntity, DocumentEntity.document_id == Document.id)
        .where(DocumentEntity.entity_id == entity.id).group_by("c").order_by(func.count().desc()).limit(12)
    ).all()
    sectors = db.execute(
        select(func.unnest(Document.sectors).label("s"), func.count()).join(DocumentEntity, DocumentEntity.document_id == Document.id)
        .where(DocumentEntity.entity_id == entity.id).group_by("s").order_by(func.count().desc()).limit(10)
    ).all()
    timeline: list[dict] = []
    if entity.type in _INDEX_FIELD:
        try:
            timeline = service.entity_timeline(_INDEX_FIELD[entity.type], entity.name)
        except OpenSearchException:
            pass
    return {
        "id": entity.id, "type": entity.type, "name": entity.name, "aliases": entity.aliases, "description": entity.description,
        "curated": entity.curated, "doc_count": entity.doc_count, "first_seen": iso(entity.first_seen_at), "last_seen": iso(entity.last_seen_at),
        "meta": entity.meta, "timeline": timeline,
        "findings": _docs_for(db, DocumentEntity, DocumentEntity.entity_id, entity.id),
        "related": [{"id": r.id, "type": r.type, "name": r.name, "shared": r.shared} for r in related],
        "iocs": [{"id": r.id, "type": r.type, "value": r.value, "shared": r.shared} for r in iocs],
        "countries": [{"value": r[0], "count": r[1]} for r in stats],
        "sectors": [{"value": r[0], "count": r[1]} for r in sectors],
    }


@router.get("/graph")
def graph(node: str = Query(..., max_length=80), db: Session = Depends(get_db), user: User = Depends(viewer)):
    """Relationship neighbourhood of an entity, indicator or finding.

    Two things are related when they appear in the same findings; edge weight is
    the number of findings they share.
    """
    kind, _, ref = node.partition(":")
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    hide_incidents = True

    def add_node(node_id: str, group: str, label: str, count: int = 0, **extra) -> None:
        nodes.setdefault(node_id, {"id": node_id, "group": group, "label": label[:80], "count": count, **extra})

    if kind == "entity" and ref.isdigit():
        seed = db.get(Entity, int(ref))
        if seed is None:
            raise HTTPException(404, "Entity not found")
        add_node(node, seed.type, seed.name, seed.doc_count, seed=True)
        doc_ids = select(DocumentEntity.document_id).where(DocumentEntity.entity_id == seed.id).order_by(DocumentEntity.document_id).limit(1500)
        exclude_entity = seed.id
        # An incident is just "actor / victim"; next to those two nodes it is clutter.
        hide_incidents = seed.type != "incident"
    elif kind == "ioc" and ref.isdigit():
        seed = db.get(Ioc, int(ref))
        if seed is None:
            raise HTTPException(404, "Indicator not found")
        add_node(node, f"ioc:{seed.type}", seed.value, seed.doc_count, seed=True)
        doc_ids = select(DocumentIoc.document_id).where(DocumentIoc.ioc_id == seed.id).limit(1500)
        exclude_entity = -1
    elif kind == "finding":
        seed = db.get(Document, parse_uuid(ref))
        if seed is None:
            raise HTTPException(404, "Finding not found")
        add_node(node, "finding", seed.title, 1, seed=True)
        # The finding itself plus other findings that share one of its less common indicators.
        own = select(DocumentIoc.ioc_id).join(Ioc, Ioc.id == DocumentIoc.ioc_id).where(DocumentIoc.document_id == seed.id, Ioc.doc_count <= 60)
        peers = db.execute(
            select(Document.id, Document.title, func.count().label("shared")).join(DocumentIoc, DocumentIoc.document_id == Document.id)
            .where(DocumentIoc.ioc_id.in_(own), Document.id != seed.id).group_by(Document.id).order_by(func.count().desc()).limit(12)
        ).all()
        for peer in peers:
            add_node(f"finding:{peer.id}", "finding", peer.title, peer.shared)
            edges.append({"source": node, "target": f"finding:{peer.id}", "weight": peer.shared})
        doc_ids = select(Document.id).where(Document.id == seed.id)
        exclude_entity = -1
    else:
        raise HTTPException(400, "node must be entity:<id>, ioc:<id> or finding:<uuid>")

    scope = doc_ids.subquery()
    in_scope = select(scope.c[0])
    neighbours = db.execute(
        select(Entity.id, Entity.type, Entity.name, func.count().label("shared"))
        .join(DocumentEntity, DocumentEntity.entity_id == Entity.id)
        .where(DocumentEntity.document_id.in_(in_scope), Entity.id != exclude_entity,
               Entity.type != ("incident" if hide_incidents else ""))
        .group_by(Entity.id).order_by(func.count().desc()).limit(28)
    ).all()
    for n in neighbours:
        add_node(f"entity:{n.id}", n.type, n.name, n.shared)
        edges.append({"source": node, "target": f"entity:{n.id}", "weight": n.shared})

    ioc_stmt = (
        select(Ioc.id, Ioc.type, Ioc.value, func.count().label("shared")).join(DocumentIoc, DocumentIoc.ioc_id == Ioc.id)
        .where(DocumentIoc.document_id.in_(in_scope), Ioc.type != "url", Ioc.benign.is_(False))
        .group_by(Ioc.id).order_by(func.count().desc(), Ioc.doc_count.asc()).limit(18)
    )
    if kind == "ioc":
        ioc_stmt = ioc_stmt.where(Ioc.id != int(ref))
    for i in db.execute(ioc_stmt).all():
        add_node(f"ioc:{i.id}", f"ioc:{i.type}", i.value, i.shared)
        edges.append({"source": node, "target": f"ioc:{i.id}", "weight": i.shared})

    # Links among the neighbours themselves give the graph its structure.
    neighbour_ids = [n.id for n in neighbours]
    if len(neighbour_ids) > 1:
        left, right = aliased(DocumentEntity), aliased(DocumentEntity)
        pairs = db.execute(
            select(left.entity_id, right.entity_id, func.count().label("shared"))
            .join(right, (right.document_id == left.document_id) & (left.entity_id < right.entity_id))
            .where(left.document_id.in_(in_scope), left.entity_id.in_(neighbour_ids), right.entity_id.in_(neighbour_ids))
            .group_by(left.entity_id, right.entity_id).order_by(func.count().desc()).limit(60)
        ).all()
        for a, b, shared in pairs:
            edges.append({"source": f"entity:{a}", "target": f"entity:{b}", "weight": shared, "secondary": True})

    # Typed relationships: how things are connected, how sure we are, and who said so.
    if kind == "entity":
        other = aliased(Entity)
        for outgoing, own, far in ((True, Relationship.src_id, Relationship.dst_id), (False, Relationship.dst_id, Relationship.src_id)):
            rows = db.execute(select(Relationship, other.id, other.type, other.name).join(other, other.id == far).where(own == int(ref))
                              .order_by(other.doc_count.desc(), Relationship.confidence.desc()).limit(45)).all()
            for rel, far_id, far_type, far_name in rows:
                far_node = f"entity:{far_id}"
                add_node(far_node, far_type, far_name, 0)
                edge = {"source": node if outgoing else far_node, "target": far_node if outgoing else node, "weight": 1, "kind": rel.kind,
                        "confidence": rel.confidence, "provenance": rel.source, "first_seen": iso(rel.first_seen_at), "last_seen": iso(rel.last_seen_at)}
                existing = next((e for e in edges if {e["source"], e["target"]} == {node, far_node} and not e.get("secondary")), None)
                if existing:
                    existing.update({k: v for k, v in edge.items() if k not in ("source", "target", "weight")})
                else:
                    edges.append(edge)

    groups = sorted({n["group"].split(":")[0] for n in nodes.values()})
    return {"seed": node, "nodes": list(nodes.values()), "edges": edges, "groups": groups}
