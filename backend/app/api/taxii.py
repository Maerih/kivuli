"""TAXII 2.1 (read-only) and STIX 2.1 import.

Point a SIEM, TIP or EDR at /api/taxii2/ with an API key (Bearer, or HTTP Basic
with the key as the password) to pull the platform's intelligence as STIX.
"""
import json
import uuid
from datetime import datetime, timezone

from dateutil import parser as dateparser
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session, aliased

from app.config import get_settings
from app.db import get_db
from app.intel import stix
from app.intel.relationships import Resolver, upsert_relationship
from app.models import RELATIONSHIP_KINDS, Document, DocumentIoc, Entity, Ioc, Relationship, Source, User
from app.security import analyst, audit, viewer
from app.worker import ingest
from app.worker.parsers import ParsedItem

router = APIRouter(tags=["taxii"])
settings = get_settings()
MEDIA = "application/taxii+json;version=2.1"
_INDICATOR_TYPES = ("domain", "onion", "ip", "url", "email", "hash")

COLLECTIONS = {
    "indicators": {"id": str(uuid.uuid5(stix.NAMESPACE, "collection:indicators")), "title": "Indicators",
                   "description": "Every indicator extracted from collected intelligence, excluding ones marked benign."},
    "high-risk": {"id": str(uuid.uuid5(stix.NAMESPACE, "collection:high-risk")), "title": "High-risk indicators",
                  "description": "Indicators from findings scored high or critical, and indicators listed by threat feeds."},
    "entities": {"id": str(uuid.uuid5(stix.NAMESPACE, "collection:entities")), "title": "Actors, malware and techniques",
                 "description": "Threat actors, malware, campaigns and ATT&CK techniques seen in collected intelligence, with their relationships."},
}
_BY_ID = {c["id"]: name for name, c in COLLECTIONS.items()}


def _taxii(payload: dict, headers: dict | None = None) -> Response:
    return Response(json.dumps(payload), media_type=MEDIA, headers=headers or {})


def _collection_out(name: str) -> dict:
    c = COLLECTIONS[name]
    return {"id": c["id"], "title": c["title"], "description": c["description"], "can_read": True, "can_write": False,
            "media_types": ["application/stix+json;version=2.1"]}


def _name(collection_id: str) -> str:
    name = _BY_ID.get(collection_id) or (collection_id if collection_id in COLLECTIONS else None)
    if name is None:
        raise HTTPException(404, "Collection not found")
    return name


@router.get("/taxii2/")
@router.get("/taxii2", include_in_schema=False)  # reverse proxies often strip the trailing slash TAXII clients send
def discovery(request: Request, user: User = Depends(viewer)):
    root = f"{settings.public_url.rstrip('/')}/api/taxii2/root/"
    return _taxii({"title": f"{settings.app_name} TAXII server", "description": "Read-only threat intelligence in STIX 2.1.", "default": root, "api_roots": [root]})


@router.get("/taxii2/root/")
@router.get("/taxii2/root", include_in_schema=False)
def api_root(user: User = Depends(viewer)):
    return _taxii({"title": settings.app_name, "description": "Collected and correlated threat intelligence.", "versions": [MEDIA], "max_content_length": 10_485_760})


@router.get("/taxii2/root/collections/")
@router.get("/taxii2/root/collections", include_in_schema=False)
def collections(user: User = Depends(viewer)):
    return _taxii({"collections": [_collection_out(name) for name in COLLECTIONS]})


@router.get("/taxii2/root/collections/{collection_id}/")
@router.get("/taxii2/root/collections/{collection_id}", include_in_schema=False)
def collection(collection_id: str, user: User = Depends(viewer)):
    return _taxii(_collection_out(_name(collection_id)))


def _objects(db: Session, name: str, added_after: datetime | None, limit: int, offset: int) -> tuple[list[dict], list[datetime], bool]:
    """One page of STIX objects for a collection, oldest first, with the 'date added' of each."""
    if name in ("indicators", "high-risk"):
        stmt = select(Ioc).where(Ioc.type.in_(_INDICATOR_TYPES), Ioc.benign.is_(False))
        if name == "high-risk":
            risky = select(DocumentIoc.ioc_id).join(Document, Document.id == DocumentIoc.document_id).where(Document.risk_score >= 60)
            stmt = stmt.where(Ioc.id.in_(risky) | (func.cardinality(Ioc.feeds) > 0))
        else:
            stmt = stmt.where(Ioc.doc_count > 0)
        if added_after:
            stmt = stmt.where(Ioc.first_seen_at > added_after)
        rows = db.scalars(stmt.order_by(Ioc.first_seen_at, Ioc.id).limit(limit + 1).offset(offset)).all()
        page = rows[:limit]
        objects = [o for o in (stix.indicator(i.type, i.value, i.first_seen_at, i.last_seen_at, [*i.tags, *i.feeds] or None) for i in page) if o]
        return objects, [i.first_seen_at for i in page], len(rows) > limit

    stmt = select(Entity).where(Entity.type.in_(("actor", "malware", "campaign", "technique")), Entity.doc_count > 0, Entity.first_seen_at.isnot(None))
    if added_after:
        stmt = stmt.where(Entity.first_seen_at > added_after)
    rows = db.scalars(stmt.order_by(Entity.first_seen_at, Entity.id).limit(limit + 1).offset(offset)).all()
    page = rows[:limit]
    refs = {e.id: stix.entity_object(e.type, e.name, e.aliases, e.description, e.meta, e.first_seen_at) for e in page}
    objects = [o for o in refs.values() if o]
    if refs:
        far = aliased(Entity)
        for rel, far_entity in db.execute(select(Relationship, far).join(far, far.id == Relationship.dst_id)
                                          .where(Relationship.src_id.in_(list(refs)), far.type.in_(("actor", "malware", "campaign", "technique", "organization"))).limit(2000)):
            target = refs.get(far_entity.id) or stix.entity_object(far_entity.type, far_entity.name, far_entity.aliases, "", far_entity.meta, far_entity.first_seen_at)
            source = refs.get(rel.src_id)
            if source and target:
                if far_entity.id not in refs:
                    objects.append(target)
                    refs[far_entity.id] = target
                objects.append(stix.relationship(rel.kind, source["id"], target["id"], rel.confidence, f"Source: {rel.source}", rel.first_seen_at, rel.last_seen_at))
    return objects, [e.first_seen_at for e in page], len(rows) > limit


def _page(db: Session, collection_id: str, added_after: str | None, limit: int, next_token: str | None):
    name = _name(collection_id)
    try:
        after = dateparser.isoparse(added_after) if added_after else None
        offset = int(next_token) if next_token else 0
    except ValueError:
        raise HTTPException(400, "Invalid added_after or next value") from None
    if after and after.tzinfo is None:
        after = after.replace(tzinfo=timezone.utc)
    limit = max(1, min(limit, 1000))
    objects, added, more = _objects(db, name, after, limit, offset)
    headers = {}
    if added:
        fmt = lambda d: d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")  # noqa: E731
        headers = {"X-TAXII-Date-Added-First": fmt(added[0]), "X-TAXII-Date-Added-Last": fmt(added[-1])}
    return objects, added, more, str(offset + limit), headers


@router.get("/taxii2/root/collections/{collection_id}/objects/")
@router.get("/taxii2/root/collections/{collection_id}/objects", include_in_schema=False)
def collection_objects(collection_id: str, request: Request, added_after: str | None = None, limit: int = 100, next: str | None = None,
                       match_type: list[str] = Query(default=[], alias="match[type]"), db: Session = Depends(get_db), user: User = Depends(viewer)):
    objects, _added, more, token, headers = _page(db, collection_id, added_after, limit, next)
    if match_type:
        wanted = {t for value in match_type for t in value.split(",")}
        objects = [o for o in objects if o["type"] in wanted]
    audit(db, request, user, "taxii.objects", "taxii", _name(collection_id), count=len(objects))
    db.commit()
    return _taxii({"more": more, **({"next": token} if more else {}), "objects": objects}, headers)


@router.get("/taxii2/root/collections/{collection_id}/manifest/")
@router.get("/taxii2/root/collections/{collection_id}/manifest", include_in_schema=False)
def collection_manifest(collection_id: str, added_after: str | None = None, limit: int = 100, next: str | None = None,
                        db: Session = Depends(get_db), user: User = Depends(viewer)):
    objects, added, more, token, headers = _page(db, collection_id, added_after, limit, next)
    stamp = added[0].astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ") if added else ""
    entries = [{"id": o["id"], "date_added": stamp, "version": o["modified"], "media_type": "application/stix+json;version=2.1"} for o in objects]
    return _taxii({"more": more, **({"next": token} if more else {}), "objects": entries}, headers)


# ── STIX import ─────────────────────────────────────────────────────────────

@router.post("/stix/import")
async def import_stix(request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    """Absorb a STIX 2.1 bundle: actors, malware, campaigns, techniques, indicators and relationships.

    The bundle becomes one finding, so its origin is preserved and its contents
    are searchable, linkable to cases and visible in the graph like anything else.
    """
    raw = await request.body()
    if len(raw) > 10_485_760:
        raise HTTPException(413, "Bundle is larger than 10 MB")
    try:
        summary = stix.summarise_import(json.loads(raw))
    except ValueError as exc:
        raise HTTPException(400, f"Not a valid STIX bundle: {exc}") from None

    resolvers: dict[str, Resolver] = {}
    by_ref: dict[str, Entity] = {}
    for item in summary["entities"]:
        resolver = resolvers.setdefault(item["kind"], Resolver(db, item["kind"]))
        if item["kind"] == "technique":
            # Techniques come only from the bundled ATT&CK catalogue, keyed by their id; unknown ids are skipped, not invented.
            entity = db.scalar(select(Entity).where(Entity.type == "technique", Entity.slug == item["name"].lower()))
            if entity is None:
                continue
        else:
            entity = resolver.ensure(item["name"], item["aliases"], description=item["description"], meta={"origin": "stix"})
        by_ref[item["ref"]] = entity
    linked = 0
    for source_ref, kind, target_ref in summary["relationships"]:
        if source_ref in by_ref and target_ref in by_ref and by_ref[source_ref].id != by_ref[target_ref].id:
            upsert_relationship(db, by_ref[source_ref].id, by_ref[target_ref].id, kind if kind in RELATIONSHIP_KINDS else "related_to",
                                confidence=70, source=f"STIX import by {user.email}")
            linked += 1

    source = db.scalar(select(Source).where(Source.url == "https://stix.import.invalid/"))
    if source is None:
        source = Source(name="STIX imports", url="https://stix.import.invalid/", host="stix.import.invalid", network="surface", connector="html",
                        route="direct", category="other", status="paused", trust=70, notes="Holds bundles imported by analysts. Never crawled.")
        db.add(source)
        db.flush()
    title = summary["title"] or f"STIX bundle imported {datetime.now(timezone.utc):%Y-%m-%d %H:%M}"
    names = sorted({e.name for e in by_ref.values()})
    text = "\n".join([f"STIX 2.1 bundle imported by {user.email}.", "", f"Entities: {', '.join(names[:200]) or 'none'}",
                      f"Indicators: {len(summary['indicators'])}", f"Vulnerabilities: {', '.join(summary['cves'][:100]) or 'none'}",
                      "", *[f"{kind}: {value}" for kind, value in summary["indicators"][:2000]]])
    digest = ingest.tu.sha256_hex(raw)
    item = ParsedItem(key=digest, namespace="stix-import", url=source.url, title=title, text=text, raw=raw.decode("utf-8", "replace")[:2_000_000],
                      extra_iocs=[*summary["indicators"][:5000], *[("cve", c) for c in summary["cves"][:500]]], meta={"origin": "stix"})
    outcome = ingest.ingest_item(db, source, item, {"http_status": None, "headers": {}})
    audit(db, request, user, "stix.import", "stix", digest[:16], entities=len(by_ref), indicators=len(summary["indicators"]), relationships=linked)
    db.commit()
    doc_id = db.scalar(select(Document.id).where(Document.doc_key == ingest.tu.sha256_hex(f"stix-import|{digest}")))
    return {"ok": True, "outcome": outcome, "finding_id": str(doc_id) if doc_id else None, "entities": len(by_ref),
            "indicators": len(summary["indicators"]), "vulnerabilities": len(summary["cves"]), "relationships": linked}
