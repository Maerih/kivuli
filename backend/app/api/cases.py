"""Case management and report export."""
import json

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.common import finding_summary, iso, parse_uuid
from app.config import get_settings
from app.db import get_db
from app.extract.iocs import defang
from app.intel import stix
from app.models import Alert, AuditLog, Case, CaseItem, ChainAddress, CrawlJob, Document, DocumentEntity, DocumentIoc, DocumentVersion, Entity, Ioc, Note, User, utcnow
from app.reports import render
from app.security import admin, analyst, audit, viewer

router = APIRouter(tags=["cases"])
settings = get_settings()

STATUSES = ("open", "in_progress", "closed")
PRIORITIES = ("low", "medium", "high", "critical")
TLPS = ("clear", "green", "amber", "red")


class CaseIn(BaseModel):
    title: str = Field(min_length=3, max_length=300)
    description: str = Field("", max_length=50000)
    priority: str = "medium"
    tlp: str = "amber"


class CasePatch(BaseModel):
    title: str | None = Field(None, min_length=3, max_length=300)
    description: str | None = Field(None, max_length=50000)
    status: str | None = None
    priority: str | None = None
    tlp: str | None = None
    owner_id: int | None = None


class ItemIn(BaseModel):
    object_type: str
    object_id: str = Field(max_length=64)
    note: str = Field("", max_length=5000)


def _validate(status: str | None, priority: str | None, tlp: str | None) -> None:
    if status is not None and status not in STATUSES:
        raise HTTPException(400, "Unknown status")
    if priority is not None and priority not in PRIORITIES:
        raise HTTPException(400, "Unknown priority")
    if tlp is not None and tlp not in TLPS:
        raise HTTPException(400, "Unknown TLP level")


def _case_out(case: Case, users: dict[int, str], items: int = 0) -> dict:
    return {"id": case.id, "title": case.title, "description": case.description, "status": case.status, "priority": case.priority,
            "tlp": case.tlp, "owner_id": case.owner_id, "owner": users.get(case.owner_id or 0, ""), "item_count": items,
            "created_at": iso(case.created_at), "updated_at": iso(case.updated_at), "closed_at": iso(case.closed_at)}


def _get(db: Session, case_id: int) -> Case:
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(404, "Case not found")
    return case


def _expanded(db: Session, case: Case) -> dict:
    """A case with its items resolved, plus indicators and entities aggregated across its findings."""
    users = dict(db.execute(select(User.id, User.name)).all())
    items = db.scalars(select(CaseItem).where(CaseItem.case_id == case.id).order_by(CaseItem.added_at)).all()
    out = _case_out(case, users, len(items))
    finding_ids = [parse_uuid(i.object_id) for i in items if i.object_type == "finding"]
    docs = {str(d.id): d for d in db.scalars(select(Document).where(Document.id.in_(finding_ids))).unique()} if finding_ids else {}
    pinned_iocs = {int(i.object_id) for i in items if i.object_type == "ioc" and i.object_id.isdigit()}
    pinned_entities = {int(i.object_id) for i in items if i.object_type == "entity" and i.object_id.isdigit()}

    out["findings"] = []
    for item in items:
        if item.object_type == "finding" and item.object_id in docs:
            doc = docs[item.object_id]
            out["findings"].append({**finding_summary(doc), "content_sha256": doc.content_sha256, "item_id": item.id, "note": item.note,
                                    "added_at": iso(item.added_at), "added_by": users.get(item.added_by or 0, "")})

    ioc_rows = {}
    if finding_ids:
        for r in db.execute(
            select(Ioc.id, Ioc.type, Ioc.value, Ioc.first_seen_at, Ioc.last_seen_at, func.count().label("shared"))
            .join(DocumentIoc, DocumentIoc.ioc_id == Ioc.id).where(DocumentIoc.document_id.in_(finding_ids))
            .group_by(Ioc.id).order_by(func.count().desc(), Ioc.type).limit(2000)
        ):
            ioc_rows[r.id] = {"id": r.id, "type": r.type, "value": r.value, "shared": r.shared, "first_seen": iso(r.first_seen_at),
                              "last_seen": iso(r.last_seen_at), "pinned": r.id in pinned_iocs}
    for ioc in db.scalars(select(Ioc).where(Ioc.id.in_(pinned_iocs - set(ioc_rows)))) if pinned_iocs - set(ioc_rows) else []:
        ioc_rows[ioc.id] = {"id": ioc.id, "type": ioc.type, "value": ioc.value, "shared": 0, "first_seen": iso(ioc.first_seen_at),
                            "last_seen": iso(ioc.last_seen_at), "pinned": True}
    out["iocs"] = sorted(ioc_rows.values(), key=lambda r: (not r["pinned"], -r["shared"], r["type"]))

    entity_rows = {}
    if finding_ids:
        for r in db.execute(
            select(Entity.id, Entity.type, Entity.name, Entity.aliases, Entity.meta, func.count().label("shared"))
            .join(DocumentEntity, DocumentEntity.entity_id == Entity.id).where(DocumentEntity.document_id.in_(finding_ids), Entity.type != "incident")
            .group_by(Entity.id).order_by(func.count().desc()).limit(300)
        ):
            entity_rows[r.id] = {"id": r.id, "type": r.type, "name": r.name, "shared": r.shared, "pinned": r.id in pinned_entities,
                                 "aliases": r.aliases or [], "meta": r.meta or {}}
    for entity in db.scalars(select(Entity).where(Entity.id.in_(pinned_entities - set(entity_rows)))) if pinned_entities - set(entity_rows) else []:
        entity_rows[entity.id] = {"id": entity.id, "type": entity.type, "name": entity.name, "shared": 0, "pinned": True}
    out["entities"] = sorted(entity_rows.values(), key=lambda r: (not r["pinned"], -r["shared"], r["name"]))
    out["pinned_items"] = [{"item_id": i.id, "object_type": i.object_type, "object_id": i.object_id, "note": i.note} for i in items if i.object_type in ("ioc", "entity")]
    out["hunts"] = [{"item_id": i.id, "kind": i.object_type, "ref": i.object_id, "text": i.note, "added_at": iso(i.added_at), "added_by": users.get(i.added_by or 0, "")}
                    for i in items if i.object_type in ("query", "graph")]
    chain_addrs = [i for i in items if i.object_type == "chain"]
    rows = {r.address: r for r in db.scalars(select(ChainAddress).where(ChainAddress.address.in_([i.object_id for i in chain_addrs])))} if chain_addrs else {}
    out["wallets"] = [{"item_id": i.id, "address": i.object_id, "note": i.note, "added_at": iso(i.added_at), "added_by": users.get(i.added_by or 0, ""),
                       "chain": (rows[i.object_id].chain if i.object_id in rows else ""), "label": (rows[i.object_id].label if i.object_id in rows else ""),
                       "category": (rows[i.object_id].category if i.object_id in rows else "unknown"), "token": (rows[i.object_id].token if i.object_id in rows else ""),
                       "balance": (rows[i.object_id].balance if i.object_id in rows else None)} for i in chain_addrs]
    # Preserved evidence: a specific capture of a page, pinned so it stays with the investigation whatever happens to the site.
    out["evidence"] = []
    preserved = [i for i in items if i.object_type == "evidence" and ":" in i.object_id]
    if preserved:
        wanted = {(parse_uuid(i.object_id.split(":")[0]), int(i.object_id.split(":")[1])) for i in preserved if i.object_id.split(":")[1].isdigit()}
        captures = {(v.document_id, v.version): v for v in db.scalars(select(DocumentVersion).where(DocumentVersion.document_id.in_({d for d, _ in wanted})))
                    if (v.document_id, v.version) in wanted}
        for item in preserved:
            doc_id, _, number = item.object_id.partition(":")
            capture = captures.get((parse_uuid(doc_id), int(number))) if number.isdigit() else None
            if capture is None:
                continue
            out["evidence"].append({"item_id": item.id, "finding_id": doc_id, "version": capture.version, "title": capture.title, "url": capture.url,
                                    "captured_at": iso(capture.captured_at), "content_sha256": capture.content_sha256, "raw_sha256": capture.raw_sha256,
                                    "chain_hash": capture.chain_hash, "bytes": capture.bytes, "note": item.note, "preserved_at": iso(item.added_at),
                                    "preserved_by": users.get(item.added_by or 0, "")})
    out["crawls"] = [{"id": j.id, "url": j.url, "status": j.status, "depth": j.depth, "created_at": iso(j.created_at)}
                     for j in db.scalars(select(CrawlJob).where(CrawlJob.case_id == case.id).order_by(CrawlJob.created_at.desc()).limit(20)).unique()]
    notes = db.scalars(select(Note).where(Note.object_type == "case", Note.object_id == str(case.id)).order_by(Note.created_at)).all()
    out["notes"] = [{"id": n.id, "body": n.body, "user_name": n.user_name, "user_id": n.user_id, "created_at": iso(n.created_at)} for n in notes]
    return out


@router.get("/cases")
def list_cases(status: str | None = None, db: Session = Depends(get_db), user: User = Depends(viewer)):
    stmt = select(Case)
    if status:
        stmt = stmt.where(Case.status == status)
    users = dict(db.execute(select(User.id, User.name)).all())
    counts = dict(db.execute(select(CaseItem.case_id, func.count()).group_by(CaseItem.case_id)).all())
    return [_case_out(c, users, counts.get(c.id, 0)) for c in db.scalars(stmt.order_by(Case.updated_at.desc()))]


@router.post("/cases")
def create_case(body: CaseIn, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    _validate(None, body.priority, body.tlp)
    case = Case(title=body.title.strip(), description=body.description, priority=body.priority, tlp=body.tlp, owner_id=user.id, created_by=user.id)
    db.add(case)
    db.flush()
    audit(db, request, user, "case.create", "case", case.id, title=case.title)
    db.commit()
    return {"id": case.id}


@router.get("/cases/{case_id}")
def case_detail(case_id: int, db: Session = Depends(get_db), user: User = Depends(viewer)):
    return _expanded(db, _get(db, case_id))


@router.patch("/cases/{case_id}")
def update_case(case_id: int, body: CasePatch, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    case = _get(db, case_id)
    _validate(body.status, body.priority, body.tlp)
    changes = body.model_dump(exclude_none=True)
    for key, value in changes.items():
        setattr(case, key, value)
    if body.status is not None:
        case.closed_at = utcnow() if body.status == "closed" else None
    case.updated_at = utcnow()
    audit(db, request, user, "case.update", "case", case.id, **{k: v for k, v in changes.items() if k != "description"})
    db.commit()
    return {"ok": True}


@router.delete("/cases/{case_id}")
def delete_case(case_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(admin)):
    case = _get(db, case_id)
    audit(db, request, user, "case.delete", "case", case.id, title=case.title)
    db.delete(case)
    db.commit()
    return {"ok": True}


@router.post("/cases/{case_id}/items")
def add_item(case_id: int, body: ItemIn, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    case = _get(db, case_id)
    if body.object_type == "finding":
        exists = db.get(Document, parse_uuid(body.object_id))
    elif body.object_type in ("query", "graph"):
        # A saved hunt (the query lives in the note) or a bookmarked graph node.
        if body.object_type == "query" and not body.note.strip():
            raise HTTPException(400, "A saved hunt needs its query")
        exists = True
    elif body.object_type in ("ioc", "entity") and body.object_id.isdigit():
        exists = db.get(Ioc if body.object_type == "ioc" else Entity, int(body.object_id))
    elif body.object_type == "chain":
        exists = True  # a wallet address; the chain tables fill in when it is looked up
    else:
        raise HTTPException(400, "object_type must be finding, ioc, entity, query, graph or chain")
    if exists is None:
        raise HTTPException(404, "Object not found")
    if db.scalar(select(CaseItem.id).where(CaseItem.case_id == case.id, CaseItem.object_type == body.object_type, CaseItem.object_id == body.object_id)):
        raise HTTPException(409, "Already in this case")
    db.add(CaseItem(case_id=case.id, object_type=body.object_type, object_id=body.object_id, note=body.note, added_by=user.id))
    case.updated_at = utcnow()
    audit(db, request, user, "case.add_item", "case", case.id, object_type=body.object_type, object_id=body.object_id)
    db.commit()
    return {"ok": True}


@router.delete("/cases/{case_id}/items/{item_id}")
def remove_item(case_id: int, item_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    item = db.get(CaseItem, item_id)
    if item is None or item.case_id != case_id:
        raise HTTPException(404, "Not found")
    audit(db, request, user, "case.remove_item", "case", case_id, object_type=item.object_type, object_id=item.object_id)
    db.delete(item)
    db.commit()
    return {"ok": True}


@router.get("/cases/{case_id}/report")
def case_report(case_id: int, request: Request, format: str = "html", db: Session = Depends(get_db), user: User = Depends(viewer)):
    data = _expanded(db, _get(db, case_id))
    audit(db, request, user, "case.report", "case", case_id, format=format)
    db.commit()
    name = f"kivuli-case-{case_id}"
    if format == "html":
        return HTMLResponse(render.to_html(data, settings.app_name, user.name or user.email),
                            headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})
    if format == "json":
        return Response(json.dumps(data, indent=2), media_type="application/json", headers={"Content-Disposition": f'attachment; filename="{name}.json"'})
    if format == "csv":
        return Response(render.to_csv(data), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="{name}-indicators.csv"'})
    if format == "stix":
        return Response(json.dumps(stix.case_bundle(data), indent=2), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{name}-stix.json"'})
    raise HTTPException(400, "format must be html, json, csv or stix")


@router.get("/cases/{case_id}/timeline")
def case_timeline(case_id: int, db: Session = Depends(get_db), user: User = Depends(viewer)):
    """Everything that happened in an investigation, in order: what the sources reported, what was collected,
    what alerted, and what analysts did."""
    case = _get(db, case_id)
    users = dict(db.execute(select(User.id, User.name)).all())
    events: list[dict] = [{"at": iso(case.created_at), "kind": "case", "text": "Case opened", "who": users.get(case.created_by or 0, "")}]
    items = db.scalars(select(CaseItem).where(CaseItem.case_id == case.id)).all()
    finding_ids = [parse_uuid(i.object_id) for i in items if i.object_type == "finding"]
    docs = {str(d.id): d for d in db.scalars(select(Document).where(Document.id.in_(finding_ids))).unique()} if finding_ids else {}
    for doc in docs.values():
        if doc.published_at:
            events.append({"at": iso(doc.published_at), "kind": "reported", "text": f"Reported by {doc.source.name}: {doc.title}", "finding_id": str(doc.id)})
        events.append({"at": iso(doc.first_seen_at), "kind": "collected", "text": f"Collected: {doc.title}", "finding_id": str(doc.id)})
        if doc.version_count > 1:
            events.append({"at": iso(doc.last_changed_at), "kind": "changed", "text": f"Source changed the page (version {doc.version_count}): {doc.title}", "finding_id": str(doc.id)})
    if finding_ids:
        for alert in db.scalars(select(Alert).where(Alert.document_id.in_(finding_ids))).unique():
            events.append({"at": iso(alert.created_at), "kind": "alert", "text": f"Alert ({alert.severity}): {alert.matched}", "finding_id": str(alert.document_id)})
    labels = {"finding": "Finding", "ioc": "Indicator", "entity": "Entity", "query": "Saved hunt", "graph": "Graph bookmark", "evidence": "Evidence preserved"}
    pinned = {kind: [int(i.object_id) for i in items if i.object_type == kind and i.object_id.isdigit()] for kind in ("ioc", "entity")}
    names = {("entity", str(e.id)): e.name for e in db.scalars(select(Entity).where(Entity.id.in_(pinned["entity"])))} if pinned["entity"] else {}
    names.update({("ioc", str(i.id)): defang(i.value) for i in db.scalars(select(Ioc).where(Ioc.id.in_(pinned["ioc"])))} if pinned["ioc"] else {})
    for item in items:
        subject = (docs[item.object_id].title if item.object_type == "finding" and item.object_id in docs
                   else names.get((item.object_type, item.object_id)) or item.note or item.object_id)
        if item.object_type == "evidence":
            page = docs.get(item.object_id.split(":")[0])
            events.append({"at": iso(item.added_at), "kind": "evidence", "text": f"Evidence preserved: {(page.title if page else item.note or 'a capture')[:160]}",
                           "who": users.get(item.added_by or 0, ""), "finding_id": item.object_id.split(":")[0]})
            continue
        events.append({"at": iso(item.added_at), "kind": "added", "text": f"{labels.get(item.object_type, item.object_type)} added: {subject[:160]}", "who": users.get(item.added_by or 0, "")})
    for note in db.scalars(select(Note).where(Note.object_type == "case", Note.object_id == str(case.id))):
        events.append({"at": iso(note.created_at), "kind": "note", "text": note.body[:400], "who": note.user_name})
    for row in db.scalars(select(AuditLog).where(AuditLog.object_type == "case", AuditLog.object_id == str(case.id), AuditLog.action == "case.update")):
        changes = ", ".join(f"{k} set to {v}" for k, v in (row.detail or {}).items() if k in ("status", "priority", "tlp"))
        if changes:
            events.append({"at": iso(row.ts), "kind": "status", "text": changes.capitalize(), "who": row.user_email})
    events.sort(key=lambda e: e["at"] or "")
    return events
