"""Threat-exposure intelligence: identity exposure, attack surface and vulnerabilities."""
import csv
import io

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select, update
from sqlalchemy.orm import Session

from app.api.common import csv_safe, finding_summary, iso, paginate
from app.db import get_db
from app.intel.priority import RISKY_PORTS
from app.models import (EXPOSURE_KINDS, EXPOSURE_STATUSES, Asset, Document, DocumentEntity, DocumentIoc, Entity, Exposure, Ioc, User,
                        Vulnerability, Watchlist)
from app.security import analyst, audit, viewer
from app.worker.celery_app import enqueue

router = APIRouter(tags=["exposure"])


def _owned_domains(db: Session) -> list[str]:
    return [w.value.lower() for w in db.scalars(select(Watchlist).where(Watchlist.kind == "domain", Watchlist.is_active.is_(True)))]


def _mine(domains: list[str]):
    """Exposures whose mailbox domain or service host is one the organisation watches."""
    clauses = []
    for d in domains:
        clauses += [Exposure.domain == d, Exposure.domain.like(f"%.{d}"), Exposure.service == d, Exposure.service.like(f"%.{d}")]
    return or_(*clauses) if clauses else Exposure.id < 0


def _exposure_filters(stmt, db: Session, kind, status, domain, q, mine):
    if kind:
        stmt = stmt.where(Exposure.kind.in_(kind))
    if status:
        stmt = stmt.where(Exposure.status.in_(status))
    if domain:
        d = domain.lower().strip()
        stmt = stmt.where(or_(Exposure.domain == d, Exposure.domain.like(f"%.{d}"), Exposure.service.like(f"%{d}")))
    if q.strip():
        needle = f"%{q.strip().lower()}%"
        stmt = stmt.where(or_(func.lower(Exposure.identity).like(needle), Exposure.domain.like(needle), Exposure.service.like(needle), Exposure.fingerprint.like(needle)))
    if mine:
        stmt = stmt.where(_mine(_owned_domains(db)))
    return stmt


def _exposure_out(e: Exposure) -> dict:
    d = e.document
    return {"id": e.id, "kind": e.kind, "identity": e.identity, "domain": e.domain, "service": e.service, "secret_type": e.secret_type,
            "fingerprint": e.fingerprint, "password_exposed": e.password_exposed, "status": e.status, "first_seen": iso(e.first_seen_at),
            "last_seen": iso(e.last_seen_at),
            "finding": {"id": str(d.id), "title": d.title, "source_name": d.source.name, "network": d.network, "threat_type": d.threat_type,
                        "risk_score": d.risk_score, "verification": d.verification}}


@router.get("/exposures")
def list_exposures(kind: list[str] = Query(default=[]), status: list[str] = Query(default=[]), domain: str = "", q: str = Query("", max_length=200),
                   mine: bool = False, page: int = 1, size: int = 50, db: Session = Depends(get_db), user: User = Depends(viewer)):
    stmt = _exposure_filters(select(Exposure), db, kind, status, domain, q, mine)
    size = max(1, min(size, 200))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(Exposure.last_seen_at.desc(), Exposure.id.desc()).limit(size).offset((max(1, page) - 1) * size)).unique().all()
    owned = _owned_domains(db)
    return {
        "total": total, "kinds": EXPOSURE_KINDS, "statuses": EXPOSURE_STATUSES, "owned_domains": owned,
        "by_kind": dict(db.execute(select(Exposure.kind, func.count()).where(Exposure.status == "open").group_by(Exposure.kind)).all()),
        "by_status": dict(db.execute(select(Exposure.status, func.count()).group_by(Exposure.status)).all()),
        "open_mine": db.scalar(select(func.count()).select_from(Exposure).where(Exposure.status == "open", _mine(owned))) or 0,
        "top_domains": [{"value": r[0], "count": r[1]} for r in db.execute(
            select(Exposure.domain, func.count()).where(Exposure.status == "open", Exposure.domain != "").group_by(Exposure.domain)
            .order_by(func.count().desc()).limit(12))],
        "items": [_exposure_out(e) for e in rows],
    }


class ExposurePatch(BaseModel):
    ids: list[int] = Field(min_length=1, max_length=1000)
    status: str


@router.post("/exposures/status")
def set_exposure_status(body: ExposurePatch, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    if body.status not in EXPOSURE_STATUSES:
        raise HTTPException(400, "Unknown status")
    changed = db.execute(update(Exposure).where(Exposure.id.in_(body.ids)).values(status=body.status)).rowcount
    audit(db, request, user, "exposure.status", "exposure", "", status=body.status, count=changed)
    db.commit()
    return {"ok": True, "changed": changed}


@router.get("/exposures/export")
def export_exposures(request: Request, kind: list[str] = Query(default=[]), status: list[str] = Query(default=[]), domain: str = "", q: str = "",
                     mine: bool = False, db: Session = Depends(get_db), user: User = Depends(viewer)):
    rows = db.scalars(_exposure_filters(select(Exposure), db, kind, status, domain, q, mine).order_by(Exposure.last_seen_at.desc()).limit(20000)).unique().all()
    audit(db, request, user, "exposure.export", "exposure", "", count=len(rows))
    db.commit()
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["kind", "identity", "domain", "service", "secret_type", "fingerprint_sha256_prefix", "password_exposed", "status", "first_seen", "last_seen", "finding", "source"])
    for e in rows:
        cells = [e.kind, e.identity, e.domain, e.service, e.secret_type, e.fingerprint, e.password_exposed, e.status, iso(e.first_seen_at), iso(e.last_seen_at), e.document.title, e.document.source.name]
        writer.writerow([csv_safe(c) for c in cells])
    return Response(buffer.getvalue(), media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="kivuli-exposures.csv"'})


# ── Attack surface ──────────────────────────────────────────────────────────

def _asset_out(a: Asset) -> dict:
    return {"id": a.id, "host": a.host, "ips": a.ips, "ports": a.ports, "risky_ports": [{"port": p, "service": RISKY_PORTS[p]} for p in a.ports or [] if p in RISKY_PORTS],
            "cpes": a.cpes, "tags": a.tags, "vulns": a.vulns, "asn": a.asn, "discovered_via": a.discovered_via, "risk": a.risk,
            "risk_factors": a.risk_factors, "first_seen": iso(a.first_seen_at), "last_seen": iso(a.last_seen_at), "last_scanned": iso(a.last_scanned_at),
            "error": (a.meta or {}).get("error", ""), "watchlist": {"id": a.watchlist.id, "name": a.watchlist.name, "value": a.watchlist.value,
                                                                     "criticality": a.watchlist.criticality}}


@router.get("/attack-surface")
def attack_surface(watchlist_id: int | None = None, q: str = Query("", max_length=200), exposed: bool = False, page: int = 1, size: int = 50,
                   db: Session = Depends(get_db), user: User = Depends(viewer)):
    stmt = select(Asset)
    if watchlist_id:
        stmt = stmt.where(Asset.watchlist_id == watchlist_id)
    if q.strip():
        needle = f"%{q.strip().lower()}%"
        stmt = stmt.where(or_(Asset.host.like(needle), func.array_to_string(Asset.ips, " ").like(needle), func.array_to_string(Asset.vulns, " ").ilike(needle)))
    if exposed:
        stmt = stmt.where(Asset.risk > 0)
    size = max(1, min(size, 200))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(Asset.risk.desc(), Asset.host).limit(size).offset((max(1, page) - 1) * size)).unique().all()
    kev = set(db.scalars(select(Vulnerability.cve).where(Vulnerability.kev.is_(True), Vulnerability.exposed_assets > 0)))
    owned = db.scalars(select(Watchlist).where(Watchlist.is_asset.is_(True), Watchlist.kind.in_(("domain", "ip"))).order_by(Watchlist.name)).all()
    counts = dict(db.execute(select(Asset.watchlist_id, func.count()).group_by(Asset.watchlist_id)).all())
    ports = db.execute(select(func.unnest(Asset.ports).label("p"), func.count()).group_by("p").order_by(func.count().desc()).limit(15)).all()
    return {
        "total": total, "items": [{**_asset_out(a), "kev_vulns": sorted(set(a.vulns or []) & kev)} for a in rows],
        "summary": {
            "hosts": db.scalar(select(func.count()).select_from(Asset)) or 0,
            "resolving": db.scalar(select(func.count()).select_from(Asset).where(func.cardinality(Asset.ips) > 0)) or 0,
            "at_risk": db.scalar(select(func.count()).select_from(Asset).where(Asset.risk >= 40)) or 0,
            "with_kev": db.scalar(select(func.count()).select_from(Asset).where(Asset.vulns.overlap(list(kev)))) if kev else 0,
            "ports": [{"port": p, "count": n, "service": RISKY_PORTS.get(p, "")} for p, n in ports],
        },
        "owned": [{"id": w.id, "name": w.name, "kind": w.kind, "value": w.value, "criticality": w.criticality, "hosts": counts.get(w.id, 0),
                   "last_scanned": iso(w.last_scanned_at)} for w in owned],
    }


class ScanIn(BaseModel):
    watchlist_id: int


@router.post("/attack-surface/scan")
def scan(body: ScanIn, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    """Start passive discovery for an owned asset: certificate logs, public DNS and scan-data lookups. Nothing is probed."""
    watch = db.get(Watchlist, body.watchlist_id)
    if watch is None or not watch.is_asset or watch.kind not in ("domain", "ip"):
        raise HTTPException(400, "Mark a domain or IP range as an owned asset first")
    enqueue("pipeline.asm_scan", watchlist_id=watch.id)
    audit(db, request, user, "asm.scan", "watchlist", watch.id, value=watch.value)
    db.commit()
    return {"ok": True}


# ── Vulnerabilities ─────────────────────────────────────────────────────────

def _vuln_out(v: Vulnerability) -> dict:
    return {"cve": v.cve, "title": v.title, "vendor": v.vendor, "product": v.product, "description": v.description, "cvss": v.cvss,
            "cvss_vector": v.cvss_vector, "epss": v.epss, "epss_percentile": v.epss_percentile, "kev": v.kev, "kev_added": iso(v.kev_added),
            "kev_due": iso(v.kev_due), "ransomware_use": v.ransomware_use, "mention_count": v.mention_count, "last_mentioned": iso(v.last_mentioned_at),
            "exposed_assets": v.exposed_assets, "priority": v.priority, "priority_factors": v.priority_factors, "enriched_at": iso(v.enriched_at)}


@router.get("/vulnerabilities")
def list_vulnerabilities(q: str = Query("", max_length=200), kev: bool = False, exposed: bool = False, mentioned: bool = False, sort: str = "priority",
                         page: int = 1, size: int = 50, db: Session = Depends(get_db), user: User = Depends(viewer)):
    stmt = select(Vulnerability)
    if q.strip():
        needle = f"%{q.strip()}%"
        stmt = stmt.where(or_(Vulnerability.cve.ilike(needle), Vulnerability.vendor.ilike(needle), Vulnerability.product.ilike(needle), Vulnerability.title.ilike(needle)))
    if kev:
        stmt = stmt.where(Vulnerability.kev.is_(True))
    if exposed:
        stmt = stmt.where(Vulnerability.exposed_assets > 0)
    if mentioned:
        stmt = stmt.where(Vulnerability.mention_count > 0)
    order = {"epss": (Vulnerability.epss.desc().nulls_last(),), "recent": (Vulnerability.kev_added.desc().nulls_last(),),
             "mentions": (Vulnerability.mention_count.desc(),), "cvss": (Vulnerability.cvss.desc().nulls_last(),)}.get(sort, (Vulnerability.priority.desc(),))
    size = max(1, min(size, 200))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(*order, Vulnerability.cve.desc()).limit(size).offset((max(1, page) - 1) * size)).all()
    count = lambda *where: db.scalar(select(func.count()).select_from(Vulnerability).where(*where)) or 0  # noqa: E731
    return {"total": total, "items": [_vuln_out(v) for v in rows], "summary": {
        "tracked": count(), "kev": count(Vulnerability.kev.is_(True)), "exposed": count(Vulnerability.exposed_assets > 0),
        "mentioned": count(Vulnerability.mention_count > 0), "high_epss": count(Vulnerability.epss >= 0.5)}}


@router.get("/vulnerabilities/{cve}")
def vulnerability_detail(cve: str, db: Session = Depends(get_db), user: User = Depends(viewer)):
    v = db.get(Vulnerability, cve.upper())
    if v is None:
        raise HTTPException(404, "Vulnerability not tracked")
    ioc = db.scalar(select(Ioc).where(Ioc.type == "cve", Ioc.value == v.cve))
    findings, entities = [], []
    if ioc is not None:
        docs = db.scalars(select(Document).join(DocumentIoc, DocumentIoc.document_id == Document.id).where(DocumentIoc.ioc_id == ioc.id)
                          .order_by(Document.first_seen_at.desc()).limit(40)).unique().all()
        findings = [finding_summary(d) for d in docs]
        doc_ids = select(DocumentIoc.document_id).where(DocumentIoc.ioc_id == ioc.id)
        entities = [{"id": r.id, "type": r.type, "name": r.name, "shared": r.shared} for r in db.execute(
            select(Entity.id, Entity.type, Entity.name, func.count().label("shared")).join(DocumentEntity, DocumentEntity.entity_id == Entity.id)
            .where(DocumentEntity.document_id.in_(doc_ids), Entity.type.in_(("actor", "malware", "campaign", "technique")))
            .group_by(Entity.id).order_by(func.count().desc()).limit(30))]
    assets = db.scalars(select(Asset).where(Asset.vulns.any(v.cve)).order_by(Asset.risk.desc()).limit(100)).unique().all()
    return {**_vuln_out(v), "ioc_id": ioc.id if ioc else None, "findings": findings, "related": entities, "assets": [_asset_out(a) for a in assets]}
