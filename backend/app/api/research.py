"""The research workstation: collection status, research crawls, source profiles, page history and the command-centre feed."""
import json
from datetime import timedelta

import redis
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.common import finding_summary, get_document, iso
from app.config import get_settings
from app.crawl.blocklist import BLOCKLIST_META
from app.db import get_db
from app.extract.iocs import defang
from app.extract.lang import LANGUAGE_NAMES
from app.intel import crawls, settings_store
from app.models import (Alert, Case, CaseItem, CrawlJob, CrawlLog, Document, DocumentEntity, DocumentVersion, Entity, Source, SourceLink, User,
                        Watchlist, utcnow)
from app.security import admin, analyst, audit, viewer
from app.worker.celery_app import celery_app, enqueue

router = APIRouter(tags=["research"])
settings = get_settings()
_redis = redis.Redis.from_url(settings.redis_url, decode_responses=True)


def source_state(s: Source) -> str:
    """online | degraded | offline | unknown"""
    if s.is_live is None:
        return "unknown"
    if not s.is_live:
        return "offline"
    return "degraded" if s.consecutive_failures or (s.status == "approved" and s.last_error) else "online"


def _source_brief(s: Source) -> dict:
    return {"id": s.id, "name": s.name, "title": s.title, "host": s.host, "network": s.network, "category": s.category, "status": s.status,
            "state": source_state(s), "doc_count": s.doc_count, "relevance": s.relevance, "created_at": iso(s.created_at),
            "last_live_at": iso(s.last_live_at), "discovery_context": s.discovery_context}


# ── Collection status ───────────────────────────────────────────────────────

def _collectors() -> dict:
    """Which worker roles answer right now. Cached briefly: asking takes a second."""
    cached = _redis.get("kivuli:status:collectors")
    if cached:
        return json.loads(cached)
    try:
        replies = celery_app.control.inspect(timeout=1.2).ping() or {}
    except Exception:
        replies = {}
    roles: dict[str, int] = {}
    for name in replies:
        roles[name.split("@")[0]] = roles.get(name.split("@")[0], 0) + 1
    expected = ("crawler", "pipeline", "enricher", "notify")
    out = {"online": sum(1 for r in expected if roles.get(r)), "expected": len(expected), "roles": {r: roles.get(r, 0) for r in expected}}
    _redis.set("kivuli:status:collectors", json.dumps(out), ex=20)
    return out


def collection_status(db: Session) -> dict:
    now = utcnow()
    day = now - timedelta(hours=24)
    tor = json.loads(_redis.get("kivuli:status:tor") or "null") or {"ok": False, "error": "no Tor check has completed yet"}
    states: dict[str, dict[str, int]] = {"onion": {}, "surface": {}}
    for s in db.scalars(select(Source).where(Source.status == "approved")):
        bucket = states.setdefault(s.network, {})
        bucket[source_state(s)] = bucket.get(source_state(s), 0) + 1
    count = lambda *where: db.scalar(select(func.count()).select_from(Source).where(*where)) or 0  # noqa: E731
    logs = lambda *where: db.scalar(select(func.count()).select_from(CrawlLog).where(CrawlLog.fetched_at >= day, CrawlLog.probe.is_(False), *where)) or 0  # noqa: E731
    blocklist = json.loads(_redis.get(BLOCKLIST_META) or "null")
    return {
        "tor": {"online": bool(tor.get("ok") and tor.get("is_tor")), "exit_ip": tor.get("exit_ip", ""), "latency_ms": tor.get("latency_ms"),
                "checked_at": tor.get("checked_at"), "error": tor.get("error", "")},
        "collectors": _collectors(),
        "sources": {"active": count(Source.status == "approved"), "active_onion": count(Source.status == "approved", Source.network == "onion"),
                    "candidates": count(Source.status == "candidate"), "candidates_onion": count(Source.status == "candidate", Source.network == "onion"),
                    "offline": count(Source.status == "approved", Source.is_live.is_(False)), "blocked": count(Source.status == "blocked"),
                    "states": states},
        "queue": {"crawl": _redis.llen("crawl"), "pipeline": _redis.llen("pipeline"), "enrich": _redis.llen("enrich")},
        "pages": {"indexed": db.scalar(select(func.count()).select_from(Document)) or 0,
                  "onion": db.scalar(select(func.count()).select_from(Document).where(Document.network == "onion")) or 0,
                  "new_24h": db.scalar(select(func.count()).select_from(Document).where(Document.first_seen_at >= day)) or 0},
        "last_collection": iso(db.scalar(select(func.max(CrawlLog.fetched_at)).where(CrawlLog.ok.is_(True), CrawlLog.probe.is_(False)))),
        "fetches_24h": logs(), "failed_24h": logs(CrawlLog.ok.is_(False)),
        "crawls_running": db.scalar(select(func.count()).select_from(CrawlJob).where(CrawlJob.status == "running")) or 0,
        "blocklist": blocklist or {"count": 0, "updated_at": None},
        "policy": settings_store.get(db, "collection"),
    }


@router.get("/collection/status")
def get_collection_status(db: Session = Depends(get_db), user: User = Depends(viewer)):
    return collection_status(db)


class CollectionSettingsIn(BaseModel):
    auto_approve: str | None = None
    relevance_threshold: int | None = None
    max_onion_sources: int | None = None
    discovery_groups_per_run: int | None = None
    research_max_depth: int | None = None
    research_max_pages: int | None = None


@router.get("/settings/collection")
def get_collection_settings(db: Session = Depends(get_db), user: User = Depends(viewer)):
    return {"values": settings_store.get(db, "collection"), "auto_approve_options": settings_store.AUTO_APPROVE, "can_edit": user.role == "admin"}


@router.put("/settings/collection")
def put_collection_settings(body: CollectionSettingsIn, request: Request, db: Session = Depends(get_db), user: User = Depends(admin)):
    try:
        values = settings_store.put(db, "collection", body.model_dump(exclude_none=True), user.id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    audit(db, request, user, "settings.collection", "settings", "collection", **body.model_dump(exclude_none=True))
    db.commit()
    enqueue("pipeline.apply_policy")  # sites that were waiting may now qualify
    return {"values": values}


# ── Research crawls ─────────────────────────────────────────────────────────

class CrawlIn(BaseModel):
    url: str = Field(min_length=8, max_length=2048)
    depth: int = Field(1, ge=0, le=6)
    max_pages: int = Field(50, ge=1, le=2000)
    monitor: bool = False  # keep collecting from this site on a schedule afterwards
    case_id: int | None = None
    note: str = Field("", max_length=500)


def _job_out(job: CrawlJob, progress: dict, users: dict[int, str]) -> dict:
    p = progress.get(job.run_id, {})
    return {"id": job.id, "url": job.url, "depth": job.depth, "max_pages": job.max_pages, "status": job.status, "note": job.note, "case_id": job.case_id,
            "created_at": iso(job.created_at), "finished_at": iso(job.finished_at), "created_by": users.get(job.created_by or 0, ""),
            "source": {"id": job.source.id, "name": job.source.name, "host": job.source.host, "network": job.source.network, "status": job.source.status},
            "progress": {**p, "last_activity": iso(p.get("last_activity"))}}


@router.post("/crawls")
def start_crawl(body: CrawlIn, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    """Start a research crawl from one URL. It stays on that site, reads text only, and follows links to the chosen depth."""
    url = body.url.strip()
    if "://" not in url:
        url = "http://" + url
    if body.case_id is not None and db.get(Case, body.case_id) is None:
        raise HTTPException(404, "Investigation not found")
    try:
        job = crawls.start(db, url=url, depth=body.depth, max_pages=body.max_pages, user_id=user.id, monitor=body.monitor, case_id=body.case_id, note=body.note)
    except crawls.CrawlRefused as exc:
        raise HTTPException(400, f"Not crawled: {exc}") from None
    audit(db, request, user, "crawl.start", "crawl", job.id, url=url[:300], depth=job.depth, max_pages=job.max_pages, monitor=body.monitor)
    db.commit()
    return _job_out(job, crawls.progress(db, [job.run_id]), {user.id: user.name})


@router.get("/crawls")
def list_crawls(status: str | None = None, source_id: int | None = None, db: Session = Depends(get_db), user: User = Depends(viewer)):
    stmt = select(CrawlJob)
    if status:
        stmt = stmt.where(CrawlJob.status == status)
    if source_id:
        stmt = stmt.where(CrawlJob.source_id == source_id)
    jobs = db.scalars(stmt.order_by(CrawlJob.created_at.desc()).limit(60)).unique().all()
    for job in jobs:
        crawls.settle(db, job)
    db.commit()
    users = dict(db.execute(select(User.id, User.name)).all())
    progress = crawls.progress(db, [j.run_id for j in jobs])
    return [_job_out(j, progress, users) for j in jobs]


@router.get("/crawls/{job_id}")
def crawl_detail(job_id: int, db: Session = Depends(get_db), user: User = Depends(viewer)):
    """A crawl and every page it has reached so far, with what led to each one."""
    job = db.get(CrawlJob, job_id)
    if job is None:
        raise HTTPException(404, "Crawl not found")
    crawls.settle(db, job)
    db.commit()
    rows = db.scalars(select(CrawlLog).where(CrawlLog.run_id == job.run_id).order_by(CrawlLog.fetched_at).limit(2500)).all()
    urls = [r.url for r in rows]
    docs = {d.url: d for d in db.scalars(select(Document).where(Document.source_id == job.source_id, Document.url.in_(urls))).unique()} if urls else {}
    pages = []
    for r in rows:
        doc = docs.get(r.url)
        pages.append({"url": r.url, "parent": r.parent_url, "depth": r.depth, "ok": r.ok, "http_status": r.http_status, "error": r.error,
                      "fetched_at": iso(r.fetched_at), "bytes": r.bytes, "new": r.new_docs, "changed": r.changed_docs,
                      "finding_id": str(doc.id) if doc else None, "title": doc.title if doc else "", "risk_score": doc.risk_score if doc else None})
    found = db.scalars(select(Source).where(Source.discovered_from_id == job.source_id, Source.created_at >= job.created_at).order_by(Source.created_at).limit(200)).all()
    users = dict(db.execute(select(User.id, User.name)).all())
    return {**_job_out(job, crawls.progress(db, [job.run_id]), users), "pages": pages, "discovered_sources": [_source_brief(s) for s in found]}


@router.post("/crawls/{job_id}/stop")
def stop_crawl(job_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    job = db.get(CrawlJob, job_id)
    if job is None:
        raise HTTPException(404, "Crawl not found")
    crawls.stop(db, job)
    audit(db, request, user, "crawl.stop", "crawl", job.id)
    db.commit()
    return {"ok": True}


# ── Source explorer ─────────────────────────────────────────────────────────

@router.get("/sources/suggest")
def suggest_sources(q: str = Query(..., min_length=2, max_length=200), db: Session = Depends(get_db), user: User = Depends(viewer)):
    """Known sites that are not being collected yet and whose name, title or discovery context matches: places a search has not reached."""
    # Words every leak site's name contains say nothing about which site covers a query.
    generic = {"leak", "leaks", "site", "sites", "ransomware", "onion", "and", "not", "the", "data", "dark", "web"}
    words = [w for w in q.lower().replace('"', " ").split() if len(w) > 2 and ":" not in w and w not in generic][:6]
    if not words:
        return []
    haystack = func.lower(func.concat(Source.name, " ", Source.title, " ", Source.discovery_context, " ", Source.host))
    rows = db.scalars(select(Source).where(Source.status.in_(("candidate", "paused")), or_(*[haystack.like(f"%{w}%") for w in words]))
                      .order_by(Source.relevance.desc(), Source.is_live.desc().nulls_last()).limit(8)).all()
    return [_source_brief(s) for s in rows]


@router.get("/sources/{source_id}/profile")
def source_profile(source_id: int, db: Session = Depends(get_db), user: User = Depends(viewer)):
    """Everything known about one source: what it is, when it has been up, what was found there and what it connects to."""
    s = db.get(Source, source_id)
    if s is None:
        raise HTTPException(404, "Source not found")
    now = utcnow()
    month = now - timedelta(days=30)
    # Availability: one row per day from top-level fetches and liveness checks.
    days = db.execute(
        select(func.date_trunc("day", CrawlLog.fetched_at).label("day"), func.count(), func.count().filter(CrawlLog.http_status.isnot(None)))
        .where(CrawlLog.source_id == s.id, CrawlLog.depth == 0, CrawlLog.fetched_at >= month).group_by("day").order_by("day")).all()
    checks, answered = sum(r[1] for r in days), sum(r[2] for r in days)
    docs = db.scalars(select(Document).where(Document.source_id == s.id).order_by(Document.last_seen_at.desc()).limit(200)).unique().all()
    span = db.execute(select(func.min(Document.first_seen_at), func.max(Document.last_seen_at), func.count()).where(Document.source_id == s.id)).one()
    stale_after = timedelta(minutes=max(s.crawl_interval_minutes * 3, 720))
    pages = [{**finding_summary(d), "missing": bool(s.last_crawled_at and d.last_seen_at < s.last_crawled_at - stale_after)} for d in docs]

    outbound = db.execute(select(SourceLink, Source).outerjoin(Source, Source.host == SourceLink.dst_host).where(SourceLink.src_source_id == s.id)
                          .order_by(SourceLink.count.desc()).limit(60)).all()
    inbound = db.execute(select(SourceLink, Source).join(Source, Source.id == SourceLink.src_source_id).where(SourceLink.dst_host == s.host)
                         .order_by(SourceLink.count.desc()).limit(60)).all()
    entities = db.execute(
        select(Entity.id, Entity.type, Entity.name, func.count().label("n")).join(DocumentEntity, DocumentEntity.entity_id == Entity.id)
        .join(Document, Document.id == DocumentEntity.document_id).where(Document.source_id == s.id, Entity.type != "incident")
        .group_by(Entity.id).order_by(func.count().desc()).limit(40)).all()
    jobs = db.scalars(select(CrawlJob).where(CrawlJob.source_id == s.id).order_by(CrawlJob.created_at.desc()).limit(10)).unique().all()
    runs = db.execute(
        select(CrawlLog.run_id, func.min(CrawlLog.fetched_at), func.count(), func.count().filter(CrawlLog.ok.is_(True)), func.coalesce(func.sum(CrawlLog.new_docs), 0),
               func.coalesce(func.sum(CrawlLog.changed_docs), 0))
        .where(CrawlLog.source_id == s.id, CrawlLog.probe.is_(False)).group_by(CrawlLog.run_id).order_by(func.min(CrawlLog.fetched_at).desc()).limit(15)).all()
    parent = db.get(Source, s.discovered_from_id) if s.discovered_from_id else None
    users = dict(db.execute(select(User.id, User.name)).all())
    return {
        **_source_brief(s), "url": s.url, "route": s.route, "connector": s.connector, "trust": s.trust, "language": s.language,
        "language_name": LANGUAGE_NAMES.get(s.language, ""), "notes": s.notes, "crawl_interval_minutes": s.crawl_interval_minutes, "max_depth": s.max_depth,
        "max_pages": s.max_pages, "last_error": s.last_error, "last_checked_at": iso(s.last_checked_at), "last_crawled_at": iso(s.last_crawled_at),
        "last_changed_at": iso(s.last_changed_at), "defanged": defang(s.url),
        "discovered_from": {"id": parent.id, "name": parent.name} if parent else None,
        "observed": {"first": iso(span[0] or s.created_at), "last": iso(span[1] or s.last_live_at), "pages": span[2]},
        "availability": {"checks_30d": checks, "answered_30d": answered, "percent": round(100 * answered / checks) if checks else None,
                         "days": [{"date": iso(r[0]), "checks": r[1], "answered": r[2]} for r in days]},
        "pages": pages,
        "links_out": [{"host": link.dst_host, "count": link.count, "last_seen": iso(link.last_seen_at),
                       "source": _source_brief(target) if target else None} for link, target in outbound],
        "links_in": [{"count": link.count, "last_seen": iso(link.last_seen_at), "source": _source_brief(origin)} for link, origin in inbound],
        "entities": [{"id": r.id, "type": r.type, "name": r.name, "count": r.n} for r in entities],
        "crawls": [_job_out(j, crawls.progress(db, [j.run_id]), users) for j in jobs],
        "runs": [{"run_id": r[0], "at": iso(r[1]), "fetched": r[2], "ok": r[3], "new": int(r[4]), "changed": int(r[5])} for r in runs],
    }


# ── Page history ────────────────────────────────────────────────────────────

@router.get("/findings/{finding_id}/observations")
def observations(finding_id: str, db: Session = Depends(get_db), user: User = Depends(viewer)):
    """When this page was seen, when it changed, and whether it is still there."""
    doc = get_document(db, finding_id)
    s = doc.source
    rows = db.execute(
        select(func.date_trunc("day", CrawlLog.fetched_at).label("day"), func.count(), func.count().filter(CrawlLog.ok.is_(True)),
               func.max(CrawlLog.http_status), func.sum(CrawlLog.changed_docs))
        .where(CrawlLog.source_id == doc.source_id, func.md5(CrawlLog.url) == func.md5(doc.url), CrawlLog.probe.is_(False))
        .group_by("day").order_by("day")).all()
    versions = db.execute(select(DocumentVersion.version, DocumentVersion.captured_at).where(DocumentVersion.document_id == doc.id)
                          .order_by(DocumentVersion.version)).all()
    last = db.execute(select(CrawlLog.ok, CrawlLog.http_status, CrawlLog.fetched_at, CrawlLog.error)
                      .where(CrawlLog.source_id == doc.source_id, func.md5(CrawlLog.url) == func.md5(doc.url), CrawlLog.probe.is_(False))
                      .order_by(CrawlLog.fetched_at.desc()).limit(1)).first()
    stale_after = timedelta(minutes=max(s.crawl_interval_minutes * 3, 720))
    if s.connector != "html":
        status, detail = "feed", "Reported by a feed: the entry is recorded when the feed lists it, not re-fetched as a page"
    elif last is not None and not last.ok and last.http_status in (404, 410):
        status, detail = "removed", f"The site answered “not found” (HTTP {last.http_status}) on {last.fetched_at:%d %b %Y}"
    elif s.is_live is False:
        status, detail = "source_offline", "The whole site is not answering; the stored copy is the last one captured"
    elif s.last_crawled_at and doc.last_seen_at < s.last_crawled_at - stale_after:
        status, detail = "missing", "The site has been crawled since, and this page was no longer reachable from it"
    elif last is not None and not last.ok:
        status, detail = "unreachable", f"The last fetch failed: {last.error[:120]}"
    else:
        status, detail = "online", "Seen on the most recent crawl"
    return {
        "url": doc.url, "defanged": defang(doc.url), "first_seen": iso(doc.first_seen_at), "last_seen": iso(doc.last_seen_at), "last_changed": iso(doc.last_changed_at),
        "status": status, "detail": detail, "version_count": doc.version_count,
        "days": [{"date": iso(r[0]), "fetches": r[1], "ok": r[2], "http_status": r[3], "changed": bool(r[4])} for r in rows],
        "versions": [{"version": v.version, "captured_at": iso(v.captured_at)} for v in versions],
        "source": _source_brief(s),
    }


class PreserveIn(BaseModel):
    case_id: int
    note: str = Field("", max_length=2000)


@router.post("/findings/{finding_id}/preserve")
def preserve_evidence(finding_id: str, body: PreserveIn, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    """Pin the current capture of a page into an investigation as evidence: the exact version, its hashes, who preserved it and when."""
    doc = get_document(db, finding_id)
    case = db.get(Case, body.case_id)
    if case is None:
        raise HTTPException(404, "Investigation not found")
    version = db.scalar(select(DocumentVersion).where(DocumentVersion.document_id == doc.id).order_by(DocumentVersion.version.desc()).limit(1))
    if version is None:
        raise HTTPException(409, "This finding has no stored capture to preserve")
    ref = f"{doc.id}:{version.version}"
    if db.scalar(select(CaseItem.id).where(CaseItem.case_id == case.id, CaseItem.object_type == "evidence", CaseItem.object_id == ref)):
        raise HTTPException(409, "This capture is already preserved in that investigation")
    db.add(CaseItem(case_id=case.id, object_type="evidence", object_id=ref, note=body.note, added_by=user.id))
    if not db.scalar(select(CaseItem.id).where(CaseItem.case_id == case.id, CaseItem.object_type == "finding", CaseItem.object_id == str(doc.id))):
        db.add(CaseItem(case_id=case.id, object_type="finding", object_id=str(doc.id), note="", added_by=user.id))
    case.updated_at = utcnow()
    audit(db, request, user, "evidence.preserve", "finding", doc.id, case_id=case.id, version=version.version, content_sha256=version.content_sha256)
    db.commit()
    return {"ok": True, "version": version.version, "content_sha256": version.content_sha256, "captured_at": iso(version.captured_at)}


# ── Command centre ──────────────────────────────────────────────────────────

@router.get("/research/home")
def research_home(db: Session = Depends(get_db), user: User = Depends(viewer)):
    """What a researcher needs on opening the workstation: what is new, what matched, what is being worked on, and whether collection is healthy."""
    week = utcnow() - timedelta(days=7)
    base = select(Document).where(Document.duplicate_of.is_(None))
    recent_onion = db.scalars(base.where(Document.network == "onion").order_by(Document.first_seen_at.desc()).limit(8)).unique().all()
    recent = db.scalars(base.order_by(Document.first_seen_at.desc()).limit(8)).unique().all()
    critical = db.scalars(base.where(Document.first_seen_at >= week, Document.risk_score >= 70).order_by(Document.risk_score.desc(), Document.first_seen_at.desc())
                          .limit(6)).unique().all()
    new_sources = db.scalars(select(Source).where(Source.created_at >= week).order_by((Source.network == "onion").desc(), Source.created_at.desc()).limit(8)).all()
    alerts = db.scalars(select(Alert).where(Alert.status == "open").order_by(Alert.created_at.desc()).limit(6)).unique().all()
    open_counts = dict(db.execute(select(Alert.watchlist_id, func.count()).where(Alert.status == "open", Alert.watchlist_id.isnot(None)).group_by(Alert.watchlist_id)).all())
    watches = db.scalars(select(Watchlist).where(Watchlist.is_active.is_(True)).order_by(Watchlist.last_matched_at.desc().nulls_last()).limit(8)).all()
    cases = db.scalars(select(Case).where(Case.status != "closed").order_by(Case.updated_at.desc()).limit(5)).all()
    items = dict(db.execute(select(CaseItem.case_id, func.count()).group_by(CaseItem.case_id)).all())
    jobs = db.scalars(select(CrawlJob).order_by((CrawlJob.status == "running").desc(), CrawlJob.created_at.desc()).limit(5)).unique().all()
    for job in jobs:
        crawls.settle(db, job)
    db.commit()
    users = dict(db.execute(select(User.id, User.name)).all())
    progress = crawls.progress(db, [j.run_id for j in jobs])
    return {
        "collection": collection_status(db),
        "recent_onion": [finding_summary(d) for d in recent_onion], "recent": [finding_summary(d) for d in recent],
        "critical": [finding_summary(d) for d in critical],
        "new_sources": [_source_brief(s) for s in new_sources],
        "matches": [{"id": a.id, "severity": a.severity, "category": a.category, "matched": a.matched, "created_at": iso(a.created_at), "priority": a.priority,
                     "title": a.title or (a.document.title if a.document is not None else a.matched), "finding_id": str(a.document_id) if a.document_id else None}
                    for a in alerts],
        "watched": [{"id": w.id, "name": w.name, "kind": w.kind, "value": w.value, "open_alerts": open_counts.get(w.id, 0), "match_count": w.match_count,
                     "last_matched_at": iso(w.last_matched_at)} for w in watches],
        "investigations": [{"id": c.id, "title": c.title, "status": c.status, "priority": c.priority, "updated_at": iso(c.updated_at), "items": items.get(c.id, 0)}
                           for c in cases],
        "crawls": [_job_out(j, progress, users) for j in jobs],
    }
