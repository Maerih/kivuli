"""Source registry: what is collected, how often, and whether it is still alive."""
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.common import iso
from app.config import get_settings
from app.crawl.fetcher import validate_url
from app.db import get_db
from app.models import SOURCE_STATUSES, CrawlLog, Source, SourceLink, User, utcnow
from app.security import admin, analyst, audit, viewer
from app.worker.celery_app import enqueue
from app.worker.parsers import CONNECTORS

router = APIRouter(tags=["sources"])
settings = get_settings()

CATEGORIES = ("ransomware_leak_site", "forum", "marketplace", "paste", "tracker", "news", "vuln_feed", "blog", "other")
USER_CONNECTORS = ("html", "rss", "telegram_public", "ioc_feed", "ransomware_live", "ransomlook_recent", "cisa_kev")


def _egress_allowed(host: str) -> bool:
    for entry in settings.egress_allow_list:
        if host == entry or (entry.startswith(".") and (host == entry[1:] or host.endswith(entry))):
            return True
    return False


def _out(s: Source) -> dict:
    return {
        "id": s.id, "name": s.name, "url": s.url, "host": s.host, "network": s.network, "connector": s.connector, "route": s.route,
        "category": s.category, "status": s.status, "trust": s.trust, "crawl_interval_minutes": s.crawl_interval_minutes,
        "max_depth": s.max_depth, "max_pages": s.max_pages, "is_live": s.is_live, "last_checked_at": iso(s.last_checked_at),
        "last_live_at": iso(s.last_live_at), "last_crawled_at": iso(s.last_crawled_at), "last_http_status": s.last_http_status,
        "last_error": s.last_error, "consecutive_failures": s.consecutive_failures, "doc_count": s.doc_count,
        "discovered_from_id": s.discovered_from_id, "discovery_context": s.discovery_context, "notes": s.notes,
        "created_at": iso(s.created_at), "title": s.title, "language": s.language, "relevance": s.relevance, "last_changed_at": iso(s.last_changed_at),
        "state": "unknown" if s.is_live is None else "offline" if not s.is_live else "degraded" if s.consecutive_failures else "online",
        "egress_blocked": s.route == "direct" and not _egress_allowed(s.host),
    }


@router.get("/sources")
def list_sources(status: str | None = None, network: str | None = None, q: str = Query("", max_length=200), view: str | None = None,
                 category: str | None = None, db: Session = Depends(get_db), user: User = Depends(viewer)):
    """Sources, optionally through one of the explorer's views: new, offline, changed, referenced, relevant."""
    week = utcnow() - timedelta(days=7)
    inbound = select(SourceLink.dst_host, func.count().label("n")).group_by(SourceLink.dst_host).subquery()
    stmt = select(Source, func.coalesce(inbound.c.n, 0)).outerjoin(inbound, inbound.c.dst_host == Source.host)
    if status:
        stmt = stmt.where(Source.status == status)
    if network:
        stmt = stmt.where(Source.network == network)
    if category:
        stmt = stmt.where(Source.category == category)
    if q.strip():
        needle = f"%{q.strip()}%"
        stmt = stmt.where(or_(Source.name.ilike(needle), Source.host.ilike(needle), Source.title.ilike(needle)))
    order = (Source.status, Source.name)
    if view == "new":
        stmt, order = stmt.where(Source.created_at >= week), (Source.created_at.desc(),)
    elif view == "offline":
        stmt, order = stmt.where(Source.is_live.is_(False), Source.status != "blocked"), (Source.last_live_at.desc().nulls_last(),)
    elif view == "changed":
        stmt, order = stmt.where(Source.last_changed_at.isnot(None)), (Source.last_changed_at.desc(),)
    elif view == "referenced":
        stmt, order = stmt.where(inbound.c.n > 0), (inbound.c.n.desc(), Source.name)
    elif view == "relevant":
        stmt, order = stmt.where(Source.relevance > 0, Source.status != "blocked"), (Source.relevance.desc(), Source.doc_count.desc())
    found = db.execute(stmt.order_by(*order).limit(1000)).all()
    rows = [r[0] for r in found]
    referenced = {r[0].id: r[1] for r in found}
    counts = dict(db.execute(select(Source.status, func.count()).group_by(Source.status)).all())
    onion = dict(db.execute(select(Source.status, func.count()).where(Source.network == "onion").group_by(Source.status)).all())
    views = {
        "new": db.scalar(select(func.count()).select_from(Source).where(Source.created_at >= week)) or 0,
        "offline": db.scalar(select(func.count()).select_from(Source).where(Source.is_live.is_(False), Source.status != "blocked")) or 0,
        "changed": db.scalar(select(func.count()).select_from(Source).where(Source.last_changed_at >= week)) or 0,
        "referenced": db.scalar(select(func.count()).select_from(Source).where(Source.host.in_(select(SourceLink.dst_host)))) or 0,
    }
    return {"counts": counts, "views": views, "referenced": referenced, "onion": {"approved": onion.get("approved", 0), "candidate": onion.get("candidate", 0)}, "categories": CATEGORIES, "connector_labels": CONNECTORS, "connectors": {k: CONNECTORS[k] for k in USER_CONNECTORS},
            "egress_allow_hosts": settings.egress_allow_list, "items": [_out(s) for s in rows]}


class SourceIn(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    url: str = Field(min_length=8, max_length=1024)
    connector: str = "html"
    category: str = "other"
    route: str = "tor"
    trust: int = Field(50, ge=0, le=100)
    crawl_interval_minutes: int = Field(360, ge=15, le=10080)
    max_depth: int = Field(1, ge=0, le=3)
    max_pages: int = Field(25, ge=1, le=200)
    notes: str = Field("", max_length=5000)
    approve: bool = False
    feed_tag: str = Field("", max_length=32, pattern=r"^[a-z0-9-]*$")  # what an indicator feed lists: phishing, c2, botnet...


class SourcePatch(BaseModel):
    name: str | None = Field(None, min_length=2, max_length=200)
    status: str | None = None
    category: str | None = None
    route: str | None = None
    trust: int | None = Field(None, ge=0, le=100)
    crawl_interval_minutes: int | None = Field(None, ge=15, le=10080)
    max_depth: int | None = Field(None, ge=0, le=3)
    max_pages: int | None = Field(None, ge=1, le=200)
    notes: str | None = Field(None, max_length=5000)


def _check_route(route: str, network: str, url: str) -> str:
    if network == "onion":
        return "tor"
    if route not in ("tor", "direct"):
        raise HTTPException(400, "route must be tor or direct")
    if route == "direct" and not url.lower().startswith("https://"):
        raise HTTPException(400, "Direct egress is HTTPS only. Use the Tor route for plain HTTP sites.")
    return route


@router.post("/sources")
def create_source(body: SourceIn, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    url = body.url.strip()
    if body.connector == "telegram_public":
        # Only the public web preview is read: t.me/s/<channel>. No account, no private chats.
        import re
        match = re.fullmatch(r"https?://t\.me/(?:s/)?([A-Za-z][A-Za-z0-9_]{3,31})/?", url)
        if not match:
            raise HTTPException(400, "Enter a public channel as https://t.me/s/<channel>")
        url = f"https://t.me/s/{match.group(1)}"
    ok, reason, host, network = validate_url(url)
    if not ok:
        raise HTTPException(400, f"This URL cannot be collected: {reason}")
    if body.connector not in USER_CONNECTORS or body.category not in CATEGORIES:
        raise HTTPException(400, "Unknown connector or category")
    if db.scalar(select(Source.id).where(Source.url == url)):
        raise HTTPException(409, "This source already exists")
    source = Source(
        name=body.name.strip(), url=url, host=host, network=network, connector=body.connector, category=body.category,
        route=_check_route(body.route, network, url), trust=body.trust, crawl_interval_minutes=body.crawl_interval_minutes,
        max_depth=body.max_depth if body.connector == "html" else 0, max_pages=body.max_pages, notes=body.notes,
        config=({"tag": body.feed_tag or "threat-feed", "max_bytes": 6_000_000} if body.connector == "ioc_feed" else {}),
        status="approved" if body.approve else "candidate", created_by=user.id,
    )
    db.add(source)
    db.flush()
    audit(db, request, user, "source.create", "source", source.id, url=url, status=source.status)
    db.commit()
    enqueue("pipeline.crawl_source", source_id=source.id, probe=not body.approve)
    return _out(source)


@router.patch("/sources/{source_id}")
def update_source(source_id: int, body: SourcePatch, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    source = db.get(Source, source_id)
    if source is None:
        raise HTTPException(404, "Source not found")
    changes = body.model_dump(exclude_none=True)
    if body.status is not None:
        if body.status not in SOURCE_STATUSES:
            raise HTTPException(400, "Unknown status")
        if source.status == "blocked" and body.status != "blocked" and user.role != "admin":
            raise HTTPException(403, "Only an admin can unblock a source")
    if body.category is not None and body.category not in CATEGORIES:
        raise HTTPException(400, "Unknown category")
    if body.route is not None:
        changes["route"] = _check_route(body.route, source.network, source.url)
    was = source.status
    for key, value in changes.items():
        setattr(source, key, value)
    if body.status == "approved" and was != "approved":
        source.consecutive_failures = 0
        source.last_crawled_at = None  # picked up by the scheduler within a minute
    audit(db, request, user, "source.update", "source", source.id, **changes)
    db.commit()
    return _out(source)


@router.delete("/sources/{source_id}")
def delete_source(source_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(admin)):
    source = db.get(Source, source_id)
    if source is None:
        raise HTTPException(404, "Source not found")
    if source.doc_count:
        raise HTTPException(409, "This source has findings. Pause or block it instead, so the evidence is kept.")
    audit(db, request, user, "source.delete", "source", source.id, url=source.url)
    db.delete(source)
    db.commit()
    return {"ok": True}


@router.post("/sources/{source_id}/crawl")
def crawl_now(source_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    source = db.get(Source, source_id)
    if source is None:
        raise HTTPException(404, "Source not found")
    if source.status != "approved":
        raise HTTPException(409, "Approve the source before crawling it")
    enqueue("pipeline.crawl_source", source_id=source.id)
    audit(db, request, user, "source.crawl", "source", source.id)
    db.commit()
    return {"ok": True}


@router.post("/sources/{source_id}/verify")
def verify_now(source_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    """Check that the link is alive. Fetches the first bytes only and stores nothing."""
    source = db.get(Source, source_id)
    if source is None:
        raise HTTPException(404, "Source not found")
    if source.status == "blocked":
        raise HTTPException(409, "Blocked sources are never contacted")
    enqueue("pipeline.crawl_source", source_id=source.id, probe=True)
    audit(db, request, user, "source.verify", "source", source.id)
    db.commit()
    return {"ok": True}


@router.get("/sources/{source_id}/log")
def source_log(source_id: int, db: Session = Depends(get_db), user: User = Depends(viewer)):
    rows = db.scalars(select(CrawlLog).where(CrawlLog.source_id == source_id).order_by(CrawlLog.fetched_at.desc()).limit(100)).all()
    return [{"id": r.id, "url": r.url, "depth": r.depth, "probe": r.probe, "fetched_at": iso(r.fetched_at), "ok": r.ok,
             "http_status": r.http_status, "bytes": r.bytes, "elapsed_ms": r.elapsed_ms, "error": r.error, "new_docs": r.new_docs,
             "changed_docs": r.changed_docs, "unchanged_docs": r.unchanged_docs, "dropped_docs": r.dropped_docs} for r in rows]


class DiscoverIn(BaseModel):
    group: str | None = Field(None, max_length=80, pattern=r"^[A-Za-z0-9 _.$()-]*$")


@router.post("/sources/discover")
def discover(body: DiscoverIn, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    """Look up where ransomware groups publish and file their sites as candidates for review."""
    enqueue("pipeline.discover_sources", group=(body.group or "").strip() or None)
    audit(db, request, user, "source.discover", "source", "", group=body.group or "")
    db.commit()
    return {"ok": True}
