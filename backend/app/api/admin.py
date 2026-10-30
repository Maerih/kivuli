"""Dashboard, user administration, audit trail and system health."""
import json
from datetime import timedelta

import redis
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from opensearchpy.exceptions import OpenSearchException
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.api.common import finding_summary, iso, paginate
from app.config import get_settings
from app.db import get_db
from app.extract.classify import THREAT_TYPES
from app.extract.geo import country_name, country_numeric
from app.intel import attack, quality
from app.models import Asset, Exposure, Relationship, Vulnerability
from app.models import ROLES, Alert, AuditLog, Case, CrawlLog, Document, EmailLog, Entity, Ioc, Source, User, Watchlist, utcnow
from app.search import index as search_index
from app.search import service
from app.security import admin, analyst, audit, hash_password, password_problem, valid_email, viewer
from app.worker.celery_app import enqueue

router = APIRouter(tags=["admin"])
settings = get_settings()
_redis = redis.Redis.from_url(settings.redis_url, decode_responses=True)


@router.get("/dashboard")
def dashboard(days: int = Query(30, ge=1, le=365), db: Session = Depends(get_db), user: User = Depends(viewer)):
    try:
        overview = service.overview(days)
    except OpenSearchException:
        overview = {"days": days, "total": 0, "in_window": 0, "prev_window": 0, "last_24h": 0, "with_credentials": 0, "severity": [],
                    "types": [], "countries": [], "actors": [], "organizations": [], "sectors": [], "network": [], "timeline": []}
    for bucket in overview["countries"]:
        bucket["label"] = country_name(bucket["value"])
    for bucket in overview.setdefault("country_map", []):
        bucket["label"] = country_name(bucket["value"])
        bucket["numeric"] = country_numeric(bucket["value"])
    for bucket in overview["types"]:
        bucket["label"] = THREAT_TYPES.get(bucket["value"], bucket["value"])

    since = utcnow() - timedelta(days=days)
    top = db.scalars(select(Document).where(Document.duplicate_of.is_(None), Document.first_seen_at >= since)
                     .order_by(Document.risk_score.desc(), Document.first_seen_at.desc()).limit(8)).unique().all()
    alerts = db.scalars(select(Alert).where(Alert.status == "open").order_by(Alert.created_at.desc()).limit(6)).unique().all()
    source_status = dict(db.execute(select(Source.status, func.count()).group_by(Source.status)).all())
    approved = db.execute(select(func.count(), func.count().filter(Source.is_live.is_(True)), func.count().filter(Source.consecutive_failures >= 3))
                          .where(Source.status == "approved")).one()
    return {
        **overview,
        "focus_countries": [{"code": c, "name": country_name(c)} for c in settings.focus_country_list],
        "top_findings": [finding_summary(d) for d in top],
        "open_alerts": {
            "total": db.scalar(select(func.count()).select_from(Alert).where(Alert.status == "open")) or 0,
            "compromise": db.scalar(select(func.count()).select_from(Alert).where(Alert.status == "open", Alert.category == "compromise")) or 0,
            "by_severity": dict(db.execute(select(Alert.severity, func.count()).where(Alert.status == "open").group_by(Alert.severity)).all()),
            # Rule and attack-surface alerts may have no watchlist or no single finding behind them.
            "recent": [{"id": a.id, "severity": a.severity, "category": a.category, "matched": a.matched, "created_at": iso(a.created_at), "priority": a.priority,
                        "watchlist": a.watchlist.name if a.watchlist is not None else a.rule.name if a.rule is not None else "Platform",
                        "finding_id": str(a.document_id) if a.document_id else None,
                        "title": a.title or (a.document.title if a.document is not None else a.matched)} for a in alerts],
        },
        "sources": {"by_status": source_status, "approved": approved[0], "live": approved[1], "failing": approved[2]},
        "counts": {
            "watchlists": db.scalar(select(func.count()).select_from(Watchlist).where(Watchlist.is_active.is_(True))) or 0,
            "open_cases": db.scalar(select(func.count()).select_from(Case).where(Case.status != "closed")) or 0,
            "iocs": db.scalar(select(func.count()).select_from(Ioc).where(Ioc.doc_count > 0)) or 0,
            "actors": db.scalar(select(func.count()).select_from(Entity).where(Entity.type == "actor", Entity.doc_count > 0)) or 0,
        },
        "movers": _movers(days),
        "exposure": {
            "identities_open": db.scalar(select(func.count()).select_from(Exposure).where(Exposure.status == "open")) or 0,
            "hosts": db.scalar(select(func.count()).select_from(Asset)) or 0,
            "hosts_at_risk": db.scalar(select(func.count()).select_from(Asset).where(Asset.risk >= 40)) or 0,
            "vulnerabilities_priority": db.scalar(select(func.count()).select_from(Vulnerability).where(Vulnerability.priority >= 60)) or 0,
            "vulnerabilities_exposed": db.scalar(select(func.count()).select_from(Vulnerability).where(Vulnerability.exposed_assets > 0)) or 0,
        },
    }


def _movers(days: int) -> dict:
    try:
        return {"actors": service.movers(days, "actors", 6), "sectors": service.movers(days, "sectors", 6), "techniques": service.movers(days, "techniques", 6)}
    except OpenSearchException:
        return {"actors": [], "sectors": [], "techniques": []}


class UserIn(BaseModel):
    email: str = Field(max_length=254)
    name: str = Field("", max_length=120)
    role: str = "analyst"
    password: str


class UserPatch(BaseModel):
    name: str | None = Field(None, max_length=120)
    role: str | None = None
    is_active: bool | None = None
    password: str | None = None
    reset_mfa: bool = False  # for a user who lost their authenticator


def _user_out(u: User) -> dict:
    return {"id": u.id, "email": u.email, "name": u.name, "role": u.role, "is_active": u.is_active, "last_login_at": iso(u.last_login_at),
            "created_at": iso(u.created_at), "locked": bool(u.locked_until and u.locked_until > utcnow()), "mfa_enabled": u.mfa_enabled}


@router.get("/users")
def list_users(db: Session = Depends(get_db), user: User = Depends(admin)):
    return [_user_out(u) for u in db.scalars(select(User).order_by(User.email))]


@router.get("/users/directory")
def user_directory(db: Session = Depends(get_db), user: User = Depends(viewer)):
    """Names only, for assignment menus."""
    return [{"id": u.id, "name": u.name or u.email} for u in db.scalars(select(User).where(User.is_active.is_(True)).order_by(User.name))]


@router.post("/users")
def create_user(body: UserIn, request: Request, db: Session = Depends(get_db), user: User = Depends(admin)):
    email = body.email.strip().lower()
    if not valid_email(email):
        raise HTTPException(400, "Invalid email address")
    if body.role not in ROLES:
        raise HTTPException(400, "Unknown role")
    if problem := password_problem(body.password):
        raise HTTPException(400, problem)
    if db.scalar(select(User.id).where(func.lower(User.email) == email)):
        raise HTTPException(409, "A user with this email already exists")
    created = User(email=email, name=body.name.strip(), role=body.role, password_hash=hash_password(body.password))
    db.add(created)
    db.flush()
    audit(db, request, user, "user.create", "user", created.id, email=email, role=body.role)
    db.commit()
    return _user_out(created)


@router.patch("/users/{user_id}")
def update_user(user_id: int, body: UserPatch, request: Request, db: Session = Depends(get_db), user: User = Depends(admin)):
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(404, "User not found")
    demoting = (body.role is not None and body.role != "admin") or body.is_active is False
    if target.role == "admin" and demoting:
        other_admins = db.scalar(select(func.count()).select_from(User).where(User.role == "admin", User.is_active.is_(True), User.id != target.id))
        if not other_admins:
            raise HTTPException(409, "This is the last active admin")
    if body.role is not None:
        if body.role not in ROLES:
            raise HTTPException(400, "Unknown role")
        target.role = body.role
    if body.name is not None:
        target.name = body.name.strip()
    if body.is_active is not None:
        target.is_active = body.is_active
    if body.reset_mfa:
        target.mfa_enabled, target.mfa_secret, target.recovery_codes = False, "", []
    if body.password is not None:
        if problem := password_problem(body.password):
            raise HTTPException(400, problem)
        target.password_hash = hash_password(body.password)
        target.failed_logins, target.locked_until = 0, None
    audit(db, request, user, "user.update", "user", target.id, **{k: v for k, v in body.model_dump(exclude_none=True).items() if k != "password"},
          password_reset=body.password is not None)
    db.commit()
    return _user_out(target)


@router.get("/audit")
def audit_log(action: str = "", user_email: str = "", page: int = 1, size: int = 100, db: Session = Depends(get_db), user: User = Depends(admin)):
    stmt = select(AuditLog.id, AuditLog.ts, AuditLog.user_email, AuditLog.action, AuditLog.object_type, AuditLog.object_id, AuditLog.ip, AuditLog.detail)
    if action:
        stmt = stmt.where(AuditLog.action.like(f"{action}%"))
    if user_email:
        stmt = stmt.where(AuditLog.user_email.ilike(f"%{user_email}%"))
    rows, total = paginate(db, stmt.order_by(AuditLog.ts.desc(), AuditLog.id.desc()), page, size)
    return {"total": total, "items": [{"id": r.id, "ts": iso(r.ts), "user": r.user_email, "action": r.action, "object_type": r.object_type,
                                       "object_id": r.object_id, "ip": r.ip, "detail": r.detail} for r in rows]}


@router.get("/system/health")
def system_health(db: Session = Depends(get_db), user: User = Depends(analyst)):
    health: dict = {"database": {"ok": False}, "search": {"ok": False}, "queue": {"ok": False}, "tor": {"ok": False}}
    try:
        db.execute(text("SELECT 1"))
        health["database"] = {"ok": True, "findings": db.scalar(select(func.count()).select_from(Document)) or 0}
    except Exception as exc:
        health["database"]["error"] = type(exc).__name__
    try:
        cluster = search_index.client().cluster.health()
        health["search"] = {"ok": cluster["status"] in ("green", "yellow"), "status": cluster["status"], "indexed": service.count()}
    except Exception as exc:
        health["search"]["error"] = type(exc).__name__
    try:
        health["queue"] = {"ok": True, **{name: _redis.llen(name) for name in ("crawl", "pipeline", "notify", "enrich")}}
        raw = _redis.get("kivuli:status:tor")
        health["tor"] = json.loads(raw) if raw else {"ok": False, "error": "no Tor check has completed yet"}
        health["email_backoff"] = bool(_redis.exists("kivuli:email:backoff"))
    except redis.RedisError as exc:
        health["queue"]["error"] = type(exc).__name__

    last_fetch = db.scalar(select(func.max(CrawlLog.fetched_at)))
    day = utcnow() - timedelta(hours=24)
    fetches = db.execute(select(func.count(), func.count().filter(CrawlLog.ok.is_(True)), func.coalesce(func.sum(CrawlLog.new_docs), 0))
                         .where(CrawlLog.fetched_at >= day)).one()
    health["crawl"] = {"last_fetch": iso(last_fetch), "fetches_24h": fetches[0], "ok_24h": fetches[1], "new_findings_24h": int(fetches[2])}
    health["email"] = {
        "enabled": settings.email_enabled, "smtp_host": settings.smtp_host, "smtp_port": settings.smtp_port, "tls": settings.smtp_tls,
        "test_inbox_port": settings.mailpit_port,
        "from": settings.smtp_from, "default_recipients": settings.default_recipients,
        "authenticated": bool(settings.smtp_username),
    }
    health["quality"] = quality.quality_stats(db)
    health["attack"] = {"version": attack.catalog()["version"], "techniques": len(attack.catalog()["techniques"]),
                        "relationships": db.scalar(select(func.count()).select_from(Relationship)) or 0}
    health["policy"] = {
        "redact_secrets": settings.redact_secrets, "store_raw_evidence": settings.evidence_store_raw,
        "egress_allow_hosts": settings.egress_allow_list, "discover_onion_links": settings.discover_onion_links,
        "max_bytes": settings.crawl_max_bytes, "host_delay_seconds": settings.crawl_host_delay_seconds,
    }
    return health


@router.get("/system/email-log")
def email_log(db: Session = Depends(get_db), user: User = Depends(analyst)):
    rows = db.scalars(select(EmailLog).order_by(EmailLog.ts.desc()).limit(50)).all()
    return [{"id": r.id, "ts": iso(r.ts), "kind": r.kind, "recipients": r.recipients, "subject": r.subject, "alert_count": r.alert_count,
             "ok": r.ok, "error": r.error} for r in rows]


class TestEmailIn(BaseModel):
    to: str = Field(max_length=254)


@router.post("/system/test-email")
def test_email(body: TestEmailIn, request: Request, db: Session = Depends(get_db), user: User = Depends(admin)):
    address = body.to.strip().lower()
    if not valid_email(address):
        raise HTTPException(400, "Invalid email address")
    enqueue("notify.send_test", recipient=address)
    audit(db, request, user, "system.test_email", "system", "", to=address)
    db.commit()
    return {"ok": True}


@router.get("/metrics", include_in_schema=False)
def metrics(db: Session = Depends(get_db), user: User = Depends(analyst)):
    """Prometheus exposition. Scrape with an API key: Authorization: Bearer <key>."""
    from fastapi.responses import PlainTextResponse

    lines: list[str] = []

    def gauge(name: str, help_text: str, samples: list[tuple[dict, float]]) -> None:
        lines.extend([f"# HELP kivuli_{name} {help_text}", f"# TYPE kivuli_{name} gauge"])
        for labels, value in samples:
            rendered = ",".join(f'{k}="{str(v).replace(chr(92), "").replace(chr(34), "")}"' for k, v in labels.items())
            lines.append(f"kivuli_{name}{{{rendered}}} {value}" if rendered else f"kivuli_{name} {value}")

    def grouped(column, model=None, *where):
        stmt = select(column, func.count()).group_by(column)
        return db.execute(stmt.where(*where) if where else stmt).all()

    gauge("findings", "Findings held, by severity", [({"severity": k}, v) for k, v in grouped(Document.severity)])
    gauge("findings_by_verification", "Findings by verification state", [({"state": k}, v) for k, v in grouped(Document.verification)])
    gauge("alerts", "Alerts by status", [({"status": k}, v) for k, v in grouped(Alert.status)])
    gauge("alerts_open", "Open alerts by severity", [({"severity": k}, v) for k, v in grouped(Alert.severity, None, Alert.status == "open")])
    gauge("sources", "Sources by status", [({"status": k}, v) for k, v in grouped(Source.status)])
    gauge("sources_failing", "Approved sources with three or more consecutive failures",
          [({}, db.scalar(select(func.count()).select_from(Source).where(Source.status == "approved", Source.consecutive_failures >= 3)) or 0)])
    gauge("exposures_open", "Open identity and secret exposures", [({"kind": k}, v) for k, v in grouped(Exposure.kind, None, Exposure.status == "open")])
    gauge("assets", "Attack-surface hosts", [({"state": "all"}, db.scalar(select(func.count()).select_from(Asset)) or 0),
                                             ({"state": "at_risk"}, db.scalar(select(func.count()).select_from(Asset).where(Asset.risk >= 40)) or 0)])
    gauge("vulnerabilities_exposed", "Vulnerabilities present on the attack surface",
          [({}, db.scalar(select(func.count()).select_from(Vulnerability).where(Vulnerability.exposed_assets > 0)) or 0)])
    day = utcnow() - timedelta(hours=24)
    fetches = db.execute(select(CrawlLog.ok, func.count()).where(CrawlLog.fetched_at >= day).group_by(CrawlLog.ok)).all()
    gauge("fetches_24h", "Fetches in the last 24 hours", [({"result": "ok" if ok else "failed"}, n) for ok, n in fetches])
    try:
        gauge("queue_depth", "Tasks waiting per queue", [({"queue": q}, _redis.llen(q)) for q in ("crawl", "pipeline", "notify", "enrich")])
        tor = json.loads(_redis.get("kivuli:status:tor") or "{}")
        gauge("tor_ok", "1 when the last Tor exit check succeeded", [({}, 1 if tor.get("ok") and tor.get("is_tor") else 0)])
        gauge("email_backoff", "1 while alert email is paused after a delivery error", [({}, 1 if _redis.exists("kivuli:email:backoff") else 0)])
    except redis.RedisError:
        gauge("queue_depth", "Tasks waiting per queue", [])
    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")
