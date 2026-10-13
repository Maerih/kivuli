"""Watchlists and the alert queue."""
import ipaddress

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.api.common import iso
from app.db import get_db
from app.extract.iocs import detect_indicator, refang
from app.models import ALERT_STATUSES, SEVERITIES, WATCH_KINDS, Alert, Document, User, Watchlist, utcnow
from app.security import analyst, audit, valid_email, viewer
from app.worker.celery_app import enqueue

router = APIRouter(tags=["watch"])


class WatchIn(BaseModel):
    name: str = Field("", max_length=200)
    kind: str
    value: str = Field(min_length=2, max_length=500)
    description: str = Field("", max_length=2000)
    min_severity: str = "info"
    notify_mode: str = "immediate"
    recipients: list[str] = Field(default=[], max_length=25)
    is_active: bool = True
    notify_existing: bool = False
    is_asset: bool = False  # something the organisation owns
    criticality: int = Field(3, ge=1, le=5)
    org: str = Field("", max_length=120)


class WatchPatch(BaseModel):
    name: str | None = Field(None, max_length=200)
    description: str | None = Field(None, max_length=2000)
    min_severity: str | None = None
    notify_mode: str | None = None
    recipients: list[str] | None = Field(None, max_length=25)
    is_active: bool | None = None
    is_asset: bool | None = None
    criticality: int | None = Field(None, ge=1, le=5)
    org: str | None = Field(None, max_length=120)


def _normalise(kind: str, value: str) -> str:
    """Validate a watch value against its kind and return its canonical form."""
    value = refang(value.strip())
    if kind not in WATCH_KINDS:
        raise HTTPException(400, "Unknown watchlist kind")
    if kind == "ip":
        try:
            return str(ipaddress.ip_network(value, strict=False)) if "/" in value else str(ipaddress.ip_address(value))
        except ValueError:
            raise HTTPException(400, "Enter an IP address or CIDR range") from None
    if kind in ("domain", "email", "cve", "hash", "crypto"):
        value = value.lower().lstrip("*.") if kind == "domain" else value
        detected = detect_indicator(value)
        if not detected or detected[0] != kind:
            raise HTTPException(400, f"That does not look like a valid {kind}")
        return detected[1]
    if kind in ("keyword", "brand", "technology", "vendor", "executive") and len(value) < 3:
        raise HTTPException(400, "Enter at least 3 characters")
    return " ".join(value.split())


def _check(min_severity: str | None, notify_mode: str | None, recipients: list[str] | None) -> list[str] | None:
    if min_severity is not None and min_severity not in SEVERITIES:
        raise HTTPException(400, "Unknown severity")
    if notify_mode is not None and notify_mode not in ("immediate", "digest", "none"):
        raise HTTPException(400, "notify_mode must be immediate, digest or none")
    if recipients is None:
        return None
    cleaned = sorted({r.strip().lower() for r in recipients if r.strip()})
    if bad := [r for r in cleaned if not valid_email(r)]:
        raise HTTPException(400, f"Invalid email address: {bad[0]}")
    return cleaned


def _out(w: Watchlist, open_alerts: int = 0) -> dict:
    return {"id": w.id, "name": w.name, "kind": w.kind, "value": w.value, "description": w.description, "is_active": w.is_active,
            "min_severity": w.min_severity, "notify_mode": w.notify_mode, "recipients": w.recipients, "match_count": w.match_count,
            "open_alerts": open_alerts, "last_matched_at": iso(w.last_matched_at), "created_at": iso(w.created_at),
            "is_asset": w.is_asset, "criticality": w.criticality, "org": w.org, "last_scanned_at": iso(w.last_scanned_at)}


@router.get("/watchlists")
def list_watchlists(db: Session = Depends(get_db), user: User = Depends(viewer)):
    open_counts = dict(db.execute(select(Alert.watchlist_id, func.count()).where(Alert.status == "open").group_by(Alert.watchlist_id)).all())
    return [_out(w, open_counts.get(w.id, 0)) for w in db.scalars(select(Watchlist).order_by(Watchlist.created_at.desc()))]


@router.post("/watchlists")
def create_watchlist(body: WatchIn, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    value = _normalise(body.kind, body.value)
    recipients = _check(body.min_severity, body.notify_mode, body.recipients) or []
    if db.scalar(select(Watchlist.id).where(Watchlist.kind == body.kind, func.lower(Watchlist.value) == value.lower())):
        raise HTTPException(409, "This value is already on a watchlist")
    watch = Watchlist(name=body.name.strip() or value, kind=body.kind, value=value, description=body.description,
                      min_severity=body.min_severity, notify_mode=body.notify_mode, recipients=recipients,
                      is_active=body.is_active, created_by=user.id, is_asset=body.is_asset, criticality=body.criticality, org=body.org.strip())
    db.add(watch)
    db.flush()
    audit(db, request, user, "watchlist.create", "watchlist", watch.id, kind=watch.kind, value=watch.value)
    db.commit()
    # Check everything already collected; history is only emailed if the analyst asked for it.
    enqueue("pipeline.retro_hunt", watchlist_id=watch.id, notify=body.notify_existing)
    if watch.is_asset and watch.kind in ("domain", "ip"):
        enqueue("pipeline.asm_scan", watchlist_id=watch.id)  # passive attack-surface discovery
    return _out(watch)


@router.patch("/watchlists/{watch_id}")
def update_watchlist(watch_id: int, body: WatchPatch, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    watch = db.get(Watchlist, watch_id)
    if watch is None:
        raise HTTPException(404, "Watchlist not found")
    recipients = _check(body.min_severity, body.notify_mode, body.recipients)
    for field_name in ("name", "description", "min_severity", "notify_mode", "is_active", "is_asset", "criticality", "org"):
        if (new := getattr(body, field_name)) is not None:
            setattr(watch, field_name, new)
    if recipients is not None:
        watch.recipients = recipients
    audit(db, request, user, "watchlist.update", "watchlist", watch.id, **body.model_dump(exclude_none=True))
    db.commit()
    return _out(watch)


@router.delete("/watchlists/{watch_id}")
def delete_watchlist(watch_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    watch = db.get(Watchlist, watch_id)
    if watch is None:
        raise HTTPException(404, "Watchlist not found")
    audit(db, request, user, "watchlist.delete", "watchlist", watch.id, kind=watch.kind, value=watch.value)
    db.delete(watch)
    db.commit()
    return {"ok": True}


@router.post("/watchlists/{watch_id}/hunt")
def hunt(watch_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    if db.get(Watchlist, watch_id) is None:
        raise HTTPException(404, "Watchlist not found")
    enqueue("pipeline.retro_hunt", watchlist_id=watch_id, notify=False)
    audit(db, request, user, "watchlist.hunt", "watchlist", watch_id)
    db.commit()
    return {"ok": True}


def _email_status(a: Alert) -> str:
    owner = a.watchlist or a.rule
    if owner is not None and owner.notify_mode == "none":
        return "off"
    if a.notified_at is None:
        return "pending"
    # Alerts that were never meant to be mailed are stamped at creation time.
    return "not_sent" if a.notified_at == a.created_at else "sent"


def _alert_out(a: Alert, users: dict[int, str]) -> dict:
    d = a.document
    return {
        "email_status": _email_status(a),
        "id": a.id, "category": a.category, "reason": a.reason, "matched": a.matched, "snippet": a.snippet, "severity": a.severity,
        "risk_score": a.risk_score, "status": a.status, "created_at": iso(a.created_at), "notified_at": iso(a.notified_at),
        "resolved_at": iso(a.resolved_at), "assigned_to": a.assigned_to, "assignee": users.get(a.assigned_to or 0, ""),
        "title": a.title or (d.title if d is not None else a.matched), "priority": a.priority, "factors": a.factors or [], "detail": a.detail or {},
        "origin": ({"type": "watchlist", "id": a.watchlist.id, "name": a.watchlist.name} if a.watchlist is not None
                   else {"type": "rule", "id": a.rule.id, "name": a.rule.name} if a.rule is not None else {"type": "system", "id": None, "name": "Platform"}),
        "watchlist": None if a.watchlist is None else {"id": a.watchlist.id, "name": a.watchlist.name, "kind": a.watchlist.kind, "value": a.watchlist.value,
                                                       "notify_mode": a.watchlist.notify_mode, "criticality": a.watchlist.criticality, "is_asset": a.watchlist.is_asset},
        "finding": None if d is None else {"id": str(d.id), "title": d.title, "threat_type": d.threat_type, "network": d.network, "source_name": d.source.name,
                                           "countries": d.countries, "first_seen": iso(d.first_seen_at), "has_credentials": d.has_credentials,
                                           "verification": d.verification, "corroboration": d.corroboration},
    }


@router.get("/alerts")
def list_alerts(status: list[str] = Query(default=[]), severity: list[str] = Query(default=[]), category: str | None = None,
                watchlist_id: int | None = None, rule_id: int | None = None, mine: bool = False, sort: str = "priority", page: int = 1, size: int = 50,
                db: Session = Depends(get_db), user: User = Depends(viewer)):
    stmt = select(Alert)
    if status:
        stmt = stmt.where(Alert.status.in_(status))
    if severity:
        stmt = stmt.where(Alert.severity.in_(severity))
    if category:
        stmt = stmt.where(Alert.category == category)
    if watchlist_id:
        stmt = stmt.where(Alert.watchlist_id == watchlist_id)
    if rule_id:
        stmt = stmt.where(Alert.rule_id == rule_id)
    if mine:
        stmt = stmt.where(Alert.assigned_to == user.id)
    size = max(1, min(size, 200))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    order = (Alert.created_at.desc(), Alert.id.desc()) if sort == "newest" else (Alert.priority.desc(), Alert.created_at.desc(), Alert.id.desc())
    alerts = db.scalars(stmt.order_by(*order).limit(size).offset((max(1, page) - 1) * size)).unique().all()
    users = dict(db.execute(select(User.id, User.name)).all())
    by_status = dict(db.execute(select(Alert.status, func.count()).group_by(Alert.status)).all())
    open_by_severity = dict(db.execute(select(Alert.severity, func.count()).where(Alert.status == "open").group_by(Alert.severity)).all())
    open_by_category = dict(db.execute(select(Alert.category, func.count()).where(Alert.status == "open").group_by(Alert.category)).all())
    return {"total": total, "by_status": by_status, "open_by_severity": open_by_severity, "open_by_category": open_by_category,
            "items": [_alert_out(a, users) for a in alerts]}


class AlertPatch(BaseModel):
    status: str | None = None
    assigned_to: int | None = None
    unassign: bool = False


class AlertBulk(BaseModel):
    ids: list[int] = Field(min_length=1, max_length=500)
    status: str


@router.patch("/alerts/{alert_id}")
def update_alert(alert_id: int, body: AlertPatch, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(404, "Alert not found")
    if body.status is not None:
        if body.status not in ALERT_STATUSES:
            raise HTTPException(400, "Unknown status")
        alert.status = body.status
        alert.resolved_at = utcnow() if body.status in ("resolved", "false_positive") else None
    if body.unassign:
        alert.assigned_to = None
    elif body.assigned_to is not None:
        if db.get(User, body.assigned_to) is None:
            raise HTTPException(400, "Unknown user")
        alert.assigned_to = body.assigned_to
    audit(db, request, user, "alert.update", "alert", alert.id, **body.model_dump(exclude_none=True))
    db.commit()
    return {"ok": True}


@router.post("/alerts/bulk")
def bulk_alerts(body: AlertBulk, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    if body.status not in ALERT_STATUSES:
        raise HTTPException(400, "Unknown status")
    resolved = utcnow() if body.status in ("resolved", "false_positive") else None
    changed = db.execute(update(Alert).where(Alert.id.in_(body.ids)).values(status=body.status, resolved_at=resolved)).rowcount
    audit(db, request, user, "alert.bulk_update", "alert", "", status=body.status, count=changed)
    db.commit()
    return {"ok": True, "changed": changed}
