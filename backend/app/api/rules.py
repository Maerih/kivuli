"""Detection rules: turn any search into an alert, on match, on volume or on a spike."""
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from opensearchpy.exceptions import OpenSearchException
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.common import iso
from app.db import get_db
from app.models import RULE_KINDS, SEVERITIES, Alert, Rule, User, utcnow
from app.search import query as query_language
from app.search import service
from app.security import analyst, audit, valid_email, viewer
from app.worker.celery_app import enqueue

router = APIRouter(tags=["rules"])


class RuleIn(BaseModel):
    name: str = Field(min_length=3, max_length=200)
    kind: str = "query"
    query: str = Field(min_length=1, max_length=1000)
    threshold: int = Field(5, ge=1, le=100000)
    window_hours: int = Field(24, ge=1, le=24 * 90)
    severity: str = "medium"
    notify_mode: str = "immediate"
    recipients: list[str] = Field(default=[], max_length=25)
    is_active: bool = True


class RulePatch(BaseModel):
    name: str | None = Field(None, min_length=3, max_length=200)
    query: str | None = Field(None, min_length=1, max_length=1000)
    threshold: int | None = Field(None, ge=1, le=100000)
    window_hours: int | None = Field(None, ge=1, le=24 * 90)
    severity: str | None = None
    notify_mode: str | None = None
    recipients: list[str] | None = Field(None, max_length=25)
    is_active: bool | None = None


def _check(kind: str | None, severity: str | None, notify_mode: str | None, recipients: list[str] | None) -> list[str] | None:
    if kind is not None and kind not in RULE_KINDS:
        raise HTTPException(400, "kind must be query, threshold or spike")
    if severity is not None and severity not in SEVERITIES:
        raise HTTPException(400, "Unknown severity")
    if notify_mode is not None and notify_mode not in ("immediate", "digest", "none"):
        raise HTTPException(400, "notify_mode must be immediate, digest or none")
    if recipients is None:
        return None
    cleaned = sorted({r.strip().lower() for r in recipients if r.strip()})
    if bad := [r for r in cleaned if not valid_email(r)]:
        raise HTTPException(400, f"Invalid email address: {bad[0]}")
    return cleaned


def _out(r: Rule, open_alerts: int = 0) -> dict:
    return {"id": r.id, "name": r.name, "kind": r.kind, "query": r.query, "threshold": r.threshold, "window_hours": r.window_hours,
            "severity": r.severity, "notify_mode": r.notify_mode, "recipients": r.recipients, "is_active": r.is_active, "match_count": r.match_count,
            "open_alerts": open_alerts, "last_run_at": iso(r.last_run_at), "last_triggered_at": iso(r.last_triggered_at), "created_at": iso(r.created_at)}


@router.get("/rules")
def list_rules(db: Session = Depends(get_db), user: User = Depends(viewer)):
    counts = dict(db.execute(select(Alert.rule_id, func.count()).where(Alert.status == "open", Alert.rule_id.isnot(None)).group_by(Alert.rule_id)).all())
    return [_out(r, counts.get(r.id, 0)) for r in db.scalars(select(Rule).order_by(Rule.created_at.desc()))]


class PreviewIn(BaseModel):
    query: str = Field(min_length=1, max_length=1000)
    window_hours: int = Field(24, ge=1, le=24 * 90)


@router.post("/rules/preview")
def preview(body: PreviewIn, user: User = Depends(viewer)):
    """How a rule would have behaved: matches in the window, and the windows before it."""
    now = utcnow()
    window = timedelta(hours=body.window_hours)
    try:
        current = service.count_matching(body.query, now - window)
        history = [service.count_matching(body.query, now - window * (n + 1), now - window * n) for n in range(1, 8)]
    except OpenSearchException as exc:
        raise HTTPException(503, f"Search is unavailable: {type(exc).__name__}") from None
    return {"current": current, "previous_windows": history, "baseline": round(sum(history) / 7, 1),
            "interpretation": query_language.parse_query(body.query).interpretation}


@router.post("/rules")
def create_rule(body: RuleIn, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    recipients = _check(body.kind, body.severity, body.notify_mode, body.recipients) or []
    rule = Rule(name=body.name.strip(), kind=body.kind, query=body.query.strip(), threshold=body.threshold, window_hours=body.window_hours,
                severity=body.severity, notify_mode=body.notify_mode, recipients=recipients, is_active=body.is_active, created_by=user.id)
    db.add(rule)
    db.flush()
    audit(db, request, user, "rule.create", "rule", rule.id, kind=rule.kind, query=rule.query[:300])
    db.commit()
    return _out(rule)


@router.patch("/rules/{rule_id}")
def update_rule(rule_id: int, body: RulePatch, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    rule = db.get(Rule, rule_id)
    if rule is None:
        raise HTTPException(404, "Rule not found")
    recipients = _check(None, body.severity, body.notify_mode, body.recipients)
    for name in ("name", "query", "threshold", "window_hours", "severity", "notify_mode", "is_active"):
        if (value := getattr(body, name)) is not None:
            setattr(rule, name, value)
    if recipients is not None:
        rule.recipients = recipients
    audit(db, request, user, "rule.update", "rule", rule.id, **body.model_dump(exclude_none=True))
    db.commit()
    return _out(rule)


@router.delete("/rules/{rule_id}")
def delete_rule(rule_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    rule = db.get(Rule, rule_id)
    if rule is None:
        raise HTTPException(404, "Rule not found")
    audit(db, request, user, "rule.delete", "rule", rule.id, name=rule.name)
    db.delete(rule)
    db.commit()
    return {"ok": True}


@router.post("/rules/{rule_id}/run")
def run_rule(rule_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    if db.get(Rule, rule_id) is None:
        raise HTTPException(404, "Rule not found")
    enqueue("pipeline.evaluate_rules", rule_id=rule_id)
    audit(db, request, user, "rule.run", "rule", rule_id)
    db.commit()
    return {"ok": True}
