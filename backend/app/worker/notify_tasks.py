"""Notification tasks. Runs in the only container that can reach the mail relay."""
import logging
from collections import defaultdict
from datetime import timedelta

import redis
from sqlalchemy import func, select

from app.config import get_settings
from app.db import session_scope
from app import crypto
from app.models import Alert, Delivery, EmailLog, Integration, Rule, Watchlist, utcnow
from app.extract.risk import severity_at_least
from app.notify import integrations, mailer
from app.worker.celery_app import celery_app

log = logging.getLogger(__name__)
settings = get_settings()
_redis = redis.Redis.from_url(settings.redis_url, decode_responses=True)

BACKOFF_KEY = "kivuli:email:backoff"


def _deliver(db, mode: str, kind: str, since=None) -> int:
    """Send every pending alert whose watchlist or rule is in ``mode``, one message per recipient."""
    if not settings.email_enabled or _redis.exists(BACKOFF_KEY):
        return 0
    stmt = (
        select(Alert).outerjoin(Watchlist, Watchlist.id == Alert.watchlist_id).outerjoin(Rule, Rule.id == Alert.rule_id)
        .where(Alert.notified_at.is_(None), Alert.status == "open", func.coalesce(Watchlist.notify_mode, Rule.notify_mode) == mode)
        .order_by(Alert.created_at).limit(500).with_for_update(of=Alert, skip_locked=True)
    )
    if since is not None:
        stmt = stmt.where(Alert.created_at >= since)
    alerts = db.scalars(stmt).unique().all()
    if not alerts:
        return 0

    per_recipient: dict[str, list[Alert]] = defaultdict(list)
    undeliverable: list[Alert] = []
    for alert in alerts:
        owner = alert.watchlist or alert.rule
        recipients = (owner.recipients if owner else None) or settings.default_recipients
        if not recipients:
            undeliverable.append(alert)
        for address in recipients:
            per_recipient[address.lower()].append(alert)

    now = utcnow()
    delivered: set[int] = set()
    sent = 0
    for address, batch in per_recipient.items():
        subject, text_body, html_body = mailer.compose_alerts(batch, digest=kind == "digest")
        try:
            mailer.send([address], subject, text_body, html_body)
        except Exception as exc:
            log.warning("alert email to %s failed: %s", address, exc)
            db.add(EmailLog(kind=kind, recipients=[address], subject=subject, alert_count=len(batch), ok=False, error=f"{type(exc).__name__}: {exc}"[:500]))
            # Stop hammering a relay that is down or rejecting us; alerts stay pending.
            _redis.set(BACKOFF_KEY, "1", ex=600)
            break
        db.add(EmailLog(kind=kind, recipients=[address], subject=subject, alert_count=len(batch), ok=True))
        delivered.update(a.id for a in batch)
        sent += 1

    for alert in alerts:
        if alert.id in delivered or alert in undeliverable:
            alert.notified_at = now
    return sent


@celery_app.task(name="notify.dispatch_alerts")
def dispatch_alerts():
    with session_scope() as db:
        return _deliver(db, "immediate", "alert")


@celery_app.task(name="notify.send_digest")
def send_digest():
    with session_scope() as db:
        return _deliver(db, "digest", "digest", since=utcnow() - timedelta(days=2))


@celery_app.task(name="notify.send_test")
def send_test(recipient: str):
    subject, text_body, html_body = mailer.compose_test()
    with session_scope() as db:
        try:
            mailer.send([recipient], subject, text_body, html_body)
            db.add(EmailLog(kind="test", recipients=[recipient], subject=subject, ok=True))
            _redis.delete(BACKOFF_KEY)
            return True
        except Exception as exc:
            db.add(EmailLog(kind="test", recipients=[recipient], subject=subject, ok=False, error=f"{type(exc).__name__}: {exc}"[:500]))
            return False


# ── Integrations ────────────────────────────────────────────────────────────

def alert_payload(alert) -> dict:
    """The JSON an integration receives for an alert. Indicators are defanged; secrets are never present."""
    view = mailer._alert_view(alert)
    doc = alert.document
    return {
        "id": alert.id, "severity": alert.severity, "priority": alert.priority, "category": alert.category, "category_label": view["category"],
        "matched": view["matched"], "title": view["title"], "origin": view["origin_line"], "snippet": view["snippet"], "link": view["link"],
        "status": alert.status, "created_at": alert.created_at.isoformat(), "factors": alert.factors or [], "detail": alert.detail or {},
        "finding": None if doc is None else {"id": str(doc.id), "threat_type": doc.threat_type, "risk_score": doc.risk_score, "countries": doc.countries,
                                             "verification": doc.verification, "techniques": doc.techniques, "source": doc.source.name},
    }


def _send(db, integration: Integration, alert) -> bool:
    url = crypto.decrypt(integration.secret) if integration.kind in integrations.URL_IS_SECRET else integration.url
    secret = "" if integration.kind in integrations.URL_IS_SECRET else crypto.decrypt(integration.secret)
    now = utcnow()
    try:
        status = integrations.deliver(integration.kind, url, integration.config or {}, secret, alert_payload(alert))
        db.add(Delivery(integration_id=integration.id, alert_id=alert.id, ts=now, ok=True, status_code=status))
        integration.last_delivery_at, integration.last_error, integration.failures = now, "", 0
        return True
    except Exception as exc:
        log.warning("integration %s delivery failed: %s", integration.id, exc)
        db.add(Delivery(integration_id=integration.id, alert_id=alert.id, ts=now, ok=False, error=str(exc)[:500]))
        integration.last_error, integration.failures = str(exc)[:500], integration.failures + 1
        return False


@celery_app.task(name="notify.dispatch_integrations")
def dispatch_integrations():
    """Push new alerts to every active integration whose filters they pass. Each alert is attempted once per integration."""
    sent = 0
    with session_scope() as db:
        for integration in db.scalars(select(Integration).where(Integration.is_active.is_(True))):
            if integration.failures >= 10:  # stop after repeated failures; an operator re-enables it
                integration.is_active = False
                continue
            done = select(Delivery.alert_id).where(Delivery.integration_id == integration.id, Delivery.alert_id.isnot(None))
            pending = db.scalars(select(Alert).where(Alert.created_at >= integration.created_at, Alert.status == "open", Alert.reason != "retro",
                                                     Alert.id.notin_(done)).order_by(Alert.created_at).limit(40)).unique().all()
            for alert in pending:
                if not severity_at_least(alert.severity, integration.min_severity) or (integration.categories and alert.category not in integration.categories):
                    db.add(Delivery(integration_id=integration.id, alert_id=alert.id, ok=True, error="filtered"))
                    continue
                sent += _send(db, integration, alert)
                db.commit()
    return sent


@celery_app.task(name="notify.test_integration")
def test_integration(integration_id: int):
    with session_scope() as db:
        integration = db.get(Integration, integration_id)
        if integration is None:
            return False

        class _Sample:  # a clearly labelled synthetic alert, shaped like a real one
            id, severity, priority, category, status, reason = 0, "info", 10, "mention", "open", "new"
            matched, title, snippet = "test-message", "Test message from Kivuli", "If you can read this, the integration is configured correctly."
            factors, detail, document, watchlist, rule, created_at = [], {}, None, None, None, utcnow()

        url = crypto.decrypt(integration.secret) if integration.kind in integrations.URL_IS_SECRET else integration.url
        secret = "" if integration.kind in integrations.URL_IS_SECRET else crypto.decrypt(integration.secret)
        now = utcnow()
        try:
            status = integrations.deliver(integration.kind, url, integration.config or {}, secret, alert_payload(_Sample))
            db.add(Delivery(integration_id=integration.id, ts=now, ok=True, status_code=status, error="test"))
            integration.last_delivery_at, integration.last_error, integration.failures = now, "", 0
            return True
        except Exception as exc:
            db.add(Delivery(integration_id=integration.id, ts=now, ok=False, error=f"test: {exc}"[:500]))
            integration.last_error = str(exc)[:500]
            return False
