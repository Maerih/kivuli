"""Integrations: outbound destinations, enrichment providers and API keys."""
import json
import uuid
from datetime import timedelta
from urllib.parse import urlsplit

import redis
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import crypto
from app.api.common import iso
from app.config import get_settings
from app.db import get_db
from app.enrich import keys, providers
from app.intel import provider_store
from app.models import SEVERITIES, ApiKey, Delivery, Enrichment, Integration, Ioc, ProviderKey, User, utcnow
from app.notify.integrations import KINDS, URL_IS_SECRET
from app.security import admin, analyst, audit, new_api_key, viewer
from app.worker.celery_app import enqueue

router = APIRouter(tags=["integrations"])
settings = get_settings()
_redis = redis.Redis.from_url(settings.redis_url, decode_responses=True)

_CONFIG_KEYS = {"webhook": (), "slack": (), "teams": (), "splunk_hec": ("index", "sourcetype"), "jira": ("project", "issue_type", "user"),
                "servicenow": ("user", "table", "category")}


class IntegrationIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    kind: str
    url: str = Field(min_length=8, max_length=1024)
    secret: str = Field("", max_length=2000)
    config: dict = {}
    min_severity: str = "high"
    categories: list[str] = Field(default=[], max_length=10)
    is_active: bool = True


class IntegrationPatch(BaseModel):
    name: str | None = Field(None, min_length=2, max_length=120)
    url: str | None = Field(None, min_length=8, max_length=1024)
    secret: str | None = Field(None, max_length=2000)
    config: dict | None = None
    min_severity: str | None = None
    categories: list[str] | None = Field(None, max_length=10)
    is_active: bool | None = None


def _validate(kind: str, url: str, min_severity: str) -> None:
    if kind not in KINDS:
        raise HTTPException(400, "Unknown integration kind")
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise HTTPException(400, "Enter a full https:// URL")
    if parts.scheme == "http" and not settings.integrations_allow_private:
        raise HTTPException(400, "Destinations must use HTTPS")
    if min_severity not in SEVERITIES:
        raise HTTPException(400, "Unknown severity")


def _out(i: Integration) -> dict:
    return {"id": i.id, "name": i.name, "kind": i.kind, "kind_label": KINDS.get(i.kind, i.kind), "url": i.url, "config": i.config,
            "has_secret": bool(i.secret), "min_severity": i.min_severity, "categories": i.categories, "is_active": i.is_active,
            "last_delivery_at": iso(i.last_delivery_at), "last_error": i.last_error, "failures": i.failures, "created_at": iso(i.created_at)}


def _store(integration: Integration, kind: str, url: str | None, secret: str | None) -> None:
    """Chat webhook URLs are credentials: keep them encrypted and show only the host."""
    if url is not None:
        if kind in URL_IS_SECRET:
            integration.secret = crypto.encrypt(url)
            integration.url = f"https://{urlsplit(url).hostname}/…"
        else:
            integration.url = url
    if secret and kind not in URL_IS_SECRET:
        integration.secret = crypto.encrypt(secret)


@router.get("/integrations")
def list_integrations(db: Session = Depends(get_db), user: User = Depends(analyst)):
    return {"kinds": KINDS, "config_keys": _CONFIG_KEYS, "allow_private": settings.integrations_allow_private,
            "items": [_out(i) for i in db.scalars(select(Integration).order_by(Integration.created_at.desc()))]}


@router.post("/integrations")
def create_integration(body: IntegrationIn, request: Request, db: Session = Depends(get_db), user: User = Depends(admin)):
    _validate(body.kind, body.url, body.min_severity)
    integration = Integration(name=body.name.strip(), kind=body.kind, config={k: str(v)[:200] for k, v in body.config.items() if k in _CONFIG_KEYS[body.kind]},
                              min_severity=body.min_severity, categories=body.categories, is_active=body.is_active, created_by=user.id)
    _store(integration, body.kind, body.url, body.secret)
    db.add(integration)
    db.flush()
    audit(db, request, user, "integration.create", "integration", integration.id, kind=body.kind, name=integration.name)
    db.commit()
    return _out(integration)


@router.patch("/integrations/{integration_id}")
def update_integration(integration_id: int, body: IntegrationPatch, request: Request, db: Session = Depends(get_db), user: User = Depends(admin)):
    integration = db.get(Integration, integration_id)
    if integration is None:
        raise HTTPException(404, "Integration not found")
    if body.url is not None:
        _validate(integration.kind, body.url, body.min_severity or integration.min_severity)
    elif body.min_severity is not None and body.min_severity not in SEVERITIES:
        raise HTTPException(400, "Unknown severity")
    _store(integration, integration.kind, body.url, body.secret)
    for name in ("name", "min_severity", "categories", "is_active"):
        if (value := getattr(body, name)) is not None:
            setattr(integration, name, value)
    if body.config is not None:
        integration.config = {k: str(v)[:200] for k, v in body.config.items() if k in _CONFIG_KEYS[integration.kind]}
    if body.is_active:
        integration.failures = 0
    audit(db, request, user, "integration.update", "integration", integration.id, fields=sorted(body.model_dump(exclude_none=True)))
    db.commit()
    return _out(integration)


@router.delete("/integrations/{integration_id}")
def delete_integration(integration_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(admin)):
    integration = db.get(Integration, integration_id)
    if integration is None:
        raise HTTPException(404, "Integration not found")
    audit(db, request, user, "integration.delete", "integration", integration.id, name=integration.name)
    db.delete(integration)
    db.commit()
    return {"ok": True}


@router.post("/integrations/{integration_id}/test")
def test_integration(integration_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(admin)):
    if db.get(Integration, integration_id) is None:
        raise HTTPException(404, "Integration not found")
    enqueue("notify.test_integration", integration_id=integration_id)
    audit(db, request, user, "integration.test", "integration", integration_id)
    db.commit()
    return {"ok": True}


@router.get("/integrations/{integration_id}/deliveries")
def deliveries(integration_id: int, db: Session = Depends(get_db), user: User = Depends(analyst)):
    rows = db.scalars(select(Delivery).where(Delivery.integration_id == integration_id, Delivery.error != "filtered").order_by(Delivery.ts.desc()).limit(50)).all()
    return [{"id": d.id, "ts": iso(d.ts), "ok": d.ok, "status_code": d.status_code, "error": d.error, "alert_id": d.alert_id} for d in rows]


# ── Enrichment providers and the AI analyst ─────────────────────────────────

AI_HOST = "api.anthropic.com"
AI_MODELS = [
    {"id": "claude-opus-5-5", "label": "Claude Opus 5.5 (recommended)"},
    {"id": "claude-sonnet-5-5", "label": "Claude Sonnet 5.5 (faster, lower cost)"},
    {"id": "claude-fable-5-1", "label": "Claude Fable 5.1 (most capable, highest cost)"},
]
_TEST_KEY = "kivuli:provider:test:{}"


def _last_test(row: ProviderKey | None) -> dict | None:
    if row is None or row.last_test_at is None:
        return None
    return {"at": iso(row.last_test_at), "ok": bool(row.last_test_ok), "message": row.last_test_message, "detail": row.last_test_detail or {}}


def _key_state(row: ProviderKey | None, reported_source: str, takes_key: bool, show_hint: bool) -> dict:
    """Where the key in force comes from. A key set in the console wins over one in .env."""
    if not takes_key:
        return {"key_source": "not_needed", "hint": "", "key_updated_at": None}
    if row is not None and row.secret:
        return {"key_source": "console", "hint": row.hint if show_hint else "", "key_updated_at": iso(row.updated_at)}
    return {"key_source": "env" if reported_source == "env" else "none", "hint": "", "key_updated_at": None}


@router.get("/providers")
def provider_status(db: Session = Depends(get_db), user: User = Depends(viewer)):
    """Every enrichment provider and the AI analyst: whether it is switched on, where its key comes from, and how its last test went."""
    raw, ai_raw = _redis.get("kivuli:status:providers"), _redis.get("kivuli:status:ai")
    reported = {p["name"]: p for p in json.loads(raw)} if raw else {}
    ai_reported = json.loads(ai_raw) if ai_raw else {}
    rows = {r.name: r for r in db.scalars(select(ProviderKey))}
    allowed = set(settings.egress_allow_list)
    is_admin = user.role == "admin"
    out = []
    for p in providers.PROVIDERS:
        row = rows.get(p.name)
        state = _key_state(row, reported.get(p.name, {}).get("key_source", ""), p.takes_key, is_admin)
        has_key = state["key_source"] in ("console", "env")
        out.append({"name": p.name, "label": p.label, "kinds": list(p.kinds), "tier": p.tier, "about": p.about, "env": p.key_setting.upper(), "hosts": list(p.hosts),
                    "takes_key": p.takes_key, "optional_key": p.optional_key, "signup": p.signup, "testable": p.probe is not None,
                    "enabled": p.tier != "planned" and (not p.takes_key or p.optional_key or has_key),
                    "blocked_hosts": [h for h in p.hosts if h not in allowed] if p.tier != "planned" else [],
                    # A test result describes a key; once that key is gone it describes nothing.
                    "last_test": _last_test(row) if not p.takes_key or p.optional_key or has_key else None, **state})
    row = rows.get("anthropic")
    state = _key_state(row, ai_reported.get("key_source", ""), True, is_admin)
    ai = {"enabled": state["key_source"] in ("console", "env"), "model": (row.config or {}).get("model") if row and row.config else None,
          "models": AI_MODELS, "blocked_hosts": [] if AI_HOST in allowed else [AI_HOST],
          "last_test": _last_test(row) if state["key_source"] in ("console", "env") else None, **state}
    ai["model"] = ai["model"] or ai_reported.get("model") or settings.ai_model
    return {"reported": raw is not None, "providers": out, "ai": ai, "egress_allow_hosts": settings.egress_allow_list, "can_manage": is_admin}


def _known(name: str, *, needs_key: bool = False) -> None:
    testable = name == "anthropic" or (name in providers.BY_NAME and providers.BY_NAME[name].probe is not None)
    if not testable or (needs_key and name not in keys.ENV_SETTING):
        raise HTTPException(404, "Unknown provider" if not testable else "This provider does not take an API key")


def _start_test(name: str) -> str:
    job_id = uuid.uuid4().hex
    _redis.set(_TEST_KEY.format(job_id), json.dumps({"status": "queued", "name": name}), ex=900)
    enqueue("enrich.test_provider", job_id=job_id, name=name)
    return job_id


class ProviderKeyIn(BaseModel):
    key: str = Field(min_length=8, max_length=400)


@router.put("/providers/{name}/key")
def set_provider_key(name: str, body: ProviderKeyIn, request: Request, db: Session = Depends(get_db), user: User = Depends(admin)):
    """Store a provider's API key (encrypted) and immediately test it against the provider."""
    _known(name, needs_key=True)
    key = body.key.strip()
    if len(key) < 8 or any(c.isspace() or ord(c) < 33 or ord(c) > 126 for c in key):
        raise HTTPException(400, "That does not look like an API key: it contains spaces or unusual characters")
    try:
        hint = provider_store.set_key(db, name, key, user.id)
    except RuntimeError as exc:
        raise HTTPException(503, str(exc)) from None
    audit(db, request, user, "provider.key_set", "provider", name, ends_with=hint)
    db.commit()
    provider_store.publish(db)
    return {"ok": True, "job_id": _start_test(name)}


@router.delete("/providers/{name}/key")
def remove_provider_key(name: str, request: Request, db: Session = Depends(get_db), user: User = Depends(admin)):
    """Forget the key entered in the console. A key in .env, if there is one, comes back into force."""
    _known(name, needs_key=True)
    removed = provider_store.remove_key(db, name, user.id)
    audit(db, request, user, "provider.key_removed", "provider", name, had_key=removed)
    db.commit()
    provider_store.publish(db)
    enqueue("enrich.status")
    return {"ok": True}


class AiConfigIn(BaseModel):
    model: str = Field(pattern=r"^claude-[a-z0-9.-]{3,60}$")


@router.put("/providers/anthropic/config")
def set_ai_config(body: AiConfigIn, request: Request, db: Session = Depends(get_db), user: User = Depends(admin)):
    """Choose the model the AI analyst uses, then test it."""
    provider_store.set_config(db, "anthropic", {"model": body.model}, user.id)
    audit(db, request, user, "provider.config", "provider", "anthropic", model=body.model)
    db.commit()
    provider_store.publish(db)
    return {"ok": True, "job_id": _start_test("anthropic")}


@router.post("/providers/{name}/test")
def test_provider(name: str, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    """Make one real request to the provider and report whether it works. Poll the returned job for the answer."""
    _known(name)
    bucket = f"kivuli:rl:provider-test:{user.id}:{int(utcnow().timestamp() // 60)}"
    if _redis.incr(bucket) > 30:
        raise HTTPException(429, "Too many tests in the last minute")
    _redis.expire(bucket, 90)
    audit(db, request, user, "provider.test", "provider", name)
    db.commit()
    return {"ok": True, "job_id": _start_test(name)}


@router.get("/providers/tests/{job_id}")
def provider_test_result(job_id: str, user: User = Depends(analyst)):
    raw = _redis.get(_TEST_KEY.format(job_id)) if job_id.isalnum() else None
    if raw is None:
        raise HTTPException(404, "Test not found or expired")
    return json.loads(raw)


@router.post("/iocs/{ioc_id}/enrich")
def enrich_indicator(ioc_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    """Ask the configured providers about an indicator. The indicator itself is never contacted."""
    ioc = db.get(Ioc, ioc_id)
    if ioc is None:
        raise HTTPException(404, "Indicator not found")
    if ioc.type not in ("ip", "domain", "url", "hash"):
        raise HTTPException(400, "No provider covers this indicator type")
    enqueue("enrich.subject", subject_type=ioc.type, value=ioc.value)
    audit(db, request, user, "indicator.enrich", "ioc", ioc.id, value=ioc.value[:200])
    db.commit()
    return {"ok": True}


@router.get("/iocs/{ioc_id}/enrichment")
def indicator_enrichment(ioc_id: int, db: Session = Depends(get_db), user: User = Depends(viewer)):
    ioc = db.get(Ioc, ioc_id)
    if ioc is None:
        raise HTTPException(404, "Indicator not found")
    rows = db.scalars(select(Enrichment).where(Enrichment.subject_type == ioc.type, Enrichment.subject == ioc.value).order_by(Enrichment.provider)).all()
    labels = {p.name: p.label for p in providers.PROVIDERS}
    return {"tags": ioc.tags, "feeds": ioc.feeds, "benign": ioc.benign, "enrichable": ioc.type in ("ip", "domain", "url", "hash"),
            "results": [{"provider": r.provider, "label": labels.get(r.provider, r.provider), "fetched_at": iso(r.fetched_at), "ok": r.ok,
                         "verdict": r.verdict, "score": r.score, "summary": r.summary, "error": r.error} for r in rows]}


class IocPatch(BaseModel):
    benign: bool


@router.patch("/iocs/{ioc_id}")
def update_indicator(ioc_id: int, body: IocPatch, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    """Mark an indicator benign (a common service, not a threat) so it stops driving correlation."""
    ioc = db.get(Ioc, ioc_id)
    if ioc is None:
        raise HTTPException(404, "Indicator not found")
    ioc.benign = body.benign
    audit(db, request, user, "indicator.benign", "ioc", ioc.id, benign=body.benign, value=ioc.value[:200])
    db.commit()
    return {"ok": True}


# ── API keys ────────────────────────────────────────────────────────────────

class ApiKeyIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    write: bool = False
    expires_days: int | None = Field(None, ge=1, le=3650)


def _key_out(k: ApiKey) -> dict:
    return {"id": k.id, "name": k.name, "prefix": k.prefix, "scopes": k.scopes, "created_at": iso(k.created_at), "last_used_at": iso(k.last_used_at),
            "expires_at": iso(k.expires_at), "revoked": k.revoked}


@router.get("/api-keys")
def list_api_keys(db: Session = Depends(get_db), user: User = Depends(viewer)):
    return [_key_out(k) for k in db.scalars(select(ApiKey).where(ApiKey.user_id == user.id).order_by(ApiKey.created_at.desc()))]


@router.post("/api-keys")
def create_api_key(body: ApiKeyIn, request: Request, db: Session = Depends(get_db), user: User = Depends(viewer)):
    """Create a key that acts as you, with your role. The key is shown once and only its hash is kept."""
    if getattr(request.state, "api_key", None) is not None:
        raise HTTPException(403, "API keys cannot create API keys; sign in to the console")
    if body.write and user.role == "viewer":
        raise HTTPException(403, "Viewers can only create read-only keys")
    key, prefix, key_hash = new_api_key()
    row = ApiKey(user_id=user.id, name=body.name.strip(), prefix=prefix, key_hash=key_hash, scopes=["read", "write"] if body.write else ["read"],
                 expires_at=utcnow() + timedelta(days=body.expires_days) if body.expires_days else None)
    db.add(row)
    db.flush()
    audit(db, request, user, "apikey.create", "apikey", row.id, name=row.name, scopes=row.scopes)
    db.commit()
    return {**_key_out(row), "key": key}


@router.delete("/api-keys/{key_id}")
def revoke_api_key(key_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(viewer)):
    row = db.get(ApiKey, key_id)
    if row is None or (row.user_id != user.id and user.role != "admin"):
        raise HTTPException(404, "Not found")
    row.revoked = True
    audit(db, request, user, "apikey.revoke", "apikey", row.id, name=row.name)
    db.commit()
    return {"ok": True}
