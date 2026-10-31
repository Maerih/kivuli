"""Settings an administrator changes in the console instead of `.env`.

`.env` stays the baseline. A value set in the console overrides it, in every
container, within SYNC_SECONDS and without a restart; clearing it goes back to
`.env`. PostgreSQL is the record (app_settings, key "runtime"); it is mirrored
to Redis, which every container can read, including the crawler and the
enricher that have no database access. Each process applies the overrides onto
its cached Settings object before every task and request, so code keeps
reading `settings.smtp_host` and the like, unchanged.

The SMTP password is stored encrypted with SECRETS_KEY. Only containers that
hold that key (the API and the notify worker) can decrypt it, and it is never
sent back to the browser.

Settings that need a container rebuilt or recreated (ports, domain, secrets,
the egress allow-list, memory) stay in `.env`: they are infrastructure, and
the egress allow-list in particular must not be widened by the application.
"""
import json
import re
import time
from dataclasses import dataclass
from typing import Any

import redis

from app import crypto
from app.config import get_settings

REDIS_KEY = "kivuli:runtime"
SYNC_SECONDS = 10
_EMAIL = re.compile(r"^[^@\s,]+@[^@\s,]+\.[^@\s,]+$")


@dataclass(frozen=True)
class Field:
    group: str
    label: str
    kind: str  # bool | int | str | choice | emails | countries | list | url | secret
    help: str = ""
    low: int = 0
    high: int = 0
    choices: tuple[str, ...] = ()


FIELDS: dict[str, Field] = {
    "email_enabled": Field("email", "Send alert email", "bool"),
    "smtp_host": Field("email", "SMTP server", "str", "e.g. smtp.example.org; mailpit is the built-in test inbox"),
    "smtp_port": Field("email", "SMTP port", "int", "587 for STARTTLS, 465 for SSL, 25 or 1025 for none", 1, 65535),
    "smtp_tls": Field("email", "Encryption", "choice", "", choices=("starttls", "ssl", "none")),
    "smtp_username": Field("email", "SMTP username", "str"),
    "smtp_password": Field("email", "SMTP password", "secret", "Stored encrypted; never shown again"),
    "smtp_from": Field("email", "From", "str", 'e.g. Kivuli Alerts <alerts@example.org>'),
    "alert_email_to": Field("email", "Alert recipients", "emails", "Comma-separated; also receives health alerts"),
    "digest_hour_utc": Field("email", "Daily digest hour (UTC)", "int", "", 0, 23),
    "focus_countries": Field("focus", "Focus countries", "countries", "ISO codes, comma-separated, e.g. KE,UG,TZ"),
    "focus_sectors": Field("focus", "Focus sectors", "list", "Comma-separated, e.g. Finance,Healthcare"),
    "require_mfa": Field("access", "Require two-step sign-in for everyone", "bool"),
    "crawl_host_delay_seconds": Field("collection", "Seconds between requests to one site", "int", "", 1, 120),
    "liveness_interval_hours": Field("collection", "Hours between liveness checks of candidates", "int", "", 1, 168),
    "discover_onion_links": Field("collection", "File onion links found in pages as candidate sources", "bool"),
    "intelowl_url": Field("intelowl", "IntelOwl address", "url", "e.g. https://intelowl.example.org; its host must be in EGRESS_ALLOW_HOSTS"),
    "intelowl_playbook": Field("intelowl", "Playbook", "str"),
    "intelowl_analyzers": Field("intelowl", "Analyzers instead of the playbook", "list", "Comma-separated; scanners are refused"),
    "intelowl_tlp": Field("intelowl", "TLP", "choice", "", choices=("CLEAR", "GREEN", "AMBER", "RED")),
}
GROUPS = {"email": "Email delivery", "focus": "Focus", "access": "Access", "collection": "Collection pacing", "intelowl": "IntelOwl"}

_baseline: dict[str, Any] = {}
_applied_at = 0.0
_redis: redis.Redis | None = None


def _r() -> redis.Redis:
    global _redis
    if _redis is None:
        _redis = redis.Redis.from_url(get_settings().redis_url, decode_responses=True, socket_timeout=2)
    return _redis


def validate(name: str, value: Any) -> Any:
    """The stored form of a console value, or ValueError. None or "" clears the override."""
    field = FIELDS.get(name)
    if field is None:
        raise ValueError(f"{name} cannot be set in the console")
    if value is None or value == "":
        return None
    if field.kind == "bool":
        if not isinstance(value, bool):
            raise ValueError(f"{field.label}: true or false")
        return value
    if field.kind == "int":
        if isinstance(value, bool) or not isinstance(value, int) or not field.low <= value <= field.high:
            raise ValueError(f"{field.label}: a whole number from {field.low} to {field.high}")
        return value
    text = " ".join(str(value).split())[:500]
    if field.kind == "choice" and text not in field.choices:
        raise ValueError(f"{field.label}: one of {', '.join(field.choices)}")
    if field.kind == "emails":
        items = [a.strip() for a in text.split(",") if a.strip()]
        if not items or any(not _EMAIL.match(a) for a in items):
            raise ValueError(f"{field.label}: comma-separated email addresses")
        return ",".join(items)
    if field.kind == "countries":
        items = [c.strip().upper() for c in text.split(",") if c.strip()]
        if any(not re.fullmatch(r"[A-Z]{2}", c) for c in items):
            raise ValueError(f"{field.label}: two-letter country codes, comma-separated")
        return ",".join(items)
    if field.kind == "list":
        return ",".join(i.strip() for i in text.split(",") if i.strip())
    if field.kind == "url" and not re.fullmatch(r"https?://[A-Za-z0-9.-]+(:\d+)?(/.*)?", text):
        raise ValueError(f"{field.label}: an http(s) address")
    return text


def apply(overrides: dict, settings=None) -> None:
    """Put console values onto the Settings object, and `.env` values back where none is set."""
    settings = settings or get_settings()
    if not _baseline:
        _baseline.update({name: getattr(settings, name) for name in FIELDS})
    for name in FIELDS:
        if name in overrides:
            value = overrides[name]
            if FIELDS[name].kind == "secret":
                try:
                    value = crypto.decrypt(value)
                except Exception:  # this container holds no SECRETS_KEY (crawler, enricher): it does not need it
                    continue
            setattr(settings, name, value)
        else:
            setattr(settings, name, _baseline[name])


def sync(force: bool = False) -> None:
    """Apply the current console overrides in this process, at most every SYNC_SECONDS."""
    global _applied_at
    now = time.monotonic()
    if not force and now - _applied_at < SYNC_SECONDS:
        return
    _applied_at = now
    try:
        raw = _r().get(REDIS_KEY)
    except redis.RedisError:
        return  # keep whatever is applied; Redis being down must not break a request
    apply(json.loads(raw) if raw else {})


def stored(db) -> dict:
    from app.models import AppSetting

    row = db.get(AppSetting, "runtime")
    return dict(row.value) if row and row.value else {}


def mirror(db) -> None:
    """Copy the record to Redis (on every save, and periodically in case Redis lost it)."""
    _r().set(REDIS_KEY, json.dumps(stored(db)))


def save(db, changes: dict, user_id: int | None) -> dict:
    """Validate and store console values; None or "" removes an override. Returns the stored overrides."""
    from app.models import AppSetting, utcnow

    current = stored(db)
    for name, value in changes.items():
        clean = validate(name, value)
        if FIELDS[name].kind == "secret":
            if value == "__keep__":
                continue
            clean = crypto.encrypt(clean) if clean else None
        if clean is None:
            current.pop(name, None)
        else:
            current[name] = clean
    row = db.get(AppSetting, "runtime")
    if row is None:
        row = AppSetting(key="runtime")
        db.add(row)
    row.value, row.updated_by, row.updated_at = current, user_id, utcnow()
    db.flush()
    mirror(db)
    sync(force=True)
    return current


def describe(db) -> list[dict]:
    """Every field with its `.env` value, its console value and which one is in effect. Secrets are masked."""
    sync(force=True)
    overrides = stored(db)
    out = []
    for name, field in FIELDS.items():
        env_value = _baseline.get(name)
        console = overrides.get(name)
        if field.kind == "secret":
            env_value = bool(env_value)
            console = bool(console) if name in overrides else None
        out.append({"name": name, "group": field.group, "group_label": GROUPS[field.group], "label": field.label, "kind": field.kind,
                    "help": field.help, "low": field.low, "high": field.high, "choices": list(field.choices),
                    "env": env_value, "console": console, "source": "console" if name in overrides else "env"})
    return out
