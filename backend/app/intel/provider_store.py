"""Console-managed provider keys: the database side.

PostgreSQL is the record. Redis carries a mirror of the same ciphertext so the
enricher, which has no database access, can pick keys up. The mirror is rewritten
on every change and on a schedule, so losing Redis loses nothing.
"""
import json

import redis
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app import crypto
from app.config import get_settings
from app.enrich.keys import CONFIG_HASH, ENV_SETTING, KEYS_HASH
from app.models import ProviderKey, utcnow

_redis = redis.Redis.from_url(get_settings().redis_url, decode_responses=True)


def publish(db: Session) -> int:
    """Rewrite the Redis mirror from the database. Returns how many keys it now holds."""
    rows = db.scalars(select(ProviderKey)).all()
    secrets = {r.name: r.secret for r in rows if r.secret}
    config = {r.name: json.dumps(r.config) for r in rows if r.config}
    pipe = _redis.pipeline(transaction=True)
    pipe.delete(KEYS_HASH, CONFIG_HASH)
    if secrets:
        pipe.hset(KEYS_HASH, mapping=secrets)
    if config:
        pipe.hset(CONFIG_HASH, mapping=config)
    pipe.execute()
    return len(secrets)


def _row(db: Session, name: str) -> ProviderKey:
    row = db.get(ProviderKey, name)
    if row is None:
        row = ProviderKey(name=name, config={}, last_test_detail={})
        db.add(row)
    return row


def set_key(db: Session, name: str, key: str, user_id: int | None) -> str:
    """Store a key encrypted. Returns the hint shown in the console (its last four characters)."""
    if name not in ENV_SETTING:
        raise ValueError("this provider does not take an API key")
    row = _row(db, name)
    row.secret, row.hint = crypto.seal(key), key[-4:]
    row.updated_by, row.updated_at = user_id, utcnow()
    # The previous test said something about the previous key.
    row.last_test_at, row.last_test_ok, row.last_test_message, row.last_test_detail = None, None, "", {}
    return row.hint


def remove_key(db: Session, name: str, user_id: int | None) -> bool:
    row = db.get(ProviderKey, name)
    if row is None or not row.secret:
        return False
    row.secret, row.hint, row.updated_by, row.updated_at = "", "", user_id, utcnow()
    row.last_test_at, row.last_test_ok, row.last_test_message, row.last_test_detail = None, None, "", {}
    return True


def set_config(db: Session, name: str, values: dict, user_id: int | None) -> None:
    row = _row(db, name)
    row.config = {**(row.config or {}), **values}
    row.updated_by, row.updated_at = user_id, utcnow()


def record_test(db: Session, name: str, ok: bool, message: str, detail: dict) -> None:
    stmt = pg_insert(ProviderKey).values(name=name, secret="", hint="", config={}, last_test_at=utcnow(), last_test_ok=ok,
                                         last_test_message=message, last_test_detail=detail)
    db.execute(stmt.on_conflict_do_update(index_elements=["name"], set_={
        "last_test_at": stmt.excluded.last_test_at, "last_test_ok": ok, "last_test_message": message, "last_test_detail": detail}))
