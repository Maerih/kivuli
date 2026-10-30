"""Remember which provider keys a provider has rejected, so they stop being used.

A rejected key (HTTP 401/403) would otherwise be tried, and fail, on every
lookup. The enricher records the rejection against a fingerprint of the key -
a truncated SHA-256, never the key itself - and skips the provider while that
same key is in place. Saving a different key changes the fingerprint, so the
provider is used again straight away; a passing connection test clears the mark.
"""
import hashlib
import json

import redis

from app.config import get_settings

_KEY = "kivuli:enrich:rejected:{}"
_TTL = 30 * 86400
_redis = redis.Redis.from_url(get_settings().redis_url, decode_responses=True)


def fingerprint(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()[:16] if api_key else ""


def mark(name: str, api_key: str, message: str) -> None:
    _redis.set(_KEY.format(name), json.dumps({"fp": fingerprint(api_key), "message": message[:300]}), ex=_TTL)


def clear(name: str) -> None:
    _redis.delete(_KEY.format(name))


def rejection(name: str, api_key: str | None = None) -> str:
    """The rejection message if this provider's key was rejected, else "".

    With ``api_key`` (in the enricher, which holds the keys) the mark only
    counts while that same key is in place. Without it (in the API) the mark is
    reported as it stands; the enricher clears or replaces it.
    """
    try:
        raw = _redis.get(_KEY.format(name))
    except redis.RedisError:
        return ""  # without the queue store, nothing is skipped: a failing key just fails as before
    if not raw:
        return ""
    data = json.loads(raw)
    if api_key is not None and data.get("fp") != fingerprint(api_key):
        return ""
    return data.get("message", "")


def all_rejections() -> dict[str, str]:
    out = {}
    try:
        for key in _redis.scan_iter(_KEY.format("*")):
            name = key.rsplit(":", 1)[-1]
            if msg := json.loads(_redis.get(key) or "{}").get("message"):
                out[name] = msg
    except redis.RedisError:
        return {}
    return out
