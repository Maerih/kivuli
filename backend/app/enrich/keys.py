"""Where provider API keys and settings come from.

A key can be set in two places: in `.env` (read from this container's
environment) or in the console. Console keys are stored encrypted in
PostgreSQL by the API and mirrored, still encrypted, to Redis. The enricher has
no database access, so it reads the mirror and decrypts with PROVIDER_KEYS_KEY.
A key set in the console takes precedence over one in `.env`.
"""
import json
import logging
import time

import redis

from app import crypto
from app.config import get_settings

log = logging.getLogger(__name__)

KEYS_HASH = "kivuli:provider:keys"  # provider name -> ciphertext
CONFIG_HASH = "kivuli:provider:config"  # provider name -> JSON of non-secret settings
# Providers that take a key, and the Settings attribute that holds the `.env` value.
ENV_SETTING = {"virustotal": "virustotal_api_key", "shodan": "shodan_api_key", "abuseipdb": "abuseipdb_api_key", "greynoise": "greynoise_api_key",
               "nvd": "nvd_api_key", "anthropic": "anthropic_api_key", "dwi": "dwi_api_key", "intelowl": "intelowl_api_key"}
_TTL = 20.0  # seconds a loaded copy is reused; a connection test always reloads

_cache: dict = {"at": 0.0, "keys": {}, "config": {}, "unreadable": set()}
_redis: redis.Redis | None = None


def _client() -> redis.Redis:
    global _redis
    if _redis is None:
        _redis = redis.Redis.from_url(get_settings().redis_url, decode_responses=True)
    return _redis


def _load() -> tuple[dict[str, str], dict[str, dict]]:
    """The console-managed keys (decrypted) and settings. Never raises: a broken mirror means "nothing set in the console"."""
    keys: dict[str, str] = {}
    config: dict[str, dict] = {}
    unreadable: set[str] = set()
    try:
        for name, token in _client().hgetall(KEYS_HASH).items():
            try:
                keys[name] = crypto.unseal(token)
            except RuntimeError:
                unreadable.add(name)
        for name, raw in _client().hgetall(CONFIG_HASH).items():
            try:
                config[name] = json.loads(raw)
            except ValueError:
                continue
    except redis.RedisError:
        log.warning("could not read console-managed provider keys")
    _cache["unreadable"] = unreadable
    return keys, config


def refresh() -> None:
    _cache["keys"], _cache["config"] = _load()
    _cache["at"] = time.monotonic()


def _current() -> dict:
    if time.monotonic() - _cache["at"] > _TTL:
        refresh()
    return _cache


def get(name: str) -> str:
    """The API key in force for a provider, or an empty string."""
    return _current()["keys"].get(name) or getattr(get_settings(), ENV_SETTING.get(name, ""), "") or ""


def source(name: str) -> str:
    """console | env | unreadable | none"""
    current = _current()
    if current["keys"].get(name):
        return "console"
    if name in current["unreadable"]:
        return "unreadable"
    return "env" if getattr(get_settings(), ENV_SETTING.get(name, ""), "") else "none"


def config(name: str) -> dict:
    return _current()["config"].get(name) or {}


def ai_model() -> str:
    return str(config("anthropic").get("model") or get_settings().ai_model)
