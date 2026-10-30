"""Enricher-side blockchain lookups.

Runs in the enricher container, the only one with egress. It reads a public
explorer about an address and hands the result to the pipeline to store. It
holds no key, signs nothing and never contacts anything but the allow-listed
explorer hosts.
"""
import json
import logging

import redis

from app.chain import providers
from app.config import get_settings
from app.enrich.http import EnrichError
from app.worker.celery_app import celery_app, enqueue

log = logging.getLogger(__name__)
settings = get_settings()
_redis = redis.Redis.from_url(settings.redis_url, decode_responses=True)

JOB_KEY = "kivuli:chain:{}"
JOB_TTL = 900
# One call per explorer every second, across all enricher processes, to stay polite and within free limits.
_DELAY = 1.0


def _job(job_id: str, **fields) -> None:
    if not job_id:
        return
    key = JOB_KEY.format(job_id)
    current = json.loads(_redis.get(key) or "{}")
    current.update(fields)
    _redis.set(key, json.dumps(current), ex=JOB_TTL)


def _throttle(chain: str) -> None:
    import time

    for _ in range(120):
        if _redis.set(f"kivuli:chain:rate:{chain}", "1", nx=True, px=int(_DELAY * 1000)):
            return
        time.sleep(_DELAY / 2)


@celery_app.task(name="chain.lookup", soft_time_limit=120, time_limit=150)
def lookup(job_id: str, chain: str, address: str, requested_by: int | None = None):
    """Look one address up on-chain and store it with its flows."""
    _job(job_id, status="running", address=address, chain=chain)
    _throttle(chain)
    try:
        result = providers.lookup(chain, address)
    except EnrichError as exc:
        enqueue("pipeline.store_chain", address=address, chain=chain, ok=False, error=str(exc)[:300])
        _job(job_id, status="error", error=str(exc)[:300])
        return
    except Exception:
        log.exception("chain lookup failed for %s", address)
        enqueue("pipeline.store_chain", address=address, chain=chain, ok=False, error="The lookup failed unexpectedly")
        _job(job_id, status="error", error="The lookup failed unexpectedly")
        return
    enqueue("pipeline.store_chain", ok=True, result=result, requested_by=requested_by)
    _job(job_id, status="done", address=address, counterparties=len(result["counterparties"]),
         tx_count=result["tx_count"], balance=result["balance"], token=result["token"])
