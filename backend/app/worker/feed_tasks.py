"""Enricher-side imports from intelligence providers that need an API key.

Dark Web Informer is read here, not by the crawler, because only the enricher
holds keys. A sync reads one prebuilt STIX export, keeps what changed since the
last sync, and hands the pipeline compact alerts and indicator lists to store.
"""
import logging
import time

import redis

from app.config import get_settings
from app.enrich import dwi
from app.enrich.http import EnrichError
from app.worker.celery_app import celery_app, enqueue

log = logging.getLogger(__name__)
settings = get_settings()
_redis = redis.Redis.from_url(settings.redis_url, decode_responses=True)

CURSOR_KEY = "kivuli:dwi:cursor:{}"
ALERT_BATCH = 100
IOC_BATCH = 5000


def _export_slot() -> None:
    """Dark Web Informer allows two exports a minute: one every 31 seconds, across all enricher processes."""
    for _ in range(40):
        if _redis.set("kivuli:dwi:export", "1", nx=True, px=31_000):
            return
        time.sleep(5)


@celery_app.task(name="enrich.dwi_sync", soft_time_limit=900, time_limit=960)
def dwi_sync(source_id: int, kind: str, run_id: str, probe: bool = False):
    """Import one Dark Web Informer export (feed, ransomware or iocs) into the pipeline."""
    started = time.monotonic()
    try:
        if probe:
            result = dwi.probe()
            enqueue("pipeline.dwi_status", source_id=source_id, run_id=run_id, ok=result["ok"], error="" if result["ok"] else result["message"],
                    probe=True, elapsed_ms=int((time.monotonic() - started) * 1000))
            return
        _export_slot()
        bundle = dwi.fetch_bundle(kind)
    except EnrichError as exc:
        enqueue("pipeline.dwi_status", source_id=source_id, run_id=run_id, ok=False, error=str(exc)[:500], probe=probe,
                elapsed_ms=int((time.monotonic() - started) * 1000))
        return
    objects = [o for o in bundle.get("objects") or [] if isinstance(o, dict)]
    cursor = _redis.get(CURSOR_KEY.format(kind)) or ""
    fresh = dwi.changed_since(objects, cursor)
    alerts, iocs = dwi.split_bundle(fresh, kind)
    for i in range(0, len(alerts), ALERT_BATCH):
        enqueue("pipeline.store_dwi", source_id=source_id, kind=kind, alerts=alerts[i:i + ALERT_BATCH], iocs=[])
    for i in range(0, len(iocs), IOC_BATCH):
        enqueue("pipeline.store_dwi", source_id=source_id, kind=kind, alerts=[], iocs=[list(x) for x in iocs[i:i + IOC_BATCH]])
    if objects:
        _redis.set(CURSOR_KEY.format(kind), dwi.cursor_of(objects))
    enqueue("pipeline.dwi_status", source_id=source_id, run_id=run_id, ok=True, error="", probe=False,
            elapsed_ms=int((time.monotonic() - started) * 1000), objects=len(objects), changed=len(fresh), alerts=len(alerts), iocs=len(iocs))
    log.info("dwi %s: %d objects, %d changed, %d alerts, %d indicators", kind, len(objects), len(fresh), len(alerts), len(iocs))
