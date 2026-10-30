"""Crawler-side tasks. Imports nothing that touches the database or the index."""
import json
import random
from datetime import datetime, timezone
from urllib.parse import urlsplit

import redis

from app.config import get_settings
from app.crawl.blocklist import is_blocked
from app.crawl.fetcher import fetch
from app.crawl.render import render as render_page
from app.extract.relevance import page_title
from app.worker.celery_app import celery_app, enqueue

settings = get_settings()
_redis = redis.Redis.from_url(settings.redis_url, decode_responses=True)

TOR_STATUS_KEY = "kivuli:status:tor"


@celery_app.task(name="crawl.fetch", bind=True, max_retries=40, soft_time_limit=200, time_limit=230)
def crawl_fetch(self, *, url: str, route: str, source_id: int, run_id: str, depth: int = 0, probe: bool = False,
                max_bytes: int | None = None, connector: str = "html", attempt: int = 0, extra: dict | None = None,
                render: bool = False):
    host = (urlsplit(url).hostname or "").lower()
    if is_blocked(_redis, host):
        # Known abuse material: never fetched, whoever or whatever asked.
        enqueue("pipeline.ingest_fetch", source_id=source_id, run_id=run_id, depth=depth, probe=probe, connector=connector, extra=extra or {},
                result={"url": url, "final_url": url, "ok": False, "http_status": None, "bytes": 0, "elapsed_ms": 0, "body": "", "blocked": True,
                        "error": "refused: this onion service is on the abuse blocklist"})
        return

    # Politeness: one request per host every few seconds, across all crawler processes.
    delay = settings.crawl_host_delay_seconds
    if not _redis.set(f"kivuli:crawl:host:{host}", "1", nx=True, px=int(delay * 1000)):
        raise self.retry(countdown=delay * (1 + random.random()))

    # A liveness probe only needs to know the site answers: a plain fetch, never the browser.
    if render and connector == "html" and not probe:
        result = render_page(url, route=route, max_bytes=max_bytes)
    else:
        result = fetch(url, route=route, max_bytes=32_768 if probe and connector == "html" else max_bytes)

    # Tor circuits fail often: transient errors get two more attempts (one for a
    # liveness probe) before the failure is reported.
    if result.transient and attempt < (1 if probe else 2):
        enqueue("crawl.fetch", countdown=20 * (attempt + 1), url=url, route=route, source_id=source_id, run_id=run_id,
                depth=depth, probe=probe, max_bytes=max_bytes, connector=connector, attempt=attempt + 1, extra=extra,
                render=render)
        return

    payload = result.as_dict()
    if probe:
        # A liveness check keeps the site's title, so a researcher knows what a candidate is, and nothing else.
        payload["title"] = page_title(payload["body"]) if connector == "html" else ""
        payload["body"] = ""
    enqueue("pipeline.ingest_fetch", result=payload, source_id=source_id, run_id=run_id, depth=depth, probe=probe,
            connector=connector, extra=extra or {})


@celery_app.task(name="crawl.tor_check", soft_time_limit=120, time_limit=150)
def tor_check():
    """Prove the gateway really exits through Tor, and publish the result for the console."""
    result = fetch("https://check.torproject.org/api/ip", route="tor", max_bytes=4096, timeout=60)
    status = {"ok": False, "is_tor": False, "exit_ip": "", "latency_ms": result.elapsed_ms, "error": result.error,
              "checked_at": datetime.now(timezone.utc).isoformat()}
    if result.ok:
        try:
            data = json.loads(result.body)
            status.update(ok=True, is_tor=bool(data.get("IsTor")), exit_ip=str(data.get("IP", "")))
        except ValueError:
            status["error"] = "unexpected response from the Tor check service"
    _redis.set(TOR_STATUS_KEY, json.dumps(status), ex=1800)
    return status
