"""Enricher-side tasks: third-party lookups and AI calls.

This role holds the provider API keys and can reach only the allowlisting egress
proxy. It never parses crawled content and has no database access; results go
back to the pipeline over the queue.
"""
import json
import logging
import time

import redis
from celery.signals import worker_ready

from app.ai import analyst
from app.config import get_settings
from app.enrich import keys, providers, rejected
from app.enrich.http import EnrichError
from app.worker.celery_app import celery_app, enqueue

log = logging.getLogger(__name__)
settings = get_settings()
_redis = redis.Redis.from_url(settings.redis_url, decode_responses=True)

PROVIDER_STATUS_KEY = "kivuli:status:providers"
AI_STATUS_KEY = "kivuli:status:ai"
AI_JOB_TTL = 3600


def _throttle(name: str, seconds: float) -> None:
    """At most one call per provider every ``seconds``, across all enricher processes."""
    for _ in range(120):
        if _redis.set(f"kivuli:enrich:rate:{name}", "1", nx=True, px=int(seconds * 1000)):
            return
        time.sleep(seconds / 2)


@celery_app.task(name="enrich.status")
def publish_status():
    """Tell the API what is switched on here. Only this container can know: it is the one that holds the keys."""
    keys.refresh()
    _redis.set(PROVIDER_STATUS_KEY, json.dumps(providers.catalogue()), ex=3600)
    _redis.set(AI_STATUS_KEY, json.dumps({"enabled": analyst.enabled(), "model": keys.ai_model(), "key_source": keys.source("anthropic")}), ex=3600)


PROVIDER_TEST_KEY = "kivuli:provider:test:{}"


@celery_app.task(name="enrich.test_provider", soft_time_limit=150, time_limit=180)
def test_provider(job_id: str, name: str):
    """Make one real request to a provider and report whether it works. The console waits on the result."""
    key = PROVIDER_TEST_KEY.format(job_id)
    _redis.set(key, json.dumps({"status": "running", "name": name}), ex=900)
    keys.refresh()  # a key saved a moment ago must be the one that is tested
    started = time.monotonic()
    if name == "anthropic":
        result = analyst.selftest()
    else:
        _throttle(name, 1.0)
        result = providers.run_probe(name)
    result = {**result, "latency_ms": int((time.monotonic() - started) * 1000), "key_source": keys.source(name) if name in keys.ENV_SETTING else "not_needed"}
    if result["ok"]:
        rejected.clear(name)
    elif (result.get("detail") or {}).get("reason") == "key_rejected":
        rejected.mark(name, keys.get(name), result["message"])
    _redis.set(key, json.dumps({"status": "done", "name": name, **result}), ex=900)
    enqueue("pipeline.store_provider_test", name=name, ok=result["ok"], message=result["message"][:500], detail=result.get("detail") or {})
    publish_status()


@worker_ready.connect
def _on_ready(**_kwargs):
    try:
        publish_status()
    except Exception:  # status is cosmetic; never block start-up on it
        log.warning("could not publish provider status")


@celery_app.task(name="enrich.subject", soft_time_limit=240, time_limit=300)
def enrich_subject(subject_type: str, value: str, only: list[str] | None = None):
    """Ask every enabled provider about one indicator."""
    for provider in providers.for_kind(subject_type):
        if only and provider.name not in only:
            continue
        _throttle(provider.name, 1.5)
        try:
            result = provider.fetch(subject_type, value)
            enqueue("pipeline.store_enrichment", subject_type=subject_type, subject=value, provider=provider.name, ok=True, **result)
            if provider.takes_key and rejected.rejection(provider.name):
                rejected.clear(provider.name)  # a replaced key answered: the old rejection no longer applies
                publish_status()
        except providers.KeyRejected as exc:
            # Stop using this key until it changes; say so once, in the console's provider list, not on every lookup.
            rejected.mark(provider.name, keys.get(provider.name), f"{exc}. Replace the key under Integrations.")
            publish_status()
        except EnrichError as exc:
            enqueue("pipeline.store_enrichment", subject_type=subject_type, subject=value, provider=provider.name, ok=False,
                    verdict="unknown", score=None, summary={}, error=str(exc)[:300])
        except Exception as exc:
            log.exception("provider %s failed", provider.name)
            enqueue("pipeline.store_enrichment", subject_type=subject_type, subject=value, provider=provider.name, ok=False,
                    verdict="unknown", score=None, summary={}, error=f"{type(exc).__name__}"[:300])


@celery_app.task(name="enrich.asm_discover", soft_time_limit=240, time_limit=300)
def asm_discover(watchlist_id: int, domain: str):
    """Find an owned domain's hostnames in certificate-transparency logs. Passive: nothing is scanned."""
    _throttle("ct", 2)
    try:
        hosts, _issuers, source = providers.ct_hostnames(domain)
        enqueue("pipeline.asm_hosts", watchlist_id=watchlist_id, hosts=hosts[: settings.asm_max_hosts], via=source, error="")
    except EnrichError as exc:
        enqueue("pipeline.asm_hosts", watchlist_id=watchlist_id, hosts=[], via="", error=str(exc)[:300])


@celery_app.task(name="enrich.asm_host", soft_time_limit=180, time_limit=240)
def asm_host(asset_id: int, host: str, is_ip: bool = False):
    """Resolve a host over public DNS and read what passive scan data says about its addresses."""
    try:
        if is_ip:
            ips = [host]
        else:
            _throttle("dns", 0.3)
            ips = providers.dns_records(host, "A")[:4]
        services: dict[str, dict] = {}
        asn = ""
        for ip in ips[:3]:
            _throttle("internetdb", 1.0)
            services[ip] = providers.internetdb("ip", ip)["summary"]
        if ips:
            _throttle("ripestat", 1.0)
            net = providers.ripestat("ip", ips[0])["summary"]
            asn = " ".join(filter(None, [net.get("asn", ""), net.get("holder", "")]))
        enqueue("pipeline.asm_host_result", asset_id=asset_id, ips=ips, services=services, asn=asn, error="")
    except EnrichError as exc:
        enqueue("pipeline.asm_host_result", asset_id=asset_id, ips=[], services={}, asn="", error=str(exc)[:300])


@celery_app.task(name="enrich.vulnerabilities", soft_time_limit=280, time_limit=320)
def enrich_vulnerabilities(cves: list[str], with_nvd: int = 8):
    """Exploit-prediction scores for a batch of CVEs, plus NVD severity for the first few."""
    rows: dict[str, dict] = {cve: {} for cve in cves}
    try:
        _throttle("epss", 1.0)
        for cve, (score, percentile) in providers.epss_scores(cves).items():
            rows.setdefault(cve, {}).update(epss=score, epss_percentile=percentile)
    except EnrichError as exc:
        log.warning("EPSS lookup failed: %s", exc)
    # NVD allows 5 requests per 30 seconds without a key, 50 with one.
    for cve in cves[:with_nvd]:
        try:
            _throttle("nvd", 0.7 if keys.get("nvd") else 6.5)
            if data := providers.nvd(cve):
                rows[cve].update(data)
        except EnrichError as exc:
            log.warning("NVD lookup failed for %s: %s", cve, exc)
            break
    enqueue("pipeline.store_vulnerability_scores", rows=rows)


# ── AI ──────────────────────────────────────────────────────────────────────

def _job(job_id: str, **fields) -> None:
    key = f"kivuli:ai:{job_id}"
    current = json.loads(_redis.get(key) or "{}")
    current.update(fields)
    _redis.set(key, json.dumps(current), ex=AI_JOB_TTL)


def _guard(job_id: str, fn):
    try:
        return fn()
    except analyst.AIUnavailable as exc:
        _job(job_id, status="error", error=str(exc))
    except Exception:
        log.exception("AI job %s failed", job_id)
        _job(job_id, status="error", error="The AI request failed unexpectedly")
    return None


@celery_app.task(name="ai.ask", soft_time_limit=200, time_limit=240)
def ai_ask(job_id: str, question: str, operators: list[dict], today: str):
    """Step 1 of a grounded answer: translate the question, then hand retrieval to the pipeline."""
    _job(job_id, status="translating")
    translated = _guard(job_id, lambda: analyst.translate_query(question, operators, today))
    if translated is not None:
        _job(job_id, status="retrieving", query=translated["query"], explanation=translated["explanation"])
        enqueue("pipeline.ai_retrieve", job_id=job_id, question=question, query=translated["query"])


@celery_app.task(name="ai.answer", soft_time_limit=280, time_limit=320)
def ai_answer(job_id: str, question: str, sources: list[dict]):
    """Step 3: answer from the findings the pipeline retrieved."""
    _job(job_id, status="answering")
    result = _guard(job_id, lambda: analyst.answer(question, sources))
    if result is not None:
        refs = [{"label": f"S{n}", "id": s["id"], "title": s["title"], "source_name": s.get("source_name", ""), "date": s.get("date", "")}
                for n, s in enumerate(sources, 1)]
        _job(job_id, status="done", sources=refs, **result)


@celery_app.task(name="ai.summarize", soft_time_limit=200, time_limit=240)
def ai_summarize(job_id: str, source: dict):
    result = _guard(job_id, lambda: analyst.summarize(source))
    if result is not None:
        _job(job_id, status="done", **result)
        enqueue("pipeline.ai_store_summary", doc_id=source["id"], summary=result)


@celery_app.task(name="ai.brief", soft_time_limit=280, time_limit=320)
def ai_brief(job_id: str, title: str, sources: list[dict], audience: str = "executive"):
    result = _guard(job_id, lambda: analyst.brief(title, sources, audience))
    if result is not None:
        refs = [{"label": f"S{n}", "id": s["id"], "title": s["title"]} for n, s in enumerate(sources, 1)]
        _job(job_id, status="done", sources=refs, **result)
