"""Pipeline-side intelligence tasks: enrichment storage, attack surface,
vulnerabilities, detection rules, feeds and the release backfill."""
import ipaddress
import json
import logging
import re
import uuid
from datetime import date, datetime, timedelta

import redis
from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.config import get_settings
from app.extract.lang import detect_language
from app.db import session_scope
from app.extract.redact import RE_COMBO
from app.intel import attack, priority, quality
from app.models import (Alert, Asset, ChainAddress, ChainEdge, Document, DocumentEntity, DocumentIoc, Enrichment, Entity, Exposure, Ioc, Rule, Source, Vulnerability,
                        Watchlist, utcnow)
from app.search import index as search_index
from app.search import service as search_service
from app.worker import ingest
from app.worker.celery_app import celery_app, enqueue

log = logging.getLogger(__name__)
settings = get_settings()
_redis = redis.Redis.from_url(settings.redis_url, decode_responses=True)


# ── Enrichment ──────────────────────────────────────────────────────────────

@celery_app.task(name="pipeline.store_enrichment")
def store_enrichment(*, subject_type: str, subject: str, provider: str, ok: bool, verdict: str = "unknown", score: int | None = None,
                     summary: dict | None = None, error: str = ""):
    with session_scope() as db:
        stmt = pg_insert(Enrichment).values(subject_type=subject_type, subject=subject[:1024], provider=provider, fetched_at=utcnow(), ok=ok,
                                            verdict=verdict, score=score, summary=summary or {}, error=error)
        db.execute(stmt.on_conflict_do_update(index_elements=["subject_type", "subject", "provider"], set_={
            "fetched_at": stmt.excluded.fetched_at, "ok": ok, "verdict": verdict, "score": score, "summary": summary or {}, "error": error}))


@celery_app.task(name="pipeline.store_chain")
def store_chain(*, ok: bool, result: dict | None = None, address: str = "", chain: str = "", error: str = "",
                requested_by: int | None = None):
    """Store a looked-up address and the flows around it. The enricher has no database; this is where it lands."""
    from app.chain import labels

    with session_scope() as db:
        if not ok:
            addr = (result or {}).get("address") or address
            stmt = pg_insert(ChainAddress).values(address=addr[:128], chain=chain or "unknown", enriched_at=utcnow(), error=error[:500])
            db.execute(stmt.on_conflict_do_update(index_elements=["address"], set_={"enriched_at": utcnow(), "error": error[:500]}))
            return
        r = result or {}
        addr = r["address"]
        in_intel = db.scalar(select(func.count()).select_from(Ioc).where(Ioc.type == "crypto", Ioc.value == addr, Ioc.doc_count > 0)) or 0
        category, label = labels.classify(r, bool(in_intel))
        first = _chain_ts(r.get("first_seen")); last = _chain_ts(r.get("last_seen"))
        stmt = pg_insert(ChainAddress).values(
            address=addr[:128], chain=r["chain"], token=r.get("token", "")[:32], label=label[:160], category=category,
            balance=r.get("balance", 0.0), total_in=r.get("total_in", 0.0), total_out=r.get("total_out", 0.0),
            tx_count=r.get("tx_count", 0), counterparty_count=len(r.get("counterparties", [])), first_tx_at=first, last_tx_at=last,
            truncated=bool(r.get("truncated")), in_intel=bool(in_intel), co_spent=r.get("co_spent", [])[:100], enriched_at=utcnow(), error="")
        db.execute(stmt.on_conflict_do_update(index_elements=["address"], set_={
            "chain": r["chain"], "token": r.get("token", "")[:32], "label": label[:160], "category": category,
            "balance": r.get("balance", 0.0), "total_in": r.get("total_in", 0.0), "total_out": r.get("total_out", 0.0),
            "tx_count": r.get("tx_count", 0), "counterparty_count": len(r.get("counterparties", [])), "first_tx_at": first,
            "last_tx_at": last, "truncated": bool(r.get("truncated")), "in_intel": bool(in_intel),
            "co_spent": r.get("co_spent", [])[:100], "enriched_at": utcnow(), "error": ""}))
        for cp in r.get("counterparties", []):
            src, dst = (addr, cp["address"]) if cp["direction"] == "out" else (cp["address"], addr)
            e = pg_insert(ChainEdge).values(chain=r["chain"], src=src[:128], dst=dst[:128], value=cp.get("value", 0.0),
                                            tx_count=cp.get("tx_count", 1), sample_txid=(cp.get("txid") or "")[:80],
                                            first_seen_at=_chain_ts(cp.get("first_seen")), last_seen_at=_chain_ts(cp.get("last_seen")))
            db.execute(e.on_conflict_do_update(constraint="uq_chain_edges", set_={
                "value": cp.get("value", 0.0), "tx_count": cp.get("tx_count", 1), "sample_txid": (cp.get("txid") or "")[:80],
                "last_seen_at": _chain_ts(cp.get("last_seen"))}))


def _chain_ts(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


@celery_app.task(name="pipeline.store_provider_test")
def store_provider_test(*, name: str, ok: bool, message: str = "", detail: dict | None = None):
    """Keep the outcome of a provider connection test, so the console shows it after the page is reloaded."""
    from app.intel import provider_store

    with session_scope() as db:
        provider_store.record_test(db, name[:32], ok, message[:500], detail or {})


@celery_app.task(name="pipeline.sync_provider_keys")
def sync_provider_keys():
    """Rewrite the encrypted key mirror the enricher reads, in case Redis lost it."""
    from app.intel import provider_store

    with session_scope() as db:
        return provider_store.publish(db)


# ── Indicator feeds ─────────────────────────────────────────────────────────

def store_feed(db, source, indicators: list[tuple[str, str]]) -> tuple[int, int]:
    """Record indicators a threat feed lists. Returns (listed, newly seen). Nothing is contacted."""
    feed, tag = source.name[:80], (source.config or {}).get("tag") or "threat-feed"
    now = utcnow()
    before = db.scalar(select(func.count()).select_from(Ioc).where(Ioc.feeds.any(feed))) or 0
    for start in range(0, len(indicators), 1000):
        rows = [{"type": t, "value": v[:1024], "first_seen_at": now, "last_seen_at": now, "feeds": [feed], "tags": [tag]} for t, v in indicators[start : start + 1000]]
        stmt = pg_insert(Ioc).values(rows)
        db.execute(stmt.on_conflict_do_update(index_elements=["type", "value"], set_={
            "last_seen_at": now,
            "feeds": func.array(select(func.unnest(Ioc.feeds.op("||")(stmt.excluded.feeds)).distinct()).scalar_subquery()),
            "tags": func.array(select(func.unnest(Ioc.tags.op("||")(stmt.excluded.tags)).distinct()).scalar_subquery()),
        }))
    after = db.scalar(select(func.count()).select_from(Ioc).where(Ioc.feeds.any(feed))) or 0
    return len(indicators), max(0, after - before)


# ── Vulnerabilities ─────────────────────────────────────────────────────────

def _day(value: str) -> date | None:
    try:
        return date.fromisoformat(value) if value else None
    except ValueError:
        return None


def sync_kev(db, rows: list[dict]) -> int:
    """Upsert the exploited-vulnerability catalogue."""
    for start in range(0, len(rows), 500):
        values = [{"cve": r["cve"], "title": r["title"], "vendor": r["vendor"], "product": r["product"], "description": r["description"], "kev": True,
                   "kev_added": _day(r["kev_added"]), "kev_due": _day(r["kev_due"]), "ransomware_use": r["ransomware_use"], "updated_at": utcnow()}
                  for r in rows[start : start + 500]]
        stmt = pg_insert(Vulnerability).values(values)
        db.execute(stmt.on_conflict_do_update(index_elements=["cve"], set_={
            "title": stmt.excluded.title, "vendor": stmt.excluded.vendor, "product": stmt.excluded.product, "kev": True,
            "kev_added": stmt.excluded.kev_added, "kev_due": stmt.excluded.kev_due, "ransomware_use": stmt.excluded.ransomware_use,
            "description": func.coalesce(func.nullif(Vulnerability.description, ""), stmt.excluded.description)}))
    return len(rows)


def _watched_technologies(db) -> list[str]:
    return [w.value.lower() for w in db.scalars(select(Watchlist).where(Watchlist.kind == "technology", Watchlist.is_active.is_(True)))]


def rescore_vulnerability(v: Vulnerability, technologies: list[str]) -> None:
    haystack = f"{v.vendor} {v.product} {v.title}".lower()
    v.priority, v.priority_factors = priority.vulnerability_priority(
        kev=v.kev, kev_added=v.kev_added, ransomware_use=v.ransomware_use, epss=v.epss, cvss=v.cvss, mention_count=v.mention_count,
        exposed_assets=v.exposed_assets, watched_technology=any(t and t in haystack for t in technologies))


@celery_app.task(name="pipeline.refresh_vulnerabilities")
def refresh_vulnerabilities():
    """Tie CVEs to collected findings and to the attack surface, queue score lookups, and re-rank."""
    with session_scope() as db:
        mentioned = db.execute(select(Ioc.value, Ioc.doc_count, Ioc.last_seen_at).where(Ioc.type == "cve", Ioc.doc_count > 0)).all()
        # A CVE whose last mentioning finding was removed must not keep its old count.
        db.execute(update(Vulnerability).where(Vulnerability.mention_count > 0, Vulnerability.cve.notin_(
            select(Ioc.value).where(Ioc.type == "cve", Ioc.doc_count > 0))).values(mention_count=0).execution_options(synchronize_session=False))
        for start in range(0, len(mentioned), 500):
            stmt = pg_insert(Vulnerability).values([{"cve": r.value, "mention_count": r.doc_count, "last_mentioned_at": r.last_seen_at} for r in mentioned[start : start + 500]])
            db.execute(stmt.on_conflict_do_update(index_elements=["cve"], set_={"mention_count": stmt.excluded.mention_count, "last_mentioned_at": stmt.excluded.last_mentioned_at}))
        exposed = dict(db.execute(select(func.unnest(Asset.vulns).label("cve"), func.count()).group_by("cve")).all())
        for start in range(0, len(exposed), 500):
            stmt = pg_insert(Vulnerability).values([{"cve": cve, "exposed_assets": n} for cve, n in list(exposed.items())[start : start + 500]])
            db.execute(stmt.on_conflict_do_update(index_elements=["cve"], set_={"exposed_assets": stmt.excluded.exposed_assets}))
        if exposed:
            db.execute(update(Vulnerability).where(Vulnerability.exposed_assets > 0, Vulnerability.cve.notin_(list(exposed))).values(exposed_assets=0))
        else:
            db.execute(update(Vulnerability).where(Vulnerability.exposed_assets > 0).values(exposed_assets=0))
        db.flush()

        technologies = _watched_technologies(db)
        for v in db.scalars(select(Vulnerability)):
            rescore_vulnerability(v, technologies)

        # Look up exploit-prediction scores for what matters most first; NVD severity for the top of that list.
        stale = utcnow() - timedelta(days=3)
        due = list(db.scalars(
            select(Vulnerability.cve).where((Vulnerability.enriched_at.is_(None)) | (Vulnerability.enriched_at < stale))
            .order_by((Vulnerability.exposed_assets > 0).desc(), Vulnerability.mention_count.desc(), Vulnerability.kev_added.desc().nulls_last()).limit(800)))
        for start in range(0, len(due), 80):
            enqueue("enrich.vulnerabilities", cves=due[start : start + 80], with_nvd=8 if start == 0 else 0, countdown=start // 80 * 20)
        return {"tracked": len(mentioned), "exposed": len(exposed), "queued": len(due)}


@celery_app.task(name="pipeline.store_vulnerability_scores")
def store_vulnerability_scores(rows: dict[str, dict]):
    with session_scope() as db:
        technologies = _watched_technologies(db)
        for v in db.scalars(select(Vulnerability).where(Vulnerability.cve.in_(list(rows)))):
            data = rows.get(v.cve) or {}
            if "epss" in data:
                v.epss, v.epss_percentile = data["epss"], data.get("epss_percentile")
            if data.get("cvss") is not None:
                v.cvss, v.cvss_vector = float(data["cvss"]), data.get("cvss_vector", "")[:120]
            if data.get("description") and not v.description:
                v.description = data["description"]
            v.enriched_at = utcnow()
            rescore_vulnerability(v, technologies)


# ── Attack surface (passive) ────────────────────────────────────────────────

def _asset_alert(db, asset: Asset, *, key: str, title: str, severity: str, detail: dict) -> None:
    watch = asset.watchlist
    score, factors = priority.alert_priority(risk=asset.risk, confidence=90, category="attack_surface", credential_exposed=False,
                                             criticality=watch.criticality, corroboration=0, verification="reported", age_days=0, severity=severity)
    now = utcnow()
    db.execute(pg_insert(Alert).values(
        watchlist_id=watch.id, category="attack_surface", reason="new", matched=asset.host, title=title[:500], snippet=title[:1000],
        severity=severity, risk_score=asset.risk, priority=score, factors=factors, detail=detail, dedupe_key=key[:80], status="open",
        created_at=now, notified_at=None if watch.notify_mode != "none" else now,
    ).on_conflict_do_nothing(index_elements=["dedupe_key"]))


@celery_app.task(name="pipeline.asm_scan")
def asm_scan(watchlist_id: int):
    """Start passive discovery for one owned asset. Certificate logs, public DNS and scan data only: nothing is probed."""
    with session_scope() as db:
        watch = db.get(Watchlist, watchlist_id)
        if watch is None or not watch.is_asset or not watch.is_active or watch.kind not in ("domain", "ip"):
            return
        watch.last_scanned_at = utcnow()
        if watch.kind == "domain":
            enqueue("enrich.asm_discover", watchlist_id=watch.id, domain=watch.value)
            return
        network = ipaddress.ip_network(watch.value, strict=False)
        if network.num_addresses > 256:
            log.info("range %s is too large for passive lookup; only /24 or smaller is enumerated", watch.value)
            return
        hosts = [str(ip) for ip in (network.hosts() if network.num_addresses > 2 else network)]
        _upsert_hosts(db, watch, hosts, "declared range", is_ip=True)


def _upsert_hosts(db, watch: Watchlist, hosts: list[str], via: str, is_ip: bool = False) -> int:
    now = utcnow()
    for n, host in enumerate(hosts[: settings.asm_max_hosts]):
        stmt = pg_insert(Asset).values(watchlist_id=watch.id, host=host[:255], discovered_via=via, first_seen_at=now, last_seen_at=now)
        asset_id = db.execute(stmt.on_conflict_do_update(index_elements=["watchlist_id", "host"], set_={"last_seen_at": now}).returning(Asset.id)).scalar_one()
        enqueue("enrich.asm_host", asset_id=asset_id, host=host, is_ip=is_ip, countdown=n * 2)
    return len(hosts)


@celery_app.task(name="pipeline.asm_hosts")
def asm_hosts(*, watchlist_id: int, hosts: list[str], via: str, error: str = ""):
    with session_scope() as db:
        watch = db.get(Watchlist, watchlist_id)
        if watch is None:
            return
        if error:
            log.warning("attack-surface discovery for %s failed: %s", watch.value, error)
        names = sorted({watch.value, *[h for h in hosts if h == watch.value or h.endswith("." + watch.value)]})
        _upsert_hosts(db, watch, names, via or "declared domain")


@celery_app.task(name="pipeline.asm_host_result")
def asm_host_result(*, asset_id: int, ips: list[str], services: dict, asn: str = "", error: str = ""):
    with session_scope() as db:
        asset = db.get(Asset, asset_id)
        if asset is None:
            return
        now = utcnow()
        asset.last_scanned_at = now
        if error:
            asset.meta = {**(asset.meta or {}), "error": error}
            return
        old_ports, old_vulns = set(asset.ports or []), set(asset.vulns or [])
        ports = sorted({p for data in services.values() for p in data.get("ports", [])})
        vulns = sorted({v for data in services.values() for v in data.get("vulns", [])})
        asset.ips, asset.ports, asset.vulns, asset.asn = ips, ports, vulns[:300], asn[:160]
        asset.cpes = sorted({c for data in services.values() for c in data.get("cpes", [])})[:60]
        asset.tags = sorted({t for data in services.values() for t in data.get("tags", [])})[:20]
        asset.last_seen_at = now
        asset.meta = {k: v for k, v in (asset.meta or {}).items() if k != "error"}

        kev = set(db.scalars(select(Vulnerability.cve).where(Vulnerability.cve.in_(vulns), Vulnerability.kev.is_(True)))) if vulns else set()
        feeds = sorted({f for row in db.scalars(select(Ioc.feeds).where(Ioc.type == "ip", Ioc.value.in_(ips), Ioc.benign.is_(False))) for f in row}) if ips else []
        asset.risk, asset.risk_factors = priority.asset_risk(ports=ports, vulns=vulns, kev_vulns=sorted(kev), feed_hits=feeds, tags=asset.tags,
                                                             criticality=asset.watchlist.criticality)
        db.flush()

        for cve in sorted(kev - old_vulns):
            _asset_alert(db, asset, key=f"asm:{asset.id}:{cve}", severity="critical",
                         title=f"{asset.host} runs software affected by {cve}, which is being exploited in the wild", detail={"cve": cve, "host": asset.host})
        for port in sorted(set(ports) - old_ports):
            if port in priority.RISKY_PORTS:
                _asset_alert(db, asset, key=f"asm:{asset.id}:port:{port}", severity="high",
                             title=f"{asset.host} exposes {priority.RISKY_PORTS[port]} (port {port}) to the internet", detail={"port": port, "host": asset.host})
        if feeds:
            _asset_alert(db, asset, key=f"asm:{asset.id}:feed", severity="critical",
                         title=f"{asset.host} resolves to an address listed by a threat feed ({', '.join(feeds[:3])})", detail={"feeds": feeds, "ips": ips})


@celery_app.task(name="pipeline.asm_sweep")
def asm_sweep():
    """Rescan owned assets whose last passive scan is older than the configured interval."""
    cutoff = utcnow() - timedelta(days=settings.asm_interval_days)
    with session_scope() as db:
        due = list(db.scalars(select(Watchlist.id).where(Watchlist.is_asset.is_(True), Watchlist.is_active.is_(True), Watchlist.kind.in_(("domain", "ip")),
                                                         (Watchlist.last_scanned_at.is_(None)) | (Watchlist.last_scanned_at < cutoff)).limit(20)))
    for n, watch_id in enumerate(due):
        enqueue("pipeline.asm_scan", watchlist_id=watch_id, countdown=n * 30)
    return len(due)


# ── Detection rules ─────────────────────────────────────────────────────────

@celery_app.task(name="pipeline.evaluate_rules")
def evaluate_rules(rule_id: int | None = None):
    """Run detection rules over what was collected since each last ran."""
    fired = 0
    with session_scope() as db:
        stmt = select(Rule).where(Rule.is_active.is_(True))
        if rule_id:
            stmt = stmt.where(Rule.id == rule_id)
        for rule in db.scalars(stmt):
            now = utcnow()
            try:
                fired += _evaluate(db, rule, now)
            except Exception:
                log.exception("rule %s failed", rule.id)
            rule.last_run_at = now
    return fired


def _rule_alert(db, rule: Rule, *, key: str, title: str, snippet: str, doc: Document | None = None, detail: dict | None = None, risk: int = 0) -> bool:
    now = utcnow()
    reference = (doc.published_at or doc.first_seen_at) if doc else now
    score, factors = priority.alert_priority(
        risk=doc.risk_score if doc else risk, confidence=doc.confidence if doc else 80, category="rule", credential_exposed=False, criticality=None,
        corroboration=doc.corroboration if doc else 0, verification=doc.verification if doc else "reported", age_days=(now - reference).days,
        severity=rule.severity)
    stmt = pg_insert(Alert).values(
        rule_id=rule.id, document_id=doc.id if doc else None, category="rule", reason="new", matched=rule.name[:500], title=title[:500],
        snippet=snippet[:1000], severity=rule.severity, risk_score=doc.risk_score if doc else risk, priority=score, factors=factors,
        detail=detail or {}, dedupe_key=key[:80], status="open", created_at=now, notified_at=None if rule.notify_mode != "none" else now,
    ).on_conflict_do_nothing(index_elements=["dedupe_key"]).returning(Alert.id)
    if not db.execute(stmt).first():
        return False
    rule.match_count += 1
    rule.last_triggered_at = now
    return True


def _evaluate(db, rule: Rule, now: datetime) -> int:
    if rule.kind == "query":
        # Only findings collected after the rule existed: creating a rule must not flood the queue with history.
        since = rule.last_run_at or rule.created_at
        fired = 0
        for doc_id in search_service.new_matches(rule.query, since):
            doc = db.get(Document, uuid.UUID(doc_id))
            if doc is not None:
                fired += _rule_alert(db, rule, key=f"rule:{rule.id}:{doc_id}", title=doc.title, snippet=doc.summary, doc=doc)
        return fired

    window = timedelta(hours=max(1, rule.window_hours))
    count = search_service.count_matching(rule.query, now - window)
    bucket = int(now.timestamp() // window.total_seconds())  # at most one alert per window
    if rule.kind == "threshold":
        if count < rule.threshold:
            return 0
        title = f"{count} findings matched “{rule.name}” in the last {rule.window_hours} h (threshold {rule.threshold})"
        return int(_rule_alert(db, rule, key=f"rule:{rule.id}:t:{bucket}", title=title, snippet=f"Query: {rule.query}",
                               detail={"count": count, "window_hours": rule.window_hours, "threshold": rule.threshold, "query": rule.query}, risk=60))
    # spike: the current window against the average of the seven before it
    baseline = search_service.count_matching(rule.query, now - window * 8, now - window) / 7
    # The rule's number is the fewest matches worth an alert (never under three); "well above" means three times the usual.
    minimum, factor = max(3, rule.threshold), 3
    if count < minimum or count < baseline * factor:
        return 0
    title = f"Activity spike for “{rule.name}”: {count} findings in {rule.window_hours} h against a usual {baseline:.1f}"
    return int(_rule_alert(db, rule, key=f"rule:{rule.id}:s:{bucket}", title=title, snippet=f"Query: {rule.query}",
                           detail={"count": count, "baseline": round(baseline, 1), "factor": factor, "query": rule.query}, risk=65))


# ── AI support (retrieval and storage happen where the data is) ─────────────

@celery_app.task(name="pipeline.ai_retrieve")
def ai_retrieve(*, job_id: str, question: str, query: str):
    try:
        sources = search_service.retrieve_for_answer(query) or search_service.retrieve_for_answer(question)
    except Exception:
        log.exception("retrieval failed for AI job %s", job_id)
        sources = []
    enqueue("ai.answer", job_id=job_id, question=question, sources=sources)


@celery_app.task(name="pipeline.ai_store_summary")
def ai_store_summary(*, doc_id: str, summary: dict):
    with session_scope() as db:
        doc = db.get(Document, uuid.UUID(doc_id))
        if doc is not None:
            doc.ai_summary = json.dumps(summary)


# ── Release backfill ────────────────────────────────────────────────────────

def backfill(batch: int = 200) -> dict:
    """Bring findings collected before release 1.1 up to date: techniques, exposure records,
    verification state. Idempotent; reads only what is already stored."""
    stats = {"findings": 0, "techniques": 0, "exposures": 0, "corroborated": 0}
    with session_scope() as db:
        technique_ids = ingest.technique_entity_ids(db)
        last = None
        while True:
            stmt = select(Document).order_by(Document.id).limit(batch)
            if last is not None:
                stmt = stmt.where(Document.id > last)
            docs = db.scalars(stmt).unique().all()
            if not docs:
                break
            for doc in docs:
                if not doc.lang:
                    doc.lang = detect_language(doc.content)
                found = attack.extract_techniques(doc.title, doc.content)
                doc.techniques = sorted(found)
                linked = set(db.scalars(select(DocumentEntity.entity_id).where(DocumentEntity.document_id == doc.id)))
                for technique, confidence in found.items():
                    entity_id = technique_ids.get(technique)
                    if entity_id and entity_id not in linked:
                        db.add(DocumentEntity(document_id=doc.id, entity_id=entity_id, role="mention", confidence=confidence))
                        db.execute(update(Entity).where(Entity.id == entity_id).values(
                            doc_count=Entity.doc_count + 1, last_seen_at=func.greatest(func.coalesce(Entity.last_seen_at, doc.first_seen_at), doc.first_seen_at),
                            first_seen_at=func.least(func.coalesce(Entity.first_seen_at, doc.first_seen_at), doc.first_seen_at)))
                        stats["techniques"] += 1
                # Passwords are already redacted, but "account:[REDACTED]" still says whose credential was exposed.
                if doc.has_credentials and not db.scalar(select(func.count()).select_from(Exposure).where(Exposure.document_id == doc.id)):
                    records = [{"kind": "credential", "identity": m.group(1).lower(), "domain": m.group(1).lower().rsplit("@", 1)[-1], "service": "",
                                "secret_type": "", "fingerprint": "", "password_exposed": True}
                               for m in RE_COMBO.finditer(doc.content) if m.group(3) == "[REDACTED]"]
                    stats["exposures"] += ingest.store_exposures(db, doc, list({r["identity"]: r for r in records}.values())[:2000], utcnow())
                db.flush()
                stats["corroborated"] += len(quality.refresh_corroboration(db, doc))
                stats["findings"] += 1
            db.flush()
            search_index.bulk_index((str(d.id), ingest.index_payload(db, d)) for d in docs)
            last = docs[-1].id
            db.commit()
    return stats


# ── Dark Web Informer ───────────────────────────────────────────────────────

@celery_app.task(name="pipeline.store_dwi", soft_time_limit=900, time_limit=960)
def store_dwi(source_id: int, kind: str, alerts: list[dict], iocs: list[list[str]]):
    """Store Dark Web Informer alerts as findings and its indicators as a feed listing."""
    from app.enrich import dwi
    from app.worker.parsers import ParsedItem

    with session_scope() as db:
        source = db.get(Source, source_id)
        if source is None:
            return
        counts: dict[str, int] = {}
        for alert in alerts:
            item = ParsedItem(
                key=alert["id"], namespace="dwi", url=alert["url"] or f"https://darkwebinformer.com/#{alert['id']}",
                title=alert["title"] or (alert["victim"] and f"{alert['victim']} listed by {alert['actor'] or 'an actor'}") or "Dark Web Informer alert",
                text=dwi.alert_text(alert, kind), published_at=dwi.published(alert),
                hint_type="ransomware" if kind == "ransomware" else None, actor=alert["actor"], victim=alert["victim"],
                countries=alert["countries"], extra_iocs=[tuple(i) for i in alert["iocs"]], meta={"origin": "dwi", "stix_id": alert["id"], "kind": kind},
            )
            outcome = ingest.ingest_item(db, source, item, {"http_status": 200, "headers": {}})
            counts[outcome] = counts.get(outcome, 0) + 1
        listed = fresh = 0
        if iocs:
            listed, fresh = store_feed(db, source, [(t, v) for t, v in iocs])
        db.commit()
    log.info("dwi %s stored: %s; %d indicators listed (%d new)", kind, counts, listed, fresh)


@celery_app.task(name="pipeline.dwi_status")
def dwi_status(source_id: int, run_id: str, ok: bool, error: str, probe: bool, elapsed_ms: int = 0, **counts):
    """Record a sync like any other fetch: source health and the crawl log, which activity patterns read."""
    from app.models import CrawlLog

    with session_scope() as db:
        source = db.get(Source, source_id)
        if source is None:
            return
        now = utcnow()
        db.add(CrawlLog(run_id=run_id, source_id=source.id, url=source.url[:2048], depth=0, probe=probe, fetched_at=now, ok=ok,
                        http_status=200 if ok else None, bytes=0, elapsed_ms=elapsed_ms, error=error[:1000],
                        new_docs=int(counts.get("alerts", 0))))
        source.last_checked_at = now
        if ok:
            source.is_live, source.last_live_at, source.last_http_status = True, now, 200
            source.consecutive_failures, source.last_error = 0, ""
        else:
            source.consecutive_failures += 1
            source.last_error = error[:1000]
        db.commit()
