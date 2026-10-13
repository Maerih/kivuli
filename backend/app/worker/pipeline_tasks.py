"""Pipeline-side tasks: scheduling, ingest, source health and discovery."""
import json
import logging
import uuid
from collections import Counter
from datetime import timedelta
from urllib.parse import quote, urlsplit

import redis
from sqlalchemy import func, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.config import get_settings
from app.crawl.blocklist import BLOCKLIST_KEY, BLOCKLIST_META, is_blocked
from app.crawl.fetcher import validate_url
from app.db import session_scope
from app.extract.lang import detect_language
from app.extract.relevance import page_title, research_relevance
from app.extract.safety import is_prohibited
from app.intel import settings_store
from app.models import CrawlJob, CrawlLog, Document, Entity, Source, SourceLink, Watchlist, utcnow
from app.search import service as search_service
from app.worker import ingest, intel_tasks, matching
from app.worker.celery_app import celery_app, enqueue
from app.worker.parsers import parse

log = logging.getLogger(__name__)
settings = get_settings()
_redis = redis.Redis.from_url(settings.redis_url, decode_responses=True)

RUN_TTL = 6 * 3600


def start_crawl(db, source: Source, probe: bool = False) -> str:
    """Queue the first fetch of a crawl run and return the run id."""
    run_id = str(uuid.uuid4())
    if not probe:
        source.last_crawled_at = utcnow()
        _redis.sadd(f"kivuli:run:{run_id}:seen", source.url)
        _redis.expire(f"kivuli:run:{run_id}:seen", RUN_TTL)
    enqueue("crawl.fetch", url=source.url, route=source.route, source_id=source.id, run_id=run_id, depth=0, probe=probe,
            max_bytes=(source.config or {}).get("max_bytes"), connector=source.connector)
    return run_id


def run_key(run_id: str, name: str) -> str:
    return f"kivuli:run:{run_id}:{name}"


def finish_job(db, run_id: str, status: str = "done") -> None:
    """Close the research crawl that owns this run, if it is still open."""
    db.execute(update(CrawlJob).where(CrawlJob.run_id == run_id, CrawlJob.status == "running").values(status=status, finished_at=utcnow()))


def apply_collection_policy(db, source: Source) -> bool:
    """Start collecting from a discovered onion site without waiting for a person, when the administrator's policy allows it."""
    if source.status != "candidate" or source.network != "onion" or not source.is_live:
        return False
    policy = settings_store.get(db, "collection")
    mode = policy["auto_approve"]
    tracker_listed = source.category == "ransomware_leak_site" and source.discovery_context.startswith("listed by RansomLook")
    relevant = mode == "relevant" and source.relevance >= policy["relevance_threshold"]
    if mode == "manual" or not (tracker_listed or relevant):
        return False
    active = db.scalar(select(func.count()).select_from(Source).where(Source.network == "onion", Source.status == "approved")) or 0
    if active >= policy["max_onion_sources"]:
        return False
    reason = "a victim tracker lists it as a leak site" if tracker_listed else f"its title scores {source.relevance}/10 for research relevance"
    source.status = "approved"
    source.notes = (source.notes + "\n" if source.notes else "") + f"{utcnow():%Y-%m-%d} approved automatically by the collection policy: {reason}."
    start_crawl(db, source)
    return True


def add_candidate(db, found: dict, parent: Source) -> bool:
    """Record a discovered site for analyst review. Whether it is then collected is decided by the collection policy."""
    ok, _reason, host, network = validate_url(found["url"])
    if not ok or db.scalar(select(Source.id).where(Source.host == host).limit(1)):
        return False
    if is_blocked(_redis, host):
        return False  # known abuse material: not even filed
    candidate = Source(
        name=found.get("name") or host, url=found["url"], host=host, network=network, connector="html", route="tor",
        category=found.get("category", "other"), status="candidate", trust=40, crawl_interval_minutes=360, max_depth=1,
        max_pages=15, config={"actor": found["actor"]} if found.get("actor") else {}, discovered_from_id=parent.id,
        discovery_context=found.get("context", "")[:500], relevance=research_relevance(found.get("name", ""), found.get("context", "")),
    )
    db.add(candidate)
    db.flush()
    # Check straight away whether the site answers, so the analyst reviewing it knows. A probe reads nothing into the platform.
    candidate.last_checked_at = utcnow()
    start_crawl(db, candidate, probe=True)
    return True


@celery_app.task(name="pipeline.schedule_due")
def schedule_due():
    """Start a crawl for every approved source whose interval has elapsed."""
    started = 0
    with session_scope() as db:
        now = utcnow()
        for source in db.scalars(select(Source).where(Source.status == "approved")):
            # Failing sources are retried progressively less often (up to 16x the interval).
            backoff = 2 ** min(source.consecutive_failures, 4)
            interval = timedelta(minutes=source.crawl_interval_minutes * backoff)
            if source.last_crawled_at is None or now - source.last_crawled_at >= interval:
                start_crawl(db, source)
                started += 1
    return started


@celery_app.task(name="pipeline.crawl_source")
def crawl_source(source_id: int, probe: bool = False):
    with session_scope() as db:
        source = db.get(Source, source_id)
        if source and (probe or source.status == "approved") and source.status != "blocked":
            return start_crawl(db, source, probe=probe)


@celery_app.task(name="pipeline.liveness_sweep")
def liveness_sweep():
    """Re-verify links: probe candidate and paused sources that have not been checked recently."""
    cutoff = utcnow() - timedelta(hours=settings.liveness_interval_hours)
    with session_scope() as db:
        stale = db.scalars(
            select(Source).where(Source.status.in_(("candidate", "paused")), (Source.last_checked_at.is_(None)) | (Source.last_checked_at < cutoff))
            .order_by(Source.last_checked_at.asc().nulls_first()).limit(40)
        ).all()
        for source in stale:
            source.last_checked_at = utcnow()
            start_crawl(db, source, probe=True)
        return len(stale)


@celery_app.task(name="pipeline.apply_policy")
def apply_policy():
    """Re-apply the collection policy to every candidate that answers. Run after the policy is changed."""
    with session_scope() as db:
        approved = 0
        for source in db.scalars(select(Source).where(Source.network == "onion", Source.relevance == 0, Source.status != "blocked")):
            source.relevance = research_relevance(f"{source.title} {source.name}", source.discovery_context)  # sites filed before relevance was scored
        for source in db.scalars(select(Source).where(Source.status == "candidate", Source.network == "onion", Source.is_live.is_(True))):
            approved += apply_collection_policy(db, source)
        return approved


@celery_app.task(name="pipeline.discover_sources")
def discover_sources(group: str | None = None):
    """Ask RansomLook where active groups publish, and file the sites as candidates."""
    with session_scope() as db:
        parent = db.scalar(select(Source).where(Source.connector == "ransomlook_recent", Source.status == "approved").limit(1))
        if parent is None:
            return 0
        if group:
            groups = [group.strip().lower()]
        else:
            # Groups named by either victim tracker. RansomLook knows most of them under the same name; an unknown one is simply not found.
            rows = db.execute(text(
                "SELECT lower(meta->>'tracker_group') AS grp, max(first_seen_at) AS seen FROM documents "
                "WHERE meta->>'tracker' IN ('ransomlook', 'ransomware_live') AND meta->>'tracker_group' IS NOT NULL "
                "GROUP BY 1 ORDER BY 2 DESC LIMIT 120")).all()
            per_run = settings_store.get(db, "collection")["discovery_groups_per_run"]
            groups = [r[0] for r in rows if r[0] and not _redis.exists(f"kivuli:discover:{r[0]}")][:per_run]
        for name in groups:
            _redis.set(f"kivuli:discover:{name}", "1", ex=7 * 86400)
            enqueue("crawl.fetch", url=f"https://www.ransomlook.io/api/group/{quote(name, safe='')}", route=parent.route,
                    source_id=parent.id, run_id=str(uuid.uuid4()), depth=0, connector="ransomlook_group", max_bytes=8_000_000)
        return len(groups)


@celery_app.task(name="pipeline.ingest_fetch", soft_time_limit=540, time_limit=600)
def ingest_fetch(*, result: dict, source_id: int, run_id: str, depth: int = 0, probe: bool = False, connector: str = "html", extra: dict | None = None):
    extra = extra or {}
    try:
        _ingest_fetch(result, source_id, run_id, depth, probe, connector, extra)
    finally:
        # A research crawl is finished when every page it queued has been dealt with, whatever the outcome.
        if extra.get("job") and _redis.decr(run_key(run_id, "pending")) <= 0:
            with session_scope() as db:
                finish_job(db, run_id, "stopped" if _redis.exists(run_key(run_id, "stop")) else "done")


def _ingest_fetch(result: dict, source_id: int, run_id: str, depth: int, probe: bool, connector: str, extra: dict) -> None:
    primary = connector != "ransomlook_group"  # discovery fetches must not alter the parent source's health
    job = extra.get("job")
    with session_scope() as db:
        source = db.get(Source, source_id)
        if source is None:
            return
        now = utcnow()
        entry = CrawlLog(run_id=run_id, source_id=source.id, url=result["url"][:2048], depth=depth, probe=probe, fetched_at=now,
                         ok=bool(result["ok"]), http_status=result.get("http_status"), bytes=result.get("bytes", 0),
                         elapsed_ms=result.get("elapsed_ms", 0), error=result.get("error", "")[:1000], parent_url=str(extra.get("parent", ""))[:2048])
        db.add(entry)

        if result.get("blocked"):
            source.status, source.is_live = "blocked", None
            source.notes = (source.notes + "\n" if source.notes else "") + f"{now:%Y-%m-%d} blocked automatically: listed on the abuse blocklist."
            db.commit()
            return

        if primary and depth == 0:
            source.last_checked_at = now
            source.last_http_status = result.get("http_status")
            # Any HTTP answer proves the service is up, whatever the status code.
            if result.get("http_status") is not None:
                source.is_live, source.last_live_at = True, now
            else:
                source.is_live = False
            if result["ok"]:
                source.consecutive_failures, source.last_error = 0, ""
            else:
                source.consecutive_failures += 1
                source.last_error = result.get("error", "")[:1000]
            # What the site calls itself, kept from the liveness check so a candidate can be judged before it is approved.
            # A liveness check sends the title on its own; a real crawl of the front page carries the page it came from.
            title = " ".join(str(result.get("title") or (page_title(result.get("body") or "") if connector == "html" else "")).split())[:200]
            if title and is_prohibited(title, ""):
                source.status = "blocked"
                source.notes = (source.notes + "\n" if source.notes else "") + f"{now:%Y-%m-%d} blocked automatically: prohibited content guardrail (site title)."
                db.commit()
                return
            if title and title != source.title:
                source.title = title
                source.language = detect_language(title) or source.language
                source.relevance = max(source.relevance, research_relevance(title, source.discovery_context))
            if probe:
                apply_collection_policy(db, source)
        db.commit()

        if probe or not result["ok"] or source.status == "blocked":
            return
        if primary and source.status != "approved" and not job:
            return  # paused or un-approved while the fetch was in flight; a research crawl is an explicit request and goes ahead

        try:
            out = parse(connector, result["body"], result.get("final_url") or result["url"], source.host, source.config)
        except Exception as exc:
            log.exception("parse failed for source %s", source.id)
            entry.error = f"parse error: {type(exc).__name__}: {str(exc)[:300]}"
            if primary and depth == 0:
                source.last_error = entry.error
            db.commit()
            return

        if out.gated:
            entry.error = out.gated
            if depth == 0:
                source.last_error = out.gated
            db.commit()
            return

        counts: Counter = Counter()
        for item in out.items:
            try:
                counts[ingest.ingest_item(db, source, item, result)] += 1
                db.commit()
            except Exception:
                db.rollback()
                log.exception("ingest failed for an item from source %s", source.id)
                counts["error"] += 1
            if counts["prohibited"]:
                source = db.get(Source, source_id)
                source.status = "blocked"
                source.notes = (source.notes + "\n" if source.notes else "") + f"{now:%Y-%m-%d} blocked automatically: prohibited content guardrail."
                db.commit()
                log.warning("source %s blocked by the content guardrail", source.id)
                return

        entry.new_docs, entry.changed_docs = counts["new"], counts["changed"]
        if counts["new"] or counts["changed"]:
            source.last_changed_at = now
        entry.unchanged_docs, entry.dropped_docs = counts["unchanged"], counts["dropped"] + counts["error"]
        if out.note and not entry.error:
            entry.error = out.note

        if out.kev_ids:
            _redis.sadd(ingest.KEV_KEY, *out.kev_ids)
        if out.vulnerabilities:
            intel_tasks.sync_kev(db, out.vulnerabilities)
            # Rank the refreshed catalogue once this crawl's findings are committed, rather than waiting for the hourly run.
            enqueue("pipeline.refresh_vulnerabilities", countdown=30)
        if out.blocklist:
            # Replace the whole set at once so there is never a moment with half a list.
            staging = BLOCKLIST_KEY + ":new"
            _redis.delete(staging)
            for start in range(0, len(out.blocklist), 2000):
                _redis.sadd(staging, *out.blocklist[start : start + 2000])
            _redis.rename(staging, BLOCKLIST_KEY)
            _redis.set(BLOCKLIST_META, json.dumps({"count": len(out.blocklist), "updated_at": now.isoformat(), "source": source.name}))
            entry.error = out.note
        if out.feed_iocs:
            listed, fresh = intel_tasks.store_feed(db, source, out.feed_iocs)
            entry.new_docs = fresh
            entry.error = f"{listed} indicators listed, {fresh} new"
        for name, description in out.actor_profiles.items():
            actor = ingest.get_or_create_entity(db, "actor", name.title() if name.islower() else name)
            if actor and not actor.description:
                actor.description = description
                actor.meta = {**(actor.meta or {}), "profile_source": "RansomLook"}

        # A research crawl carries its own limits; a scheduled crawl uses the source's.
        max_depth = int(extra.get("max_depth", source.max_depth))
        max_pages = int(extra.get("max_pages", source.max_pages))
        if connector == "html" and depth < max_depth and not _redis.exists(run_key(run_id, "stop")):
            seen_key = run_key(run_id, "seen")
            for link in out.links:
                if _redis.scard(seen_key) >= max_pages:
                    break
                if _redis.sadd(seen_key, link):
                    _redis.expire(seen_key, RUN_TTL)
                    if job:
                        _redis.incr(run_key(run_id, "pending"))
                    enqueue("crawl.fetch", url=link, route=source.route, source_id=source.id, run_id=run_id, depth=depth + 1,
                            max_bytes=(source.config or {}).get("max_bytes"), connector="html",
                            extra={**extra, "parent": result.get("final_url") or result["url"]} if job else {"parent": result.get("final_url") or result["url"]})

        # Which sites this one points at: the map behind "related sources" and "frequently referenced".
        if connector == "html":
            for found in out.discovered[:200]:
                target = (urlsplit(found["url"]).hostname or "").lower()
                if not target or target == source.host:
                    continue
                stmt = pg_insert(SourceLink).values(src_source_id=source.id, dst_host=target[:255], first_seen_at=now, last_seen_at=now, count=1)
                db.execute(stmt.on_conflict_do_update(constraint="uq_source_links_pair", set_={"last_seen_at": now, "count": SourceLink.count + 1}))

        if settings.discover_onion_links or connector == "ransomlook_group":
            added = 0
            for found in out.discovered:
                if added >= settings.max_candidates_per_crawl:
                    break
                added += add_candidate(db, found, source)
        db.commit()


@celery_app.task(name="pipeline.retro_hunt")
def retro_hunt(watchlist_id: int, notify: bool = False):
    """Run a new watchlist entry against everything already collected."""
    with session_scope() as db:
        watch = db.get(Watchlist, watchlist_id)
        if watch is None or not watch.is_active:
            return 0
        created = 0
        for doc_id in search_service.retro_candidates(watch.kind, watch.value):
            doc = db.get(Document, uuid.UUID(doc_id))
            if doc is None:
                continue
            created += _raise_for(db, doc, watch, notify)
        db.commit()
        return created


def _raise_for(db, doc: Document, watch: Watchlist, notify: bool) -> int:
    view = ingest.build_view(db, doc)
    match = matching.match_watch(watch.kind, watch.value, view, lookalikes=watch.is_asset)
    return int(bool(match and ingest.make_alert(db, watch, doc, view, match, "retro", notify)))


def reindex_all(batch: int = 200) -> int:
    """Rebuild the search index from PostgreSQL. Called by ``manage reindex``."""
    from app.search import index as search_index

    search_index.ensure_index(recreate=True)
    total = 0
    with session_scope() as db:
        last = None
        while True:
            stmt = select(Document).order_by(Document.id).limit(batch)
            if last is not None:
                stmt = stmt.where(Document.id > last)
            docs = db.scalars(stmt).unique().all()
            if not docs:
                break
            total += search_index.bulk_index((str(d.id), ingest.index_payload(db, d)) for d in docs)
            last = docs[-1].id
    return total
