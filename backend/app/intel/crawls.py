"""Research crawls: a researcher names a starting URL and how far to follow it.

Supplying the URL is the authorisation for that site. The crawl stays on the
site it started on; other sites it finds are recorded as discovered sources and
handled by the collection policy like any other discovery.
"""
import uuid
from datetime import timedelta

import redis
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.crawl.blocklist import is_blocked
from app.crawl.fetcher import validate_url
from app.intel import settings_store
from app.models import CrawlJob, CrawlLog, Source, utcnow
from app.worker.celery_app import enqueue

_redis = redis.Redis.from_url(get_settings().redis_url, decode_responses=True)
RUN_TTL = 6 * 3600
STALE_AFTER = timedelta(minutes=12)


class CrawlRefused(ValueError):
    pass


def _key(run_id: str, name: str) -> str:
    return f"kivuli:run:{run_id}:{name}"


def start(db: Session, *, url: str, depth: int, max_pages: int, user_id: int | None, monitor: bool = False, case_id: int | None = None,
          note: str = "") -> CrawlJob:
    policy = settings_store.get(db, "collection")
    ok, reason, host, network = validate_url(url)
    if not ok:
        raise CrawlRefused(reason)
    if is_blocked(_redis, host):
        raise CrawlRefused("this onion service is on the abuse blocklist and is never fetched")
    depth = max(0, min(int(depth), policy["research_max_depth"]))
    max_pages = max(1, min(int(max_pages), policy["research_max_pages"]))

    source = db.scalar(select(Source).where(Source.host == host).order_by(Source.id).limit(1))
    if source is not None and source.status == "blocked":
        raise CrawlRefused("this source is blocked")
    if source is None:
        source = Source(name=host if network != "onion" else f"{host[:16]}… (research)", url=f"{url.split('://')[0]}://{host}/", host=host, network=network,
                        connector="html", route="tor", category="other", status="approved" if monitor else "paused", trust=40, max_depth=1, max_pages=25,
                        notes=f"{utcnow():%Y-%m-%d} added by a research crawl.", created_by=user_id, discovery_context="added by a research crawl")
        db.add(source)
        db.flush()
    elif monitor and source.status in ("candidate", "paused"):
        source.status = "approved"
    if source.connector != "html":
        raise CrawlRefused("this source is a structured feed, not a site that can be crawled page by page")

    running = db.scalar(select(func.count()).select_from(CrawlJob).where(CrawlJob.status == "running")) or 0
    if running >= 12:
        raise CrawlRefused("twelve research crawls are already running; wait for one to finish or stop one")

    run_id = str(uuid.uuid4())
    job = CrawlJob(source_id=source.id, url=url[:2048], run_id=run_id, depth=depth, max_pages=max_pages, status="running", note=note[:500],
                   case_id=case_id, created_by=user_id)
    db.add(job)
    db.flush()
    pipe = _redis.pipeline()
    pipe.sadd(_key(run_id, "seen"), url)
    pipe.expire(_key(run_id, "seen"), RUN_TTL)
    pipe.set(_key(run_id, "pending"), 1, ex=RUN_TTL)
    pipe.execute()
    source.last_crawled_at = utcnow()
    enqueue("crawl.fetch", url=url, route=source.route, source_id=source.id, run_id=run_id, depth=0, connector="html",
            max_bytes=(source.config or {}).get("max_bytes"), extra={"job": job.id, "max_depth": depth, "max_pages": max_pages, "parent": ""})
    return job


def stop(db: Session, job: CrawlJob) -> None:
    """No further pages are queued; ones already being fetched finish."""
    _redis.set(_key(job.run_id, "stop"), "1", ex=RUN_TTL)
    if job.status == "running":
        job.status, job.finished_at = "stopped", utcnow()


def settle(db: Session, job: CrawlJob) -> None:
    """Close a crawl whose workers went quiet without reporting the last page (a crash or a restart)."""
    if job.status != "running":
        return
    last = db.scalar(select(func.max(CrawlLog.fetched_at)).where(CrawlLog.run_id == job.run_id)) or job.created_at
    if utcnow() - last > STALE_AFTER:
        job.status, job.finished_at = "done", last


def progress(db: Session, run_ids: list[str]) -> dict[str, dict]:
    """Counts per run, read from the crawl log."""
    if not run_ids:
        return {}
    rows = db.execute(
        select(CrawlLog.run_id, func.count(), func.count().filter(CrawlLog.ok.is_(True)), func.coalesce(func.sum(CrawlLog.new_docs), 0),
               func.coalesce(func.sum(CrawlLog.changed_docs), 0), func.max(CrawlLog.depth), func.max(CrawlLog.fetched_at))
        .where(CrawlLog.run_id.in_(run_ids)).group_by(CrawlLog.run_id)).all()
    out = {r[0]: {"fetched": r[1], "ok": r[2], "failed": r[1] - r[2], "new": int(r[3]), "changed": int(r[4]), "deepest": r[5] or 0, "last_activity": r[6]} for r in rows}
    for run_id in run_ids:
        entry = out.setdefault(run_id, {"fetched": 0, "ok": 0, "failed": 0, "new": 0, "changed": 0, "deepest": 0, "last_activity": None})
        entry["queued"] = max(0, int(_redis.get(_key(run_id, "pending")) or 0))
        entry["discovered"] = _redis.scard(_key(run_id, "seen"))
    return out
