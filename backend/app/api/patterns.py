"""Activity patterns of a threat actor: tempo, the days it posts, where it appears and how its targeting shifts.

Counted from the actor's own claims: findings where trackers name it as the
actor of a victim post, and pages of its own leak site. News and research that
only mention it are reported separately as who writes about it, because a
mention is not activity.

Days are the day the post was first dated by its source. For the trackers
that is when they discovered the post, usually within hours of it going up, so
weekdays are meaningful but hours of the day are not; hours are left out.
"""
from collections import Counter
from datetime import date, datetime, timedelta
from statistics import median

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.common import iso
from app.db import get_db
from app.extract.geo import country_name
from app.models import CrawlLog, Document, DocumentEntity, Entity, Source, User, utcnow
from app.security import viewer

router = APIRouter(tags=["intel"])
WEEKDAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
MONTHS = 12


def _month(d: datetime) -> str:
    return f"{d.year:04d}-{d.month:02d}"


def summarise(claims: list[tuple[datetime | None, list[str], list[str]]], now: datetime, covered: set[date] | None = None) -> dict:
    """Tempo, weekdays and month-by-month targeting from (date, countries, sectors) per claim. Pure, for testing.

    ``covered`` is the set of days on which the actor's sources were actually
    collected. Silence on a day Kivuli did not collect says nothing about the
    actor, so quiet stretches count covered days only, an uncollected day ends a
    stretch, and gaps that span an uncollected day are left out of the median.
    """
    dated = sorted(d for d, _, _ in claims if d is not None)
    weekdays = Counter(d.weekday() for d in dated)
    days = sorted({d.date() for d in dated})
    seen = (lambda day: True) if covered is None else (lambda day: day in covered)

    def spans_cover(a: date, b: date) -> bool:
        return all(seen(a + timedelta(days=i)) for i in range(1, (b - a).days))

    gaps = [(b - a).days for a, b in zip(days, days[1:]) if spans_cover(a, b)]
    recent = sum(1 for d in dated if d >= now - timedelta(days=30))
    previous = sum(1 for d in dated if now - timedelta(days=60) <= d < now - timedelta(days=30))
    # Longest run of collected days without a claim in the last 180 days.
    claim_days = set(days)
    start = (now - timedelta(days=180)).date()
    if covered is not None and covered:
        start = max(start, min(covered))
    quiet = run = 0
    uncovered = 0
    day_ = start
    while day_ <= now.date():
        if not seen(day_):
            uncovered += 1
            run = 0
        elif day_ in claim_days:
            run = 0
        else:
            run += 1
            quiet = max(quiet, run)
        day_ += timedelta(days=1)

    months: dict[str, dict] = {}
    start = (now.replace(day=1) - timedelta(days=31 * (MONTHS - 1))).replace(day=1)
    seen_sectors: set[str] = set()
    seen_countries: set[str] = set()
    for d, countries, sectors in sorted((c for c in claims if c[0] is not None), key=lambda c: c[0]):
        key = _month(d)
        if d < start:
            seen_sectors.update(sectors)
            seen_countries.update(countries)
            continue
        m = months.setdefault(key, {"month": key, "claims": 0, "sectors": Counter(), "countries": Counter(), "new_sectors": set(), "new_countries": set()})
        m["claims"] += 1
        m["sectors"].update(sectors)
        m["countries"].update(countries)
        m["new_sectors"].update(s for s in sectors if s not in seen_sectors)
        m["new_countries"].update(c for c in countries if c not in seen_countries)
        seen_sectors.update(sectors)
        seen_countries.update(countries)
    first_month = min(months) if months else None
    monthly = []
    for key in sorted(months):
        m = months[key]
        monthly.append({
            "month": key, "claims": m["claims"],
            "top_sectors": [s for s, _ in m["sectors"].most_common(3)],
            "top_countries": [{"code": c, "name": country_name(c)} for c, _ in m["countries"].most_common(3)],
            # The first month in view has no "before" to compare with, so nothing in it is called new.
            "new_sectors": [] if key == first_month else sorted(m["new_sectors"])[:5],
            "new_countries": [] if key == first_month else [{"code": c, "name": country_name(c)} for c in sorted(m["new_countries"])[:5]],
        })
    return {
        "claims": len(claims), "dated": len(dated), "claim_days": len(days),
        "first": iso(dated[0]) if dated else None, "last": iso(dated[-1]) if dated else None,
        "last_30_days": recent, "previous_30_days": previous,
        "median_gap_days": median(gaps) if gaps else None, "longest_quiet_days": quiet if dated else None,
        "uncollected_days": uncovered if covered is not None else None,
        "weekdays": [{"day": WEEKDAYS[i], "count": weekdays.get(i, 0)} for i in range(7)],
        "monthly": monthly,
    }


@router.get("/entities/{entity_id}/patterns")
def actor_patterns(entity_id: int, db: Session = Depends(get_db), user: User = Depends(viewer)):
    """How an actor operates: tempo, weekdays, where it posts, how its targeting changes, and who reports on it."""
    entity = db.get(Entity, entity_id)
    if entity is None:
        raise HTTPException(404, "Entity not found")
    if entity.type != "actor":
        raise HTTPException(400, "Activity patterns are for threat actors")
    is_claim = or_(DocumentEntity.role == "actor", Source.category == "ransomware_leak_site")
    base = (select(Document).join(DocumentEntity, DocumentEntity.document_id == Document.id).join(Source, Source.id == Document.source_id)
            .where(DocumentEntity.entity_id == entity.id, Document.duplicate_of.is_(None)))
    claims = db.scalars(base.where(is_claim).limit(5000)).unique().all()
    now = utcnow()
    claim_sources = {d.source_id for d in claims}
    covered = {r[0].date() for r in db.execute(
        select(func.date_trunc("day", CrawlLog.fetched_at)).where(CrawlLog.source_id.in_(claim_sources), CrawlLog.ok.is_(True),
                                                                  CrawlLog.fetched_at >= now - timedelta(days=181)).distinct())} if claim_sources else set()
    out = summarise([(d.published_at, d.countries or [], d.sectors or []) for d in claims], now, covered)

    where = db.execute(
        select(Source.id, Source.name, Source.category, Source.network, func.count(), func.max(Document.first_seen_at))
        .join(Document, Document.source_id == Source.id).join(DocumentEntity, DocumentEntity.document_id == Document.id)
        .where(DocumentEntity.entity_id == entity.id).group_by(Source.id).order_by(func.count().desc()).limit(20)).all()
    sites, reporters = [], []
    for sid, name, category, network, count, last in where:
        row = {"id": sid, "name": name, "category": category, "network": network, "findings": count, "last_seen": iso(last)}
        (reporters if category in ("news", "blog", "vuln_feed") else sites).append(row)
    # Comparing two 30-day periods only means something once collection covers both.
    since = db.scalar(select(func.min(Document.first_seen_at)))
    out["collecting_since"] = iso(since)
    out["comparable"] = bool(since and since <= now - timedelta(days=60))
    return {**out, "id": entity.id, "name": entity.name, "sites": sites, "reporters": reporters,
            "note": "Days are when each post was first dated by its source; trackers date posts when they discover them."}
