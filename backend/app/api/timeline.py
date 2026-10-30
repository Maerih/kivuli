"""The event timeline: incidents on a time axis, one row per threat actor, with the links between them.

An event is a finding, placed at the date its source reported it (or first
seen, when the source gave none). Two events are linked when they name the
same victim organisation, the same CVE, or share a specific indicator. Widely
shared values (an indicator in more than MAX_IOC_SPREAD findings overall, or
one marked benign) are left out: a CDN or webmail domain would otherwise link
unrelated incidents. An indicator link is only drawn between events of
different actors (or with no named actor) found in different sources: a
gang's own leak-site address would otherwise join every post in a row that
already groups them, and a source's boilerplate (an advisory footer's link)
every item from that source. A group
of linked events is joined in time order, not
every pair with every other, so a busy victim draws a chain, not a web.
"""
from collections import Counter, defaultdict
from datetime import timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.common import iso
from app.db import get_db
from app.extract.classify import THREAT_TYPES
from app.extract.geo import country_name
from app.extract.iocs import registered_domain
from app.models import Document, DocumentEntity, DocumentIoc, Entity, Ioc, User, utcnow
from app.security import viewer

router = APIRouter(tags=["intel"])

MAX_EVENTS = 800
MAX_LANES = 12
MAX_IOC_SPREAD = 25
MAX_LINKS = 600
ALIAS_MIN_SHARED = 3  # victims two actor names must share before they are suggested as one group
# Platforms everyone links to. Their bare domains connect nothing; a specific URL on them
# (one repository, one channel) still can, so URLs are kept.
COMMON_PLATFORMS = {
    "github.com", "gitlab.com", "githubusercontent.com", "t.me", "telegram.me", "telegram.org", "twitter.com", "x.com",
    "youtube.com", "youtu.be", "google.com", "microsoft.com", "apple.com", "linkedin.com", "facebook.com", "instagram.com",
    "reddit.com", "medium.com", "wikipedia.org", "discord.com", "discord.gg", "amazonaws.com", "cloudflare.com",
    "archive.org", "virustotal.com", "mitre.org", "nist.gov", "cisa.gov", "first.org", "bit.ly", "gmail.com", "outlook.com",
}


def _chain(ids: list[str], when: dict[str, str]) -> list[tuple[str, str]]:
    ordered = sorted(set(ids), key=lambda i: when[i])
    return list(zip(ordered, ordered[1:]))


@router.get("/timeline")
def timeline(days: int = Query(30, ge=1, le=365), actor: int | None = None, country: str | None = Query(None, max_length=2),
             sector: str | None = Query(None, max_length=64), type: str | None = Query(None, max_length=32),
             db: Session = Depends(get_db), user: User = Depends(viewer)):
    """Incidents over time by actor, and the victims, CVEs and indicators that connect them."""
    since = utcnow() - timedelta(days=days)
    when_col = func.coalesce(Document.published_at, Document.first_seen_at)
    q = select(Document).where(Document.duplicate_of.is_(None), when_col >= since, Document.threat_type != "other")
    if type:
        q = q.where(Document.threat_type == type)
    if country:
        q = q.where(Document.countries.any(country.upper()))
    if sector:
        q = q.where(Document.sectors.any(sector))
    if actor:
        q = q.where(Document.id.in_(select(DocumentEntity.document_id).where(DocumentEntity.entity_id == actor)))
    docs = db.scalars(q.order_by(when_col.desc()).limit(MAX_EVENTS)).unique().all()
    ids = [d.id for d in docs]

    # Who did it and who was hit, per event.
    actors: dict[str, tuple[int, str]] = {}
    victims: dict[str, list[tuple[int, str]]] = defaultdict(list)
    if ids:
        rows = db.execute(select(DocumentEntity.document_id, DocumentEntity.role, DocumentEntity.confidence, Entity.id, Entity.type, Entity.name)
                          .join(Entity, Entity.id == DocumentEntity.entity_id)
                          .where(DocumentEntity.document_id.in_(ids), Entity.type.in_(("actor", "organization")))
                          .order_by(DocumentEntity.confidence.desc())).all()
        for doc_id, role, _conf, eid, etype, name in rows:
            key = str(doc_id)
            if etype == "actor" and key not in actors:
                actors[key] = (eid, name)
            elif etype == "organization" and role == "victim":
                victims[key].append((eid, name))

    lane_counts = Counter(actors[str(d.id)] for d in docs if str(d.id) in actors)
    lanes = [{"id": eid, "name": name, "count": n} for (eid, name), n in lane_counts.most_common(MAX_LANES)]
    lane_ids = {lane["id"] for lane in lanes}

    when = {str(d.id): iso(d.published_at or d.first_seen_at) for d in docs}
    events = []
    for d in docs:
        key = str(d.id)
        a = actors.get(key)
        events.append({
            "id": key, "date": when[key], "title": d.title[:200], "type": d.threat_type,
            "type_label": THREAT_TYPES.get(d.threat_type, d.threat_type), "severity": d.severity, "risk": d.risk_score,
            "actor": a[1] if a else None, "actor_id": a[0] if a else None,
            "lane": a[0] if a and a[0] in lane_ids else (None if not a else "other"),
            "victims": [n for _, n in victims.get(key, [])][:3],
            "countries": [{"code": c, "name": country_name(c)} for c in (d.countries or [])][:4],
            "sectors": (d.sectors or [])[:3], "source": d.source.name, "network": d.network,
        })

    # Links: same victim, same CVE, or a specific shared indicator.
    links: list[dict] = []
    seen: set[tuple[str, str]] = set()
    actor_of = {key: a[0] for key, a in actors.items()}
    source_of = {str(d.id): d.source_id for d in docs}

    def add(group: list[str], kind: str, label: str, across_actors: bool = False) -> None:
        for a, b in _chain(group, when):
            if across_actors and ((actor_of.get(a) is not None and actor_of.get(a) == actor_of.get(b))
                                  or source_of[a] == source_of[b]):
                continue
            if (a, b) not in seen and len(links) < MAX_LINKS:
                seen.add((a, b))
                links.append({"a": a, "b": b, "kind": kind, "label": label})

    by_victim: dict[tuple[int, str], list[str]] = defaultdict(list)
    for key, vs in victims.items():
        for v in vs:
            by_victim[v].append(key)
    for (_eid, name), group in by_victim.items():
        if len(set(group)) > 1:
            add(group, "victim", name)
    # The same actor naming the same victim again is a relisting, or a second tracker reporting the
    # same claim: worth seeing, but not the same thing as two different actors hitting one victim.
    for link in links:
        if link["kind"] == "victim" and actor_of.get(link["a"]) is not None and actor_of.get(link["a"]) == actor_of.get(link["b"]):
            link["kind"] = "relisted"

    if ids:
        shared = db.execute(
            select(Ioc.type, Ioc.value, func.array_agg(DocumentIoc.document_id))
            .join(DocumentIoc, DocumentIoc.ioc_id == Ioc.id)
            .where(DocumentIoc.document_id.in_(ids), Ioc.benign.is_(False), Ioc.doc_count <= MAX_IOC_SPREAD)
            .group_by(Ioc.id).having(func.count() > 1).order_by(func.count().desc()).limit(300)).all()
        for kind, value, doc_ids in shared:
            if kind == "domain" and registered_domain(value) in COMMON_PLATFORMS:
                continue
            if kind == "cve":
                add([str(i) for i in doc_ids], "vulnerability", value)
            else:
                add([str(i) for i in doc_ids], "indicator", value, across_actors=True)

    # Two actor names that keep sharing victims are usually one group that two trackers spell
    # differently. Flag them for an analyst to check and merge; never merge automatically.
    pair_victims: dict[tuple[int, int], set[int]] = defaultdict(set)
    for (eid, _name), group in by_victim.items():
        named = sorted({actor_of[k] for k in group if actor_of.get(k) is not None})
        for i, x in enumerate(named):
            for y in named[i + 1:]:
                pair_victims[(x, y)].add(eid)
    names = {a[0]: a[1] for a in actors.values()}
    aliases = [{"a": {"id": x, "name": names[x]}, "b": {"id": y, "name": names[y]}, "shared_victims": len(v)}
               for (x, y), v in sorted(pair_victims.items(), key=lambda kv: -len(kv[1])) if len(v) >= ALIAS_MIN_SHARED][:10]

    types = Counter(e["type"] for e in events)
    return {
        "days": days, "events": events, "lanes": lanes, "links": links, "truncated": len(docs) >= MAX_EVENTS,
        "types": [{"value": t, "label": THREAT_TYPES.get(t, t), "count": n} for t, n in types.most_common()],
        "unattributed": sum(1 for e in events if e["actor"] is None),
        "possible_aliases": aliases,
    }
