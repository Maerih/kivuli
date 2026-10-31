"""The ingest pipeline: one parsed item in, one tracked finding out.

    normalise -> guardrail -> redact -> fingerprint -> dedupe / version
      -> extract indicators and entities -> classify -> watchlists -> score
      -> persist with an evidence record -> index
"""
import gzip
import hashlib
import hmac
import logging
import os
import re
import time
from datetime import timezone

import redis
from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.config import get_settings
from app.extract import textutil as tu
from app.extract.classify import classify
from app.extract.entities import EntityMatcher, KnownEntity, propose_organizations
from app.extract.geo import detect_countries
from app.extract.iocs import extract_iocs, refang
from app.extract.lang import detect_language
from app.extract.redact import Exposure, redact
from app.extract.risk import score_risk, severity_at_least
from app.extract.safety import is_prohibited
from app.models import (Alert, Document, DocumentEntity, DocumentIoc, DocumentTag, DocumentVersion, Entity, Ioc, Source, Tag,
                        Watchlist, utcnow)
from app.intel import attack, priority, quality
from app.intel.relationships import upsert_relationship
from app.models import Exposure as ExposureRow
from app.search import index as search_index
from app.worker import matching
from app.worker.parsers import ParsedItem

log = logging.getLogger(__name__)
settings = get_settings()
_redis = redis.Redis.from_url(settings.redis_url, decode_responses=True)

KEV_KEY = "kivuli:kev"
MAX_CONTENT_CHARS = 400_000
# SimHash distance at which two long documents count as the same page. The band
# lookup is exhaustive up to 3 bits and finds roughly 90% of pairs at 4.
NEAR_DUPLICATE_BITS = 4
_CATEGORY_HINTS = {"ransomware_leak_site": "ransomware", "vuln_feed": "vulnerability"}

_matcher: EntityMatcher | None = None
_matcher_built = 0.0


def get_matcher(db: Session, force: bool = False) -> EntityMatcher:
    """Entity gazetteer, rebuilt when it is stale or the entity table has grown."""
    global _matcher, _matcher_built
    if _matcher is None or force or time.monotonic() - _matcher_built > 180:
        rows = db.execute(select(Entity.id, Entity.type, Entity.name, Entity.aliases, Entity.curated, Entity.meta)
                          .where(Entity.type.in_(("actor", "malware", "organization", "campaign")))).all()
        _matcher = EntityMatcher([KnownEntity(r.id, r.type, r.name, tuple(r.aliases or ()), r.curated,
                                              bool((r.meta or {}).get("needs_context"))) for r in rows])
        _matcher_built = time.monotonic()
    return _matcher


def _compact(name: str) -> str:
    """Letters and digits only: "The Gentlemen", "Thegentlemen" and "the-gentlemen" are one name."""
    return re.sub(r"[^a-z0-9]", "", name.lower())


# Spelling-insensitive matching only where names are distinctive: actors and malware, five characters or more.
_COMPACT_KINDS = ("actor", "malware")
_COMPACT_MIN = 5


def _by_alias(db: Session, kind: str, name: str, slug: str) -> Entity | None:
    """The existing entity a new name refers to, through an alias or a spacing/punctuation variant.

    Aliases count on every entity, not only curated ones: a merge records the
    merged name as an alias, and that is what keeps the next mention of it from
    recreating the duplicate. Curated entities win, then the most-seen one.
    """
    key = _compact(name)
    compact = kind in _COMPACT_KINDS and len(key) >= _COMPACT_MIN
    query = select(Entity).where(Entity.type == kind).order_by(Entity.curated.desc(), Entity.doc_count.desc())
    if not compact:
        query = query.where(func.cardinality(Entity.aliases) > 0)
    candidates = db.scalars(query)
    for candidate in candidates:
        names = candidate.aliases or []
        if slug in {tu.slugify(alias) for alias in names}:
            return candidate
        if compact and key in {_compact(n) for n in (candidate.name, *names)}:
            if name not in names:
                candidate.aliases = [*names, name]  # remember the spelling it was seen under
            return candidate
    return None


def get_or_create_entity(db: Session, kind: str, name: str, **fields) -> Entity:
    name = " ".join(name.split())[:300]
    slug = tu.slugify(name)
    entity = db.scalar(select(Entity).where(Entity.type == kind, Entity.slug == slug))
    if entity is None:
        entity = _by_alias(db, kind, name, slug)
    if entity is None:
        db.execute(pg_insert(Entity).values(type=kind, name=name, slug=slug, aliases=[], **fields)
                   .on_conflict_do_nothing(index_elements=["type", "slug"]))
        entity = db.scalar(select(Entity).where(Entity.type == kind, Entity.slug == slug))
        global _matcher_built
        _matcher_built = 0.0  # pick the new name up on the next document
    return entity


def evidence_chain(prev_hash: str, document_id, version: int, url: str, captured_at, raw_sha256: str, content_sha256: str) -> tuple[str, str]:
    """Hash-chain a capture to the one before it and sign it.

    Editing or removing any stored version breaks every later link, and the HMAC
    key lives outside the database, so tampering is detectable.
    """
    material = "|".join([prev_hash, str(document_id), str(version), url, captured_at.astimezone(timezone.utc).isoformat(), raw_sha256, content_sha256])
    chain_hash = hashlib.sha256(material.encode()).hexdigest()
    signature = hmac.new(settings.evidence_hmac_key.encode(), chain_hash.encode(), hashlib.sha256).hexdigest()
    return chain_hash, signature


def _store_raw(raw: str, raw_sha256: str) -> None:
    if not settings.evidence_store_raw or not raw:
        return
    path = os.path.join(settings.evidence_dir, raw_sha256[:2], raw_sha256[2:4])
    try:
        os.makedirs(path, exist_ok=True)
        target = os.path.join(path, f"{raw_sha256}.gz")
        if not os.path.exists(target):
            with gzip.open(target, "wb") as fh:
                fh.write(raw.encode("utf-8", "replace"))
    except OSError as exc:
        log.warning("could not store raw evidence: %s", exc)


def _find_duplicate(db: Session, doc_id, content_sha256: str, simhash: int, text_len: int):
    exact = db.scalar(select(Document.id).where(Document.content_sha256 == content_sha256, Document.id != doc_id,
                                                Document.duplicate_of.is_(None)).order_by(Document.first_seen_at).limit(1))
    if exact or text_len < 400:
        return exact
    b = tu.simhash_bands(simhash)
    candidates = db.execute(
        select(Document.id, Document.simhash)
        .where(Document.id != doc_id, Document.duplicate_of.is_(None),
               (Document.sh0 == b[0]) | (Document.sh1 == b[1]) | (Document.sh2 == b[2]) | (Document.sh3 == b[3]))
        .order_by(Document.first_seen_at).limit(200)
    ).all()
    for cand_id, cand_hash in candidates:
        if tu.hamming(simhash, tu.from_signed64(cand_hash)) <= NEAR_DUPLICATE_BITS:
            return cand_id
    return None


def _link_indicators(db: Session, doc: Document, found: dict[tuple[str, str], tuple[int, str]], now) -> list[tuple[str, str]]:
    old_ids = set(db.scalars(select(DocumentIoc.ioc_id).where(DocumentIoc.document_id == doc.id)))
    if not found:
        if old_ids:
            db.execute(delete(DocumentIoc).where(DocumentIoc.document_id == doc.id))
            db.execute(update(Ioc).where(Ioc.id.in_(old_ids)).values(doc_count=func.greatest(Ioc.doc_count - 1, 0)))
        return []
    rows = [{"type": t, "value": v, "first_seen_at": now, "last_seen_at": now} for (t, v) in found]
    ids: dict[tuple[str, str], int] = {}
    for start in range(0, len(rows), 500):
        stmt = pg_insert(Ioc).values(rows[start : start + 500])
        stmt = stmt.on_conflict_do_update(index_elements=["type", "value"], set_={"last_seen_at": now}).returning(Ioc.id, Ioc.type, Ioc.value)
        for ioc_id, t, v in db.execute(stmt):
            ids[(t, v)] = ioc_id
    new_ids = set(ids.values())
    if removed := old_ids - new_ids:
        db.execute(delete(DocumentIoc).where(DocumentIoc.document_id == doc.id, DocumentIoc.ioc_id.in_(removed)))
        db.execute(update(Ioc).where(Ioc.id.in_(removed)).values(doc_count=func.greatest(Ioc.doc_count - 1, 0)))
    links = [{"document_id": doc.id, "ioc_id": ids[key], "count": count, "context": context[:400]} for key, (count, context) in found.items() if key in ids]
    for start in range(0, len(links), 500):
        stmt = pg_insert(DocumentIoc).values(links[start : start + 500])
        db.execute(stmt.on_conflict_do_update(index_elements=["document_id", "ioc_id"], set_={"count": stmt.excluded.count, "context": stmt.excluded.context}))
    if added := new_ids - old_ids:
        db.execute(update(Ioc).where(Ioc.id.in_(added)).values(doc_count=Ioc.doc_count + 1))
    return list(found)


def _link_entities(db: Session, doc: Document, wanted: dict[int, tuple[str, int]], when) -> None:
    old_ids = set(db.scalars(select(DocumentEntity.entity_id).where(DocumentEntity.document_id == doc.id)))
    new_ids = set(wanted)
    if removed := old_ids - new_ids:
        db.execute(delete(DocumentEntity).where(DocumentEntity.document_id == doc.id, DocumentEntity.entity_id.in_(removed)))
        db.execute(update(Entity).where(Entity.id.in_(removed)).values(doc_count=func.greatest(Entity.doc_count - 1, 0)))
    for entity_id, (role, confidence) in wanted.items():
        stmt = pg_insert(DocumentEntity).values(document_id=doc.id, entity_id=entity_id, role=role, confidence=confidence)
        db.execute(stmt.on_conflict_do_update(index_elements=["document_id", "entity_id"], set_={"role": role, "confidence": confidence}))
    if added := new_ids - old_ids:
        db.execute(update(Entity).where(Entity.id.in_(added)).values(
            doc_count=Entity.doc_count + 1,
            first_seen_at=func.least(func.coalesce(Entity.first_seen_at, when), when),
            last_seen_at=func.greatest(func.coalesce(Entity.last_seen_at, when), when),
        ))


def index_payload(db: Session, doc: Document) -> dict:
    iocs = db.execute(select(Ioc.type, Ioc.value).join(DocumentIoc, DocumentIoc.ioc_id == Ioc.id).where(DocumentIoc.document_id == doc.id)).all()
    entities = db.execute(select(Entity.type, Entity.name).join(DocumentEntity, DocumentEntity.entity_id == Entity.id)
                          .where(DocumentEntity.document_id == doc.id, Entity.type != "incident")).all()
    tags = db.scalars(select(Tag.name).join(DocumentTag, DocumentTag.tag_id == Tag.id).where(DocumentTag.document_id == doc.id)).all()
    copies = db.scalar(select(func.count()).select_from(Document).where(Document.duplicate_of == doc.id)) or 0
    return search_index.build_index_doc(doc, [tuple(r) for r in iocs], [tuple(r) for r in entities], tags, copies)


def reindex_document(db: Session, doc: Document, refresh: bool = False) -> None:
    search_index.index_document(str(doc.id), index_payload(db, doc), refresh=refresh)


def build_view(db: Session, doc: Document) -> matching.DocView:
    """Reload a stored finding in the shape the watchlist matcher expects."""
    view = matching.DocView(title=doc.title, text=doc.content, threat_type=doc.threat_type, severity=doc.severity,
                            confidence=doc.confidence, has_credentials=doc.has_credentials)
    for kind, value, context in db.execute(select(Ioc.type, Ioc.value, DocumentIoc.context).join(DocumentIoc, DocumentIoc.ioc_id == Ioc.id)
                                           .where(DocumentIoc.document_id == doc.id)):
        view.iocs.setdefault(kind, {})[value] = context
    for kind, name, aliases in db.execute(select(Entity.type, Entity.name, Entity.aliases).join(DocumentEntity, DocumentEntity.entity_id == Entity.id)
                                          .where(DocumentEntity.document_id == doc.id)):
        target = view.actors if kind == "actor" else view.organizations if kind == "organization" else None
        if target is not None:
            target.update(n.lower() for n in (name, *(aliases or [])))
    return view


_technique_entities: dict[str, int] = {}


def technique_entity_ids(db: Session) -> dict[str, int]:
    """ATT&CK technique id -> entity id (loaded once; the catalogue is seeded at start-up)."""
    if not _technique_entities:
        for entity_id, meta in db.execute(select(Entity.id, Entity.meta).where(Entity.type == "technique")):
            if technique := (meta or {}).get("attack_id"):
                _technique_entities[technique] = entity_id
    return _technique_entities


def store_exposures(db: Session, doc: Document, records: list[dict], now) -> int:
    """Replace a finding's exposure records, keeping the triage status of ones that are still present."""
    wanted = {(r["kind"], r["identity"], r["service"], r["fingerprint"]): r for r in records}
    existing = {(e.kind, e.identity, e.service, e.fingerprint): e for e in db.scalars(select(ExposureRow).where(ExposureRow.document_id == doc.id))}
    for key, row in existing.items():
        if key in wanted:
            row.last_seen_at = now
        else:
            db.delete(row)
    for key, record in wanted.items():
        if key not in existing:
            db.add(ExposureRow(document_id=doc.id, first_seen_at=doc.first_seen_at or now, last_seen_at=now, **record))
    return len(wanted)


def make_alert(db: Session, watch: Watchlist, doc: Document, view: matching.DocView, match: matching.Match, reason: str, notify: bool) -> bool:
    """Create one watchlist alert with an explainable priority. Returns False if it existed or is below the watch's threshold."""
    category = matching.alert_category(watch.kind, view, match)
    severity = matching.alert_severity(category, view, match)
    if not severity_at_least(severity, watch.min_severity):
        return False
    now = utcnow()
    reference = doc.published_at or doc.first_seen_at or now
    score, factors = priority.alert_priority(
        risk=doc.risk_score, confidence=doc.confidence, category=category, credential_exposed=match.credential_exposed,
        criticality=watch.criticality if watch.is_asset else None, corroboration=doc.corroboration, verification=doc.verification,
        age_days=(now - reference).days, severity=severity,
    )
    matched = match.matched + (" (password exposed)" if match.credential_exposed else "") + (f" ({match.lookalike})" if match.lookalike else "")
    stmt = pg_insert(Alert).values(
        watchlist_id=watch.id, document_id=doc.id, category=category, reason=reason, matched=matched[:500], title=doc.title[:500],
        snippet=match.snippet[:1000], severity=severity, risk_score=doc.risk_score, priority=score, factors=factors, status="open", created_at=now,
        # Alerts that must not be emailed (history, or a watch with email off) are marked as already handled.
        notified_at=None if notify and watch.notify_mode != "none" else now,
    ).on_conflict_do_nothing(index_elements=["watchlist_id", "document_id"]).returning(Alert.id)
    if not db.execute(stmt).first():
        return False
    watch.match_count += 1
    watch.last_matched_at = now
    return True


def raise_alerts(db: Session, doc: Document, view: matching.DocView, reason: str, notify: bool = True) -> int:
    """Create alerts for every active watchlist the finding matches. Returns the number created.

    A duplicate only stays quiet for watchlists that already alerted on its
    original: a near-copy that names a watched asset the original did not must
    still raise an alert.
    """
    created = 0
    now = utcnow()
    already: set[int] = set()
    if doc.duplicate_of is not None:
        already = set(db.scalars(select(Alert.watchlist_id).where(Alert.document_id == doc.duplicate_of)))
    for watch in db.scalars(select(Watchlist).where(Watchlist.is_active.is_(True))):
        if watch.id in already:
            continue
        match = matching.match_watch(watch.kind, watch.value, view, lookalikes=watch.is_asset)
        if match and make_alert(db, watch, doc, view, match, reason, notify):
            created += 1
    return created


def ingest_item(db: Session, source: Source, item: ParsedItem, fetch: dict) -> str:
    """Process one item. Returns new | changed | unchanged | dropped | prohibited."""
    now = utcnow()
    title = " ".join(refang(item.title or "").split())[:500]
    text = tu.normalize_text(refang(item.text or ""))
    if len(text) < 40 and len(title) < 12:
        return "dropped"
    if is_prohibited(title, text):
        return "prohibited"

    exposure = Exposure()
    if settings.redact_secrets:
        text, exposure = redact(text)
        title, _ = redact(title)
    if len(text) > MAX_CONTENT_CHARS:
        text = text[:MAX_CONTENT_CHARS] + "\n[content truncated at the storage limit]"

    content_sha256 = tu.sha256_hex(f"{title}\n{text}")
    raw_sha256 = tu.sha256_hex(item.raw or item.text or "")
    doc_key = tu.sha256_hex(f"{item.namespace or f'source:{source.id}'}|{item.key}")

    doc = db.scalar(select(Document).where(Document.doc_key == doc_key).with_for_update(of=Document))
    if doc is not None and doc.content_sha256 == content_sha256:
        doc.last_seen_at = now
        return "unchanged"

    is_new = doc is None
    full = f"{title}\n{text}"
    indicators, truncated = extract_iocs(full)
    found: dict[tuple[str, str], tuple[int, str]] = {(i.type, i.value): (i.count, i.context) for i in indicators}
    for kind, value in item.extra_iocs:
        found.setdefault((kind, value), (1, f"reported by {source.name}"))
    domains = [v for (t, v) in found if t == "domain"]

    countries = list(dict.fromkeys([c for c in item.countries if len(c) == 2] + detect_countries(full, domains)))[:8]
    hint = item.hint_type or _CATEGORY_HINTS.get(source.category)
    threat_type, threat_types, confidence = classify(title, text, hint)
    techniques = attack.extract_techniques(title, text)

    # Entities: asserted by the source first, then recognised in the text.
    wanted: dict[int, tuple[str, int]] = {}
    actor = victim = None
    if item.actor:
        actor = get_or_create_entity(db, "actor", item.actor)
        wanted[actor.id] = ("actor", 95)
    if item.victim:
        victim = get_or_create_entity(db, "organization", item.victim)
        wanted[victim.id] = ("victim", 95)
    for entity_id in get_matcher(db).find(full):
        wanted.setdefault(entity_id, ("mention", 70))
    if not item.namespace:  # free text only; tracker rows already name their parties
        for name in propose_organizations(full, limit=8):
            org = get_or_create_entity(db, "organization", name, meta={"origin": "pattern"})
            wanted.setdefault(org.id, ("mention", 50))
    if actor and victim:
        incident = get_or_create_entity(db, "incident", f"{actor.name} / {victim.name}", meta={
            "actor_id": actor.id, "organization_id": victim.id, "countries": countries, "sectors": item.sectors,
        })
        wanted[incident.id] = ("mention", 95)
    technique_ids = technique_entity_ids(db)
    for technique, technique_confidence in techniques.items():
        if technique in technique_ids:
            wanted.setdefault(technique_ids[technique], ("mention", technique_confidence))
    entity_types = dict(db.execute(select(Entity.id, Entity.type).where(Entity.id.in_(wanted))).all()) if wanted else {}

    simhash = tu.simhash64(text)
    bands = tu.simhash_bands(simhash)
    reference_time = item.published_at or (doc.first_seen_at if doc else now)

    if is_new:
        doc = Document(doc_key=doc_key, source_id=source.id, first_seen_at=now, version_count=0, status="new")
        db.add(doc)
    previous_content = doc.content or ""
    previous_iocs = set()
    if not is_new:
        previous_iocs = {tuple(r) for r in db.execute(select(Ioc.type, Ioc.value).join(DocumentIoc, DocumentIoc.ioc_id == Ioc.id)
                                                      .where(DocumentIoc.document_id == doc.id))}

    doc.url = (item.url or fetch.get("final_url") or source.url)[:2048]
    doc.host = source.host
    doc.network = source.network
    doc.title = title or tu.summarize(text, 120)
    doc.summary = tu.summarize(text)
    doc.content = text
    doc.lang = detect_language(text) or doc.lang or ""
    doc.content_sha256 = content_sha256
    doc.raw_sha256 = raw_sha256
    doc.simhash = tu.to_signed64(simhash)
    doc.sh0, doc.sh1, doc.sh2, doc.sh3 = bands
    doc.threat_type, doc.threat_types, doc.confidence = threat_type, threat_types, confidence
    doc.countries = countries
    doc.sectors = [s[:64] for s in item.sectors][:6]
    doc.has_credentials = bool(exposure.credential_pairs)
    doc.exposure = exposure.as_dict()
    doc.published_at = item.published_at
    doc.last_seen_at = doc.last_changed_at = now
    doc.version_count += 1
    doc.meta = {**(doc.meta or {}), **item.meta, "truncated_indicator_types": sorted(truncated)}
    doc.techniques = sorted(techniques)
    if doc.verification != "confirmed":
        doc.verification = quality.verification_for(source.trust, doc.corroboration or 0, doc.verification or "unverified")
    doc.source = source
    db.flush()

    doc.duplicate_of = _find_duplicate(db, doc.id, content_sha256, simhash, len(text))
    _link_indicators(db, doc, found, now)
    _link_entities(db, doc, wanted, reference_time)
    store_exposures(db, doc, exposure.records, now)

    # Typed relationships with provenance: who targeted whom, and how, according to this source.
    if actor and victim:
        upsert_relationship(db, actor.id, victim.id, "targets", confidence=80, source=source.name, when=reference_time)
    if actor:
        for technique, technique_confidence in techniques.items():
            if technique in technique_ids and technique_confidence >= 60:
                upsert_relationship(db, actor.id, technique_ids[technique], "uses", confidence=55, source="Derived from collected findings", when=reference_time)
    db.flush()
    corroborated = quality.refresh_corroboration(db, doc)
    linked_feeds = db.scalar(select(func.count()).select_from(DocumentIoc).join(Ioc, Ioc.id == DocumentIoc.ioc_id)
                             .where(DocumentIoc.document_id == doc.id, func.cardinality(Ioc.feeds) > 0, Ioc.benign.is_(False))) or 0

    view = matching.DocView(title=doc.title, text=text, threat_type=threat_type, severity="info", confidence=confidence,
                            has_credentials=doc.has_credentials)
    for (kind, value), (_count, context) in found.items():
        view.iocs.setdefault(kind, {})[value] = context
    for entity_id, kind in entity_types.items():
        entity = db.get(Entity, entity_id)
        target = view.actors if kind == "actor" else view.organizations if kind == "organization" else None
        if target is not None and entity is not None:
            target.update(n.lower() for n in (entity.name, *(entity.aliases or [])))

    hits = [w for w in db.scalars(select(Watchlist).where(Watchlist.is_active.is_(True))) if matching.match_watch(w.kind, w.value, view, lookalikes=w.is_asset)]
    watch_hit = bool(hits)
    asset_criticality = max((w.criticality for w in hits if w.is_asset), default=None)
    focus_sectors = settings.focus_sector_list
    cves = [v for (t, v) in found if t == "cve"]
    known_exploited = bool(cves) and any(_redis.sismember(KEV_KEY, c) for c in cves[:50])
    doc.risk_score, doc.severity, doc.risk_factors = score_risk(
        threat_type=threat_type, confidence=confidence, source_trust=source.trust, network=source.network,
        exposure=doc.exposure, ioc_count=len(found), has_actor="actor" in entity_types.values(),
        has_victim=victim is not None, in_focus_country=bool(set(countries) & set(settings.focus_country_list)),
        reference_time=reference_time, known_exploited=known_exploited, watchlist_hit=watch_hit,
        corroboration=doc.corroboration, feed_listed=bool(linked_feeds), criticality=asset_criticality, techniques=len(techniques),
        in_focus_sector=bool(focus_sectors) and any(f in s.lower() for s in doc.sectors for f in focus_sectors),
    )
    view.severity = doc.severity

    change: dict = {}
    if not is_new:
        change = tu.line_diff_stats(previous_content, text)
        change["new_indicators"] = [f"{t}:{v}" for (t, v) in sorted(set(found) - previous_iocs)][:50]
        change["removed_indicators"] = [f"{t}:{v}" for (t, v) in sorted(previous_iocs - set(found))][:50]
    prev = db.scalar(select(DocumentVersion.chain_hash).where(DocumentVersion.document_id == doc.id).order_by(DocumentVersion.version.desc()).limit(1)) or ""
    chain_hash, signature = evidence_chain(prev, doc.id, doc.version_count, doc.url, now, raw_sha256, content_sha256)
    db.add(DocumentVersion(
        document_id=doc.id, version=doc.version_count, captured_at=now, url=doc.url, title=doc.title, content=text,
        content_sha256=content_sha256, raw_sha256=raw_sha256, http_status=fetch.get("http_status"),
        headers=fetch.get("headers") or {}, bytes=len(item.raw or ""), prev_chain_hash=prev, chain_hash=chain_hash,
        signature=signature, change=change,
    ))
    _store_raw(item.raw, raw_sha256)

    raise_alerts(db, doc, view, "new" if is_new else "changed")
    if is_new:
        source.doc_count += 1
    db.flush()
    reindex_document(db, doc)
    if is_new and doc.duplicate_of:
        # The original now exists at one more source: its "seen at" count has changed.
        original = db.get(Document, doc.duplicate_of)
        if original is not None:
            reindex_document(db, original)
    for other in corroborated:
        if other.id != doc.id:  # another source's report of the same incident just gained corroboration
            search_index.update_fields(str(other.id), {"verification": other.verification, "corroboration": other.corroboration,
                                                       "admiralty": quality.admiralty(other.source, other.verification)})
    return "new" if is_new else "changed"
