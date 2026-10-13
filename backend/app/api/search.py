import csv
import io
import json
import uuid
from datetime import datetime, timezone

from dateutil import parser as dateparser
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from opensearchpy.exceptions import OpenSearchException
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.common import csv_safe, iso
from app.config import get_settings
from app.db import get_db
from app.extract.classify import THREAT_TYPES
from app.extract.geo import all_countries, country_name
from app.extract.lang import LANGUAGE_NAMES
from app.extract.iocs import IOC_TYPES, defang
from app.intel import attack, quality
from app.models import RULE_KINDS
from app.models import (ALERT_STATUSES, ENTITY_TYPES, FINDING_STATUSES, SEVERITIES, WATCH_KINDS, Document, DocumentIoc, Entity, Ioc,
                        SavedSearch, User)
from app.search import service
from app.search.query import FIELD_ALIASES
from app.security import audit, viewer
from app.worker.parsers import CONNECTORS

router = APIRouter(tags=["search"])
settings = get_settings()

OPERATOR_HELP = [
    ("actor:", "Threat actor or group", "actor:lockbit"),
    ("org:", "Victim or organisation", 'org:"Kenya Airways"'),
    ("country:", "Country name or ISO code", "country:KE"),
    ("type:", "Threat type", "type:ransomware"),
    ("domain:", "Domain, its subdomains and mailboxes", "domain:example.co.ke"),
    ("email:", "Email address", "email:ceo@example.com"),
    ("ip:", "IP address or CIDR range", "ip:41.90.0.0/16"),
    ("cve:", "Vulnerability", "cve:CVE-2024-3400"),
    ("hash:", "MD5 / SHA-1 / SHA-256", "hash:44d88612fea8a8f36de82e1278abb02f"),
    ("crypto:", "Wallet address", "crypto:bc1q..."),
    ("malware:", "Malware family", "malware:lumma"),
    ("sector:", "Industry", "sector:healthcare"),
    ("source:", "Source name", "source:ransomware.live"),
    ("network:", "onion or surface", "network:onion"),
    ("severity:", "info, low, medium, high, critical", "severity:critical"),
    ("risk:", "Risk score range", "risk:>70"),
    ("after:", "Since a date or period", "after:30d"),
    ("before:", "Until a date", "before:2026-06-01"),
    ("has:", "creds, iocs, changes, actor, victim, cve", "has:creds"),
    ("tag:", "Analyst tag", "tag:priority"),
    ("title:", "Words in the title only", "title:breach"),
    ("NOT", "Exclude what follows (same as a leading -)", "ransomware NOT advertisement"),
    ("/…/", "Regular expression, matched against whole words", "/cve-2026-[0-9]+/"),
    ("site:", "One site or onion service", "site:example.onion"),
    ("kind:", "Source type: leak, forum, market, paste, news, tracker", "kind:leak"),
    ("lang:", "Language of the page", "lang:russian"),
    ("inurl:", "Text in the page address", "inurl:thread"),
]


def _date(value: str | None, end: bool = False) -> datetime | None:
    if not value:
        return None
    try:
        parsed = dateparser.parse(value)
    except (ValueError, OverflowError):
        raise HTTPException(400, f"Unrecognised date: {value}") from None
    if end and len(value) <= 10:
        parsed = parsed.replace(hour=23, minute=59, second=59)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def search_params(
    q: str = Query("", max_length=1000),
    strict: bool = False,
    type: list[str] = Query(default=[]),
    country: list[str] = Query(default=[]),
    severity: list[str] = Query(default=[]),
    network: list[str] = Query(default=[]),
    source: list[str] = Query(default=[]),
    actor: list[str] = Query(default=[]),
    org: list[str] = Query(default=[]),
    malware: list[str] = Query(default=[]),
    sector: list[str] = Query(default=[]),
    tag: list[str] = Query(default=[]),
    status: list[str] = Query(default=[]),
    technique: list[str] = Query(default=[]),
    verified: list[str] = Query(default=[]),
    lang: list[str] = Query(default=[]),
    kind: list[str] = Query(default=[]),
    site: list[str] = Query(default=[]),
    date_from: str | None = Query(None, alias="from"),
    date_to: str | None = Query(None, alias="to"),
    min_risk: int | None = Query(None, ge=0, le=100),
    min_confidence: int | None = Query(None, ge=0, le=100),
    creds: bool | None = None,
    dupes: bool = False,
    sort: str = "",
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
) -> service.SearchParams:
    return service.SearchParams(
        q=q, strict=strict, threat_types=type, countries=[c.upper() for c in country], severities=severity, networks=network,
        sources=source, actors=actor, organizations=org, malware=malware, sectors=sector, tags=tag, statuses=status,
        techniques=[t.upper() for t in technique], verification=verified, languages=[v.lower() for v in lang], source_types=kind,
        hosts=[v.lower() for v in site],
        date_from=_date(date_from), date_to=_date(date_to, end=True), min_risk=min_risk, min_confidence=min_confidence,
        has_credentials=creds, include_duplicates=dupes, sort=sort, page=page, size=size,
    )


@router.get("/meta")
def meta(user: User = Depends(viewer)):
    """Vocabularies the console needs to render filters and forms."""
    return {
        "app_name": settings.app_name,
        "threat_types": THREAT_TYPES,
        "countries": all_countries(),
        "focus_countries": settings.focus_country_list,
        "severities": SEVERITIES,
        "finding_statuses": FINDING_STATUSES,
        "alert_statuses": ALERT_STATUSES,
        "watch_kinds": WATCH_KINDS,
        "entity_types": ENTITY_TYPES,
        "ioc_types": IOC_TYPES,
        "connectors": CONNECTORS,
        "operators": [{"op": op, "help": text, "example": example} for op, text, example in OPERATOR_HELP],
        "redaction": settings.redact_secrets,
        "verification": quality.VERIFICATION_LABELS,
        "reliability": quality.RELIABILITY,
        "credibility": quality.CREDIBILITY,
        "tactics": [{"shortname": t["shortname"], "name": t["name"]} for t in attack.catalog()["tactics"]],
        "attack_version": attack.catalog()["version"],
        "techniques": {t["id"]: t["name"] for t in attack.catalog()["techniques"]},
        "rule_kinds": RULE_KINDS,
        "focus_sectors": settings.focus_sector_list,
        "languages": LANGUAGE_NAMES,
        "source_categories": ["ransomware_leak_site", "forum", "marketplace", "paste", "tracker", "news", "vuln_feed", "blog", "other"],
    }


@router.get("/search")
def run_search(params: service.SearchParams = Depends(search_params), user: User = Depends(viewer)):
    try:
        result = service.search(params)
    except OpenSearchException as exc:
        raise HTTPException(503, f"Search is unavailable: {type(exc).__name__}") from None
    for bucket in result["facets"]["countries"]:
        bucket["label"] = country_name(bucket["value"])
    for bucket in result["facets"]["threat_types"]:
        bucket["label"] = THREAT_TYPES.get(bucket["value"], bucket["value"])
    return result


@router.get("/search/suggest")
def suggest(q: str = Query("", max_length=200), db: Session = Depends(get_db), user: User = Depends(viewer)):
    """Type-ahead: operators, entities, indicators, countries and matching titles."""
    term = q.strip().split(" ")[-1] if q.strip() else ""
    out: dict = {"operators": [], "entities": [], "iocs": [], "countries": [], "titles": []}
    if len(term) < 2:
        return out
    lowered = term.lower()
    if ":" not in term:
        out["operators"] = [{"op": op, "help": text, "example": ex} for op, text, ex in OPERATOR_HELP if op.startswith(lowered)][:4]
        out["countries"] = [{"code": code, "name": name} for code, name in all_countries().items() if name.lower().startswith(lowered)][:4]
        like = lowered.replace("%", "").replace("_", r"\_")
        rows = db.execute(
            select(Entity.id, Entity.type, Entity.name, Entity.doc_count)
            .where(Entity.type != "incident", or_(Entity.name.ilike(f"{like}%"), Entity.name.ilike(f"% {like}%")))
            .order_by(Entity.doc_count.desc()).limit(6)
        ).all()
        out["entities"] = [{"id": r.id, "type": r.type, "name": r.name, "count": r.doc_count} for r in rows]
        if len(term) >= 3:
            rows = db.execute(select(Ioc.id, Ioc.type, Ioc.value, Ioc.doc_count).where(Ioc.value.like(f"{like}%")).order_by(Ioc.doc_count.desc()).limit(5)).all()
            out["iocs"] = [{"id": r.id, "type": r.type, "value": r.value, "count": r.doc_count} for r in rows]
    elif term.split(":", 1)[0].lower() in FIELD_ALIASES:
        field, _, value = term.partition(":")
        kind = {"actor": "actor", "organization": "organization", "malware": "malware", "campaign": "campaign"}.get(FIELD_ALIASES[field.lower()])
        if kind and len(value) >= 1:
            rows = db.execute(select(Entity.id, Entity.type, Entity.name, Entity.doc_count).where(Entity.type == kind, Entity.name.ilike(f"{value}%"))
                              .order_by(Entity.doc_count.desc()).limit(6)).all()
            out["entities"] = [{"id": r.id, "type": r.type, "name": r.name, "count": r.doc_count} for r in rows]
    try:
        out["titles"] = service.suggest_titles(q.strip()[-80:]) if ":" not in term else []
    except OpenSearchException:
        pass
    return out


@router.get("/search/export")
def export(request: Request, format: str = "csv", params: service.SearchParams = Depends(search_params),
           db: Session = Depends(get_db), user: User = Depends(viewer)):
    """Export up to 5,000 matching findings as CSV or JSON."""
    if format not in ("csv", "json"):
        raise HTTPException(400, "format must be csv or json")
    ids = [uuid.UUID(i) for i in service.scan_ids(params, limit=5000)]
    audit(db, request, user, "search.export", "search", "", query=params.q[:500], format=format, count=len(ids))
    db.commit()
    order = {doc_id: n for n, doc_id in enumerate(ids)}
    docs: list[Document] = []
    for start in range(0, len(ids), 500):
        docs += db.scalars(select(Document).where(Document.id.in_(ids[start : start + 500]))).unique().all()
    docs.sort(key=lambda d: order[d.id])

    def row(doc: Document) -> dict:
        return {
            "id": str(doc.id), "first_seen": iso(doc.first_seen_at), "published": iso(doc.published_at), "title": doc.title,
            "threat_type": doc.threat_type, "severity": doc.severity, "risk_score": doc.risk_score, "confidence": doc.confidence,
            "countries": " ".join(doc.countries), "source": doc.source.name, "network": doc.network, "url": defang(doc.url),
            "has_credentials": doc.has_credentials, "status": doc.status, "content_sha256": doc.content_sha256, "summary": doc.summary,
        }

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    if format == "json":
        payload = json.dumps({"query": params.q, "exported_at": iso(datetime.now(timezone.utc)), "count": len(docs), "findings": [row(d) for d in docs]}, indent=2)
        return StreamingResponse(iter([payload]), media_type="application/json", headers={"Content-Disposition": f'attachment; filename="kivuli-findings-{stamp}.json"'})
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(row(docs[0]).keys()) if docs else ["id"])
    writer.writeheader()
    for doc in docs:
        # Leading =, +, - or @ would be run as a formula by spreadsheet software.
        writer.writerow({k: csv_safe(v) for k, v in row(doc).items()})
    return StreamingResponse(iter([buffer.getvalue()]), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="kivuli-findings-{stamp}.csv"'})


class SavedSearchIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    query: str = Field("", max_length=1000)
    params: dict = {}


@router.get("/saved-searches")
def list_saved(db: Session = Depends(get_db), user: User = Depends(viewer)):
    rows = db.scalars(select(SavedSearch).where(SavedSearch.user_id == user.id).order_by(SavedSearch.created_at.desc())).all()
    return [{"id": r.id, "name": r.name, "query": r.query, "params": r.params, "created_at": iso(r.created_at)} for r in rows]


@router.post("/saved-searches")
def save_search(body: SavedSearchIn, db: Session = Depends(get_db), user: User = Depends(viewer)):
    row = SavedSearch(user_id=user.id, name=body.name.strip(), query=body.query, params=body.params)
    db.add(row)
    db.commit()
    return {"id": row.id}


@router.delete("/saved-searches/{search_id}")
def delete_saved(search_id: int, db: Session = Depends(get_db), user: User = Depends(viewer)):
    row = db.get(SavedSearch, search_id)
    if row is None or row.user_id != user.id:
        raise HTTPException(404, "Not found")
    db.delete(row)
    db.commit()
    return {"ok": True}
