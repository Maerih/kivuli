"""Investigation tools: email header analysis, payload decoding and a quick verdict on any indicator.

The header analyser and the decoder work on text an analyst pastes in, entirely
offline. The verdict reads what collected intelligence already says and asks
the enrichment providers, which run in the enricher; the indicator itself is
never contacted. Pasted content is not stored or logged, only that a tool ran.
"""
import json

import redis
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, tuple_
from sqlalchemy.orm import Session

from app.api.common import finding_summary, iso
from app.config import get_settings
from app.db import get_db
from app.enrich import providers, rejected
from app.chain.addresses import can_look_up, detect_chain
from app.chain.labels import CATEGORY_LABELS
from app.extract.iocs import defang, detect_indicator
from app.models import ChainAddress, Document, DocumentIoc, Enrichment, Ioc, User, Watchlist
from app.security import analyst, audit, viewer
from app.tools import decoder, headers
from app.worker.celery_app import enqueue

router = APIRouter(tags=["tools"])
_redis = redis.Redis.from_url(get_settings().redis_url, decode_responses=True)
ENRICHABLE = ("ip", "domain", "url", "hash")


class TextIn(BaseModel):
    text: str = Field(min_length=1, max_length=600_000)


def _known(db: Session, found: list[dict]) -> list[dict]:
    """Mark each indicator with what collected intelligence already holds about it."""
    pairs = {(i["type"], i["value"]) for i in found}
    rows = {(r.type, r.value): r for r in db.scalars(select(Ioc).where(tuple_(Ioc.type, Ioc.value).in_(list(pairs))))} if pairs else {}
    out = []
    for i in found:
        r = rows.get((i["type"], i["value"]))
        out.append({**i, "defanged": defang(i["value"]),
                    "known": {"id": r.id, "findings": r.doc_count, "feeds": r.feeds, "benign": r.benign, "last_seen": iso(r.last_seen_at)} if r else None})
    # Known ones first: they are what an analyst looks at.
    return sorted(out, key=lambda x: (x["known"] is None, x["type"]))


@router.post("/tools/headers")
def analyse_headers(body: TextIn, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    """Where an email came from and whether it is who it claims to be. Offline."""
    result = headers.analyse(body.text)
    if result.get("ok"):
        result["indicators"] = _known(db, result["indicators"])
    audit(db, request, user, "tools.headers", "tool", "headers", size=len(body.text))
    db.commit()
    return result


@router.post("/tools/decode")
def decode_payload(body: TextIn, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    """Undo obfuscation layer by layer and report what the decoded text does. Nothing is run."""
    result = decoder.decode(body.text)
    if result.get("ok"):
        result["indicators"] = _known(db, result["indicators"])
    audit(db, request, user, "tools.decode", "tool", "decode", size=len(body.text))
    db.commit()
    return result


def _verdict(feeds: list[str], benign: bool, results: list[dict], findings: int) -> tuple[str, list[str]]:
    """Combine local intelligence and provider answers into one verdict, with the reasons."""
    reasons = []
    if benign:
        reasons.append("Marked benign by an analyst")
    if feeds:
        reasons.append(f"Listed by threat feeds: {', '.join(feeds)}")
    bad = [r["label"] for r in results if r["ok"] and r["verdict"] == "malicious"]
    odd = [r["label"] for r in results if r["ok"] and r["verdict"] == "suspicious"]
    clean = [r["label"] for r in results if r["ok"] and r["verdict"] == "clean"]
    if bad:
        reasons.append(f"Malicious according to {', '.join(bad)}")
    if odd:
        reasons.append(f"Suspicious according to {', '.join(odd)}")
    if findings:
        reasons.append(f"Appears in {findings} collected finding{'s' if findings != 1 else ''}")
    if clean and not (bad or odd or feeds):
        reasons.append(f"Clean according to {', '.join(clean)}")
    if benign and not bad:
        return "benign", reasons
    if bad or feeds:
        return "malicious", reasons
    if odd:
        return "suspicious", reasons
    # Being mentioned is not being malicious: victims, vendors and news sites appear in findings too.
    if findings:
        return "seen", reasons
    if clean:
        return "clean", reasons
    return "unknown", reasons or ["Nothing known about it yet"]


@router.get("/tools/verdict")
def verdict(value: str = Query(min_length=3, max_length=1024), db: Session = Depends(get_db), user: User = Depends(viewer)):
    """Everything known about one indicator: collected intelligence, watchlists and provider answers."""
    detected = detect_indicator(value)
    if detected is None:
        raise HTTPException(400, "That is not a recognised indicator (IP, domain, URL, hash, email, wallet, CVE or handle)")
    kind, norm = detected
    ioc = db.scalar(select(Ioc).where(Ioc.type == kind, Ioc.value == norm))
    findings = []
    if ioc is not None:
        docs = db.scalars(select(Document).join(DocumentIoc, DocumentIoc.document_id == Document.id)
                          .where(DocumentIoc.ioc_id == ioc.id).order_by(Document.first_seen_at.desc()).limit(10)).unique().all()
        findings = [finding_summary(d) for d in docs]
    watch_kind = {"username": "username"}.get(kind, kind)
    watches = db.scalars(select(Watchlist).where(Watchlist.kind == watch_kind, Watchlist.value == norm, Watchlist.is_active.is_(True))).all()
    labels = {p.name: p.label for p in providers.PROVIDERS}
    rows = db.scalars(select(Enrichment).where(Enrichment.subject_type == kind, Enrichment.subject == norm).order_by(Enrichment.provider)).all()
    skipped = rejected.all_rejections()
    rows = [r for r in rows if r.ok or r.provider not in skipped]  # stale "key rejected" rows; reported once instead
    results = [{"provider": r.provider, "label": labels.get(r.provider, r.provider), "fetched_at": iso(r.fetched_at), "ok": r.ok,
                "verdict": r.verdict, "score": r.score, "summary": r.summary, "error": r.error} for r in rows]
    wallet = db.get(ChainAddress, norm) if kind == "crypto" else None
    feeds = list(ioc.feeds or []) if ioc else []
    overall, reasons = _verdict(feeds, bool(ioc and ioc.benign), results, ioc.doc_count if ioc else 0)
    if wallet is not None and wallet.category in ("sanctioned", "mixer"):
        overall, reasons = "malicious", [f"Wallet classed as {wallet.category}" + (f": {wallet.label}" if wallet.label else ""), *reasons]
    return {
        "value": norm, "type": kind, "defanged": defang(norm), "verdict": overall, "reasons": reasons,
        "enrichable": kind in ENRICHABLE, "providers_for_type": _providers_for(kind),
        "indicator": {"id": ioc.id, "findings": ioc.doc_count, "first_seen": iso(ioc.first_seen_at), "last_seen": iso(ioc.last_seen_at),
                      "feeds": feeds, "tags": ioc.tags, "benign": ioc.benign} if ioc else None,
        "key_rejected": [{"provider": n, "label": labels.get(n, n), "message": m} for n, m in skipped.items()
                         if kind in (providers.BY_NAME[n].kinds if n in providers.BY_NAME else ())],
        "findings": findings, "watchlists": [{"id": w.id, "name": w.name} for w in watches], "results": results,
        "wallet": {"category": wallet.category, "category_label": CATEGORY_LABELS.get(wallet.category, wallet.category), "label": wallet.label, "balance": wallet.balance, "token": wallet.token,
                   "total_in": wallet.total_in, "total_out": wallet.total_out, "tx_count": wallet.tx_count,
                   "counterparties": wallet.counterparty_count, "first_tx": iso(wallet.first_tx_at), "last_tx": iso(wallet.last_tx_at),
                   "looked_up": wallet.enriched_at is not None, "error": wallet.error, "truncated": wallet.truncated} if wallet else None,
        "chain_supported": kind == "crypto" and can_look_up((detect_chain(norm) or ("", ""))[0]),
    }


def _providers_for(kind: str) -> list[str]:
    """Providers switched on for this type, as the enricher (which holds the keys) last reported."""
    raw = _redis.get("kivuli:status:providers")
    reported = json.loads(raw) if raw else []
    return [p["label"] for p in reported if kind in p.get("kinds", []) and p.get("enabled") and not p.get("key_rejected")]


class VerdictIn(BaseModel):
    value: str = Field(min_length=3, max_length=1024)


@router.post("/tools/verdict")
def run_verdict(body: VerdictIn, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    """Ask the providers about an indicator now. Poll GET /tools/verdict for the answers as they arrive."""
    detected = detect_indicator(body.value)
    if detected is None:
        raise HTTPException(400, "That is not a recognised indicator")
    kind, norm = detected
    queued = kind in ENRICHABLE
    if queued:
        enqueue("enrich.subject", subject_type=kind, value=norm)
    elif kind == "crypto":
        # A wallet: read it on-chain from the public explorer, next to what collected intelligence says.
        from app.api.chain import _queue as queue_chain_lookup
        queued = bool(queue_chain_lookup(db, norm, user).get("job_id"))
    audit(db, request, user, "tools.verdict", "ioc", norm[:200], type=kind, queued=queued)
    db.commit()
    return {"value": norm, "type": kind, "queued": queued}
