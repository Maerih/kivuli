"""Blockchain investigation: look up a wallet, draw the flow of value around it,
and expand it hop by hop. Read-only: public on-chain data, nothing is signed or sent.
"""
import json
import uuid

import redis
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.common import finding_summary, iso
from app.chain import addresses as chainaddr
from app.chain import labels, providers
from app.chain.addresses import can_look_up, chain_label, detect_chain
from app.config import get_settings
from app.db import get_db
from app.models import CaseItem, ChainAddress, ChainEdge, Document, DocumentIoc, Ioc, User, utcnow
from app.security import analyst, audit, viewer
from app.worker.celery_app import enqueue

router = APIRouter(tags=["chain"])
settings = get_settings()
_redis = redis.Redis.from_url(settings.redis_url, decode_responses=True)
JOB_KEY = "kivuli:chain:{}"


def _node(address: str, chain: str, row: ChainAddress | None) -> dict:
    """A graph node: full when the address has been looked up, a stub otherwise."""
    if row is None:
        return {"address": address, "chain": chain, "enriched": False, "category": "unknown",
                "category_label": labels.CATEGORY_LABELS["unknown"], "label": "", "balance": None, "token": "",
                "tx_count": None, "in_intel": False, "risk": False, "defanged": _defang(address)}
    return {
        "address": row.address, "chain": row.chain, "enriched": True, "category": row.category,
        "category_label": labels.CATEGORY_LABELS.get(row.category, row.category), "label": row.label,
        "balance": row.balance, "token": row.token, "total_in": row.total_in, "total_out": row.total_out,
        "tx_count": row.tx_count, "counterparty_count": row.counterparty_count, "truncated": row.truncated,
        "in_intel": row.in_intel, "co_spent": row.co_spent or [], "first_tx": iso(row.first_tx_at), "last_tx": iso(row.last_tx_at),
        "risk": row.category in labels.RISK_CATEGORIES, "error": row.error, "defanged": _defang(row.address),
    }


def _defang(address: str) -> str:
    # A wallet is not clickable and not a link; show it whole but visually inert at the ends.
    return address if len(address) <= 16 else f"{address[:10]}…{address[-6:]}"




@router.get("/chain/{address}")
def get_address(address: str, db: Session = Depends(get_db), user: User = Depends(viewer)):
    """A looked-up address, the flow around it, and where it appears in collected intelligence.

    If the address has never been looked up, this records what chain it is and
    returns `enriched: false`; call POST /chain/lookup to fetch it.
    """
    detected = detect_chain(address)
    if detected is None:
        raise HTTPException(400, "That is not a recognised cryptocurrency address")
    chain, norm = detected
    row = db.get(ChainAddress, norm)

    # The subgraph: this address, its direct counterparties, and edges among them.
    edges = db.scalars(select(ChainEdge).where(or_(ChainEdge.src == norm, ChainEdge.dst == norm)).order_by(ChainEdge.value.desc()).limit(120)).all()
    neighbour_addrs = {norm} | {e.src for e in edges} | {e.dst for e in edges}
    rows = {r.address: r for r in db.scalars(select(ChainAddress).where(ChainAddress.address.in_(neighbour_addrs)))}
    # Also include edges strictly between two already-known neighbours, so expansion fills the graph in.
    extra = db.scalars(select(ChainEdge).where(ChainEdge.src.in_(neighbour_addrs), ChainEdge.dst.in_(neighbour_addrs))).all()
    seen = {(e.src, e.dst) for e in edges}
    for e in extra:
        if (e.src, e.dst) not in seen:
            edges.append(e)
            seen.add((e.src, e.dst))

    nodes = [_node(a, rows[a].chain if a in rows else chain, rows.get(a)) for a in neighbour_addrs]
    edge_out = [{"src": e.src, "dst": e.dst, "value": e.value, "tx_count": e.tx_count, "sample_txid": e.sample_txid,
                 "first_seen": iso(e.first_seen_at), "last_seen": iso(e.last_seen_at)} for e in edges]

    findings = _findings_for(db, norm)
    return {
        "address": norm, "chain": chain, "chain_label": chain_label(chain), "can_look_up": can_look_up(chain),
        "enriched": row is not None and row.enriched_at is not None, "root": _node(norm, chain, row),
        "nodes": nodes, "edges": edge_out, "findings": findings,
        "note": "" if can_look_up(chain) else f"On-chain lookup is not available for {chain_label(chain)}; it can still be traced where it appears in collected intelligence.",
    }


def _findings_for(db: Session, address: str) -> list[dict]:
    ioc = db.scalar(select(Ioc).where(Ioc.type == "crypto", Ioc.value == address))
    if ioc is None:
        return []
    docs = db.scalars(select(Document).join(DocumentIoc, DocumentIoc.document_id == Document.id)
                      .where(DocumentIoc.ioc_id == ioc.id).order_by(Document.first_seen_at.desc()).limit(25)).unique().all()
    return [finding_summary(d) for d in docs]


class LookupIn(BaseModel):
    address: str = Field(min_length=10, max_length=128)


def _queue(db: Session, address: str, user: User) -> dict:
    detected = detect_chain(address)
    if detected is None:
        raise HTTPException(400, "That is not a recognised cryptocurrency address")
    chain, norm = detected
    if not can_look_up(chain):
        # Record it so it can be searched and linked, but there is nothing to fetch.
        if db.get(ChainAddress, norm) is None:
            db.add(ChainAddress(address=norm, chain=chain, category="unknown", enriched_at=utcnow(),
                                error=f"on-chain lookup not available for {chain}"))
            db.commit()
        return {"address": norm, "chain": chain, "supported": False, "job_id": None}
    job_id = uuid.uuid4().hex
    _redis.set(JOB_KEY.format(job_id), json.dumps({"status": "queued", "address": norm, "chain": chain}), ex=900)
    enqueue("chain.lookup", job_id=job_id, chain=chain, address=norm, requested_by=user.id)
    return {"address": norm, "chain": chain, "supported": True, "job_id": job_id}


@router.post("/chain/lookup")
def lookup(body: LookupIn, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    """Look an address up on-chain. Returns a job to poll; the result lands in the graph."""
    out = _queue(db, body.address.strip(), user)
    audit(db, request, user, "chain.lookup", "chain", out["address"][:120], chain=out["chain"])
    db.commit()
    return out


@router.post("/chain/{address}/expand")
def expand(address: str, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    """Look up the counterparties of an address that have not been looked up yet: the next hop."""
    detected = detect_chain(address)
    if detected is None:
        raise HTTPException(400, "That is not a recognised cryptocurrency address")
    chain, norm = detected
    neighbours = set(db.scalars(select(ChainEdge.dst).where(ChainEdge.src == norm))) | set(db.scalars(select(ChainEdge.src).where(ChainEdge.dst == norm)))
    known = set(db.scalars(select(ChainAddress.address).where(ChainAddress.address.in_(neighbours), ChainAddress.enriched_at.isnot(None)))) if neighbours else set()
    todo = [a for a in neighbours if a not in known and can_look_up((detect_chain(a) or ("", ""))[0])][:25]
    jobs = []
    for a in todo:
        d = detect_chain(a)
        if d:
            jobs.append(_queue(db, a, user)["job_id"])
    audit(db, request, user, "chain.expand", "chain", norm[:120], queued=len(jobs))
    db.commit()
    return {"queued": len([j for j in jobs if j]), "already_known": len(known), "job_ids": [j for j in jobs if j]}


@router.get("/chain/jobs/{job_id}")
def job(job_id: str, user: User = Depends(viewer)):
    raw = _redis.get(JOB_KEY.format(job_id)) if job_id.isalnum() else None
    if raw is None:
        raise HTTPException(404, "Job not found or expired")
    return json.loads(raw)


class ChainCaseIn(BaseModel):
    case_id: int
    note: str = Field("", max_length=2000)


@router.post("/chain/{address}/case")
def add_to_case(address: str, body: ChainCaseIn, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    """Pin a wallet (and the trace rooted at it) to an investigation."""
    detected = detect_chain(address)
    if detected is None:
        raise HTTPException(400, "That is not a recognised cryptocurrency address")
    norm = detected[1]
    if db.scalar(select(CaseItem.id).where(CaseItem.case_id == body.case_id, CaseItem.object_type == "chain", CaseItem.object_id == norm)):
        raise HTTPException(409, "This wallet is already in that investigation")
    db.add(CaseItem(case_id=body.case_id, object_type="chain", object_id=norm, note=body.note, added_by=user.id))
    audit(db, request, user, "chain.add_to_case", "chain", norm[:120], case_id=body.case_id)
    db.commit()
    return {"ok": True}
