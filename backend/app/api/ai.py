"""AI analyst endpoints.

The API never calls the model. It prepares grounded context from the platform's
own data, hands the job to the enricher over the queue, and the console polls
for the result. With no API key configured the endpoints say so and, where they
can, fall back to the deterministic query interpreter.
"""
import json
import uuid
from datetime import datetime, timezone

import redis
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.common import get_document, parse_uuid
from app.api.search import OPERATOR_HELP
from app.config import get_settings
from app.db import get_db
from app.models import Case, CaseItem, Document, DocumentEntity, Entity, User
from app.search import query as query_language
from app.security import analyst, audit, viewer
from app.worker.celery_app import enqueue

router = APIRouter(tags=["ai"])
settings = get_settings()
_redis = redis.Redis.from_url(settings.redis_url, decode_responses=True)


def _status() -> dict:
    raw = _redis.get("kivuli:status:ai")
    return json.loads(raw) if raw else {"enabled": False, "model": ""}


def _new_job(kind: str, user: User) -> str:
    job_id = uuid.uuid4().hex
    _redis.set(f"kivuli:ai:{job_id}", json.dumps({"status": "queued", "kind": kind, "user": user.id}), ex=3600)
    return job_id


def _source(doc: Document, actors: list[str] | None = None, limit: int = 6000) -> dict:
    return {"id": str(doc.id), "title": doc.title, "content": doc.content[:limit], "source_name": doc.source.name, "date": (doc.published_at or doc.first_seen_at).isoformat(),
            "threat_type": doc.threat_type, "verification": doc.verification, "countries": doc.countries, "actors": actors or []}


def _require_ai() -> None:
    if not _status()["enabled"]:
        raise HTTPException(409, "The AI analyst is not configured. An administrator can add an Anthropic API key under Integrations > Enrichment and AI.")


@router.get("/ai/status")
def status(user: User = Depends(viewer)):
    return _status()


class AskIn(BaseModel):
    question: str = Field(min_length=3, max_length=1500)


@router.post("/ai/ask")
def ask(body: AskIn, request: Request, db: Session = Depends(get_db), user: User = Depends(viewer)):
    """Answer a question from collected intelligence, with citations."""
    if not _status()["enabled"]:
        # No model: still useful, because the query interpreter understands countries, concepts and indicators.
        parsed = query_language.parse_query(body.question)
        return {"status": "disabled", "query": body.question, "interpretation": parsed.interpretation,
                "message": "The AI analyst is not configured, so this ran as an interpreted search instead."}
    job_id = _new_job("ask", user)
    operators = [{"example": example, "help": text} for _, text, example in OPERATOR_HELP]
    enqueue("ai.ask", job_id=job_id, question=body.question, operators=operators, today=datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    audit(db, request, user, "ai.ask", "ai", job_id, question=body.question[:300])
    db.commit()
    return {"status": "queued", "job_id": job_id}


class SummarizeIn(BaseModel):
    finding_id: str
    refresh: bool = False


@router.post("/ai/summarize")
def summarize(body: SummarizeIn, request: Request, db: Session = Depends(get_db), user: User = Depends(viewer)):
    doc = get_document(db, body.finding_id)
    if doc.ai_summary and not body.refresh:
        return {"status": "done", **json.loads(doc.ai_summary)}
    _require_ai()
    job_id = _new_job("summarize", user)
    enqueue("ai.summarize", job_id=job_id, source=_source(doc, limit=24000))
    audit(db, request, user, "ai.summarize", "finding", doc.id)
    db.commit()
    return {"status": "queued", "job_id": job_id}


class BriefIn(BaseModel):
    case_id: int | None = None
    entity_id: int | None = None


@router.post("/ai/brief")
def brief(body: BriefIn, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    """Draft an executive summary for a case, or a profile for an actor, from its findings."""
    _require_ai()
    if body.case_id is not None:
        case = db.get(Case, body.case_id)
        if case is None:
            raise HTTPException(404, "Case not found")
        ids = [parse_uuid(i) for i in db.scalars(select(CaseItem.object_id).where(CaseItem.case_id == case.id, CaseItem.object_type == "finding"))]
        title, audience = case.title, "executive"
        docs = db.scalars(select(Document).where(Document.id.in_(ids)).order_by(Document.risk_score.desc()).limit(20)).unique().all() if ids else []
    elif body.entity_id is not None:
        entity = db.get(Entity, body.entity_id)
        if entity is None:
            raise HTTPException(404, "Entity not found")
        title, audience = entity.name, "profile"
        docs = db.scalars(select(Document).join(DocumentEntity, DocumentEntity.document_id == Document.id).where(DocumentEntity.entity_id == entity.id)
                          .order_by(Document.first_seen_at.desc()).limit(20)).unique().all()
    else:
        raise HTTPException(400, "Give a case_id or an entity_id")
    if not docs:
        raise HTTPException(409, "There are no findings to base a draft on yet")
    job_id = _new_job("brief", user)
    enqueue("ai.brief", job_id=job_id, title=title, sources=[_source(d, limit=2500) for d in docs], audience=audience)
    audit(db, request, user, "ai.brief", "case" if body.case_id else "entity", body.case_id or body.entity_id)
    db.commit()
    return {"status": "queued", "job_id": job_id}


@router.get("/ai/jobs/{job_id}")
def job(job_id: str, user: User = Depends(viewer)):
    raw = _redis.get(f"kivuli:ai:{job_id}") if job_id.isalnum() else None
    if raw is None:
        raise HTTPException(404, "Job not found or expired")
    data = json.loads(raw)
    if data.get("user") not in (None, user.id) and user.role != "admin":
        raise HTTPException(404, "Job not found or expired")
    data.pop("user", None)
    return data
