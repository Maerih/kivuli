"""Intelligence quality: source reliability, information credibility, corroboration.

Uses the Admiralty (NATO) system analysts already know: a letter for how
reliable the source is and a number for how credible this piece of information
is. "B2" reads "usually reliable source, probably true".
"""
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Document, DocumentEntity, Entity, Source

RELIABILITY = {"A": "Completely reliable", "B": "Usually reliable", "C": "Fairly reliable", "D": "Not usually reliable",
               "E": "Unreliable", "F": "Reliability cannot be judged"}
CREDIBILITY = {1: "Confirmed by other sources", 2: "Probably true", 3: "Possibly true", 4: "Doubtful", 5: "Improbable", 6: "Truth cannot be judged"}
_VERIFICATION_CREDIBILITY = {"confirmed": 1, "corroborated": 2, "reported": 3, "unverified": 6}
VERIFICATION_LABELS = {
    "unverified": "Unverified: single source of unknown or low reliability",
    "reported": "Reported: stated by an established source, not yet corroborated",
    "corroborated": "Corroborated: independently seen by more than one source",
    "confirmed": "Confirmed: validated by an analyst",
}


def reliability(source: Source) -> str:
    """Admiralty letter: the operator's explicit grade, else derived from the trust score."""
    if source.reliability in RELIABILITY:
        return source.reliability
    for floor, letter in ((90, "A"), (75, "B"), (60, "C"), (40, "D"), (20, "E")):
        if source.trust >= floor:
            return letter
    return "F"


def admiralty(source: Source, verification: str) -> str:
    return f"{reliability(source)}{_VERIFICATION_CREDIBILITY.get(verification, 6)}"


def verification_for(trust: int, corroboration: int, current: str = "unverified") -> str:
    if current == "confirmed":  # only an analyst sets or clears this
        return "confirmed"
    if corroboration >= 1:
        return "corroborated"
    return "reported" if trust >= 60 else "unverified"


def _family(doc: Document) -> str:
    """Two feeds of the same tracker are one source; different trackers are independent."""
    return (doc.meta or {}).get("tracker") or f"source:{doc.source_id}"


def refresh_corroboration(db: Session, doc: Document) -> list[Document]:
    """Recount independent sources for a finding and everything reporting the same incident.

    Returns the findings whose verification state changed.
    """
    incident_ids = list(db.scalars(
        select(DocumentEntity.entity_id).join(Entity, Entity.id == DocumentEntity.entity_id)
        .where(DocumentEntity.document_id == doc.id, Entity.type == "incident")))
    group: dict = {doc.id: doc}
    if incident_ids:
        for other in db.scalars(select(Document).join(DocumentEntity, DocumentEntity.document_id == Document.id)
                                .where(DocumentEntity.entity_id.in_(incident_ids)).limit(200)).unique():
            group[other.id] = other
    root = doc.duplicate_of or doc.id
    for other in db.scalars(select(Document).where((Document.duplicate_of == root) | (Document.id == root)).limit(200)).unique():
        group[other.id] = other

    families = {_family(d) for d in group.values()}
    changed = []
    for member in group.values():
        count = len(families - {_family(member)})
        state = verification_for(member.source.trust, count, member.verification)
        if member.corroboration != count or member.verification != state:
            member.corroboration, member.verification = count, state
            changed.append(member)
    return changed


def quality_stats(db: Session) -> dict:
    """Headline data-quality numbers for the system page and metrics."""
    total = db.scalar(select(func.count()).select_from(Document)) or 0
    by_state = dict(db.execute(select(Document.verification, func.count()).group_by(Document.verification)).all())
    duplicates = db.scalar(select(func.count()).select_from(Document).where(Document.duplicate_of.isnot(None))) or 0
    unclassified = db.scalar(select(func.count()).select_from(Document).where(Document.threat_type == "other")) or 0
    return {"findings": total, "verification": by_state, "duplicates": duplicates, "unclassified": unclassified,
            "duplicate_rate": round(duplicates / total, 3) if total else 0, "unclassified_rate": round(unclassified / total, 3) if total else 0}
