"""Entity resolution and typed relationships.

Co-occurrence says two things were mentioned together. A relationship says how
they are connected, how sure we are, and who said so - and it carries first and
last seen dates so a link can be read historically.
"""
import logging
from datetime import datetime

from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.extract.entities import distinctive
from app.extract.textutil import slugify
from app.intel import attack
from app.models import CaseItem, DocumentEntity, Entity, Note, Relationship, utcnow

log = logging.getLogger(__name__)

# Built-in operating-system utilities that ATT&CK lists as "tools": matching them in prose is noise.
_TOOL_STOP = {"net", "ping", "cmd", "at", "ftp", "reg", "arp", "route", "tor", "ipconfig", "ifconfig", "netstat", "nbtstat", "netsh",
              "tasklist", "systeminfo", "schtasks", "dsquery", "sdelete", "certutil", "esentutl", "forfiles", "wevtutil", "bitsadmin",
              "expand", "attrib", "cacls", "icacls", "xcopy", "robocopy", "nltest", "quser", "rclone", "ngrok", "sqlmap", "pacu"}


def upsert_relationship(db: Session, src_id: int, dst_id: int, kind: str, *, confidence: int, source: str,
                        when: datetime | None = None) -> None:
    when = when or utcnow()
    stmt = pg_insert(Relationship).values(src_id=src_id, dst_id=dst_id, kind=kind, confidence=confidence, source=source[:120],
                                          first_seen_at=when, last_seen_at=when)
    db.execute(stmt.on_conflict_do_update(
        index_elements=["src_id", "dst_id", "kind"],
        set_={"last_seen_at": func.greatest(Relationship.last_seen_at, when), "first_seen_at": func.least(Relationship.first_seen_at, when),
              "confidence": func.greatest(Relationship.confidence, confidence)},
    ))


class Resolver:
    """Finds the existing entity that a name or any of its aliases refers to."""

    def __init__(self, db: Session, kind: str):
        self.db, self.kind = db, kind
        self.by_slug: dict[str, Entity] = {}
        for entity in db.scalars(select(Entity).where(Entity.type == kind)):
            self._index(entity)

    def _index(self, entity: Entity) -> None:
        for name in (entity.name, *(entity.aliases or [])):
            self.by_slug.setdefault(slugify(name), entity)

    def find(self, name: str, aliases: list[str] | tuple[str, ...] = ()) -> Entity | None:
        for candidate in (name, *aliases):
            if entity := self.by_slug.get(slugify(candidate)):
                return entity
        return None

    def ensure(self, name: str, aliases: list[str], **fields) -> Entity:
        entity = self.find(name, aliases)
        if entity is None:
            entity = Entity(type=self.kind, name=name, slug=slugify(name), aliases=aliases, **fields)
            self.db.add(entity)
            self.db.flush()
        else:
            known = {slugify(a) for a in (entity.name, *(entity.aliases or []))}
            extra = [a for a in (name, *aliases) if slugify(a) not in known]
            if extra:
                entity.aliases = [*(entity.aliases or []), *extra]
            for key, value in fields.items():
                if key == "meta":
                    entity.meta = {**(entity.meta or {}), **value}
                elif key == "description" and not entity.description:
                    entity.description = value
                elif key == "curated":
                    entity.curated = entity.curated or value
        self._index(entity)
        return entity


def seed_attack(db: Session) -> dict:
    """Load ATT&CK techniques, groups and software, resolving them onto entities that already exist."""
    data = attack.catalog()
    origin = f"MITRE ATT&CK v{data['version']}"

    techniques = Resolver(db, "technique")
    technique_ids: dict[str, int] = {}
    for item in data["techniques"]:
        existing = techniques.by_slug.get(item["id"].lower())
        if existing is None:
            existing = Entity(type="technique", name=f"{item['id']} {item['name']}", slug=item["id"].lower(), aliases=[], curated=True,
                              description=item["description"], meta={"attack_id": item["id"], "tactics": item["tactics"]})
            db.add(existing)
            db.flush()
            techniques.by_slug[item["id"].lower()] = existing
        technique_ids[item["id"]] = existing.id

    software = Resolver(db, "malware")
    software_ids: dict[str, int] = {}
    for item in data["software"]:
        name = item["name"]
        if item["kind"] == "tool" and (name.lower() in _TOOL_STOP or (len(name) < 6 and not distinctive(name))):
            continue
        aliases = [a for a in item["aliases"] if len(a) >= 4 and a.lower() not in _TOOL_STOP]
        entity = software.ensure(name, aliases, curated=True, description=item["description"],
                                 meta={"attack_id": item["id"], "kind": item["kind"], "needs_context": True})
        software_ids[item["id"]] = entity.id

    actors = Resolver(db, "actor")
    links = 0
    for item in data["groups"]:
        entity = actors.ensure(item["name"], item["aliases"], curated=True, description=item["description"],
                               meta={"attack_id": item["id"], "needs_context": True})
        for technique_id in item["techniques"]:
            if technique_id in technique_ids:
                upsert_relationship(db, entity.id, technique_ids[technique_id], "uses", confidence=85, source=origin)
                links += 1
        for software_id in item["software"]:
            if software_id in software_ids:
                upsert_relationship(db, entity.id, software_ids[software_id], "uses", confidence=85, source=origin)
                links += 1
    db.flush()
    stats = {"techniques": len(technique_ids), "software": len(software_ids), "groups": len(data["groups"]), "relationships": links, "version": data["version"]}
    log.info("ATT&CK loaded: %s", stats)
    return stats


def merge_entities(db: Session, keep: Entity, drop: Entity) -> list:
    """Fold ``drop`` into ``keep``. Returns the ids of findings whose index entry must be refreshed."""
    if keep.id == drop.id or keep.type != drop.type:
        raise ValueError("entities must be different and of the same type")
    affected = list(db.scalars(select(DocumentEntity.document_id).where(DocumentEntity.entity_id == drop.id)))
    already = set(db.scalars(select(DocumentEntity.document_id).where(DocumentEntity.entity_id == keep.id)))
    db.execute(delete(DocumentEntity).where(DocumentEntity.entity_id == drop.id, DocumentEntity.document_id.in_(already)))
    db.execute(update(DocumentEntity).where(DocumentEntity.entity_id == drop.id).values(entity_id=keep.id))

    for rel in db.scalars(select(Relationship).where((Relationship.src_id == drop.id) | (Relationship.dst_id == drop.id))):
        src = keep.id if rel.src_id == drop.id else rel.src_id
        dst = keep.id if rel.dst_id == drop.id else rel.dst_id
        if src != dst:
            upsert_relationship(db, src, dst, rel.kind, confidence=rel.confidence, source=rel.source, when=rel.first_seen_at)
    db.execute(delete(Relationship).where((Relationship.src_id == drop.id) | (Relationship.dst_id == drop.id)))
    for model in (CaseItem, Note):
        db.execute(update(model).where(model.object_type == "entity", model.object_id == str(drop.id)).values(object_id=str(keep.id)))

    known = {slugify(a) for a in (keep.name, *(keep.aliases or []))}
    keep.aliases = [*(keep.aliases or []), *[a for a in (drop.name, *(drop.aliases or [])) if slugify(a) not in known]]
    keep.description = keep.description or drop.description
    keep.first_seen_at = min(filter(None, (keep.first_seen_at, drop.first_seen_at)), default=None)
    keep.last_seen_at = max(filter(None, (keep.last_seen_at, drop.last_seen_at)), default=None)
    keep.meta = {**(drop.meta or {}), **(keep.meta or {})}
    db.delete(drop)
    db.flush()
    keep.doc_count = db.scalar(select(func.count()).select_from(DocumentEntity).where(DocumentEntity.entity_id == keep.id)) or 0
    return affected
