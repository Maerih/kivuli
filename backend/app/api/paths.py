"""Path finding: how one actor, organisation, malware family or indicator connects to another.

The graph is the one the Relationships page draws. Its nodes are entities
(entity:<id>) and indicators (ioc:<id>). Two nodes are linked when they appear
in the same finding, or when a stated relationship joins two entities. The
answer is the shortest chains between two nodes, each hop shown with the
finding (or the statement) behind it.

Hubs would make every pair look connected: a technique every ransomware group
uses, a country, a CDN domain. So ATT&CK techniques and incidents are never
stepping stones, nor is any entity or indicator seen in more than HUB findings,
an indicator marked benign, or a common platform domain. They can still be a
path's start or end.

The search runs from both ends at once (bidirectional breadth-first), at most
MAX_HOPS hops, and stops after EXPANSION_BUDGET node expansions so it always
answers quickly.
"""
from collections import defaultdict
from typing import Callable

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.common import iso
from app.api.timeline import COMMON_PLATFORMS
from app.db import get_db
from app.extract.iocs import defang, registered_domain
from app.models import Document, DocumentEntity, DocumentIoc, Entity, Ioc, Relationship, User
from app.security import viewer

router = APIRouter(tags=["intel"])

MAX_HOPS = 4
HUB = 150
DOCS_PER_NODE = 300
EXPANSION_BUDGET = 400
NOT_STEPPING_STONES = ("technique", "incident")

Neighbours = Callable[[str], dict[str, tuple]]


def find_paths(start: str, goal: str, neighbours: Neighbours, max_hops: int = MAX_HOPS, limit: int = 3,
               budget: int = EXPANSION_BUDGET) -> tuple[list[list[str]], int]:
    """Up to ``limit`` shortest node paths from start to goal, and how many nodes were expanded. Pure.

    ``neighbours(node)`` returns {neighbour: evidence}. Each side keeps every
    parent found at the level a node was first reached, so equally short paths
    through different nodes are all found.
    """
    if start == goal:
        return [[start]], 0
    parents = ({start: []}, {goal: []})  # node -> parents, per side
    depth = ({start: 0}, {goal: 0})
    frontier = ([start], [goal])
    expanded = 0
    meet: set[str] = set()
    while frontier[0] and frontier[1] and not meet:
        if max(depth[0].values()) + max(depth[1].values()) >= max_hops:
            break
        side = 0 if len(frontier[0]) <= len(frontier[1]) else 1
        level = max(depth[side][n] for n in frontier[side]) + 1
        next_frontier: list[str] = []
        for node in frontier[side]:
            if expanded >= budget:
                break
            expanded += 1
            for nb in neighbours(node):
                if nb not in depth[side]:
                    depth[side][nb] = level
                    parents[side][nb] = [node]
                    next_frontier.append(nb)
                elif depth[side][nb] == level:
                    parents[side][nb].append(node)
                if nb in depth[1 - side]:
                    meet.add(nb)
        frontier = (next_frontier, frontier[1]) if side == 0 else (frontier[0], next_frontier)
        if expanded >= budget:
            break
    if not meet:
        return [], expanded
    best = min(depth[0][m] + depth[1][m] for m in meet)

    def walk(side: int, node: str) -> list[list[str]]:
        if not parents[side][node]:
            return [[node]]
        return [[node, *rest] for p in parents[side][node][:limit] for rest in walk(side, p)][:limit * 4]

    paths: list[list[str]] = []
    for m in sorted(meet):
        if depth[0][m] + depth[1][m] != best:
            continue
        for left in walk(0, m):
            for right in walk(1, m):
                path = [*reversed(left), *right[1:]]
                if path not in paths:
                    paths.append(path)
                if len(paths) >= limit:
                    return paths, expanded
    return paths, expanded


class GraphIndex:
    """Neighbours of a node in the database, with the evidence for each link."""

    def __init__(self, db: Session, endpoints: set[str]):
        self.db, self.endpoints = db, endpoints
        self.evidence: dict[tuple[str, str], tuple] = {}

    def _stepping_stone(self, kind: str, row) -> bool:
        if kind == "entity":
            return row.type not in NOT_STEPPING_STONES and row.doc_count <= HUB
        return not row.benign and row.doc_count <= HUB and not (row.type == "domain" and registered_domain(row.value) in COMMON_PLATFORMS)

    def _passable(self, node: str) -> bool:
        """Endpoints are always allowed; anything else only if it is not a hub."""
        if node in self.endpoints:
            return True
        kind, _, ref = node.partition(":")
        row = self.db.get(Entity if kind == "entity" else Ioc, int(ref))
        return row is not None and self._stepping_stone(kind, row)

    def __call__(self, node: str) -> dict[str, tuple]:
        if not self._passable(node):
            return {}
        kind, _, ref = node.partition(":")
        link = DocumentEntity if kind == "entity" else DocumentIoc
        column = link.entity_id if kind == "entity" else link.ioc_id
        docs = select(link.document_id).join(Document, Document.id == link.document_id).where(column == int(ref), Document.duplicate_of.is_(None)) \
            .order_by(Document.first_seen_at.desc()).limit(DOCS_PER_NODE).scalar_subquery()
        out: dict[str, tuple] = {}
        for eid, etype, count, doc_id in self.db.execute(
                select(Entity.id, Entity.type, Entity.doc_count, DocumentEntity.document_id).join(DocumentEntity, DocumentEntity.entity_id == Entity.id)
                .where(DocumentEntity.document_id.in_(docs))):
            nb = f"entity:{eid}"
            if nb != node and (nb in self.endpoints or (etype not in NOT_STEPPING_STONES and count <= HUB)):
                out.setdefault(nb, ("finding", doc_id))
        for iid, itype, value, count, benign, doc_id in self.db.execute(
                select(Ioc.id, Ioc.type, Ioc.value, Ioc.doc_count, Ioc.benign, DocumentIoc.document_id).join(DocumentIoc, DocumentIoc.ioc_id == Ioc.id)
                .where(DocumentIoc.document_id.in_(docs))):
            nb = f"ioc:{iid}"
            if nb != node and (nb in self.endpoints or (not benign and count <= HUB and not (itype == "domain" and registered_domain(value) in COMMON_PLATFORMS))):
                out.setdefault(nb, ("finding", doc_id))
        if kind == "entity":
            # Stated relationships, under the same rule: "uses T1486" joins every ransomware group, so a
            # technique or a very common entity is never a stepping stone here either.
            for src, dst, rkind, source in self.db.execute(
                    select(Relationship.src_id, Relationship.dst_id, Relationship.kind, Relationship.source)
                    .where((Relationship.src_id == int(ref)) | (Relationship.dst_id == int(ref)))):
                other = dst if src == int(ref) else src
                nb = f"entity:{other}"
                if nb in self.endpoints or self._passable(nb):
                    out.setdefault(nb, ("relationship", rkind.replace("_", " "), source))
        for nb, ev in out.items():
            self.evidence.setdefault((node, nb), ev)
            self.evidence.setdefault((nb, node), ev)
        return out


def _describe(db: Session, node: str) -> dict:
    kind, _, ref = node.partition(":")
    if kind == "entity":
        e = db.get(Entity, int(ref))
        return {"id": node, "kind": "entity", "type": e.type, "label": e.name, "findings": e.doc_count, "href": f"/entities/{e.id}"}
    i = db.get(Ioc, int(ref))
    return {"id": node, "kind": "ioc", "type": i.type, "label": defang(i.value), "findings": i.doc_count, "href": f"/indicators/{i.id}"}


def _node(db: Session, value: str) -> str:
    kind, _, ref = value.partition(":")
    if kind not in ("entity", "ioc") or not ref.isdigit() or db.get(Entity if kind == "entity" else Ioc, int(ref)) is None:
        raise HTTPException(400, f"Not a known entity or indicator: {value} (use entity:<id> or ioc:<id>)")
    return value


@router.get("/graph/path")
def path(src: str = Query(..., alias="from", max_length=40), dst: str = Query(..., alias="to", max_length=40),
         db: Session = Depends(get_db), user: User = Depends(viewer)):
    """The shortest chains linking two entities or indicators, each hop with the finding or statement behind it."""
    start, goal = _node(db, src), _node(db, dst)
    index = GraphIndex(db, {start, goal})
    found, expanded = find_paths(start, goal, index)
    docs: dict = {}
    out = []
    for nodes in found:
        hops = []
        for a, b in zip(nodes, nodes[1:]):
            ev = index.evidence.get((a, b)) or index.evidence.get((b, a))
            if ev and ev[0] == "finding":
                doc = docs.get(ev[1]) or db.get(Document, ev[1])
                docs[ev[1]] = doc
                hops.append({"via": "finding", "id": str(doc.id), "title": doc.title[:200], "date": iso(doc.published_at or doc.first_seen_at),
                             "source": doc.source.name})
            elif ev:
                hops.append({"via": "relationship", "label": ev[1], "source": ev[2]})
            else:
                hops.append({"via": "unknown"})
        out.append({"length": len(nodes) - 1, "nodes": [_describe(db, n) for n in nodes], "hops": hops})
    return {"from": _describe(db, start), "to": _describe(db, goal), "paths": out, "expanded": expanded, "max_hops": MAX_HOPS,
            "note": "" if out else f"No connection within {MAX_HOPS} hops through specific nodes (common techniques, platforms and very common entities are not used as stepping stones)."}
