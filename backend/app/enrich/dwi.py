"""Dark Web Informer: its threat feed, ransomware victims and IOC feed, as STIX 2.1 bundles.

Runs in the enricher, which holds the API key. Dark Web Informer authenticates
each request with ``X-API-Key`` and a single-use ``X-Nonce`` (Unix time and a
random suffix, valid for two minutes), and allows 5 requests a minute, 2
exports a minute and 150 a day. Kivuli asks for three exports per sync and
syncs every six hours, well inside that.

The prebuilt bundles carry reports (the alerts), the indicators, victim
identities, intrusion sets and malware they refer to, and the relationships
between them. ``split_bundle`` turns them into what Kivuli stores: one finding
per alert or victim claim, and the indicator list for the feed. It is pure, so
the mapping is tested without a key.
"""
import ipaddress
import secrets
import time
from datetime import datetime

from app.config import get_settings
from app.enrich import keys
from app.enrich.http import EnrichError, api_request
from app.extract.iocs import detect_indicator
from app.intel.stix import parse_pattern

EXPORTS = {"feed": "/api/stix/export_feed.json", "ransomware": "/api/stix/export_ransomware.json", "iocs": "/api/stix/export_iocs.json"}
LABELS = {"feed": "threat feed", "ransomware": "ransomware victims", "iocs": "IOC feed"}
HOST = "api.darkwebinformer.com"

_ACTOR_TYPES = ("intrusion-set", "threat-actor")
_SCO = {"domain-name": "domain", "ipv4-addr": "ip", "ipv6-addr": "ip", "url": "url", "email-addr": "email"}


def nonce() -> str:
    """``<10-digit epoch>:<random>``, new for every request."""
    return f"{int(time.time())}:{secrets.token_urlsafe(8)}"


def _get(path: str, params: dict | None = None, max_bytes: int = 80_000_000):
    # Imported here: providers imports this module to register the provider.
    from app.enrich.providers import _checked

    api_key = keys.get("dwi")
    if not api_key:
        raise EnrichError("No Dark Web Informer API key is set. Add it under Integrations.")
    base = get_settings().dwi_base_url.rstrip("/")
    status, body = _checked("Dark Web Informer", api_request(f"{base}{path}", headers={"X-API-Key": api_key, "X-Nonce": nonce()},
                                                              params=params, timeout=300, max_bytes=max_bytes))
    if status != 200 or not isinstance(body, dict):
        raise EnrichError(f"Dark Web Informer returned HTTP {status}")
    return body


def fetch_bundle(kind: str) -> dict:
    return _get(EXPORTS[kind])


def probe() -> dict:
    from app.enrich.providers import _probe

    body = _get("/api/stix.json", {"source": "all", "limit": "1"}, max_bytes=2_000_000)
    count = len(body.get("objects") or [])
    return _probe(True, f"Answered: the key works ({count} STIX object{'s' if count != 1 else ''} in a one-item preview)")


# ── mapping ──────────────────────────────────────────────────────────────────

def _when(obj: dict) -> str:
    return str(obj.get("modified") or obj.get("created") or obj.get("published") or "")


def changed_since(objects: list[dict], cursor: str) -> list[dict]:
    """Objects modified after the cursor, plus everything they refer to, so each alert arrives whole."""
    if not cursor:
        return objects
    by_id = {o.get("id"): o for o in objects}
    keep = {o["id"] for o in objects if o.get("id") and _when(o) > cursor and o.get("type") != "identity"}
    for o in objects:
        if o.get("id") in keep:
            keep.update(r for r in o.get("object_refs") or [] if r in by_id)
            keep.update(r for k in ("source_ref", "target_ref") if (r := o.get(k)) in by_id)
    # And whatever is tied to a kept object by a relationship (an indicator that "indicates" an alert).
    for o in objects:
        if o.get("type") == "relationship" and (o.get("source_ref") in keep or o.get("target_ref") in keep):
            keep.update(r for r in (o.get("id"), o.get("source_ref"), o.get("target_ref")) if r in by_id)
    return [o for o in objects if o.get("id") in keep]


def cursor_of(objects: list[dict]) -> str:
    return max((_when(o) for o in objects), default="")


# What a STIX type may turn into once Kivuli has classified the value: a domain can be an onion service.
_COMPATIBLE = {"domain": ("domain", "onion"), "ip": ("ip",), "url": ("url",), "email": ("email",), "hash": ("hash",)}


def _normalise(kind: str, value: str) -> tuple[str, str] | None:
    """Classify a value the way Kivuli does everywhere else, as the IOC-feed parser does.

    A leak site's .onion becomes an onion, not a domain; hashes Kivuli does not
    track (SHA-512 and the like) and private or reserved IP addresses are dropped.
    """
    found = detect_indicator(str(value).strip())
    if not found or found[0] not in _COMPATIBLE.get(kind, ()):
        return None
    if found[0] == "ip" and not ipaddress.ip_address(found[1]).is_global:
        return None
    return found


def _indicators(obj: dict) -> list[tuple[str, str]]:
    raw: list[tuple[str, str]] = []
    if obj.get("type") == "indicator":
        raw = parse_pattern(obj.get("pattern", ""))
    elif obj.get("type") in _SCO and obj.get("value"):
        raw = [(_SCO[obj["type"]], str(obj["value"]))]
    elif obj.get("type") == "file":
        raw = [("hash", str(h)) for h in (obj.get("hashes") or {}).values() if h]
    return [n for kind, value in raw if (n := _normalise(kind, value))]


def _date(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None
    except ValueError:
        return None


def split_bundle(objects: list[dict], kind: str) -> tuple[list[dict], list[tuple[str, str]]]:
    """Alerts to store as findings, and every indicator the bundle lists. Pure."""
    by_id = {o.get("id"): o for o in objects if isinstance(o, dict) and o.get("id")}
    neighbours: dict[str, set[str]] = {}
    for o in by_id.values():
        if o.get("type") == "relationship" and o.get("source_ref") and o.get("target_ref"):
            neighbours.setdefault(o["source_ref"], set()).add(o["target_ref"])
            neighbours.setdefault(o["target_ref"], set()).add(o["source_ref"])
    authors = {o.get("created_by_ref") for o in by_id.values()} - {None}

    def related(oid: str) -> list[dict]:
        ids = set(by_id[oid].get("object_refs") or []) | neighbours.get(oid, set())
        return [by_id[i] for i in ids if i in by_id and i not in authors]

    def describe(head: dict, around: list[dict]) -> dict:
        actors = sorted({str(o["name"]) for o in around if o.get("type") in _ACTOR_TYPES and o.get("name")})
        if head.get("type") in _ACTOR_TYPES:
            actors = [str(head["name"])]
        victims = sorted({str(o["name"]) for o in around if o.get("type") == "identity" and o.get("name")})
        if head.get("type") == "identity" and head.get("name"):
            victims = [str(head["name"]), *[v for v in victims if v != head["name"]]]  # a claim built around its victim
        malware = sorted({str(o["name"]) for o in around if o.get("type") in ("malware", "tool") and o.get("name")})
        countries = sorted({str(o.get("country", "")).upper() for o in around if o.get("type") == "location" and len(str(o.get("country", ""))) == 2})
        iocs = sorted({i for o in (head, *around) for i in _indicators(o)})
        ref_url = next((r.get("url") for r in head.get("external_references") or [] if r.get("url")), "")
        return {"id": head["id"], "title": str(head.get("name") or "")[:400], "description": str(head.get("description") or "")[:20000],
                "published": head.get("published") or head.get("created") or "", "url": ref_url, "labels": [str(x) for x in head.get("labels") or []][:20],
                "actor": actors[0] if actors else None, "actors": actors[:10], "victim": victims[0] if victims else None, "victims": victims[:10],
                "malware": malware[:10], "countries": countries[:10], "iocs": iocs[:2000]}

    alerts = [describe(o, related(o["id"])) for o in by_id.values() if o.get("type") in ("report", "note") and (o.get("name") or o.get("description"))]
    covered = {v for a in alerts for v in a["victims"]}
    # Victim claims that are not wrapped in a report: an intrusion set "targets" an identity.
    for rel in by_id.values():
        if rel.get("type") == "relationship" and rel.get("relationship_type") == "targets":
            src, dst = by_id.get(rel.get("source_ref")), by_id.get(rel.get("target_ref"))
            if src and dst and src.get("type") in _ACTOR_TYPES and dst.get("type") == "identity" and dst.get("name") and dst["name"] not in covered:
                claim = describe(dst, [src, *related(dst["id"])])
                claim.update(id=rel["id"], title=f"{dst['name']} listed by {src.get('name', 'an actor')}",
                             published=rel.get("start_time") or rel.get("created") or dst.get("created") or "", actor=src.get("name"))
                alerts.append(claim)
                covered.add(dst["name"])
    iocs = sorted({i for o in by_id.values() for i in _indicators(o)})
    return alerts, iocs


def alert_text(alert: dict, kind: str) -> str:
    """The searchable body of a finding made from an alert."""
    lines = [alert["description"], ""]
    if alert["actors"]:
        lines.append(f"Threat actor: {', '.join(alert['actors'])}")
    if alert["victims"]:
        lines.append(f"Victim: {', '.join(alert['victims'])}")
    if alert["malware"]:
        lines.append(f"Malware: {', '.join(alert['malware'])}")
    if alert["labels"]:
        lines.append(f"Labels: {', '.join(alert['labels'])}")
    if alert["iocs"]:
        lines += ["", "Indicators:", *[f"{t}: {v}" for t, v in alert["iocs"][:500]]]
    lines += ["", f"Reported by Dark Web Informer ({LABELS.get(kind, kind)})."]
    return "\n".join(lines).strip()


def published(alert: dict) -> datetime | None:
    return _date(str(alert.get("published") or ""))
