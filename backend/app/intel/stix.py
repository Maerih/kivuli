"""STIX 2.1 export and import.

Identifiers are deterministic (UUIDv5), so re-exporting the same indicator or
actor always yields the same STIX id and consumers can deduplicate.
"""
import re
import uuid
from datetime import datetime, timezone

from app.intel import attack

NAMESPACE = uuid.UUID("7c9f3c1e-2d0a-4f6b-9a56-5d3e6f0b8a11")
ENTITY_TYPES = {"actor": "threat-actor", "malware": "malware", "organization": "identity", "campaign": "campaign", "technique": "attack-pattern"}
RELATIONSHIP_TYPES = {"uses": "uses", "targets": "targets", "attributed_to": "attributed-to", "exploits": "exploits", "delivers": "delivers",
                      "related_to": "related-to"}
_HASH = {32: "MD5", 40: "'SHA-1'", 64: "'SHA-256'"}
_PATTERN = re.compile(r"\[\s*([a-z0-9-]+):([\w.'-]+)\s*=\s*'((?:[^'\\]|\\.)*)'\s*\]", re.I)


def _stamp(value: datetime | None = None) -> str:
    return (value or datetime.now(timezone.utc)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def stix_id(stix_type: str, *parts: str) -> str:
    return f"{stix_type}--{uuid.uuid5(NAMESPACE, '|'.join(parts))}"


def pattern_for(kind: str, value: str) -> str | None:
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    if kind in ("domain", "onion"):
        return f"[domain-name:value = '{escaped}']"
    if kind == "ip":
        return f"[ipv4-addr:value = '{escaped}']"
    if kind == "url":
        return f"[url:value = '{escaped}']"
    if kind == "email":
        return f"[email-addr:value = '{escaped}']"
    if kind == "hash" and len(value) in _HASH:
        return f"[file:hashes.{_HASH[len(value)]} = '{escaped}']"
    return None


def indicator(kind: str, value: str, first_seen: datetime | None = None, last_seen: datetime | None = None, labels: list[str] | None = None) -> dict | None:
    pattern = pattern_for(kind, value)
    if not pattern:
        return None
    created = _stamp(first_seen)
    return {"type": "indicator", "spec_version": "2.1", "id": stix_id("indicator", kind, value), "created": created, "modified": _stamp(last_seen or first_seen),
            "name": f"{kind}: {value}"[:250], "pattern": pattern, "pattern_type": "stix", "valid_from": created,
            "indicator_types": ["malicious-activity"], **({"labels": labels} if labels else {})}


def vulnerability(cve: str, description: str = "") -> dict:
    now = _stamp()
    return {"type": "vulnerability", "spec_version": "2.1", "id": stix_id("vulnerability", cve), "created": now, "modified": now, "name": cve,
            **({"description": description[:2000]} if description else {}),
            "external_references": [{"source_name": "cve", "external_id": cve}]}


def entity_object(kind: str, name: str, aliases: list[str] | None = None, description: str = "", meta: dict | None = None,
                  first_seen: datetime | None = None) -> dict | None:
    stix_type = ENTITY_TYPES.get(kind)
    if not stix_type:
        return None
    created = _stamp(first_seen)
    obj: dict = {"type": stix_type, "spec_version": "2.1", "id": stix_id(stix_type, kind, name), "created": created, "modified": created, "name": name}
    if description:
        obj["description"] = description[:2000]
    if aliases and stix_type in ("threat-actor", "campaign", "malware"):
        obj["aliases"] = aliases[:30]
    if stix_type == "malware":
        obj["is_family"] = True
    if stix_type == "identity":
        obj["identity_class"] = "organization"
    if stix_type == "attack-pattern":
        technique = (meta or {}).get("attack_id", "")
        if technique:
            obj["name"] = attack.techniques().get(technique, {}).get("name", name)
            obj["external_references"] = [{"source_name": "mitre-attack", "external_id": technique,
                                           "url": f"https://attack.mitre.org/techniques/{technique.replace('.', '/')}/"}]
            obj["kill_chain_phases"] = [{"kill_chain_name": "mitre-attack", "phase_name": t} for t in (meta or {}).get("tactics", [])]
    return obj


def relationship(kind: str, source_ref: str, target_ref: str, confidence: int | None = None, description: str = "",
                 first_seen: datetime | None = None, last_seen: datetime | None = None) -> dict:
    stix_kind = RELATIONSHIP_TYPES.get(kind, "related-to")
    obj = {"type": "relationship", "spec_version": "2.1", "id": stix_id("relationship", stix_kind, source_ref, target_ref), "created": _stamp(first_seen),
           "modified": _stamp(last_seen or first_seen), "relationship_type": stix_kind, "source_ref": source_ref, "target_ref": target_ref}
    if confidence is not None:
        obj["confidence"] = confidence
    if description:
        obj["description"] = description
    return obj


def bundle(objects: list[dict]) -> dict:
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def case_bundle(case: dict) -> dict:
    """A case as a STIX report referencing its indicators, vulnerabilities and entities."""
    objects: list[dict] = []
    for ioc in case.get("iocs", []):
        obj = vulnerability(ioc["value"]) if ioc["type"] == "cve" else indicator(ioc["type"], ioc["value"])
        if obj:
            objects.append(obj)
    for entity in case.get("entities", []):
        obj = entity_object(entity["type"], entity["name"], entity.get("aliases"), meta=entity.get("meta"))
        if obj:
            objects.append(obj)
    now = _stamp()
    report = {"type": "report", "spec_version": "2.1", "id": stix_id("report", "case", str(case["id"])), "created": now, "modified": now,
              "name": case["title"], "description": case.get("description", ""), "published": now, "report_types": ["threat-report"],
              "object_refs": [o["id"] for o in objects] or [stix_id("report", "case", str(case["id"]))]}
    return bundle([report, *objects])


def parse_pattern(pattern: str) -> list[tuple[str, str]]:
    """Indicators in a simple STIX comparison pattern. Unsupported patterns yield nothing."""
    out = []
    for object_type, path, value in _PATTERN.findall(pattern or ""):
        value = value.replace("\\'", "'").replace("\\\\", "\\")
        object_type, path = object_type.lower(), path.lower()
        if object_type == "domain-name":
            out.append(("domain", value.lower()))
        elif object_type == "ipv4-addr":
            out.append(("ip", value))
        elif object_type == "url":
            out.append(("url", value))
        elif object_type == "email-addr":
            out.append(("email", value.lower()))
        elif object_type == "file" and "hashes" in path:
            out.append(("hash", value.lower()))
    return out


def summarise_import(data: dict) -> dict:
    """Split a bundle into what the platform can absorb. Pure: no database access."""
    objects = data.get("objects") if isinstance(data, dict) else None
    if not isinstance(objects, list):
        raise ValueError("not a STIX bundle: no objects array")
    by_id = {o.get("id"): o for o in objects if isinstance(o, dict)}
    entities, indicators, cves, relationships = [], [], [], []
    kinds = {"threat-actor": "actor", "intrusion-set": "actor", "malware": "malware", "tool": "malware", "campaign": "campaign", "identity": "organization"}
    for obj in by_id.values():
        stix_type = obj.get("type")
        if stix_type in kinds and obj.get("name"):
            if stix_type == "identity" and obj.get("identity_class") not in (None, "organization"):
                continue
            entities.append({"ref": obj["id"], "kind": kinds[stix_type], "name": str(obj["name"])[:300], "aliases": [str(a)[:300] for a in obj.get("aliases") or obj.get("x_mitre_aliases") or []][:30],
                             "description": str(obj.get("description", ""))[:4000]})
        elif stix_type == "attack-pattern":
            technique = next((r.get("external_id") for r in obj.get("external_references") or [] if r.get("source_name") == "mitre-attack"), None)
            if technique:
                entities.append({"ref": obj["id"], "kind": "technique", "name": technique, "aliases": [], "description": ""})
        elif stix_type == "indicator":
            indicators.extend(parse_pattern(obj.get("pattern", "")))
        elif stix_type == "vulnerability":
            cve = next((r.get("external_id") for r in obj.get("external_references") or [] if r.get("source_name") == "cve"), obj.get("name", ""))
            if re.fullmatch(r"CVE-\d{4}-\d{4,7}", str(cve), re.I):
                cves.append(str(cve).upper())
        elif stix_type == "relationship":
            relationships.append((obj.get("source_ref"), str(obj.get("relationship_type", "related-to")).replace("-", "_"), obj.get("target_ref")))
    title = next((o.get("name") for o in by_id.values() if o.get("type") == "report" and o.get("name")), "")
    return {"title": str(title)[:200], "entities": entities, "indicators": list(dict.fromkeys(indicators)), "cves": list(dict.fromkeys(cves)),
            "relationships": relationships}
