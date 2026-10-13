#!/usr/bin/env python3
"""Build backend/app/data/attack.json from the official MITRE ATT&CK STIX bundle.

    python3 tools/build_attack_catalog.py path/to/enterprise-attack.json

The bundle (about 50 MB) is published at
https://github.com/mitre-attack/attack-stix-data. The platform ships only this
compact derivative: technique names and tactics, groups with their aliases, and
software, plus which groups use what. ATT&CK is (c) The MITRE Corporation and is
reproduced under the ATT&CK terms of use (https://attack.mitre.org/resources/terms-of-use/).
"""
import json
import os
import re
import sys

src = sys.argv[1]
out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend", "app", "data", "attack.json")
bundle = json.load(open(src))
objects = [o for o in bundle["objects"] if not o.get("revoked") and not o.get("x_mitre_deprecated")]
by_id = {o["id"]: o for o in objects}


def attack_id(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def first_sentence(text: str, limit: int = 320) -> str:
    text = re.sub(r"\(Citation:[^)]*\)", "", text or "")
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    text = " ".join(text.replace("<code>", "").replace("</code>", "").split())
    cut = text[:limit]
    return cut if len(text) <= limit else cut.rsplit(". ", 1)[0].rstrip(".") + "."


tactics = sorted(({"id": attack_id(o), "shortname": o["x_mitre_shortname"], "name": o["name"]} for o in objects if o["type"] == "x-mitre-tactic"), key=lambda t: t["id"])
order = ["reconnaissance", "resource-development", "initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion",
         "stealth", "defense-impairment", "credential-access", "discovery", "lateral-movement", "collection", "command-and-control",
         "exfiltration", "impact"]
tactics.sort(key=lambda t: order.index(t["shortname"]) if t["shortname"] in order else 99)

techniques = []
for o in objects:
    if o["type"] != "attack-pattern":
        continue
    tid = attack_id(o)
    if not tid.startswith("T"):
        continue
    techniques.append({"id": tid, "name": o["name"], "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"],
                       "description": first_sentence(o.get("description", ""), 240)})
techniques.sort(key=lambda t: t["id"])

uses_technique: dict[str, set] = {}
uses_software: dict[str, set] = {}
for o in objects:
    if o["type"] != "relationship" or o.get("relationship_type") != "uses":
        continue
    source, target = by_id.get(o["source_ref"]), by_id.get(o["target_ref"])
    if not source or not target or source["type"] != "intrusion-set":
        continue
    if target["type"] == "attack-pattern":
        uses_technique.setdefault(source["id"], set()).add(attack_id(target))
    elif target["type"] in ("malware", "tool"):
        uses_software.setdefault(source["id"], set()).add(attack_id(target))

groups = []
for o in objects:
    if o["type"] != "intrusion-set":
        continue
    groups.append({"id": attack_id(o), "name": o["name"], "aliases": [a for a in o.get("aliases", []) if a != o["name"]],
                   "description": first_sentence(o.get("description", "")),
                   "techniques": sorted(t for t in uses_technique.get(o["id"], ()) if t), "software": sorted(s for s in uses_software.get(o["id"], ()) if s)})
groups.sort(key=lambda g: g["id"])

software = []
for o in objects:
    if o["type"] not in ("malware", "tool"):
        continue
    software.append({"id": attack_id(o), "name": o["name"], "kind": o["type"],
                     "aliases": [a for a in o.get("x_mitre_aliases", []) if a != o["name"]], "description": first_sentence(o.get("description", ""), 200)})
software.sort(key=lambda s: s["id"])

collection = next((o for o in bundle["objects"] if o["type"] == "x-mitre-collection"), {})
catalog = {"source": "MITRE ATT&CK Enterprise", "version": collection.get("x_mitre_version", ""), "modified": collection.get("modified", "")[:10],
           "license": "(c) The MITRE Corporation. Reproduced and distributed with the permission of The MITRE Corporation.",
           "tactics": tactics, "techniques": techniques, "groups": groups, "software": software}
json.dump(catalog, open(out, "w"), separators=(",", ":"), ensure_ascii=False)
print(f"wrote {out}: {len(tactics)} tactics, {len(techniques)} techniques, {len(groups)} groups, {len(software)} software, {os.path.getsize(out) / 1024:.0f} KB")
