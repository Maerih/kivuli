"""Dark Web Informer: authentication nonce and the STIX bundle mapping."""
import re

from app.enrich import dwi

AUTHOR = {"type": "identity", "id": "identity--dwi", "name": "Dark Web Informer", "identity_class": "organization"}
BUNDLE = [
    AUTHOR,
    {"type": "report", "id": "report--1", "name": "Access to a Kenyan bank's VPN offered for sale", "created_by_ref": "identity--dwi",
     "description": "A forum user offers VPN access.", "published": "2026-10-29T10:00:00Z", "modified": "2026-10-29T10:00:00Z",
     "labels": ["initial-access"], "object_refs": ["identity--victim1", "intrusion-set--seller", "indicator--1", "location--ke"],
     "external_references": [{"source_name": "dwi", "url": "https://darkwebinformer.com/alert-1"}]},
    {"type": "identity", "id": "identity--victim1", "name": "Example Bank Kenya", "identity_class": "organization", "modified": "2026-10-29T10:00:00Z"},
    {"type": "intrusion-set", "id": "intrusion-set--seller", "name": "AccessBroker99", "modified": "2026-10-29T10:00:00Z"},
    {"type": "location", "id": "location--ke", "country": "ke", "modified": "2026-10-29T10:00:00Z"},
    {"type": "indicator", "id": "indicator--1", "pattern": "[domain-name:value = 'vpn.example-bank.co.ke']", "modified": "2026-10-29T10:00:00Z"},
    # A ransomware claim with no report around it: the group "targets" the victim.
    {"type": "intrusion-set", "id": "intrusion-set--qilin", "name": "Qilin", "modified": "2026-10-01T00:00:00Z"},
    {"type": "identity", "id": "identity--victim2", "name": "Acme Logistics", "identity_class": "organization", "modified": "2026-10-28T08:00:00Z"},
    {"type": "relationship", "id": "relationship--t1", "relationship_type": "targets", "source_ref": "intrusion-set--qilin",
     "target_ref": "identity--victim2", "created": "2026-10-28T08:00:00Z", "modified": "2026-10-28T08:00:00Z"},
    # IOC feed entries: an observable and an indicator.
    {"type": "ipv4-addr", "id": "ipv4-addr--1", "value": "203.0.113.50"},
    {"type": "indicator", "id": "indicator--2", "pattern": "[file:hashes.'SHA-256' = 'AB" + "c" * 62 + "']", "modified": "2026-09-01T00:00:00Z"},
]


def test_nonce_matches_the_documented_form():
    n1, n2 = dwi.nonce(), dwi.nonce()
    assert re.fullmatch(r"\d{10}:[A-Za-z0-9_-]{6,}", n1) and n1 != n2  # single use: never repeated


def test_alerts_and_claims_from_a_bundle():
    alerts, iocs = dwi.split_bundle(BUNDLE, "feed")
    by_title = {a["title"]: a for a in alerts}
    access = by_title["Access to a Kenyan bank's VPN offered for sale"]
    assert access["actor"] == "AccessBroker99" and access["victim"] == "Example Bank Kenya"
    assert access["countries"] == ["KE"] and access["url"] == "https://darkwebinformer.com/alert-1"
    assert ("domain", "vpn.example-bank.co.ke") in access["iocs"]
    assert "Dark Web Informer" not in access["victims"]  # the author identity is not a victim
    claim = by_title["Acme Logistics listed by Qilin"]
    assert claim["actor"] == "Qilin" and claim["victim"] == "Acme Logistics" and claim["published"].startswith("2026-10-28")
    assert ("ip", "203.0.113.50") in iocs and ("hash", "ab" + "c" * 62) in iocs
    text = dwi.alert_text(access, "feed")
    assert "Threat actor: AccessBroker99" in text and "domain: vpn.example-bank.co.ke" in text


def test_incremental_sync_keeps_changed_alerts_whole():
    fresh = dwi.changed_since(BUNDLE, "2026-10-28T12:00:00Z")
    ids = {o["id"] for o in fresh}
    assert "report--1" in ids and {"identity--victim1", "intrusion-set--seller", "indicator--1"} <= ids  # with what it refers to
    assert "relationship--t1" not in ids and "indicator--2" not in ids  # older than the cursor
    assert dwi.cursor_of(BUNDLE) == "2026-10-29T10:00:00Z"
    assert dwi.changed_since(BUNDLE, "") == BUNDLE  # first sync: everything
