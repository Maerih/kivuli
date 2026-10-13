"""Case report rendering: HTML (printable), JSON, CSV of indicators and a STIX 2.1 bundle."""
import csv
import html
import io
import uuid
from datetime import datetime, timezone

from app.extract.classify import THREAT_TYPES
from app.extract.geo import country_name
from app.extract.iocs import defang

TLP_COLORS = {"clear": "#667085", "green": "#067647", "amber": "#b54708", "red": "#b42318"}
_STIX_NS = uuid.UUID("7c9f3c1e-2d0a-4f6b-9a56-5d3e6f0b8a11")


def _stix_pattern(kind: str, value: str) -> str | None:
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    if kind == "domain" or kind == "onion":
        return f"[domain-name:value = '{escaped}']"
    if kind == "ip":
        return f"[ipv4-addr:value = '{escaped}']"
    if kind == "url":
        return f"[url:value = '{escaped}']"
    if kind == "email":
        return f"[email-addr:value = '{escaped}']"
    if kind == "hash":
        algo = {32: "MD5", 40: "'SHA-1'", 64: "'SHA-256'"}.get(len(value))
        return f"[file:hashes.{algo} = '{escaped}']" if algo else None
    return None


def to_stix(case: dict) -> dict:
    """Minimal STIX 2.1 bundle: a report object referencing indicators and threat actors."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    objects, refs = [], []
    for ioc in case["iocs"]:
        pattern = _stix_pattern(ioc["type"], ioc["value"])
        if not pattern:
            continue
        stix_id = f"indicator--{uuid.uuid5(_STIX_NS, ioc['type'] + ioc['value'])}"
        objects.append({"type": "indicator", "spec_version": "2.1", "id": stix_id, "created": now, "modified": now,
                        "name": f"{ioc['type']}: {ioc['value']}", "pattern": pattern, "pattern_type": "stix", "valid_from": now,
                        "indicator_types": ["malicious-activity"]})
        refs.append(stix_id)
    for entity in case["entities"]:
        stix_type = {"actor": "threat-actor", "malware": "malware", "organization": "identity", "campaign": "campaign"}.get(entity["type"])
        if not stix_type:
            continue
        stix_id = f"{stix_type}--{uuid.uuid5(_STIX_NS, entity['type'] + entity['name'])}"
        obj = {"type": stix_type, "spec_version": "2.1", "id": stix_id, "created": now, "modified": now, "name": entity["name"]}
        if stix_type == "malware":
            obj["is_family"] = True
        if stix_type == "identity":
            obj["identity_class"] = "organization"
        objects.append(obj)
        refs.append(stix_id)
    report_id = f"report--{uuid.uuid5(_STIX_NS, 'case' + str(case['id']))}"
    objects.insert(0, {"type": "report", "spec_version": "2.1", "id": report_id, "created": now, "modified": now, "name": case["title"],
                       "description": case["description"], "published": now, "report_types": ["threat-report"],
                       "object_refs": refs or [report_id]})
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def to_csv(case: dict) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["type", "value", "defanged", "findings_in_case", "first_seen", "last_seen"])
    for ioc in case["iocs"]:
        value = ioc["value"]
        writer.writerow([ioc["type"], "'" + value if value[:1] in ("=", "+", "-", "@") else value, defang(value), ioc["shared"], ioc["first_seen"], ioc["last_seen"]])
    return buffer.getvalue()


def to_html(case: dict, app_name: str, generated_by: str) -> str:
    e = html.escape
    tlp = case["tlp"]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    def finding_block(f: dict) -> str:
        countries = ", ".join(country_name(c) for c in f["countries"]) or "n/a"
        note = f'<p class="note"><b>Analyst note:</b> {e(f["note"])}</p>' if f.get("note") else ""
        return f"""<section class="finding">
  <h3>{e(f['title'])}</h3>
  <p class="meta">{e(THREAT_TYPES.get(f['threat_type'], f['threat_type']))} &middot; severity {e(f['severity'])} &middot; risk {f['risk_score']}/100 &middot;
  confidence {f['confidence']}% &middot; {e(countries)}</p>
  <table><tr><th>Source</th><td>{e(f['source_name'])} ({'Tor hidden service' if f['network'] == 'onion' else 'surface web'})</td></tr>
  <tr><th>URL</th><td class="mono">{e(defang(f['url']))}</td></tr>
  <tr><th>First seen</th><td>{e((f['first_seen'] or '')[:19])} UTC</td></tr>
  <tr><th>Captures</th><td>{f['version_count']}</td></tr>
  <tr><th>Content SHA-256</th><td class="mono">{e(f['content_sha256'])}</td></tr></table>
  <p>{e(f['summary'])}</p>{note}
</section>"""

    findings = "".join(finding_block(f) for f in case["findings"]) or "<p>No findings attached.</p>"
    iocs = "".join(f"<tr><td>{e(i['type'])}</td><td class='mono'>{e(defang(i['value']))}</td><td>{i['shared']}</td></tr>" for i in case["iocs"][:500])
    entities = "".join(f"<tr><td>{e(x['type'])}</td><td>{e(x['name'])}</td><td>{x['shared']}</td></tr>" for x in case["entities"])
    notes = "".join(f"<div class='casenote'><div class='meta'>{e(n['user_name'])} &middot; {e((n['created_at'] or '')[:16])}</div><p>{e(n['body'])}</p></div>" for n in case["notes"])
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{e(case['title'])} - {e(app_name)} report</title>
<style>
  body {{ font: 14px/1.55 -apple-system, "Segoe UI", Roboto, Arial, sans-serif; color: #101828; max-width: 860px; margin: 32px auto; padding: 0 24px; }}
  h1 {{ font-size: 26px; margin: 8px 0 4px; }} h2 {{ font-size: 17px; margin: 32px 0 10px; border-bottom: 1px solid #e4e7ec; padding-bottom: 6px; }}
  h3 {{ font-size: 15px; margin: 0 0 4px; }}
  .tlp {{ display: inline-block; font-weight: 700; font-size: 12px; letter-spacing: .06em; color: #fff; background: {TLP_COLORS.get(tlp, '#667085')}; padding: 3px 10px; border-radius: 4px; }}
  .meta {{ color: #475467; font-size: 12.5px; margin: 0 0 8px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 8px 0; font-size: 13px; }}
  th, td {{ text-align: left; padding: 5px 10px 5px 0; vertical-align: top; border-bottom: 1px solid #f2f4f7; }}
  th {{ color: #475467; font-weight: 600; white-space: nowrap; width: 150px; }}
  .mono {{ font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12px; word-break: break-all; }}
  .finding {{ border: 1px solid #e4e7ec; border-radius: 8px; padding: 14px 16px; margin: 0 0 12px; break-inside: avoid; }}
  .note, .casenote {{ background: #f9fafb; border-radius: 6px; padding: 8px 12px; }}
  .casenote {{ margin-bottom: 8px; }} .casenote p {{ margin: 0; white-space: pre-wrap; }}
  footer {{ margin: 36px 0 12px; color: #667085; font-size: 12px; border-top: 1px solid #e4e7ec; padding-top: 10px; }}
  @media print {{ body {{ margin: 0; }} }}
</style></head><body>
<span class="tlp">TLP:{e(tlp.upper())}</span>
<h1>{e(case['title'])}</h1>
<p class="meta">Case #{case['id']} &middot; status {e(case['status'].replace('_', ' '))} &middot; priority {e(case['priority'])} &middot; generated {now} by {e(generated_by)}</p>
<h2>Summary</h2><p style="white-space:pre-wrap">{e(case['description'] or 'No summary written.')}</p>
<h2>Findings ({len(case['findings'])})</h2>{findings}
<h2>Indicators ({len(case['iocs'])})</h2>
<p class="meta">Indicators are defanged. Do not connect to them from a production network.</p>
<table><tr><th>Type</th><th style="width:auto">Value</th><th>Findings</th></tr>{iocs}</table>
<h2>Actors, organisations and malware</h2>
<table><tr><th>Type</th><th style="width:auto">Name</th><th>Findings</th></tr>{entities}</table>
<h2>Analyst notes</h2>{notes or '<p>No notes.</p>'}
<footer>Generated by {e(app_name)}. Content hashes are SHA-256 of the stored capture; the full evidence chain for each finding is available in the console.</footer>
</body></html>"""
