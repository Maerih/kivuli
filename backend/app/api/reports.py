"""Executive reporting: the threat landscape and the organisation's exposure for a period, in plain language."""
import html
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from opensearchpy.exceptions import OpenSearchException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.common import finding_summary
from app.config import get_settings
from app.db import get_db
from app.extract.classify import THREAT_TYPES
from app.extract.geo import country_name
from app.intel import quality
from app.models import Alert, Asset, Document, Exposure, User, Vulnerability, utcnow
from app.search import service
from app.security import audit, viewer

router = APIRouter(tags=["reports"])
settings = get_settings()


def executive_data(db: Session, days: int) -> dict:
    since = utcnow() - timedelta(days=days)
    try:
        overview = service.overview(days)
        rising = service.movers(days, "actors", 6)
        sectors = service.movers(days, "sectors", 6)
    except OpenSearchException:
        overview, rising, sectors = {"in_window": 0, "prev_window": 0, "types": [], "countries": [], "actors": [], "with_credentials": 0}, [], []
    focus = settings.focus_country_list
    focus_docs = db.scalars(select(Document).where(Document.duplicate_of.is_(None), Document.first_seen_at >= since, Document.countries.overlap(focus))
                            .order_by(Document.risk_score.desc(), Document.first_seen_at.desc()).limit(8)).unique().all() if focus else []
    top = db.scalars(select(Document).where(Document.duplicate_of.is_(None), Document.first_seen_at >= since)
                     .order_by(Document.risk_score.desc(), Document.first_seen_at.desc()).limit(6)).unique().all()
    count = lambda model, *where: db.scalar(select(func.count()).select_from(model).where(*where)) or 0  # noqa: E731
    return {
        "days": days, "generated": utcnow().isoformat(), "focus": [{"code": c, "name": country_name(c)} for c in focus],
        "findings": overview["in_window"], "previous": overview["prev_window"], "with_credentials": overview.get("with_credentials", 0),
        "types": [{"label": THREAT_TYPES.get(b["value"], b["value"]), "count": b["count"]} for b in overview.get("types", [])[:6]],
        "countries": [{"label": country_name(b["value"]), "count": b["count"]} for b in overview.get("countries", [])[:6]],
        "rising_actors": rising, "rising_sectors": sectors,
        "alerts": {"open": count(Alert, Alert.status == "open"), "raised": count(Alert, Alert.created_at >= since),
                   "compromise": count(Alert, Alert.created_at >= since, Alert.category == "compromise"),
                   "resolved": count(Alert, Alert.resolved_at >= since)},
        "exposure": {"open": count(Exposure, Exposure.status == "open"), "new": count(Exposure, Exposure.first_seen_at >= since),
                     "with_password": count(Exposure, Exposure.status == "open", Exposure.password_exposed.is_(True))},
        "attack_surface": {"hosts": count(Asset), "at_risk": count(Asset, Asset.risk >= 40)},
        "vulnerabilities": [{"cve": v.cve, "title": v.title or v.product, "priority": v.priority, "kev": v.kev, "exposed_assets": v.exposed_assets,
                             "why": [f["factor"] for f in (v.priority_factors or [])[:2]]}
                            for v in db.scalars(select(Vulnerability).where(Vulnerability.priority >= 40).order_by(Vulnerability.priority.desc()).limit(6))],
        "focus_findings": [finding_summary(d) for d in focus_docs], "top_findings": [finding_summary(d) for d in top],
        "quality": quality.quality_stats(db),
    }


def _render(d: dict, user_name: str) -> str:
    e = html.escape
    change = ""
    if d["previous"]:
        pct = round((d["findings"] - d["previous"]) / d["previous"] * 100)
        change = f" ({'up' if pct >= 0 else 'down'} {abs(pct)}% on the previous {d['days']} days)"
    focus_names = ", ".join(f["name"] for f in d["focus"]) or "your focus area"

    def rows(items, cells):
        return "".join("<tr>" + "".join(f"<td>{e(str(c(i)))}</td>" for c in cells) + "</tr>" for i in items) or '<tr><td colspan="9">None in this period.</td></tr>'

    def findings(items):
        return "".join(f"<li><b>{e(f['title'])}</b><br><span class='m'>{e(f['threat_label'])} &middot; {e(f['severity'])} &middot; risk {f['risk_score']}/100 "
                       f"&middot; {e(f['source_name'])} &middot; {e((f['first_seen'] or '')[:10])}</span></li>" for f in items) or "<li>None in this period.</li>"

    headline = []
    if d["alerts"]["compromise"]:
        headline.append(f"{d['alerts']['compromise']} alert{'s' if d['alerts']['compromise'] != 1 else ''} indicated a possible compromise of a monitored asset")
    if d["exposure"]["with_password"]:
        headline.append(f"{d['exposure']['with_password']} exposed account{'s' if d['exposure']['with_password'] != 1 else ''} with a password remain open")
    if d["attack_surface"]["at_risk"]:
        headline.append(f"{d['attack_surface']['at_risk']} internet-facing host{'s' if d['attack_surface']['at_risk'] != 1 else ''} need attention")
    if not headline:
        headline.append("no monitored asset was reported as compromised in this period")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{e(settings.app_name)} executive brief</title><style>
body{{font:14px/1.55 -apple-system,"Segoe UI",Roboto,Arial,sans-serif;color:#101828;max-width:880px;margin:32px auto;padding:0 24px}}
h1{{font-size:26px;margin:0 0 4px}}h2{{font-size:17px;margin:30px 0 10px;border-bottom:1px solid #e4e7ec;padding-bottom:6px}}
.m{{color:#475467;font-size:12.5px}}.k{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:18px 0}}
.k div{{border:1px solid #e4e7ec;border-radius:8px;padding:12px 14px}}.k b{{display:block;font-size:24px}}
table{{border-collapse:collapse;width:100%;font-size:13px}}td,th{{text-align:left;padding:6px 10px 6px 0;border-bottom:1px solid #f2f4f7;vertical-align:top}}
th{{color:#475467;font-weight:600}}ul{{padding-left:18px}}li{{margin-bottom:8px}}.two{{display:grid;grid-template-columns:1fr 1fr;gap:28px}}
footer{{margin:34px 0 12px;color:#667085;font-size:12px;border-top:1px solid #e4e7ec;padding-top:10px}}@media print{{body{{margin:0}}}}
</style></head><body>
<p class="m">{e(settings.app_name)} &middot; executive threat brief</p>
<h1>Threat and exposure summary, last {d['days']} days</h1>
<p class="m">Generated {e(d['generated'][:16].replace('T', ' '))} UTC by {e(user_name)} &middot; focus: {e(focus_names)}</p>
<h2>In brief</h2>
<p>The platform collected <b>{d['findings']:,}</b> findings{e(change)}. In that time {e('; '.join(headline))}.</p>
<div class="k"><div><b>{d['alerts']['raised']}</b>alerts raised<br><span class="m">{d['alerts']['open']} still open</span></div>
<div><b>{d['alerts']['compromise']}</b>possible compromises<br><span class="m">{d['alerts']['resolved']} alerts resolved</span></div>
<div><b>{d['exposure']['open']}</b>open identity exposures<br><span class="m">{d['exposure']['new']} new this period</span></div>
<div><b>{d['attack_surface']['at_risk']}</b>hosts at risk<br><span class="m">of {d['attack_surface']['hosts']} discovered</span></div></div>
<h2>What concerns {e(focus_names)}</h2><ul>{findings(d['focus_findings'])}</ul>
<h2>Vulnerabilities to act on first</h2>
<p class="m">Ranked by evidence of exploitation and by your own exposure, not by severity score alone.</p>
<table><tr><th>CVE</th><th>What</th><th>Priority</th><th>Why</th></tr>{rows(d['vulnerabilities'], [lambda v: v['cve'], lambda v: v['title'][:70], lambda v: f"{v['priority']}/100", lambda v: '; '.join(v['why'])])}</table>
<div class="two"><div><h2>Threat actors gaining activity</h2><table><tr><th>Actor</th><th>This period</th><th>Before</th></tr>
{rows(d['rising_actors'], [lambda r: r['value'], lambda r: r['count'], lambda r: r['previous']])}</table></div>
<div><h2>Sectors most targeted</h2><table><tr><th>Sector</th><th>This period</th><th>Before</th></tr>
{rows(d['rising_sectors'], [lambda r: r['value'], lambda r: r['count'], lambda r: r['previous']])}</table></div></div>
<div class="two"><div><h2>Kinds of threat</h2><table>{rows(d['types'], [lambda r: r['label'], lambda r: r['count']])}</table></div>
<div><h2>Countries most reported</h2><table>{rows(d['countries'], [lambda r: r['label'], lambda r: r['count']])}</table></div></div>
<h2>Highest-risk findings overall</h2><ul>{findings(d['top_findings'])}</ul>
<footer>Figures come from intelligence the platform collected and are only as complete as its sources. A ransomware group listing an organisation is a claim, not confirmation of a breach.
Of all findings held, {d['quality']['verification'].get('corroborated', 0) + d['quality']['verification'].get('confirmed', 0):,} are corroborated or analyst-confirmed.</footer>
</body></html>"""


@router.get("/reports/executive")
def executive(request: Request, days: int = Query(30, ge=1, le=365), format: str = "html", db: Session = Depends(get_db), user: User = Depends(viewer)):
    data = executive_data(db, days)
    audit(db, request, user, "report.executive", "report", "", days=days, format=format)
    db.commit()
    if format == "json":
        return data
    return HTMLResponse(_render(data, user.name or user.email), headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})
