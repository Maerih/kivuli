"""Explainable prioritisation for alerts, vulnerabilities and exposed assets.

Each function returns a 0-100 score and the named factors behind it, the same
shape as finding risk, so the console can always show why something ranks where
it does.
"""
from datetime import datetime, timezone

# Services that should rarely face the internet.
RISKY_PORTS = {21: "FTP", 23: "Telnet", 135: "RPC", 139: "NetBIOS", 445: "SMB", 1433: "MS SQL", 1521: "Oracle DB", 2375: "Docker API",
               3306: "MySQL", 3389: "Remote Desktop", 5432: "PostgreSQL", 5900: "VNC", 5984: "CouchDB", 6379: "Redis", 9200: "Elasticsearch",
               11211: "Memcached", 27017: "MongoDB"}


def _finish(factors: list[dict]) -> tuple[int, list[dict]]:
    factors = [f for f in factors if round(f["points"])]
    return int(max(0, min(100, round(sum(f["points"] for f in factors))))), [{"factor": f["factor"], "points": round(f["points"])} for f in factors]


def alert_priority(*, risk: int, confidence: int, category: str, credential_exposed: bool, criticality: int | None,
                   corroboration: int, verification: str, age_days: int | None, severity: str = "medium") -> tuple[int, list[dict]]:
    """How urgently an analyst should look at an alert.

    Starts from the finding's own risk and adjusts for what the watchlist knows
    that the finding does not: whose asset it is and how much it matters.
    """
    factors = [{"factor": "Risk of the underlying finding", "points": risk * 0.55}]
    if category == "compromise":
        factors.append({"factor": "A monitored asset appears in a leak, extortion post or dump", "points": 14})
    elif category in ("attack_surface", "vulnerability", "exposure"):
        factors.append({"factor": "Directly concerns your own exposure", "points": 12})
    elif category == "lookalike":
        factors.append({"factor": "Domain imitating your brand", "points": 10})
    if credential_exposed:
        factors.append({"factor": "A password was exposed with the account", "points": 12})
    if criticality is not None:
        factors.append({"factor": f"Asset criticality {criticality}/5", "points": (criticality - 3) * 6})
    if verification == "confirmed":
        factors.append({"factor": "Confirmed by an analyst", "points": 8})
    elif corroboration >= 1:
        factors.append({"factor": f"Corroborated by {corroboration} other source{'s' if corroboration != 1 else ''}", "points": min(8, 4 + corroboration * 2)})
    elif verification == "unverified":
        factors.append({"factor": "Single unverified source", "points": -8})
    if confidence < 50:
        factors.append({"factor": f"Low classification confidence ({confidence}%)", "points": -6})
    if age_days is not None:
        if age_days <= 2:
            factors.append({"factor": "Reported in the last 48 hours", "points": 8})
        elif age_days > 180:
            factors.append({"factor": "Historic: more than six months old", "points": -20})
        elif age_days > 30:
            factors.append({"factor": "More than a month old", "points": -8})
    if severity == "critical" and risk < 60:
        factors.append({"factor": "Rule or policy marks this critical", "points": 20})
    return _finish(factors)


def vulnerability_priority(*, kev: bool, kev_added: datetime | None, ransomware_use: bool, epss: float | None, cvss: float | None,
                           mention_count: int, exposed_assets: int, watched_technology: bool) -> tuple[int, list[dict]]:
    """Rank a vulnerability by evidence that it matters *now and to you*, not by CVSS alone."""
    factors: list[dict] = []
    if exposed_assets:
        factors.append({"factor": f"Present on {exposed_assets} of your internet-facing hosts", "points": min(35, 25 + exposed_assets * 2)})
    if kev:
        factors.append({"factor": "Known to be exploited in the wild (CISA KEV)", "points": 30})
    if ransomware_use:
        factors.append({"factor": "Used in ransomware campaigns", "points": 10})
    if epss is not None:
        if epss >= 0.5:
            factors.append({"factor": f"Exploitation very likely within 30 days (EPSS {epss:.0%})", "points": 18})
        elif epss >= 0.1:
            factors.append({"factor": f"Exploitation likely (EPSS {epss:.0%})", "points": 10})
        elif epss >= 0.01:
            factors.append({"factor": f"Some exploitation likelihood (EPSS {epss:.1%})", "points": 4})
    if watched_technology:
        factors.append({"factor": "Affects a technology you have said you use", "points": 15})
    if mention_count:
        factors.append({"factor": f"Mentioned in {mention_count} collected finding{'s' if mention_count != 1 else ''}", "points": min(12, 3 + mention_count * 1.5)})
    if cvss is not None:
        factors.append({"factor": f"Severity (CVSS {cvss:.1f})", "points": 10 if cvss >= 9 else 6 if cvss >= 7 else 2 if cvss >= 4 else 0})
    if kev_added is not None:
        added = datetime(kev_added.year, kev_added.month, kev_added.day, tzinfo=timezone.utc)
        if (datetime.now(timezone.utc) - added).days <= 30:
            factors.append({"factor": "Added to the exploited list in the last 30 days", "points": 6})
    return _finish(factors)


def asset_risk(*, ports: list[int], vulns: list[str], kev_vulns: list[str], feed_hits: list[str], tags: list[str],
               criticality: int) -> tuple[int, list[dict]]:
    factors: list[dict] = []
    if kev_vulns:
        factors.append({"factor": f"Runs software with {len(kev_vulns)} actively exploited vulnerabilit{'ies' if len(kev_vulns) != 1 else 'y'}", "points": min(55, 40 + len(kev_vulns) * 5)})
    other = len(vulns) - len(kev_vulns)
    if other > 0:
        factors.append({"factor": f"{other} other known vulnerabilit{'ies' if other != 1 else 'y'} reported for its software", "points": min(20, 6 + other * 2)})
    risky = sorted(p for p in ports if p in RISKY_PORTS)
    if risky:
        names = ", ".join(f"{RISKY_PORTS[p]} ({p})" for p in risky[:4])
        factors.append({"factor": f"Sensitive service exposed to the internet: {names}", "points": min(30, 14 + len(risky) * 6)})
    if feed_hits:
        factors.append({"factor": f"Address is listed by a threat feed ({', '.join(feed_hits[:3])})", "points": 30})
    if "compromised" in tags or "malware" in tags:
        factors.append({"factor": "Flagged as compromised by the scan data provider", "points": 30})
    if len(ports) > 12:
        factors.append({"factor": f"Large exposed surface ({len(ports)} open ports)", "points": 6})
    if factors:
        factors.append({"factor": f"Asset criticality {criticality}/5", "points": (criticality - 3) * 5})
    return _finish(factors)
