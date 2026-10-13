"""Risk scoring. Every point is attributed to a named factor so analysts can see why."""
from datetime import datetime, timezone

_BASE = {
    "ransomware": 55, "access_sale": 55, "credential_leak": 50, "data_breach": 50, "malware": 35,
    "phishing": 35, "defacement": 35, "fraud": 35, "ddos": 30, "vulnerability": 30, "hacktivism": 30, "other": 10,
}
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def severity_for(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "info"


def severity_at_least(severity: str, minimum: str) -> bool:
    return SEVERITY_ORDER.index(severity) >= SEVERITY_ORDER.index(minimum)


def score_risk(
    *,
    threat_type: str,
    confidence: int,
    source_trust: int,
    network: str,
    exposure: dict,
    ioc_count: int,
    has_actor: bool,
    has_victim: bool,
    in_focus_country: bool,
    reference_time: datetime | None,
    known_exploited: bool = False,
    watchlist_hit: bool = False,
    corroboration: int = 0,
    feed_listed: bool = False,
    in_focus_sector: bool = False,
    criticality: int | None = None,
    techniques: int = 0,
) -> tuple[int, str, list[dict]]:
    factors: list[dict] = []

    def add(label: str, points: float) -> None:
        if round(points):
            factors.append({"factor": label, "points": round(points)})

    add(f"Threat type: {threat_type.replace('_', ' ')}", _BASE.get(threat_type, 10))
    add("Source reliability", (source_trust - 50) / 5)
    if network == "onion":
        add("Seen on a Tor hidden service", 5)
    pairs = exposure.get("credential_pairs", 0)
    if pairs:
        add(f"Exposed credentials ({pairs})", 15 if pairs >= 100 else 10)
    if exposure.get("private_keys") or exposure.get("secrets"):
        add("Exposed keys or secrets", 10)
    if exposure.get("cards"):
        add("Payment card data", 8)
    add("Indicator density", min(8, ioc_count / 5))
    if has_actor:
        add("Attributed to a tracked threat actor", 6)
    if has_victim:
        add("Names a victim organisation", 6)
    if in_focus_country:
        add("Concerns a focus country", 8)
    if known_exploited:
        add("References a known-exploited vulnerability", 5)
    if watchlist_hit:
        add("Matches a watchlist", 15)
    if criticality is not None and criticality != 3:
        add(f"Concerns an asset of criticality {criticality}/5", (criticality - 3) * 5)
    if in_focus_sector:
        add("Concerns a focus sector", 5)
    if corroboration:
        add(f"Corroborated by {corroboration} other source{'s' if corroboration != 1 else ''}", min(8, 3 + corroboration * 2))
    if feed_listed:
        add("An indicator is listed by a threat feed", 6)
    if techniques >= 3:
        add("Several attack techniques described", 3)
    if reference_time:
        if reference_time.tzinfo is None:
            reference_time = reference_time.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - reference_time).days
        if age_days <= 7:
            add("Reported in the last 7 days", 6)
        elif age_days > 365:
            add("More than a year old", -25)
        elif age_days > 180:
            add("More than six months old", -15)

    raw = sum(f["points"] for f in factors)
    # Low-confidence classifications should not produce high scores on their own.
    scaled = raw * (0.6 + 0.4 * confidence / 100)
    if scaled != raw:
        factors.append({"factor": f"Classification confidence {confidence}%", "points": round(scaled - raw)})
    score = int(max(0, min(100, round(scaled))))
    return score, severity_for(score), factors
