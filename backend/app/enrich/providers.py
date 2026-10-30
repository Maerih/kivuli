"""Enrichment providers.

Free providers work out of the box. Keyed providers switch on when their API
key is present in the enricher's environment. Each returns the same shape:

    {"verdict": malicious | suspicious | clean | unknown, "score": 0-100 or None, "summary": {...}}

The response parsers are pure functions so they can be tested without network.
"""
import base64
from dataclasses import dataclass
from typing import Callable

from app.enrich import dwi, keys, rejected
from app.enrich.http import EnrichError, api_request

Result = dict


def _result(verdict: str = "unknown", score: int | None = None, **summary) -> Result:
    return {"verdict": verdict, "score": score, "summary": {k: v for k, v in summary.items() if v not in (None, "", [], {})}}


class KeyRejected(EnrichError):
    """The provider answered, and said the API key is not valid."""


class QuotaExhausted(EnrichError):
    """The provider accepted the key but will not serve more requests for now."""


def _checked(label: str, response: tuple) -> tuple:
    """Turn a provider's "bad key" and "over quota" answers into errors, so they are never mistaken for "no data"."""
    status, body = response
    if status in (401, 403):
        raise KeyRejected(f"{label} rejected the API key (HTTP {status})")
    if status == 429:
        raise QuotaExhausted(f"{label} accepted the key, but its rate limit or quota is used up (HTTP 429)")
    return status, body


# ── Free ────────────────────────────────────────────────────────────────────

def parse_internetdb(status: int, body) -> Result:
    if status == 404 or not isinstance(body, dict) or "ports" not in body:
        return _result(note="No scan data for this address")
    tags = body.get("tags") or []
    bad = {"compromised", "malware", "c2", "botnet"} & set(tags)
    return _result("suspicious" if bad else "unknown", ports=sorted(body.get("ports") or []), cpes=(body.get("cpes") or [])[:30],
                   hostnames=(body.get("hostnames") or [])[:20], tags=tags, vulns=sorted(body.get("vulns") or [])[:200])


def internetdb(kind: str, value: str) -> Result:
    return parse_internetdb(*api_request(f"https://internetdb.shodan.io/{value}"))


def ripestat(kind: str, value: str) -> Result:
    status, body = api_request("https://stat.ripe.net/data/network-info/data.json", params={"resource": value})
    data = (body or {}).get("data") or {}
    asns = data.get("asns") or []
    if status != 200 or not asns:
        return _result(note="No routing data")
    holder = ""
    status, body = api_request("https://stat.ripe.net/data/as-overview/data.json", params={"resource": f"AS{asns[0]}"})
    if status == 200:
        holder = ((body or {}).get("data") or {}).get("holder", "")
    return _result(asn=f"AS{asns[0]}", holder=holder, prefix=data.get("prefix", ""))


def dns_records(name: str, record: str) -> list[str]:
    status, body = api_request("https://dns.google/resolve", params={"name": name, "type": record})
    if status != 200 or not isinstance(body, dict):
        return []
    wanted = {"A": 1, "AAAA": 28, "MX": 15, "NS": 2, "TXT": 16, "CNAME": 5}[record]
    return [str(a.get("data", "")).strip('"').rstrip(".") for a in body.get("Answer") or [] if a.get("type") == wanted]


def dns(kind: str, value: str) -> Result:
    return _result(a=dns_records(value, "A")[:20], mx=dns_records(value, "MX")[:10], ns=dns_records(value, "NS")[:10])


def parse_certspotter(body, domain: str) -> tuple[list[str], list[str]]:
    hosts, issuers = set(), set()
    for cert in body if isinstance(body, list) else []:
        for name in cert.get("dns_names") or []:
            name = name.lower().lstrip("*.")
            if name == domain or name.endswith("." + domain):
                hosts.add(name)
        issuer = (cert.get("issuer") or {}).get("friendly_name") or (cert.get("issuer") or {}).get("name") or ""
        if issuer:
            issuers.add(issuer[:80])
    return sorted(hosts), sorted(issuers)


def ct_hostnames(domain: str) -> tuple[list[str], list[str], str]:
    """Hostnames seen in certificate-transparency logs for a domain. Returns (hosts, issuers, source)."""
    try:
        status, body = api_request("https://api.certspotter.com/v1/issuances",
                                   params={"domain": domain, "include_subdomains": "true", "expand": ["dns_names", "issuer"]}, timeout=60)
        if status == 200:
            hosts, issuers = parse_certspotter(body, domain)
            return hosts, issuers, "certspotter"
    except EnrichError:
        pass
    status, body = api_request("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, timeout=90, max_bytes=20_000_000)
    if status != 200 or not isinstance(body, list):
        raise EnrichError(f"certificate transparency lookup failed (HTTP {status})")
    hosts = set()
    for row in body:
        for name in str(row.get("name_value", "")).split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name == domain or name.endswith("." + domain):
                hosts.add(name)
    return sorted(hosts), sorted({str(r.get("issuer_name", ""))[:80] for r in body[:200]} - {""})[:10], "crt.sh"


def ct(kind: str, value: str) -> Result:
    hosts, issuers, source = ct_hostnames(value)
    return _result(hostnames=hosts[:200], hostname_count=len(hosts), issuers=issuers[:10], source=source)


def parse_epss(body) -> dict[str, tuple[float, float]]:
    out = {}
    for row in (body or {}).get("data") or []:
        try:
            out[str(row["cve"]).upper()] = (float(row["epss"]), float(row["percentile"]))
        except (KeyError, TypeError, ValueError):
            continue
    return out


def epss_scores(cves: list[str]) -> dict[str, tuple[float, float]]:
    out: dict[str, tuple[float, float]] = {}
    for start in range(0, len(cves), 80):
        status, body = api_request("https://api.first.org/data/v1/epss", params={"cve": ",".join(cves[start : start + 80])})
        if status == 200:
            out.update(parse_epss(body))
    return out


def parse_nvd(body) -> dict | None:
    items = (body or {}).get("vulnerabilities") or []
    if not items:
        return None
    cve = items[0].get("cve") or {}
    metrics = cve.get("metrics") or {}
    score, vector = None, ""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            data = metrics[key][0].get("cvssData") or {}
            score, vector = data.get("baseScore"), data.get("vectorString", "")
            break
    description = next((d.get("value", "") for d in cve.get("descriptions") or [] if d.get("lang") == "en"), "")
    return {"cvss": score, "cvss_vector": vector, "description": description[:2000], "published": (cve.get("published") or "")[:10]}


def nvd(cve: str) -> dict | None:
    key = keys.get("nvd")
    status, body = api_request("https://services.nvd.nist.gov/rest/json/cves/2.0", params={"cveId": cve}, headers={"apiKey": key} if key else None)
    return parse_nvd(body) if status == 200 else None


# ── Keyed (commercial) ──────────────────────────────────────────────────────

def parse_virustotal(status: int, body) -> Result:
    if status == 404:
        return _result(note="Not known to VirusTotal")
    attrs = ((body or {}).get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    malicious, suspicious, harmless = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0)), int(stats.get("harmless", 0))
    total = sum(int(v) for v in stats.values()) or 1
    verdict = "malicious" if malicious >= 3 else "suspicious" if malicious or suspicious >= 3 else "clean" if harmless else "unknown"
    label = ((attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")) or ""
    return _result(verdict, round(100 * (malicious + suspicious * 0.5) / total), malicious=malicious, suspicious=suspicious, harmless=harmless,
                   engines=total, reputation=attrs.get("reputation"), threat_label=label, tags=(attrs.get("tags") or [])[:12],
                   name=attrs.get("meaningful_name"), file_type=attrs.get("type_description"), registrar=attrs.get("registrar"),
                   as_owner=attrs.get("as_owner"), country=attrs.get("country"))


def virustotal(kind: str, value: str) -> Result:
    path = {"ip": f"ip_addresses/{value}", "domain": f"domains/{value}", "hash": f"files/{value}",
            "url": "urls/" + base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")}[kind]
    return parse_virustotal(*_checked("VirusTotal", api_request(f"https://www.virustotal.com/api/v3/{path}", headers={"x-apikey": keys.get("virustotal")})))


def parse_shodan(status: int, body) -> Result:
    if status == 404 or not isinstance(body, dict) or "ports" not in body:
        return _result(note="No Shodan data for this address")
    vulns = sorted(body.get("vulns") or [])
    return _result("suspicious" if {"compromised", "malware", "c2"} & set(body.get("tags") or []) else "unknown", ports=sorted(body.get("ports") or []),
                   org=body.get("org"), isp=body.get("isp"), asn=body.get("asn"), os=body.get("os"), country=body.get("country_name"),
                   hostnames=(body.get("hostnames") or [])[:20], vulns=vulns[:200], tags=body.get("tags") or [], last_update=body.get("last_update"))


def shodan(kind: str, value: str) -> Result:
    return parse_shodan(*_checked("Shodan", api_request(f"https://api.shodan.io/shodan/host/{value}", params={"key": keys.get("shodan"), "minify": "true"})))


def parse_abuseipdb(status: int, body) -> Result:
    data = (body or {}).get("data") or {}
    if status != 200 or not data:
        return _result(note=f"AbuseIPDB returned HTTP {status}")
    score = int(data.get("abuseConfidenceScore") or 0)
    return _result("malicious" if score >= 75 else "suspicious" if score >= 25 else "clean" if data.get("totalReports") == 0 else "unknown", score,
                   reports=data.get("totalReports"), distinct_reporters=data.get("numDistinctUsers"), usage=data.get("usageType"), isp=data.get("isp"),
                   country=data.get("countryCode"), last_reported=data.get("lastReportedAt"), is_tor=data.get("isTor"))


def abuseipdb(kind: str, value: str) -> Result:
    return parse_abuseipdb(*_checked("AbuseIPDB", api_request("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": value, "maxAgeInDays": "90"},
                                                              headers={"Key": keys.get("abuseipdb")})))


def parse_greynoise(status: int, body) -> Result:
    if status == 404 or not isinstance(body, dict):
        return _result(note="Not observed scanning the internet")
    classification = body.get("classification", "unknown")
    verdict = {"malicious": "malicious", "benign": "clean"}.get(classification, "unknown")
    return _result(verdict, noise=body.get("noise"), known_benign_service=body.get("riot"), classification=classification, name=body.get("name"),
                   last_seen=body.get("last_seen"))


def greynoise(kind: str, value: str) -> Result:
    return parse_greynoise(*_checked("GreyNoise", api_request(f"https://api.greynoise.io/v3/community/{value}", headers={"key": keys.get("greynoise")})))


# ── Connection tests ────────────────────────────────────────────────────────
# One real, minimal request per provider about a harmless, well-known subject.
# The answer says whether the route, the allow-list and (where there is one) the
# key actually work, in words an operator can act on.

SAMPLE_IP, SAMPLE_DOMAIN, SAMPLE_CVE = "8.8.8.8", "example.com", "CVE-2021-44228"


def _probe(ok: bool, message: str, **detail) -> dict:
    return {"ok": ok, "message": message, "detail": {k: v for k, v in detail.items() if v not in (None, "", [], {})}}


def probe_internetdb() -> dict:
    status, body = api_request(f"https://internetdb.shodan.io/{SAMPLE_IP}")
    if status == 200 and isinstance(body, dict) and "ports" in body:
        return _probe(True, f"Answered: {len(body['ports'])} open ports on record for {SAMPLE_IP}", ports=sorted(body["ports"])[:12])
    return _probe(False, f"Unexpected answer (HTTP {status})")


def probe_ripestat() -> dict:
    summary = ripestat("ip", SAMPLE_IP)["summary"]
    if summary.get("asn"):
        return _probe(True, f"Answered: {SAMPLE_IP} is announced by {summary['asn']} {summary.get('holder', '')}".strip(), **summary)
    return _probe(False, "Answered, but without routing data")


def probe_dns() -> dict:
    records = dns_records(SAMPLE_DOMAIN, "A")
    return _probe(True, f"Answered: {SAMPLE_DOMAIN} resolves to {', '.join(records[:3])}", a=records[:6]) if records else _probe(False, "No answer for a domain that certainly resolves")


def parse_wayback(status: int, body) -> Result:
    rows = body if isinstance(body, list) else []
    snapshots = rows[1:] if rows and rows[0] and rows[0][0] == "urlkey" else rows
    if status != 200 or not snapshots:
        return _result(note="No snapshots in the Wayback Machine")
    stamps = sorted(r[1] for r in snapshots if len(r) > 1 and r[1])
    def _fmt(t):
        return f"{t[0:4]}-{t[4:6]}-{t[6:8]}" if len(t) >= 8 else t
    digests = {r[5] for r in snapshots if len(r) > 5}
    return _result("unknown", snapshots=len(snapshots), first=_fmt(stamps[0]) if stamps else "",
                   last=_fmt(stamps[-1]) if stamps else "", distinct_versions=len(digests),
                   url=f"https://web.archive.org/web/*/{snapshots[0][2]}" if len(snapshots[0]) > 2 else "")


def wayback(kind: str, value: str) -> Result:
    target = value if kind == "url" else f"{value}/*"
    return parse_wayback(*api_request("https://web.archive.org/cdx/search/cdx",
                                      params={"url": target, "output": "json", "limit": "200", "collapse": "digest", "fl": "urlkey,timestamp,original,mimetype,statuscode,digest"}))


def probe_wayback() -> dict:
    r = wayback("domain", "example.com")
    if r["summary"].get("snapshots"):
        return _probe(True, f"Answered: {r['summary']['snapshots']} snapshots of example.com on record")
    return _probe(False, "No snapshots returned for a domain that is certainly archived")


def probe_ct() -> dict:
    hosts, _issuers, via = ct_hostnames(SAMPLE_DOMAIN)
    return _probe(True, f"Answered through {via}: {len(hosts)} hostnames for {SAMPLE_DOMAIN}", source=via) if hosts else _probe(False, "No certificates returned for a domain that certainly has some")


def probe_epss() -> dict:
    scores = epss_scores([SAMPLE_CVE])
    if SAMPLE_CVE in scores:
        return _probe(True, f"Answered: {SAMPLE_CVE} scores {scores[SAMPLE_CVE][0]:.1%}", epss=scores[SAMPLE_CVE][0])
    return _probe(False, "No score returned for a well-known CVE")


def probe_nvd() -> dict:
    key = keys.get("nvd")
    status, body = api_request("https://services.nvd.nist.gov/rest/json/cves/2.0", params={"cveId": SAMPLE_CVE}, headers={"apiKey": key} if key else None)
    if status == 200 and parse_nvd(body):
        return _probe(True, "Answered with your API key (50 requests per 30 seconds)" if key else "Answered without a key (5 requests per 30 seconds; a key raises this)",
                      cvss=parse_nvd(body)["cvss"])
    if key and status in (401, 403, 404):
        return _probe(False, f"NVD did not accept this API key (HTTP {status}). Remove it to use NVD without one.")
    return _probe(False, f"NVD is rate limiting this address (HTTP {status}); try again in a minute" if status in (403, 429) else f"Unexpected answer (HTTP {status})")


def probe_virustotal() -> dict:
    status, body = _checked("VirusTotal", api_request(f"https://www.virustotal.com/api/v3/ip_addresses/{SAMPLE_IP}", headers={"x-apikey": keys.get("virustotal")}))
    if status == 200:
        return _probe(True, "Key accepted: VirusTotal returned a report", as_owner=(((body or {}).get("data") or {}).get("attributes") or {}).get("as_owner"))
    return _probe(False, f"Unexpected answer (HTTP {status})")


def probe_shodan() -> dict:
    status, body = _checked("Shodan", api_request("https://api.shodan.io/api-info", params={"key": keys.get("shodan")}))
    if status == 200 and isinstance(body, dict):
        return _probe(True, f"Key accepted: plan “{body.get('plan', 'unknown')}”, {body.get('query_credits', 0)} query credits left",
                      plan=body.get("plan"), query_credits=body.get("query_credits"), scan_credits=body.get("scan_credits"))
    return _probe(False, f"Unexpected answer (HTTP {status})")


def probe_abuseipdb() -> dict:
    status, body = _checked("AbuseIPDB", api_request("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": SAMPLE_IP, "maxAgeInDays": "30"},
                                                     headers={"Key": keys.get("abuseipdb")}))
    if status == 200 and (body or {}).get("data"):
        return _probe(True, "Key accepted: AbuseIPDB returned a report")
    detail = "; ".join(str(e.get("detail", "")) for e in (body or {}).get("errors") or [])[:160] if isinstance(body, dict) else ""
    return _probe(False, f"AbuseIPDB refused the request (HTTP {status}){': ' + detail if detail else ''}")


def probe_greynoise() -> dict:
    # The lookup endpoint answers with or without a valid key, so it proves nothing. /ping is the call that checks the key.
    status, body = _checked("GreyNoise", api_request("https://api.greynoise.io/ping", headers={"key": keys.get("greynoise")}))
    if status == 200 and isinstance(body, dict):
        return _probe(True, f"Key accepted: GreyNoise plan “{body.get('offering', 'unknown')}”", offering=body.get("offering"), expires=body.get("expiration"))
    return _probe(False, f"Unexpected answer (HTTP {status})")


@dataclass(frozen=True)
class Provider:
    name: str
    label: str
    kinds: tuple[str, ...]
    fetch: Callable[[str, str], Result] | None  # indicator lookup; None for services the platform uses internally, and for planned ones
    key_setting: str = ""  # Settings attribute holding the `.env` API key; empty for providers that take none
    hosts: tuple[str, ...] = ()
    about: str = ""
    probe: Callable[[], dict] | None = None  # connection test
    optional_key: bool = False  # works without a key; a key only raises limits
    signup: str = ""  # where an operator gets a key

    @property
    def tier(self) -> str:
        if self.fetch is None and self.probe is None:
            return "planned"
        return "commercial" if self.key_setting and not self.optional_key else "free"

    @property
    def takes_key(self) -> bool:
        return bool(self.key_setting)

    def enabled(self) -> bool:
        return self.tier != "planned" and (not self.key_setting or self.optional_key or bool(keys.get(self.name)))

    def key_rejected(self) -> str:
        """Why this provider's current key is not being used, or "" when it is fine."""
        api_key = keys.get(self.name) if self.takes_key else ""
        return rejected.rejection(self.name, api_key) if api_key else ""


PROVIDERS: list[Provider] = [
    Provider("internetdb", "Shodan InternetDB", ("ip",), internetdb, hosts=("internetdb.shodan.io",), about="Open ports, software and known vulnerabilities from passive scan data", probe=probe_internetdb),
    Provider("ripestat", "RIPEstat", ("ip",), ripestat, hosts=("stat.ripe.net",), about="Announcing network (ASN), holder and prefix", probe=probe_ripestat),
    Provider("dns", "Public DNS", ("domain",), dns, hosts=("dns.google",), about="A, MX and NS records over DNS-over-HTTPS", probe=probe_dns),
    Provider("ct", "Certificate transparency", ("domain",), ct, hosts=("api.certspotter.com", "crt.sh"), about="Hostnames and issuers from public certificate logs", probe=probe_ct),
    Provider("wayback", "Wayback Machine", ("domain", "url"), wayback, hosts=("web.archive.org",), about="Historical snapshots: how long a site or page has existed and when it changed", probe=probe_wayback),
    Provider("epss", "FIRST EPSS", ("cve",), None, hosts=("api.first.org",), about="How likely each vulnerability is to be exploited in the next 30 days", probe=probe_epss),
    Provider("nvd", "NVD", ("cve",), None, "nvd_api_key", ("services.nvd.nist.gov",), "Severity (CVSS) and descriptions for vulnerabilities. Works without a key; a key raises the rate limit",
             probe_nvd, optional_key=True, signup="https://nvd.nist.gov/developers/request-an-api-key"),
    Provider("virustotal", "VirusTotal", ("ip", "domain", "url", "hash"), virustotal, "virustotal_api_key", ("www.virustotal.com",), "Multi-engine reputation for files, URLs, domains and addresses",
             probe_virustotal, signup="https://www.virustotal.com/gui/my-apikey"),
    Provider("shodan", "Shodan", ("ip",), shodan, "shodan_api_key", ("api.shodan.io",), "Full host record: services, organisation, operating system, vulnerabilities",
             probe_shodan, signup="https://account.shodan.io/"),
    Provider("abuseipdb", "AbuseIPDB", ("ip",), abuseipdb, "abuseipdb_api_key", ("api.abuseipdb.com",), "Community abuse reports and confidence score",
             probe_abuseipdb, signup="https://www.abuseipdb.com/account/api"),
    Provider("greynoise", "GreyNoise", ("ip",), greynoise, "greynoise_api_key", ("api.greynoise.io",), "Whether an address is internet background noise or a known benign service",
             probe_greynoise, signup="https://viz.greynoise.io/account/api-key"),
    # A source of intelligence rather than a lookup: it feeds findings and indicators through its own sources.
    Provider("dwi", "Dark Web Informer", (), None, "dwi_api_key", (dwi.HOST,),
             "Threat feed alerts, ransomware victims and indicators from Dark Web Informer, imported every six hours",
             dwi.probe, signup="https://darkwebinformer.com/api-details/"),
    Provider("hibp", "Have I Been Pwned", ("email", "domain"), None, about="Breach history for corporate mailboxes (planned)"),
    Provider("urlscan", "urlscan.io", ("url", "domain"), None, about="Page scans and verdicts for URLs (planned)"),
    Provider("securitytrails", "SecurityTrails", ("domain", "ip"), None, about="Passive DNS and WHOIS history (planned)"),
    Provider("censys", "Censys", ("ip", "domain"), None, about="Host and certificate search (planned)"),
]
BY_NAME = {p.name: p for p in PROVIDERS}


def catalogue() -> list[dict]:
    """What exists and whether it is switched on, as seen from the container this runs in."""
    return [{"name": p.name, "label": p.label, "kinds": list(p.kinds), "tier": p.tier, "enabled": p.enabled(), "about": p.about,
             "env": p.key_setting.upper(), "hosts": list(p.hosts), "takes_key": p.takes_key, "optional_key": p.optional_key, "signup": p.signup,
             "testable": p.probe is not None, "key_source": keys.source(p.name) if p.takes_key else "not_needed",
             "key_rejected": p.key_rejected()} for p in PROVIDERS]


def for_kind(kind: str) -> list[Provider]:
    """Providers that will be asked about this kind: switched on, and not holding a key they rejected."""
    return [p for p in PROVIDERS if p.fetch is not None and kind in p.kinds and p.enabled() and not p.key_rejected()]


def run_probe(name: str) -> dict:
    """Run a provider's connection test and explain the outcome. Never raises."""
    provider = BY_NAME.get(name)
    if provider is None or provider.probe is None:
        return _probe(False, "This provider has no connection test")
    if provider.takes_key and not provider.optional_key and not keys.get(name):
        if keys.source(name) == "unreadable":
            return _probe(False, "The stored key cannot be read because PROVIDER_KEYS_KEY has changed. Enter the key again.")
        return _probe(False, "No API key is set for this provider")
    try:
        return provider.probe()
    except KeyRejected as exc:
        return _probe(False, f"{exc}. Check that the key was copied in full and is still active.", reason="key_rejected")
    except QuotaExhausted as exc:
        return _probe(False, str(exc), reason="quota")
    except EnrichError as exc:
        text = str(exc)
        if "egress proxy refused" in text:
            missing = ", ".join(provider.hosts)
            return _probe(False, f"Blocked by the egress allow-list. Add {missing} to EGRESS_ALLOW_HOSTS in .env and restart.", reason="egress")
        return _probe(False, f"Could not reach {provider.label}: {text}", reason="network")
    except Exception as exc:  # a test must always report something
        return _probe(False, f"The test failed unexpectedly ({type(exc).__name__})", reason="error")
