"""Analyst query language -> OpenSearch query.

    cyber attack Kenya                 free text; countries and broad terms are understood
    "initial access" bank              exact phrase plus a term
    actor:lockbit country:KE           fields
    domain:example.co.ke               the domain, its subdomains and mailboxes under it
    41.90.0.0/16  user@corp.com        bare indicators are recognised (defanged ones too)
    type:ransomware -type:phishing     negation
    risk:>70 after:30d has:creds       ranges, relative dates, flags
    lockbit OR akira                   alternatives

The parser never raises on user input: anything it cannot interpret as an
operator is searched as text, and the interpretation is returned to the UI.
"""
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from dateutil import parser as dateparser

from app.extract.classify import THREAT_TYPES
from app.extract.geo import country_from_term, country_name
from app.extract.lang import LANGUAGE_NAMES
from app.extract.iocs import detect_indicator, refang

TEXT_FIELDS = ["title^4", "content", "actors.text^4", "organizations.text^4", "malware.text^3", "campaigns.text^3", "sectors.text^2"]
EXACT_FIELDS = ["title.exact^4", "content.exact", "actors.text^4", "organizations.text^4", "malware.text^3", "campaigns.text^3"]

FIELD_ALIASES = {
    "actor": "actor", "group": "actor", "gang": "actor", "threat_actor": "actor",
    "org": "organization", "organization": "organization", "organisation": "organization", "victim": "organization", "company": "organization",
    "malware": "malware", "family": "malware", "campaign": "campaign",
    "country": "country", "geo": "country",
    "type": "type", "threat": "type",
    "severity": "severity", "sev": "severity",
    "source": "source", "network": "network", "net": "network",
    "domain": "domain", "email": "email", "ip": "ip", "url": "url", "onion": "onion",
    "hash": "hash", "md5": "hash", "sha1": "hash", "sha256": "hash",
    "cve": "cve", "crypto": "crypto", "btc": "crypto", "eth": "crypto", "wallet": "crypto",
    "user": "username", "username": "username", "handle": "username",
    "ioc": "ioc", "tag": "tag", "status": "status",
    "title": "title", "intitle": "title", "host": "host", "site": "host", "inurl": "inurl",
    "lang": "lang", "language": "lang", "category": "category", "kind": "category", "similar": "similar", "like": "similar",
    "re": "regex", "regex": "regex", "source_id": "source_id",
    "sector": "sector", "industry": "sector",
    "has": "has", "risk": "risk", "confidence": "confidence", "conf": "confidence",
    "technique": "technique", "ttp": "technique", "attack": "technique", "tactic": "tactic",
    "verified": "verified", "verification": "verified",
    "after": "after", "since": "after", "before": "before", "until": "before", "seen": "seen",
}

TYPE_ALIASES = {
    "ransomware": "ransomware", "extortion": "ransomware", "ransom": "ransomware",
    "breach": "data_breach", "leak": "data_breach", "leaks": "data_breach", "leaked": "data_breach", "databreach": "data_breach", "data_breach": "data_breach",
    "credentials": "credential_leak", "credential": "credential_leak", "creds": "credential_leak", "combolist": "credential_leak",
    "credential_leak": "credential_leak", "stealer": "credential_leak", "passwords": "credential_leak",
    "access": "access_sale", "access_sale": "access_sale", "iab": "access_sale",
    "defacement": "defacement", "defaced": "defacement", "deface": "defacement",
    "malware": "malware", "phishing": "phishing", "phish": "phishing", "ddos": "ddos",
    "vulnerability": "vulnerability", "vuln": "vulnerability", "exploit": "vulnerability", "exploits": "vulnerability",
    "fraud": "fraud", "carding": "fraud", "hacktivism": "hacktivism", "hacktivist": "hacktivism", "other": "other",
}
# Bare words that also imply a threat type. "access" and "other" are too generic to imply one.
CONCEPT_TYPES = {k: v for k, v in TYPE_ALIASES.items() if k not in ("access", "other")}

# Words nearly every document in a threat-intelligence index is "about". Requiring
# them would hide relevant results, so they only influence ranking.
BROAD_TERMS = {
    "cyber", "cyberattack", "cyberattacks", "cybersecurity", "attack", "attacks", "attacked", "attacker", "attackers",
    "hack", "hacks", "hacked", "hacking", "hacker", "hackers", "incident", "incidents", "threat", "threats",
    "security", "darkweb", "darknet", "dark", "web", "deepweb", "intelligence", "intel", "news", "report", "reports",
    "latest", "recent", "new", "targeting", "targeted", "targets", "related", "activity", "mentions", "mention",
}
STOP_TERMS = {"the", "a", "an", "of", "in", "on", "and", "for", "to", "at", "by", "with", "about", "against", "from", "is", "are"}
# Two-letter words and abbreviations that are also ISO country codes. Typed bare
# they are almost never meant as a country; country:XX is always available.
WORDLIKE_CODES = {
    "IN", "IS", "IT", "TO", "NO", "AT", "BE", "BY", "ME", "MY", "AM", "AS", "DO", "SO", "ID", "AI", "IO", "TV", "CO",
    "LA", "MA", "PA", "AD", "TG", "PM", "MS", "MR", "ST", "SA", "CA", "AL", "DE", "ES", "PS", "SH", "SS", "GG", "IM",
}
OR_WORDS = ("OR", "|", "||")
LANGUAGE_CODES = {name.lower(): code for code, name in LANGUAGE_NAMES.items()}
SOURCE_KINDS = {"leak": "ransomware_leak_site", "leaks": "ransomware_leak_site", "leak_site": "ransomware_leak_site", "ransomware": "ransomware_leak_site",
                "extortion": "ransomware_leak_site", "market": "marketplace", "markets": "marketplace", "shop": "marketplace", "forums": "forum",
                "board": "forum", "pastes": "paste", "pastebin": "paste", "blogs": "blog"}

NETWORK_ALIASES = {"tor": "onion", "onion": "onion", "darkweb": "onion", "dark": "onion", "surface": "surface", "clearnet": "surface", "web": "surface", "clear": "surface"}
HAS_FLAGS = {
    "creds": "credentials", "credentials": "credentials", "passwords": "credentials", "iocs": "iocs", "ioc": "iocs",
    "changes": "changes", "history": "changes", "actor": "actor", "victim": "organization", "org": "organization", "cve": "cve",
}
IOC_FIELD = {"email": "ioc_email", "hash": "ioc_hash", "cve": "ioc_cve", "crypto": "ioc_crypto", "username": "ioc_username", "onion": "ioc_onion", "url": "ioc_url"}

_TOKEN = re.compile(r'(?P<neg>-)?(?:(?P<field>[A-Za-z_]{2,20}):)?(?:"(?P<quoted>[^"]*)"|(?P<bare>[^\s"]+))')
_RELATIVE = re.compile(r"^(\d{1,4})\s*(h|d|w|m|y)$", re.I)
_RANGE = re.compile(r"^(>=|<=|>|<)?\s*(\d{1,3})(?:\.\.(\d{1,3}))?$")


@dataclass
class Parsed:
    must: list[dict] = field(default_factory=list)
    should: list[dict] = field(default_factory=list)
    must_not: list[dict] = field(default_factory=list)
    filters: list[dict] = field(default_factory=list)
    interpretation: list[dict] = field(default_factory=list)
    text_terms: list[str] = field(default_factory=list)  # for "did you mean"
    similar_to: str = ""  # id of the finding a similar: search starts from

    def note(self, kind: str, label: str, detail: str = "") -> None:
        self.interpretation.append({"kind": kind, "label": label, "detail": detail})


def _text_query(value: str) -> dict:
    return {
        "bool": {
            "should": [
                {"multi_match": {"query": value, "fields": TEXT_FIELDS, "type": "best_fields", "fuzziness": "AUTO:5,9", "prefix_length": 2, "operator": "and"}},
                {"multi_match": {"query": value, "fields": EXACT_FIELDS, "type": "best_fields", "boost": 2}},
                {"term": {"ioc_all": {"value": value, "boost": 4}}},
            ],
            "minimum_should_match": 1,
        }
    }


def _phrase_query(value: str, fields: list[str] | None = None) -> dict:
    return {"multi_match": {"query": value, "fields": fields or EXACT_FIELDS, "type": "phrase"}}


def _wildcard_query(value: str) -> dict:
    should: list[dict] = [
        {"wildcard": {"ioc_all": {"value": value.lower(), "case_insensitive": True}}},
        {"wildcard": {"host": {"value": value.lower(), "case_insensitive": True}}},
    ]
    if value.endswith("*") and "*" not in value[:-1] and "?" not in value:
        should.append({"multi_match": {"query": value[:-1], "fields": ["title.exact^4", "content.exact", "actors.text^4", "organizations.text^4"], "type": "phrase_prefix"}})
    return {"bool": {"should": should, "minimum_should_match": 1}}


def _regex_query(pattern: str) -> dict | None:
    """A regular expression over words in titles and content. Lucene matches a pattern against one whole word at a time."""
    pattern = pattern.strip()
    if not 1 < len(pattern) <= 120:
        return None
    try:
        re.compile(pattern)
    except re.error:
        return None
    clause = {"value": pattern.lower(), "flags": "ALL", "case_insensitive": True, "max_determinized_states": 20000}
    return {"bool": {"minimum_should_match": 1, "should": [{"regexp": {"title": {**clause, "boost": 3}}}, {"regexp": {"content": clause}},
                                                           {"regexp": {"ioc_all": clause}}]}}


def _name_query(index_field: str, value: str) -> dict:
    if "*" in value or "?" in value:
        return {"wildcard": {f"{index_field}.lc": {"value": value.lower(), "case_insensitive": True}}}
    return {
        "bool": {
            "should": [
                {"term": {f"{index_field}.lc": {"value": value, "boost": 3}}},
                {"match_phrase": {f"{index_field}.text": value}},
            ],
            "minimum_should_match": 1,
        }
    }


def indicator_query(kind: str, value: str) -> dict:
    """Exact lookup for one indicator. Domains also match subdomains and mailboxes."""
    if kind == "domain":
        return {
            "bool": {
                "should": [
                    {"term": {"domain_suffixes": {"value": value, "boost": 3}}},
                    {"term": {"email_domains": value}},
                    {"term": {"host": value}},
                    {"match_phrase": {"content.exact": value}},
                ],
                "minimum_should_match": 1,
            }
        }
    if kind in ("ip", "cidr"):
        return {"term": {"ioc_ip": value}}
    if kind == "url":
        return {"bool": {"should": [{"term": {"ioc_url": value}}, {"term": {"url": value}}, {"prefix": {"ioc_url": value.lower()}}], "minimum_should_match": 1}}
    if kind in IOC_FIELD:
        return {"term": {IOC_FIELD[kind]: value}}
    return {"term": {"ioc_all": value}}


def _parse_when(value: str, end_of_day: bool = False) -> datetime | None:
    value = value.strip()
    if m := _RELATIVE.match(value):
        amount, unit = int(m.group(1)), m.group(2).lower()
        delta = {"h": timedelta(hours=amount), "d": timedelta(days=amount), "w": timedelta(weeks=amount), "m": timedelta(days=30 * amount), "y": timedelta(days=365 * amount)}[unit]
        return datetime.now(timezone.utc) - delta
    try:
        default = datetime(datetime.now().year, 1, 1, 23, 59, 59) if end_of_day else datetime(datetime.now().year, 1, 1)
        parsed = dateparser.parse(value, default=default)
    except (ValueError, OverflowError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _range_filter(index_field: str, value: str) -> dict | None:
    m = _RANGE.match(value.strip())
    if not m:
        return None
    op, low, high = m.group(1), int(m.group(2)), m.group(3)
    if high is not None:
        return {"range": {index_field: {"gte": low, "lte": int(high)}}}
    key = {">": "gt", ">=": "gte", "<": "lt", "<=": "lte", None: "gte"}[op]
    return {"range": {index_field: {key: low}}}


def _field_clause(name: str, value: str, parsed: Parsed) -> dict | None:
    """Translate ``field:value``. Returns a query, or None if the value is unusable."""
    value = value.strip()
    if not value:
        return None
    if name in ("actor", "organization", "malware", "campaign"):
        index_field = {"actor": "actors", "organization": "organizations", "malware": "malware", "campaign": "campaigns"}[name]
        parsed.note(name, f"{name.title()}: {value}")
        return _name_query(index_field, value)
    if name == "country":
        code = country_from_term(value) or (value.upper() if len(value) == 2 else None)
        if not code:
            return None
        parsed.note("country", f"Country: {country_name(code)}")
        return {"term": {"countries": code}}
    if name == "type":
        kind = TYPE_ALIASES.get(value.lower().replace(" ", "_").replace("-", "_"))
        if not kind:
            return None
        parsed.note("type", f"Type: {THREAT_TYPES[kind]}")
        return {"term": {"threat_types": kind}}
    if name == "severity":
        parsed.note("filter", f"Severity: {value.lower()}")
        return {"term": {"severity": value.lower()}}
    if name == "source":
        parsed.note("filter", f"Source: {value}")
        return {"wildcard": {"source_name.lc": {"value": f"*{value.lower().strip('*')}*", "case_insensitive": True}}}
    if name == "network":
        network = NETWORK_ALIASES.get(value.lower())
        if not network:
            return None
        parsed.note("filter", "Tor hidden services" if network == "onion" else "Surface web")
        return {"term": {"network": network}}
    if name == "domain":
        value = refang(value).lower().lstrip("*.")
        parsed.note("ioc", f"Domain: {value}", "includes subdomains and mailboxes under it")
        return indicator_query("domain", value)
    if name == "ip":
        detected = detect_indicator(value)
        if not detected or detected[0] not in ("ip", "cidr"):
            return None
        parsed.note("ioc", f"IP: {detected[1]}")
        return indicator_query(detected[0], detected[1])
    if name in IOC_FIELD:
        value = refang(value)
        if name == "cve":
            value = value.upper() if value.upper().startswith("CVE-") else f"CVE-{value}"
        parsed.note("ioc", f"{name.upper() if name in ('cve', 'url') else name.title()}: {value}")
        if "*" in value:
            return {"wildcard": {IOC_FIELD[name]: {"value": value, "case_insensitive": True}}}
        return indicator_query(name, value)
    if name == "ioc":
        parsed.note("ioc", f"Indicator: {value}")
        value = refang(value)
        if "*" in value:
            return {"wildcard": {"ioc_all": {"value": value.lower(), "case_insensitive": True}}}
        return {"term": {"ioc_all": value}}
    if name in ("tag", "status"):
        parsed.note("filter", f"{name.title()}: {value}")
        return {"term": {"tags" if name == "tag" else "status": value.lower()}}
    if name == "title":
        parsed.note("text", f"In title: {value}")
        return {"match": {"title": {"query": value, "operator": "and"}}}
    if name == "lang":
        code = LANGUAGE_CODES.get(value.lower(), value.lower())
        if code not in LANGUAGE_NAMES:
            return None
        parsed.note("filter", f"Language: {LANGUAGE_NAMES[code]}")
        return {"term": {"lang": code}}
    if name == "category":
        wanted = SOURCE_KINDS.get(value.lower().replace(" ", "_"), value.lower().replace(" ", "_"))
        parsed.note("filter", f"Source type: {wanted.replace('_', ' ')}")
        return {"term": {"source_category": wanted}}
    if name == "source_id":
        if not value.isdigit():
            return None
        parsed.note("filter", f"Source #{value}")
        return {"term": {"source_id": int(value)}}
    if name == "inurl":
        parsed.note("filter", f"Address contains: {value}")
        return {"wildcard": {"url": {"value": f"*{value.lower()}*", "case_insensitive": True}}}
    if name == "regex":
        clause = _regex_query(value)
        if clause is not None:
            parsed.note("text", f"/{value}/", "regular expression, matched against whole words")
        return clause
    if name == "similar":
        if not re.fullmatch(r"[0-9a-fA-F-]{36}", value):
            return None
        parsed.note("text", "Similar content", "findings whose wording resembles the one you chose")
        parsed.similar_to = value
        return {"more_like_this": {"fields": ["title", "content"], "like": [{"_id": value}], "min_term_freq": 1, "min_doc_freq": 1,
                                   "max_query_terms": 40, "minimum_should_match": "30%"}}
    if name == "host":
        parsed.note("filter", f"Host: {value}")
        value = refang(value).lower()
        return {"wildcard": {"host": {"value": value if "*" in value else f"*{value}", "case_insensitive": True}}}
    if name == "sector":
        parsed.note("filter", f"Sector: {value}")
        return {"bool": {"should": [{"term": {"sectors.lc": value}}, {"match_phrase": {"sectors.text": value}}], "minimum_should_match": 1}}
    if name == "has":
        flag = HAS_FLAGS.get(value.lower())
        query = {
            "credentials": {"term": {"has_credentials": True}},
            "iocs": {"range": {"ioc_count": {"gt": 0}}},
            "changes": {"range": {"version_count": {"gt": 1}}},
            "actor": {"exists": {"field": "actors"}},
            "organization": {"exists": {"field": "organizations"}},
            "cve": {"exists": {"field": "ioc_cve"}},
        }.get(flag or "")
        if query:
            parsed.note("filter", f"Has {flag}")
        return query
    if name == "technique":
        technique = value.upper()
        parsed.note("filter", f"Technique: {technique}")
        # T1566 also matches its sub-techniques (T1566.001, ...).
        return {"bool": {"should": [{"term": {"techniques": technique}}, {"prefix": {"techniques": technique + "."}}], "minimum_should_match": 1}}
    if name == "tactic":
        parsed.note("filter", f"Tactic: {value}")
        return {"term": {"tactics": value.lower().replace(" ", "-")}}
    if name == "verified":
        state = value.lower()
        if state not in ("unverified", "reported", "corroborated", "confirmed"):
            return None
        parsed.note("filter", f"Verification: {state}")
        return {"term": {"verification": state}}
    if name in ("risk", "confidence"):
        query = _range_filter("risk_score" if name == "risk" else "confidence", value)
        if query:
            parsed.note("filter", f"{name.title()} {value}")
        return query
    if name in ("after", "before", "seen"):
        when = _parse_when(value, end_of_day=name == "before")
        if not when:
            return None
        parsed.note("filter", f"{'Before' if name == 'before' else 'Since'} {when:%Y-%m-%d}")
        return {"range": {"date": {"lte" if name == "before" else "gte": when.isoformat()}}}
    return None


def parse_query(raw: str, strict: bool = False) -> Parsed:
    parsed = Parsed()
    raw = (raw or "").strip()[:1000]
    tokens = [m for m in _TOKEN.finditer(raw)]
    i = 0
    or_groups: list[list[dict]] = []
    pending_or = False

    def emit(query: dict, negate: bool = False, optional: bool = False, filter_only: bool = False) -> None:
        nonlocal pending_or
        if not negate and not filter_only and parsed.interpretation:
            # Name the clause after its line in "Understood as", so each result can say which parts of the query it matched.
            query = {"bool": {"must": [query], "_name": f"q{len(parsed.interpretation) - 1}"}}
        if negate:
            parsed.must_not.append(query)
        elif optional:
            parsed.should.append(query)
        elif pending_or and or_groups:
            or_groups[-1].append(query)
        elif filter_only:
            parsed.filters.append(query)
            return  # filters never take part in OR groups
        else:
            or_groups.append([query])
        pending_or = False

    negate_next = False
    while i < len(tokens):
        m = tokens[i]
        i += 1
        negate, name, quoted, bare = bool(m.group("neg")), m.group("field"), m.group("quoted"), m.group("bare")
        if not name and quoted is None and bare in ("NOT", "!") and i < len(tokens):
            negate_next = True  # NOT x is the same as -x
            continue
        negate, negate_next = negate or negate_next, False

        if name and name.lower() not in FIELD_ALIASES:
            # Not an operator (e.g. "https://x" or "12:30"): search the whole token as text.
            bare, quoted, name = f"{name}:{quoted if quoted is not None else bare}", None, None
        if name:
            canonical = FIELD_ALIASES[name.lower()]
            clause = _field_clause(canonical, quoted if quoted is not None else bare, parsed)
            if clause is None:
                parsed.note("warning", f"Ignored {name}:{quoted or bare}", "unrecognised value for this field")
                continue
            if negate:
                parsed.interpretation[-1].update(kind="exclude", label=f"Not {parsed.interpretation[-1]['label']}")
            exact_filter = canonical in ("country", "type", "severity", "network", "tag", "status", "has", "risk", "confidence", "after", "before",
                                         "seen", "source", "host", "technique", "tactic", "verified", "lang", "category", "source_id", "inurl")
            next_is_or = i < len(tokens) and not tokens[i].group("field") and tokens[i].group("bare") in OR_WORDS
            emit(clause, negate=negate, filter_only=exact_filter and not pending_or and not next_is_or)
            continue

        if quoted is not None:
            if quoted.strip():
                parsed.note("exclude" if negate else "phrase", f"{'Not ' if negate else ''}“{quoted}”", "exact phrase")
                emit(_phrase_query(quoted), negate=negate)
            continue

        if bare in OR_WORDS and not negate:
            pending_or = bool(or_groups)
            continue
        if bare in ("AND", "&&") or (bare.lower() in STOP_TERMS and not negate):
            continue

        # Multi-word country names ("South Africa", "United States") before single words.
        country, used = None, 0
        if not negate:
            for span in (3, 2, 1):
                window = [bare] + [t.group("bare") for t in tokens[i : i + span - 1] if t.group("bare") and not t.group("field") and not t.group("neg")]
                if len(window) != span:
                    continue
                candidate = " ".join(window)
                if span == 1 and len(candidate) == 2 and candidate.upper() in WORDLIKE_CODES:
                    continue
                code = country_from_term(candidate)
                if code:
                    country, used = (code, candidate), span - 1
                    break
        if country:
            i += used
            code, candidate = country
            parsed.note("country", f"Country: {country_name(code)}", "tagged with this country, or mentioning it")
            # Constant score: a finding tagged with the country counts the same whether or
            # not its text spells the name out, so risk and recency decide the order.
            emit({"constant_score": {"boost": 3, "filter": {"bool": {"minimum_should_match": 1, "should": [
                {"term": {"countries": {"value": code}}}, {"multi_match": {"query": candidate, "fields": ["title", "content"], "type": "phrase"}}]}}}})
            continue

        term = bare.strip(",;")
        lowered = term.lower()
        if not term:
            continue

        if len(term) > 2 and term.startswith("/") and term.endswith("/"):
            clause = _regex_query(term[1:-1])
            if clause is None:
                parsed.note("warning", f"Ignored {term}", "not a usable regular expression")
            else:
                parsed.note("exclude" if negate else "text", f"{'Not ' if negate else ''}{term}", "regular expression, matched against whole words")
                emit(clause, negate=negate)
            continue

        if "*" in term or "?" in term:
            parsed.note("text", term, "wildcard")
            emit(_wildcard_query(term), negate=negate)
            continue

        indicator = detect_indicator(term)
        if indicator:
            kind, value = indicator
            label = {"cidr": "Network", "ip": "IP", "cve": "CVE", "url": "URL"}.get(kind, kind.title())
            parsed.note("ioc", f"{label}: {value}", "exact indicator" + (" (incl. subdomains and mailboxes)" if kind == "domain" else ""))
            emit(indicator_query(kind, value), negate=negate)
            continue

        if lowered in CONCEPT_TYPES and not negate:
            kind = CONCEPT_TYPES[lowered]
            parsed.note("type", term, f"also matches findings classified as {THREAT_TYPES[kind].lower()}")
            emit({"bool": {"should": [_text_query(term), {"term": {"threat_types": {"value": kind, "boost": 1.5}}}], "minimum_should_match": 1}})
            parsed.text_terms.append(term)
            continue

        if lowered in BROAD_TERMS and not strict and not negate:
            parsed.note("broad", term, "broad term: improves ranking but is not required")
            parsed.should.append({"bool": {"must": [_text_query(term)], "_name": f"q{len(parsed.interpretation) - 1}"}})
            continue

        if negate:
            parsed.note("exclude", f"Not {term}")
        else:
            parsed.note("text", term)
            parsed.text_terms.append(term)
        emit(_text_query(term), negate=negate)

    for group in or_groups:
        parsed.must.append(group[0] if len(group) == 1 else {"bool": {"should": group, "minimum_should_match": 1}})
    return parsed


def to_bool_query(parsed: Parsed, extra_filters: list[dict] | None = None) -> dict:
    bool_query: dict = {"filter": [*parsed.filters, *(extra_filters or [])]}
    if parsed.must:
        bool_query["must"] = parsed.must
    if parsed.should:
        bool_query["should"] = parsed.should
        if not parsed.must:
            bool_query["minimum_should_match"] = 1
    if parsed.must_not:
        bool_query["must_not"] = parsed.must_not
    if not parsed.must and not parsed.should:
        bool_query["must"] = [{"match_all": {}}]
    return {"bool": bool_query}
