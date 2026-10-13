"""Watchlist matching: decides whether a finding concerns something an analyst watches."""
import ipaddress
import re
from dataclasses import dataclass, field

from app.extract.risk import SEVERITY_ORDER
from app.intel.lookalike import lookalike_reason

COMPROMISE_TYPES = {"ransomware", "data_breach", "credential_leak", "access_sale", "defacement"}
ASSET_KINDS = {"domain", "email", "organization", "ip", "brand", "vendor", "executive"}


@dataclass
class DocView:
    title: str
    text: str
    threat_type: str
    severity: str
    confidence: int
    has_credentials: bool
    iocs: dict[str, dict[str, str]] = field(default_factory=dict)  # type -> {value: context}
    actors: set[str] = field(default_factory=set)  # lower-cased names and aliases
    organizations: set[str] = field(default_factory=set)

    @property
    def haystack(self) -> str:
        return f"{self.title}\n{self.text}"


@dataclass
class Match:
    matched: str
    snippet: str
    credential_exposed: bool = False
    lookalike: str = ""  # why a domain is considered an imitation


def _phrase_pattern(value: str) -> re.Pattern:
    words = [re.escape(w) for w in value.split()]
    return re.compile(r"(?<![\w@.-])" + r"[\s\-_.,]*".join(words) + r"(?![\w@-])", re.I)


def _snippet(text: str, start: int, end: int, radius: int = 110) -> str:
    left, right = max(0, start - radius), min(len(text), end + radius)
    return ("…" if left else "") + " ".join(text[left:right].split()) + ("…" if right < len(text) else "")


def _in_text(view: DocView, value: str) -> Match | None:
    if m := _phrase_pattern(value).search(view.haystack):
        return Match(m.group(0), _snippet(view.haystack, m.start(), m.end()))
    return None


def _exposed(context: str, account: str) -> bool:
    """True when the capture showed this account next to a (now redacted) password."""
    return bool(re.search(re.escape(account) + r"\s*[:;|]\s*\[REDACTED\]", context, re.I))


def _lookalike(view: DocView, brand: str) -> Match | None:
    """A domain in this finding that imitates ``brand``."""
    for ioc_type in ("domain", "url"):
        for candidate, context in view.iocs.get(ioc_type, {}).items():
            host = candidate if ioc_type == "domain" else re.sub(r"^https?://([^/:?#]+).*$", r"\1", candidate, flags=re.I)
            if reason := lookalike_reason(host, brand):
                return Match(host, context, lookalike=reason)
    return None


def match_watch(kind: str, value: str, view: DocView, lookalikes: bool = False) -> Match | None:
    """``lookalikes`` also reports domains imitating the value (for owned domains and brands)."""
    value = value.strip()
    lowered = value.lower()
    if not value:
        return None

    if kind in ("keyword", "executive"):
        return _in_text(view, value)

    if kind == "brand":
        return _in_text(view, value) or _lookalike(view, value)

    if kind == "technology":
        # A product you run only matters when the finding is about a weakness in it.
        if view.threat_type != "vulnerability" and not view.iocs.get("cve"):
            return None
        return _in_text(view, value)

    if kind == "vendor":
        kind = "organization"

    if kind == "email":
        context = view.iocs.get("email", {}).get(lowered)
        if context is not None:
            return Match(lowered, context, _exposed(context, lowered))
        return _in_text(view, value)

    if kind == "domain":
        domain = lowered.lstrip("*.")
        for email, context in view.iocs.get("email", {}).items():
            host = email.rsplit("@", 1)[-1]
            if host == domain or host.endswith("." + domain):
                exposed = _exposed(context, email)
                if exposed or not view.has_credentials:
                    return Match(email, context, exposed)
        for ioc_type in ("domain", "url"):
            for candidate, context in view.iocs.get(ioc_type, {}).items():
                host = candidate if ioc_type == "domain" else re.sub(r"^https?://([^/:?#]+).*$", r"\1", candidate, flags=re.I)
                if host == domain or host.endswith("." + domain):
                    return Match(candidate, context)
        for email, context in view.iocs.get("email", {}).items():
            host = email.rsplit("@", 1)[-1]
            if host == domain or host.endswith("." + domain):
                return Match(email, context, _exposed(context, email))
        return _in_text(view, domain) or (_lookalike(view, domain) if lookalikes else None)

    if kind == "ip":
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return None
        for candidate, context in view.iocs.get("ip", {}).items():
            try:
                if ipaddress.ip_address(candidate) in network:
                    return Match(candidate, context)
            except ValueError:
                continue
        return None

    if kind in ("organization", "actor"):
        names = view.organizations if kind == "organization" else view.actors
        if lowered in names:
            found = _in_text(view, value)
            return found or Match(value, " ".join(view.haystack[:240].split()))
        return _in_text(view, value) if len(value) >= 4 else None

    if kind in ("cve", "hash", "crypto", "username"):
        table = view.iocs.get(kind, {})
        for candidate, context in table.items():
            if candidate.lower() == lowered:
                return Match(candidate, context)
        return None

    return None


def alert_category(kind: str, view: DocView, match: Match) -> str:
    if match.lookalike:
        return "lookalike"
    if kind == "technology":
        return "vulnerability"
    if kind in ASSET_KINDS and (match.credential_exposed or view.threat_type in COMPROMISE_TYPES):
        return "compromise"
    return "mention"


def alert_severity(category: str, view: DocView, match: Match) -> str:
    level = SEVERITY_ORDER.index(view.severity)
    if match.credential_exposed:
        level = max(level, SEVERITY_ORDER.index("high"))
    elif category == "compromise" and view.confidence >= 60:
        level = max(level, SEVERITY_ORDER.index("medium"))
    return SEVERITY_ORDER[level]
