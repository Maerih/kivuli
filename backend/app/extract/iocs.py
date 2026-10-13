"""Indicator extraction. Pure functions, no I/O.

Indicators are *recorded*, never contacted: nothing in the platform resolves,
probes or connects to a value extracted here.
"""
import hashlib
import ipaddress
import re
from dataclasses import dataclass

import tldextract

# Bundled public-suffix snapshot only; never fetches the list at runtime.
_tld = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

IOC_TYPES = ("domain", "onion", "url", "ip", "email", "hash", "cve", "crypto", "username")
MAX_PER_TYPE = 400  # a single combo-list page can hold 100k addresses

_REFANG = [
    (re.compile(r"\bh(?:xx|tt)p(s?)\[?:\]?//", re.I), r"http\1://"),
    (re.compile(r"\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*\.\s*\}", re.I), "."),
    (re.compile(r"\[\s*(?:@|at)\s*\]|\(\s*at\s*\)", re.I), "@"),
    (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\[:\]"), ":"),
]


def refang(text: str) -> str:
    """Undo common defanging (hxxp, [.], [at]) so indicators can be parsed."""
    for pattern, repl in _REFANG:
        text = pattern.sub(repl, text)
    return text


def defang(value: str) -> str:
    """Make an indicator safe to paste into email or chat."""
    value = re.sub(r"^http", "hxxp", value, flags=re.I)
    return value.replace("://", "[://]").replace(".", "[.]").replace("@", "[@]")


_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
RE_URL = re.compile(r"\bhttps?://[^\s<>\"'`\\^{}|\[\]]{3,1000}", re.I)
RE_EMAIL = re.compile(rf"(?<![\w.+%-])([a-z0-9][a-z0-9._%+-]{{0,63}})@((?:{_LABEL}\.)+[a-z]{{2,24}})(?![\w-])", re.I)
RE_DOMAIN = re.compile(rf"(?<![\w@./-])((?:{_LABEL}\.)+[a-z][a-z0-9-]{{1,23}})(?![\w-]|\.[a-z0-9])", re.I)
RE_IPV4 = re.compile(
    r"(?<![\w.])((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})(?!\.?\d|\w)"
)
RE_SHA256 = re.compile(r"(?<![a-f0-9])[a-f0-9]{64}(?![a-f0-9])", re.I)
RE_SHA1 = re.compile(r"(?<![a-f0-9x])[a-f0-9]{40}(?![a-f0-9])", re.I)
RE_MD5 = re.compile(r"(?<![a-f0-9])[a-f0-9]{32}(?![a-f0-9])", re.I)
RE_CVE = re.compile(r"\bCVE[-_ ]?(\d{4})[-_](\d{4,7})\b", re.I)
RE_BTC = re.compile(r"(?<![A-Za-z0-9])([13][a-km-zA-HJ-NP-Z1-9]{25,34})(?![A-Za-z0-9])")
RE_BECH32 = re.compile(r"(?<![A-Za-z0-9])(bc1[ac-hj-np-z02-9]{11,71})(?![A-Za-z0-9])")
RE_ETH = re.compile(r"(?<![A-Za-z0-9])(0x[a-fA-F0-9]{40})(?![A-Za-z0-9])")
RE_XMR = re.compile(r"(?<![A-Za-z0-9])([48][0-9AB][1-9A-HJ-NP-Za-km-z]{93})(?![A-Za-z0-9])")
RE_TELEGRAM = re.compile(r"(?:t\.me|telegram\.me)/(?!joinchat|share|s/)\+?([A-Za-z][A-Za-z0-9_]{3,31})", re.I)
RE_LABELLED_HANDLE = re.compile(
    r"\b(?:telegram|tg|jabber|xmpp|tox|username|user|author|seller|posted by)\s*[:=]\s*@?"
    r"([A-Za-z][A-Za-z0-9_.-]{2,31})",
    re.I,
)
RE_AT_HANDLE = re.compile(r"(?<![\w@/.])@([A-Za-z][A-Za-z0-9_]{3,31})(?![\w@.]*\.[a-z]{2,})")

# TLDs that are usually a file extension when seen bare in running text.
_FILE_EXT_TLDS = {"zip", "mov", "md", "py", "sh", "rs", "so", "ps", "cab"}
# TLDs that are also short English words: "finished.It was" is a missing space, not a domain.
_WORD_TLDS = {"in", "do", "to", "is", "it", "at", "be", "by", "no", "me", "my", "am", "as", "us"}
_TRAILING = ".,;:!?)]}'\"…"
_HANDLE_STOP = {"admin", "everyone", "here", "channel", "media", "gmail", "yahoo", "none", "null", "unknown", "anonymous", "the", "and", "for", "not", "name", "password", "staff", "team", "guest"}

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _btc_checksum_ok(addr: str) -> bool:
    try:
        n = 0
        for ch in addr:
            n = n * 58 + _B58.index(ch)
        raw = n.to_bytes(25, "big")
    except (ValueError, OverflowError):
        return False
    return hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4] == raw[21:]


def is_onion_v3(host: str) -> bool:
    return bool(re.fullmatch(r"(?:[a-z0-9-]+\.)*[a-z2-7]{56}\.onion", host.lower()))


def registered_domain(host: str) -> str:
    """example.co.ke for mail.example.co.ke; the bare onion address for onion hosts."""
    host = host.lower().strip(".")
    if host.endswith(".onion"):
        return ".".join(host.split(".")[-2:])
    ext = _tld(host)
    if not ext.suffix or not ext.domain:
        return ""
    return f"{ext.domain}.{ext.suffix}"


def valid_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_global


def classify_host(host: str) -> tuple[str, str] | None:
    """Return (ioc_type, normalised_value) for a hostname, or None if it is not one."""
    host = host.lower().strip(".")
    if not host or len(host) > 253:
        return None
    if host.endswith(".onion"):
        return ("onion", host) if is_onion_v3(host) else None
    if re.fullmatch(r"[\d.]+", host):
        return ("ip", host) if valid_public_ip(host) else None
    if registered_domain(host):
        return ("domain", host)
    return None


@dataclass
class Indicator:
    type: str
    value: str
    count: int = 1
    context: str = ""


class _Collector:
    def __init__(self, text: str):
        self.text = text
        self.items: dict[tuple[str, str], Indicator] = {}
        self.per_type: dict[str, int] = {}
        self.truncated: set[str] = set()

    def add(self, kind: str, value: str, pos: int) -> None:
        key = (kind, value)
        existing = self.items.get(key)
        if existing:
            existing.count += 1
            return
        if self.per_type.get(kind, 0) >= MAX_PER_TYPE:
            self.truncated.add(kind)
            return
        self.per_type[kind] = self.per_type.get(kind, 0) + 1
        start, end = max(0, pos - 70), min(len(self.text), pos + len(value) + 70)
        context = " ".join(self.text[start:end].split())
        self.items[key] = Indicator(kind, value, 1, context)


def _blank(text: str, spans: list[tuple[int, int]]) -> str:
    if not spans:
        return text
    chars = list(text)
    for start, end in spans:
        chars[start:end] = " " * (end - start)
    return "".join(chars)


def extract_iocs(text: str) -> tuple[list[Indicator], set[str]]:
    """Extract indicators from already-refanged text.

    Returns (indicators, types that hit the per-document cap).
    """
    col = _Collector(text)
    spans: list[tuple[int, int]] = []

    for m in RE_URL.finditer(text):
        url = m.group(0).rstrip(_TRAILING)
        host_match = re.match(r"https?://(?:[^/@\s]*@)?([^/:?#\s]+)", url, re.I)
        if not host_match:
            continue
        host = classify_host(host_match.group(1))
        if not host:
            continue
        col.add("url", url, m.start())
        col.add(host[0], host[1], m.start())
        spans.append((m.start(), m.start() + len(url)))

    for m in RE_EMAIL.finditer(text):
        domain = m.group(2).lower()
        if not registered_domain(domain) or domain.endswith(".onion") and not is_onion_v3(domain):
            continue
        col.add("email", f"{m.group(1).lower()}@{domain}", m.start())
        spans.append(m.span())

    rest = _blank(text, spans)
    spans = []

    for m in RE_ETH.finditer(rest):
        col.add("crypto", m.group(1).lower(), m.start())
        spans.append(m.span())
    for m in RE_XMR.finditer(rest):
        col.add("crypto", m.group(1), m.start())
        spans.append(m.span())
    for m in RE_BECH32.finditer(rest):
        col.add("crypto", m.group(1), m.start())
    for m in RE_BTC.finditer(rest):
        if _btc_checksum_ok(m.group(1)):
            col.add("crypto", m.group(1), m.start())
    rest = _blank(rest, spans)

    for pattern in (RE_SHA256, RE_SHA1, RE_MD5):
        for m in pattern.finditer(rest):
            value = m.group(0).lower()
            if len(set(value)) > 4 and not value.isdigit():  # skip padding and counters
                col.add("hash", value, m.start())

    for m in RE_CVE.finditer(rest):
        col.add("cve", f"CVE-{m.group(1)}-{m.group(2)}", m.start())

    for m in RE_IPV4.finditer(rest):
        if valid_public_ip(m.group(1)):
            col.add("ip", m.group(1), m.start())

    for m in RE_DOMAIN.finditer(rest):
        raw = m.group(1)
        host = raw.lower()
        kind = classify_host(host)
        if not kind or kind[0] == "ip":
            continue
        if kind[0] == "domain":
            suffix = host.rsplit(".", 1)[-1]
            if host.count(".") == 1:
                if suffix in _FILE_EXT_TLDS:
                    continue
                if suffix in _WORD_TLDS and raw.rsplit(".", 1)[-1] != suffix:
                    continue
            if host.split(".")[0].isdigit():
                continue
        col.add(kind[0], kind[1], m.start())

    for pattern in (RE_TELEGRAM, RE_LABELLED_HANDLE, RE_AT_HANDLE):
        for m in pattern.finditer(rest):
            handle = m.group(1).strip("._-")
            if len(handle) >= 3 and handle.lower() not in _HANDLE_STOP:
                col.add("username", handle, m.start())

    return list(col.items.values()), col.truncated


def detect_indicator(token: str) -> tuple[str, str] | None:
    """Classify a single search token as an indicator, e.g. for query parsing."""
    token = refang(token.strip()).strip(_TRAILING)
    if not token:
        return None
    if m := RE_CVE.fullmatch(token):
        return "cve", f"CVE-{m.group(1)}-{m.group(2)}"
    if RE_EMAIL.fullmatch(token):
        return "email", token.lower()
    if re.match(r"https?://", token, re.I):
        return "url", token
    if re.fullmatch(r"[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}", token, re.I):
        return "hash", token.lower()
    if RE_ETH.fullmatch(token):
        return "crypto", token.lower()
    if RE_BECH32.fullmatch(token) or RE_XMR.fullmatch(token) or (RE_BTC.fullmatch(token) and _btc_checksum_ok(token)):
        return "crypto", token
    if "/" in token:
        try:
            return "cidr", str(ipaddress.ip_network(token, strict=False))
        except ValueError:
            return None
    try:
        return "ip", str(ipaddress.ip_address(token))
    except ValueError:
        pass
    if "." in token and RE_DOMAIN.fullmatch(token):
        kind = classify_host(token)
        if kind and kind[0] in ("domain", "onion"):
            return kind
    return None
