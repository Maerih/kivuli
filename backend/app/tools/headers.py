"""Email header analysis: where a message really came from and whether it is who it says.

Works on headers pasted by an analyst (a whole message is fine; only the header
block is read). Purely offline: no address, host or link in the message is
resolved or contacted. What it reports:

  * the delivery path, hop by hop, oldest first, with the delay at each hop
  * the originating address: the first public IP in the path
  * SPF, DKIM and DMARC results as the receiving server recorded them
  * mismatches typical of spoofing and phishing: From vs Return-Path, Reply-To
    to another domain, a display name that shows a different address, DKIM
    signed by an unrelated domain, a Message-ID from elsewhere
  * the indicators found in the headers
"""
import ipaddress
import re
from email.parser import HeaderParser
from email.utils import getaddresses, parseaddr, parsedate_to_datetime

from app.extract.iocs import extract_iocs, refang, registered_domain

MAX_INPUT = 256_000

_RECEIVED_FROM = re.compile(r"\bfrom\s+(\S+)(?:\s+\(([^)]*)\))?", re.I)
_RECEIVED_BY = re.compile(r"\bby\s+(\S+)", re.I)
_RECEIVED_WITH = re.compile(r"\bwith\s+(\S+)", re.I)
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6 = re.compile(r"\b(?:IPv6:)?([0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7})\b", re.I)
_AUTH = re.compile(r"\b(spf|dkim|dmarc|arc|compauth)\s*=\s*([a-z]+)", re.I)
_AUTH_DOMAIN = {
    "spf": re.compile(r"smtp\.mailfrom=([^\s;]+)", re.I),
    "dkim": re.compile(r"header\.(?:d|i)=@?([^\s;]+)", re.I),
    "dmarc": re.compile(r"header\.from=([^\s;]+)", re.I),
}
_DKIM_D = re.compile(r"\bd=([^;\s]+)", re.I)
_GOOD = {"pass"}
_BAD = {"fail", "softfail", "permerror", "temperror", "none", "neutral", "policy", "hardfail"}


def _domain(address: str) -> str:
    address = (address or "").strip().strip("<>").lower()
    host = address.rsplit("@", 1)[-1] if "@" in address else address
    return registered_domain(host.strip(".")) or host


def _public_ip(text: str) -> str:
    candidates = _IPV4.findall(text) + [m for m in _IPV6.findall(text) if m.count(":") >= 2]
    for raw in candidates:
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if ip.is_global:
            return str(ip)
    return ""


def _when(value: str):
    try:
        return parsedate_to_datetime(value.strip())
    except (TypeError, ValueError, IndexError):
        return None


def _hops(received: list[str]) -> list[dict]:
    """Received headers are prepended by each server, so the last one is the first hop."""
    hops = []
    for raw in reversed(received):
        text = " ".join(raw.split())
        stamp = _when(text.rsplit(";", 1)[1]) if ";" in text else None
        m_from = _RECEIVED_FROM.search(text)
        m_by = _RECEIVED_BY.search(text)
        m_with = _RECEIVED_WITH.search(text)
        hops.append({
            "from": m_from.group(1) if m_from else "",
            "from_detail": (m_from.group(2) or "") if m_from else "",
            "by": m_by.group(1).rstrip(";") if m_by else "",
            "with": m_with.group(1).rstrip(";") if m_with else "",
            "ip": _public_ip(m_from.group(0) if m_from else text) or _public_ip(text.split(" by ", 1)[0]),
            "time": stamp.isoformat() if stamp else None,
            "delay_seconds": None,
            "raw": text[:600],
        })
    previous = None
    for hop in hops:
        current = _when_iso(hop["time"])
        if current and previous:
            hop["delay_seconds"] = int((current - previous).total_seconds())
        previous = current or previous
    return hops


def _when_iso(value):
    from datetime import datetime
    try:
        return datetime.fromisoformat(value) if value else None
    except ValueError:
        return None


def _auth(msg) -> dict:
    """The receiving server's verdicts. Prefer Authentication-Results; fall back to Received-SPF."""
    out: dict[str, dict] = {}
    for header in msg.get_all("Authentication-Results", []) + msg.get_all("ARC-Authentication-Results", []):
        text = " ".join(str(header).split())
        for name, result in _AUTH.findall(text):
            name = name.lower()
            if name in out:
                continue
            m = _AUTH_DOMAIN.get(name)
            dm = m.search(text) if m else None
            out[name] = {"result": result.lower(), "domain": dm.group(1).lower().strip(".") if dm else ""}
    if "spf" not in out and (spf := msg.get("Received-SPF")):
        out["spf"] = {"result": str(spf).split()[0].lower() if str(spf).split() else "", "domain": ""}
    return out


def analyse(text: str) -> dict:
    text = (text or "")[:MAX_INPUT]
    # Pasted headers often have Windows line endings or leading blank lines.
    text = text.replace("\r\n", "\n").lstrip("\n")
    msg = HeaderParser().parsestr(text, headersonly=True)
    if not msg.keys():
        return {"ok": False, "error": "No email headers found. Paste the full header block (\"Show original\" / \"View source\")."}

    def h(name: str) -> str:
        return " ".join(str(msg.get(name, "")).split())

    from_name, from_addr = parseaddr(h("From"))
    _, return_path = parseaddr(h("Return-Path"))
    _, sender = parseaddr(h("Sender"))
    reply_to = [a for _, a in getaddresses(msg.get_all("Reply-To", [])) if a]
    to = [a for _, a in getaddresses(msg.get_all("To", []) + msg.get_all("Cc", [])) if a]
    message_id = h("Message-ID").strip("<>")
    hops = _hops([str(r) for r in msg.get_all("Received", [])])
    auth = _auth(msg)
    dkim_domains = sorted({_DKIM_D.search(" ".join(str(s).split())).group(1).lower()
                           for s in msg.get_all("DKIM-Signature", []) if _DKIM_D.search(" ".join(str(s).split()))})
    origin = next((hop for hop in hops if hop["ip"]), None)

    from_dom = _domain(from_addr)
    warnings: list[dict] = []

    def warn(level: str, title: str, detail: str) -> None:
        warnings.append({"level": level, "title": title, "detail": detail})

    if return_path and from_dom and _domain(return_path) != from_dom:
        warn("medium", "Return-Path domain differs from From",
             f"Bounces go to {_domain(return_path)} while the message claims to be from {from_dom}. Common for mailing services, and for spoofing.")
    for addr in reply_to:
        if from_dom and _domain(addr) != from_dom:
            warn("high", "Replies go to another domain", f"Reply-To is {addr}; the sender is {from_addr}. A classic phishing and BEC pattern.")
    if from_name and (shown := re.search(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", from_name)) and shown.group(0).lower() != from_addr.lower():
        warn("high", "Display name shows a different address", f"The name reads {shown.group(0)} but the real sender is {from_addr}.")
    for name in ("spf", "dkim", "dmarc"):
        result = auth.get(name, {}).get("result")
        if result in _BAD:
            warn("high" if name == "dmarc" or result in ("fail", "hardfail") else "medium",
                 f"{name.upper()} {result}", f"The receiving server recorded {name.upper()}={result}.")
    if "dmarc" not in auth and auth:
        warn("low", "No DMARC result recorded", "The receiving server did not record a DMARC verdict.")
    if dkim_domains and from_dom and not any(_domain(d) == from_dom for d in dkim_domains):
        warn("medium", "DKIM signed by an unrelated domain", f"Signed by {', '.join(dkim_domains)}, not {from_dom}.")
    if message_id and "@" in message_id and from_dom and _domain(message_id.rsplit("@", 1)[1]) != from_dom:
        warn("low", "Message-ID from another domain", f"Generated by {message_id.rsplit('@', 1)[1]}. Normal for hosted mail; worth noting otherwise.")
    if sender and from_dom and _domain(sender) != from_dom:
        warn("medium", "Sent on behalf of another domain", f"Sender header is {sender}.")
    for hop in hops:
        if hop["delay_seconds"] is not None and hop["delay_seconds"] < -300:
            warn("low", "Clock goes backwards in the path", f"A hop at {hop['by'] or 'an unnamed server'} is stamped before the one before it; a header may be forged.")
            break

    header_text = refang("\n".join(f"{k}: {v}" for k, v in msg.items()))
    indicators, _ = extract_iocs(header_text)
    return {
        "ok": True,
        "summary": {
            "from": from_addr, "from_name": from_name, "return_path": return_path, "reply_to": reply_to, "sender": sender,
            "to": to[:20], "subject": h("Subject")[:500], "date": h("Date"), "message_id": message_id,
            "mailer": h("X-Mailer") or h("User-Agent"), "hops": len(hops),
        },
        "origin": {"ip": origin["ip"], "host": origin["from"], "detail": origin["from_detail"]} if origin else None,
        "auth": auth, "dkim_domains": dkim_domains, "hops": hops, "warnings": warnings,
        "indicators": [{"type": i.type, "value": i.value} for i in indicators][:200],
    }
