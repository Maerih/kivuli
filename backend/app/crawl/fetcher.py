"""Fetching untrusted pages. This module runs only in the crawler container.

Rules enforced here, independent of the network policy around the container:
  * GET only. No forms, no logins, no cookies carried between requests.
  * Text only. Anything that is not HTML, plain text, JSON or a feed is refused
    before the body is read, so archives, dumps and media are never downloaded.
  * Hard size and time limits.
  * Hostnames only, resolved by the proxy. Never an IP literal, never an internal
    name - so a hostile page cannot steer the crawler at infrastructure.
  * Every hop of a redirect is validated again and must stay on the same site.
"""
import hashlib
import ipaddress
import re
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

import httpx

from app.config import get_settings
from app.extract.iocs import is_onion_v3, registered_domain

ALLOWED_TYPES = (
    "text/html", "application/xhtml+xml", "text/plain", "application/json", "application/xml", "text/xml",
    "application/rss+xml", "application/atom+xml", "application/feed+json", "application/ld+json",
)
_INTERNAL_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".home", ".arpa", ".corp", ".test", ".invalid", ".example")
_SURFACE_PORTS = {None, 80, 443, 8080, 8443}
_KEPT_HEADERS = ("content-type", "content-length", "last-modified", "etag", "server", "date", "content-language")


@dataclass
class FetchResult:
    url: str
    final_url: str = ""
    ok: bool = False
    http_status: int | None = None
    content_type: str = ""
    body: str = ""
    raw_sha256: str = ""
    bytes: int = 0
    truncated: bool = False
    elapsed_ms: int = 0
    error: str = ""
    transient: bool = False
    headers: dict = field(default_factory=dict)
    fetched_at: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


def validate_url(url: str) -> tuple[bool, str, str, str]:
    """Return (ok, reason, host, network)."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return False, "malformed URL", "", ""
    host = (parts.hostname or "").lower().rstrip(".")
    if parts.scheme not in ("http", "https"):
        return False, "only http and https are fetched", host, ""
    if not host or parts.username or parts.password:
        return False, "URL must have a host and no embedded credentials", host, ""
    try:
        ipaddress.ip_address(host.strip("[]"))
        return False, "IP-literal URLs are never fetched", host, ""
    except ValueError:
        pass
    if "." not in host or host.endswith(_INTERNAL_SUFFIXES):
        return False, "internal or single-label hostnames are never fetched", host, ""
    if host.endswith(".onion"):
        if not is_onion_v3(host):
            return False, "not a valid v3 onion address", host, ""
        return True, "", host, "onion"
    if not registered_domain(host):
        return False, "not a public hostname", host, ""
    if port not in _SURFACE_PORTS:
        return False, "non-web port", host, ""
    return True, "", host, "surface"


def same_site(a: str, b: str) -> bool:
    return registered_domain(a) == registered_domain(b) != ""


def _client(route: str, onion: bool, timeout: float) -> httpx.Client:
    settings = get_settings()
    proxy = settings.tor_socks_url if route == "tor" else settings.egress_proxy_url
    kwargs = dict(
        follow_redirects=False,
        timeout=httpx.Timeout(timeout, connect=min(timeout, 45)),
        # Hidden services are authenticated by their address; most use self-signed or no TLS.
        verify=not onion,
        headers={
            "User-Agent": settings.tor_user_agent if route == "tor" else settings.direct_user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.9,text/plain;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
        },
        trust_env=False,
    )
    try:
        return httpx.Client(proxy=proxy, **kwargs)
    except ValueError:
        # Older httpx spells remote-DNS SOCKS as socks5://; the hostname is still resolved by the proxy.
        return httpx.Client(proxy=proxy.replace("socks5h://", "socks5://"), **kwargs)


def _charset(content_type: str, raw: bytes) -> str:
    if m := re.search(r"charset=([\w-]+)", content_type, re.I):
        return m.group(1)
    if m := re.search(rb"<meta[^>]+charset=[\"']?([\w-]+)", raw[:4096], re.I):
        return m.group(1).decode("ascii", "replace")
    return "utf-8"


def fetch(url: str, route: str = "tor", max_bytes: int | None = None, timeout: float | None = None) -> FetchResult:
    settings = get_settings()
    max_bytes = max_bytes or settings.crawl_max_bytes
    timeout = timeout or settings.crawl_timeout_seconds
    result = FetchResult(url=url, fetched_at=datetime.now(timezone.utc).isoformat())

    ok, reason, host, network = validate_url(url)
    if not ok:
        result.error = f"refused: {reason}"
        return result
    onion = network == "onion"
    if onion:
        route = "tor"
    if route == "direct" and not url.lower().startswith("https://"):
        result.error = "refused: direct egress is HTTPS only"
        return result

    started = time.monotonic()
    current = url
    try:
        with _client(route, onion, timeout) as client:
            for _hop in range(settings.crawl_max_redirects + 1):
                with client.stream("GET", current) as resp:
                    if resp.status_code in (301, 302, 303, 307, 308) and resp.headers.get("location"):
                        target = urljoin(current, resp.headers["location"])
                        t_ok, t_reason, t_host, t_network = validate_url(target)
                        if not t_ok:
                            result.error = f"refused redirect: {t_reason}"
                            break
                        if t_network != network or not same_site(host, t_host):
                            result.error = f"refused redirect off-site to {t_host}"
                            break
                        if route == "direct" and not target.lower().startswith("https://"):
                            result.error = "refused redirect to plain HTTP"
                            break
                        current = target
                        continue

                    result.http_status = resp.status_code
                    result.final_url = current
                    result.content_type = resp.headers.get("content-type", "").split(";")[0].strip().lower()
                    result.headers = {k: resp.headers[k] for k in _KEPT_HEADERS if k in resp.headers}
                    if result.content_type and not result.content_type.startswith(ALLOWED_TYPES):
                        result.error = f"refused: content type {result.content_type} is not collected"
                        break
                    declared = resp.headers.get("content-length", "")
                    if not result.content_type and declared.isdigit() and int(declared) > max_bytes:
                        result.error = "refused: untyped response larger than the size limit"
                        break

                    chunks, size = [], 0
                    for chunk in resp.iter_bytes(65536):
                        size += len(chunk)
                        if size > max_bytes:
                            chunks.append(chunk[: max_bytes - (size - len(chunk))])
                            result.truncated = True
                            break
                        chunks.append(chunk)
                        if time.monotonic() - started > timeout * 2:
                            result.truncated = True
                            break
                    raw = b"".join(chunks)
                    if b"\x00" in raw[:2048]:
                        result.error = "refused: binary content"
                        break
                    result.bytes = len(raw)
                    result.raw_sha256 = hashlib.sha256(raw).hexdigest()
                    try:
                        result.body = raw.decode(_charset(resp.headers.get("content-type", ""), raw), "replace")
                    except LookupError:
                        result.body = raw.decode("utf-8", "replace")
                    result.ok = 200 <= resp.status_code < 300
                    if not result.ok:
                        result.error = f"HTTP {resp.status_code}"
                        result.transient = resp.status_code in (408, 425, 429, 500, 502, 503, 504)
                    break
            else:
                result.error = "too many redirects"
    except (httpx.TimeoutException, httpx.ConnectError, httpx.ProxyError, httpx.RemoteProtocolError, httpx.ReadError) as exc:
        result.error = f"{type(exc).__name__}: {str(exc)[:200]}".rstrip(": ")
        result.transient = True
    except httpx.HTTPError as exc:
        result.error = f"{type(exc).__name__}: {str(exc)[:200]}".rstrip(": ")
    except Exception as exc:  # a hostile server must not be able to crash the worker
        result.error = f"{type(exc).__name__}: {str(exc)[:200]}".rstrip(": ")
    result.elapsed_ms = int((time.monotonic() - started) * 1000)
    return result
