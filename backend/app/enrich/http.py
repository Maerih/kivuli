"""Outbound HTTP for enrichment. Runs only in the enricher container.

Every request leaves through the allowlisting egress proxy: HTTPS only, no
redirects, bounded size. Providers are asked *about* an indicator; nothing here
ever connects to the indicator itself.
"""
import json
from typing import Any

import httpx

from app.config import get_settings


class EnrichError(Exception):
    pass


def api_request(url: str, *, headers: dict | None = None, params: dict | None = None, timeout: float = 45.0,
                max_bytes: int = 8_000_000) -> tuple[int, Any]:
    """GET a JSON API. Returns (status, parsed body); body is None when it is not JSON."""
    settings = get_settings()
    if not url.lower().startswith("https://"):
        raise EnrichError("enrichment requests are HTTPS only")
    try:
        with httpx.Client(proxy=settings.egress_proxy_url, follow_redirects=False, timeout=httpx.Timeout(timeout, connect=20), trust_env=False,
                          headers={"User-Agent": settings.direct_user_agent, "Accept": "application/json"}) as client:
            with client.stream("GET", url, headers=headers, params=params) as resp:
                chunks, size = [], 0
                for chunk in resp.iter_bytes(65536):
                    size += len(chunk)
                    if size > max_bytes:
                        raise EnrichError("response exceeds the size limit")
                    chunks.append(chunk)
                raw = b"".join(chunks)
                try:
                    return resp.status_code, json.loads(raw) if raw else None
                except ValueError:
                    return resp.status_code, None
    except httpx.ProxyError as exc:
        raise EnrichError(f"egress proxy refused the request (is the host in EGRESS_ALLOW_HOSTS?): {str(exc)[:120]}") from None
    except httpx.HTTPError as exc:
        raise EnrichError(f"{type(exc).__name__}: {str(exc)[:160]}".rstrip(": ")) from None
