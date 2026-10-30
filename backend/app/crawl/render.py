"""Ask the render container for a page's DOM after its JavaScript ran.

Runs only in the crawler. The URL is validated with the same rules as a plain
fetch before it is handed over, and the answer comes back as an ordinary
FetchResult, so parsing, link-following and indicator extraction treat a
rendered page exactly like a fetched one.
"""
import hashlib
from datetime import datetime, timezone

import httpx

from app.config import get_settings
from app.crawl.fetcher import FetchResult, validate_url


def render(url: str, route: str = "tor", max_bytes: int | None = None) -> FetchResult:
    settings = get_settings()
    result = FetchResult(url=url, final_url=url, fetched_at=datetime.now(timezone.utc).isoformat())
    ok, reason, _host, network = validate_url(url)
    if not ok:
        result.error = f"refused: {reason}"
        return result
    if network == "onion":
        route = "tor"
    if route == "direct" and not url.lower().startswith("https://"):
        result.error = "refused: direct egress is HTTPS only"
        return result
    timeout = settings.render_timeout_seconds
    try:
        # The renderer is on the internal network: no proxy, and none taken from the environment.
        with httpx.Client(timeout=timeout + 30, trust_env=False) as client:
            resp = client.post(f"{settings.render_url}/render", json={"url": url, "route": route, "timeout": timeout})
        data = resp.json() if resp.status_code == 200 else {"error": f"renderer returned HTTP {resp.status_code}"}
    except (httpx.HTTPError, ValueError) as exc:
        result.error = f"renderer unavailable: {type(exc).__name__}"
        result.transient = True
        return result
    result.elapsed_ms = int(data.get("elapsed_ms") or 0)
    if not data.get("ok"):
        result.error = str(data.get("error") or "rendering failed")[:300]
        # A slow onion or a busy renderer is worth another try; a refusal is not.
        result.transient = not result.error.startswith("refused")
        return result
    body = str(data.get("body") or "")
    raw = body.encode("utf-8")
    limit = max_bytes or settings.crawl_max_bytes
    if len(raw) > limit:
        raw = raw[:limit]
        body = raw.decode("utf-8", "ignore")
        result.truncated = True
    result.truncated = result.truncated or bool(data.get("truncated"))
    result.ok = True
    # The browser does not report the status code of a dumped DOM; a page that rendered is recorded as 200.
    result.http_status = 200
    result.content_type = "text/html"
    result.headers = {"x-kivuli-rendered": "javascript"}
    result.body = body
    result.bytes = len(raw)
    result.raw_sha256 = hashlib.sha256(raw).hexdigest()
    return result
