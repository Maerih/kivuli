"""Render one page with headless Chromium and return the DOM after its scripts ran.

POST /render {"url": ..., "route": "tor" | "direct", "timeout": seconds}
  -> {"ok": bool, "body": str, "bytes": int, "truncated": bool, "error": str, "elapsed_ms": int}

The crawler has already validated the URL; it is checked again here because this
service must never be pointed at anything but a public web or onion address.

What the browser is allowed to do:
  * Every request goes through a proxy: Tor for onion sites and the Tor route,
    the allow-listing egress proxy for the direct route. Local name resolution
    is switched off, so nothing bypasses the proxy, and the container has no
    internet route of its own in any case.
  * No images, media, plugins, extensions, downloads, sync, crash reports or
    background updates. Nothing is kept: the profile lives in tmpfs and is
    deleted after each page.
  * Chromium's own sandbox is off (it needs privileges the hardened container
    does not grant). The container is the sandbox: read-only root, all
    capabilities dropped, unprivileged user, no secrets, no database or queue
    access, and a fresh browser process per page.
"""
import ipaddress
import json
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

TOR_PROXY = os.environ.get("RENDER_TOR_PROXY", "socks5://tor:9050")
EGRESS_PROXY = os.environ.get("RENDER_EGRESS_PROXY", "http://egress:8888")
MAX_BYTES = int(os.environ.get("RENDER_MAX_BYTES", "2000000"))
MAX_TIMEOUT = int(os.environ.get("RENDER_TIMEOUT_SECONDS", "90"))
# Chromium is heavy: a small number of pages at once, the rest wait their turn.
SLOTS = threading.BoundedSemaphore(int(os.environ.get("RENDER_CONCURRENCY", "2")))
BROWSER = next((p for p in ("/usr/bin/chromium-browser", "/usr/bin/chromium") if os.path.exists(p)), "chromium")


def check_url(url: str) -> str:
    """Return an error message, or "" when the URL may be rendered."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "malformed URL"
    host = (parts.hostname or "").lower().rstrip(".")
    if parts.scheme not in ("http", "https") or not host or parts.username or parts.password:
        return "only http(s) URLs with a host and no credentials are rendered"
    try:
        ipaddress.ip_address(host.strip("[]"))
        return "IP-literal URLs are never rendered"
    except ValueError:
        pass
    if "." not in host:
        return "single-label hostnames are never rendered"
    return ""


def browser_args(url: str, route: str, profile: str, budget_ms: int) -> list[str]:
    onion = (urlsplit(url).hostname or "").endswith(".onion")
    proxy = TOR_PROXY if onion or route != "direct" else EGRESS_PROXY
    proxy_host = urlsplit(proxy).hostname or ""
    return [
        BROWSER, "--headless=new", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
        f"--user-data-dir={profile}", "--incognito", "--no-first-run", "--no-default-browser-check",
        "--disable-extensions", "--disable-plugins", "--disable-sync", "--disable-background-networking",
        "--disable-component-update", "--disable-default-apps", "--disable-breakpad", "--disable-crash-reporter",
        "--disable-domain-reliability", "--disable-client-side-phishing-detection", "--metrics-recording-only",
        "--mute-audio", "--blink-settings=imagesEnabled=false", "--disable-remote-fonts",
        "--disable-features=MediaRouter,OptimizationHints,Translate,AutofillServerCommunication,DownloadBubble",
        "--webrtc-ip-handling-policy=disable_non_proxied_udp", "--force-webrtc-ip-handling-policy",
        f"--proxy-server={proxy}", "--proxy-bypass-list=<-loopback>",
        # No local DNS at all: names are resolved by the proxy (Tor resolves onion and web names itself).
        f"--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE {proxy_host}",
        f"--virtual-time-budget={budget_ms}", "--dump-dom", url,
    ]


def render(url: str, route: str, timeout: int) -> dict:
    started = time.monotonic()
    out = {"ok": False, "body": "", "bytes": 0, "truncated": False, "error": "", "elapsed_ms": 0}
    if err := check_url(url):
        out["error"] = f"refused: {err}"
        return out
    timeout = max(15, min(timeout or MAX_TIMEOUT, MAX_TIMEOUT))
    profile = tempfile.mkdtemp(prefix="profile-", dir="/tmp")
    try:
        with SLOTS:
            proc = subprocess.Popen(browser_args(url, route, profile, budget_ms=min(15000, timeout * 400)),
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
            try:
                raw, _ = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.communicate()
                out["error"] = f"rendering took longer than {timeout}s"
                return out
            finally:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)  # helpers left behind by the browser
                except ProcessLookupError:
                    pass
    finally:
        shutil.rmtree(profile, ignore_errors=True)
        out["elapsed_ms"] = int((time.monotonic() - started) * 1000)
    if len(raw) > MAX_BYTES:
        raw, out["truncated"] = raw[:MAX_BYTES], True
    body = raw.decode("utf-8", "replace")
    out["bytes"] = len(raw)
    # An unreachable page still dumps an empty document or Chromium's error page.
    stripped = body.replace(" ", "").lower()
    if len(stripped) < 60 or "<body></body>" in stripped and len(stripped) < 120:
        out["error"] = "the page rendered empty (unreachable, or it showed nothing)"
        return out
    if 'id="main-frame-error"' in body or "neterror" in body[:4000].lower() and "err_" in body.lower():
        out["error"] = "the browser could not load the page"
        return out
    out["ok"] = True
    out["body"] = body
    return out


class Handler(BaseHTTPRequestHandler):
    def _send(self, status: int, payload: dict) -> None:
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {"ok": True, "browser": BROWSER})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/render":
            return self._send(404, {"error": "not found"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
            req = json.loads(self.rfile.read(min(length, 8192)) or b"{}")
            url, route, timeout = str(req.get("url", "")), str(req.get("route", "tor")), int(req.get("timeout") or 0)
        except (ValueError, TypeError):
            return self._send(400, {"error": "bad request"})
        self._send(200, render(url, route, timeout))

    def log_message(self, fmt, *args):  # one line per page, no bodies
        print(f"{self.address_string()} {fmt % args}", flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 9300), Handler).serve_forever()
