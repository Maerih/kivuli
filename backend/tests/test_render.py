"""The crawler's client for the JavaScript renderer."""
import httpx
import pytest

from app.crawl import render as render_mod


class _Client:
    """Stands in for httpx.Client, answering every POST with one canned response."""
    answer: object = None
    seen: list = []

    def __init__(self, **kwargs):
        assert kwargs.get("trust_env") is False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def post(self, url, json):
        _Client.seen.append((url, json))
        if isinstance(self.answer, Exception):
            raise self.answer
        return httpx.Response(200, json=self.answer)


@pytest.fixture
def client(monkeypatch):
    _Client.seen = []
    monkeypatch.setattr(render_mod.httpx, "Client", _Client)
    return _Client


def test_rendered_page_becomes_an_ordinary_fetch_result(client):
    client.answer = {"ok": True, "body": "<html><body><h1>Leak list</h1></body></html>", "elapsed_ms": 4200}
    r = render_mod.render("https://example.com/victims", route="direct")
    assert r.ok and r.http_status == 200 and r.content_type == "text/html"
    assert "Leak list" in r.body and r.raw_sha256 and r.bytes == len(r.body)
    assert r.headers["x-kivuli-rendered"] == "javascript"
    assert client.seen[0][1]["route"] == "direct"


def test_onion_is_always_rendered_through_tor(client):
    client.answer = {"ok": True, "body": "<html><body>" + "x" * 100 + "</body></html>"}
    onion = "http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/"
    assert render_mod.render(onion, route="direct").ok
    assert client.seen[0][1]["route"] == "tor"


def test_refused_before_reaching_the_renderer(client):
    for url in ("http://10.0.0.5/", "http://localhost/", "file:///etc/passwd", "http://example.com/"):
        r = render_mod.render(url, route="direct")
        assert not r.ok and r.error.startswith("refused")
    assert client.seen == []


def test_failures_and_size_limit(client):
    client.answer = httpx.ConnectError("down")
    r = render_mod.render("https://example.com/")
    assert not r.ok and r.transient and "renderer unavailable" in r.error

    client.answer = {"ok": False, "error": "rendering took longer than 90s"}
    r = render_mod.render("https://example.com/")
    assert not r.ok and r.transient

    client.answer = {"ok": False, "error": "refused: IP-literal URLs are never rendered"}
    assert not render_mod.render("https://example.com/").transient

    client.answer = {"ok": True, "body": "<p>" + "é" * 5000 + "</p>"}
    r = render_mod.render("https://example.com/", max_bytes=1000)
    assert r.ok and r.truncated and r.bytes <= 1000
