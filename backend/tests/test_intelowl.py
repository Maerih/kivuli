"""IntelOwl: request bodies, refusing scanners, polling a job, summarising its reports."""
from types import SimpleNamespace

import pytest

from app.enrich import intelowl
from app.enrich.http import EnrichError


def _settings(**over):
    base = dict(intelowl_url="https://intelowl.example.org", intelowl_direct=False, intelowl_playbook="FREE_TO_USE_ANALYZERS",
                intelowl_analyzers="", intelowl_tlp="amber")
    return SimpleNamespace(**{**base, **over})


def test_playbook_by_default_and_named_analyzers_when_set(monkeypatch):
    monkeypatch.setattr(intelowl, "get_settings", lambda: _settings())
    path, body = intelowl.request_body("domain", "bad.example.net")
    assert path == "/api/playbook/analyze_multiple_observables"
    assert body["observables"] == [["domain", "bad.example.net"]] and body["playbook_requested"] == "FREE_TO_USE_ANALYZERS" and body["tlp"] == "AMBER"

    monkeypatch.setattr(intelowl, "get_settings", lambda: _settings(intelowl_analyzers="AbuseIPDB, GreyNoiseCommunity"))
    path, body = intelowl.request_body("ip", "203.0.113.9")
    assert path == "/api/analyze_observable" and body["analyzers_requested"] == ["AbuseIPDB", "GreyNoiseCommunity"]


def test_scanning_analyzers_are_refused(monkeypatch):
    monkeypatch.setattr(intelowl, "get_settings", lambda: _settings(intelowl_analyzers="AbuseIPDB,Nmap,Nuclei"))
    with pytest.raises(EnrichError, match="Nmap, Nuclei"):
        intelowl.request_body("ip", "203.0.113.9")


def test_job_flow_and_summary(monkeypatch):
    monkeypatch.setattr(intelowl, "get_settings", lambda: _settings())
    monkeypatch.setattr(intelowl.time, "sleep", lambda s: None)
    calls = []
    job = {"id": 42, "status": "reported_with_fails", "playbook_to_execute": "FREE_TO_USE_ANALYZERS", "analyzer_reports": [
        {"name": "ThreatFox", "status": "SUCCESS", "data_model": {"evaluation": "malicious"}},
        {"name": "Tranco", "status": "SUCCESS", "data_model": {"evaluation": "trusted"}},
        {"name": "Robtex", "status": "SUCCESS", "report": {"x": 1}},
        {"name": "VirusTotal_v3_Get_Observable", "status": "FAILED", "errors": ["no key"]},
    ]}
    answers = iter([(200, {"results": [{"job_id": 42, "status": "pending"}]}), (200, {"id": 42, "status": "running"}), (200, job)])

    def fake_call(method, path, body=None, timeout=60):
        calls.append((method, path))
        return next(answers)

    monkeypatch.setattr(intelowl, "_call", fake_call)
    result = intelowl.lookup("domain", "bad.example.net")
    assert calls == [("POST", "/api/playbook/analyze_multiple_observables"), ("GET", "/api/jobs/42"), ("GET", "/api/jobs/42")]
    assert result["verdict"] == "malicious"
    s = result["summary"]
    assert s["malicious_by"] == ["ThreatFox"] and s["clean_by"] == ["Tranco"] and s["analyzers_run"] == 3 and s["analyzers_failed"] == 1
    assert s["link"] == "https://intelowl.example.org/jobs/42"


def test_no_job_started_is_an_error(monkeypatch):
    monkeypatch.setattr(intelowl, "get_settings", lambda: _settings())
    monkeypatch.setattr(intelowl, "_call", lambda *a, **k: (400, {"errors": {"detail": "playbook not found"}}))
    with pytest.raises(EnrichError, match="did not start a job.*playbook not found"):
        intelowl.lookup("ip", "203.0.113.9")
