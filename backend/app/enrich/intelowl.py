"""IntelOwl: send an indicator to the operator's own IntelOwl and bring its analyzers' verdicts back.

IntelOwl (intelowlproject/IntelOwl) runs many analyzers against an observable
and keeps the reports. Kivuli asks it through its REST API:

  POST /api/playbook/analyze_multiple_observables   {"observables": [[type, value]], "playbook_requested", "tlp"}
  POST /api/analyze_observable                       {"observable_name", "observable_classification", "analyzers_requested", "tlp"}
  GET  /api/jobs/<id>                                status and analyzer_reports
  Authorization: Token <key>

What runs is IntelOwl's own playbook. By default Kivuli asks for
FREE_TO_USE_ANALYZERS at TLP AMBER, which IntelOwl uses to hold back analyzers
that would share the indicator publicly. Analyzers that scan or probe the
target itself (Nmap, Nuclei and the like) are refused here even if named in
INTELOWL_ANALYZERS: Kivuli asks about indicators, it never touches them.

IntelOwl is reached over HTTPS through the egress proxy (its host must be in
EGRESS_ALLOW_HOSTS), or, when it runs on the same machine, directly over its
Docker network with INTELOWL_DIRECT=true (docker-compose.intelowl.yml).
"""
import time
from urllib.parse import urlsplit

from app.config import get_settings
from app.enrich import keys
from app.enrich.http import EnrichError, api_request

CLASSIFICATION = {"ip": "ip", "domain": "domain", "url": "url", "hash": "hash"}
# Analyzers that interact with the target rather than look it up. Never requested.
ACTIVE = ("nmap", "nuclei", "masscan", "zmap", "naabu", "rustscan", "sqlmap", "nikto", "dirsearch", "gobuster", "ffuf", "wpscan",
          "port_scan", "portscan", "vulnerability_scan", "ssh_audit", "sslscan", "testssl", "whatweb_active")
DONE = ("reported_without_fails", "reported_with_fails", "failed", "killed")
POLL_SECONDS = 150


def host() -> str:
    return urlsplit(get_settings().intelowl_url).hostname or ""


def configured() -> bool:
    return bool(get_settings().intelowl_url)


def is_active(name: str) -> bool:
    low = name.lower()
    return any(word in low for word in ACTIVE)


def _call(method: str, path: str, body: dict | None = None, timeout: float = 60):
    from app.enrich.providers import _checked

    settings = get_settings()
    if not settings.intelowl_url:
        raise EnrichError("INTELOWL_URL is not set")
    token = keys.get("intelowl")
    if not token:
        raise EnrichError("No IntelOwl API key is set. Create one in IntelOwl (API access) and add it under Integrations.")
    return _checked("IntelOwl", api_request(f"{settings.intelowl_url.rstrip('/')}{path}", method=method, json_body=body,
                                            headers={"Authorization": f"Token {token}", "Content-Type": "application/json"},
                                            timeout=timeout, max_bytes=20_000_000, direct=settings.intelowl_direct))


def request_body(kind: str, value: str) -> tuple[str, dict]:
    """The endpoint and body for an analysis. Pure, for testing."""
    settings = get_settings()
    analyzers = [a.strip() for a in settings.intelowl_analyzers.split(",") if a.strip()]
    refused = [a for a in analyzers if is_active(a)]
    if refused:
        raise EnrichError(f"Refused: {', '.join(refused)} would scan or probe the target. Kivuli only asks about indicators.")
    tlp = settings.intelowl_tlp.upper()
    if analyzers:
        return "/api/analyze_observable", {"observable_name": value, "observable_classification": CLASSIFICATION[kind],
                                           "analyzers_requested": analyzers, "tlp": tlp, "tags_labels": ["kivuli"]}
    return "/api/playbook/analyze_multiple_observables", {"observables": [[CLASSIFICATION[kind], value]], "playbook_requested": settings.intelowl_playbook,
                                                          "tlp": tlp, "tags_labels": ["kivuli"]}


def summarise(job: dict, base_url: str) -> dict:
    """A provider result from an IntelOwl job. Pure, for testing.

    IntelOwl's analyzers report in their own formats; recent versions add a
    normalised data model with an ``evaluation`` per report, which is what the
    verdict is built from. Reports without one count as run, not as a verdict.
    """
    reports = job.get("analyzer_reports") or []
    malicious, suspicious, clean, failed = [], [], [], []
    for r in reports:
        name = str(r.get("name") or r.get("analyzer_name") or "?")
        if str(r.get("status", "")).upper() in ("FAILED", "KILLED"):
            failed.append(name)
            continue
        model = r.get("data_model") or {}
        evaluation = str(model.get("evaluation") or "").lower() if isinstance(model, dict) else ""
        if evaluation == "malicious":
            malicious.append(name)
        elif evaluation in ("suspicious", "likely_malicious"):
            suspicious.append(name)
        elif evaluation in ("trusted", "clean", "benign"):
            clean.append(name)
    verdict = "malicious" if malicious else "suspicious" if suspicious else "clean" if clean else "unknown"
    job_id = job.get("id") or job.get("job_id")
    return {"verdict": verdict, "score": None, "summary": {
        "job": job_id, "status": job.get("status"), "playbook": job.get("playbook_to_execute") or job.get("playbook_requested") or "",
        "analyzers_run": len(reports) - len(failed), "analyzers_failed": len(failed), "malicious_by": malicious[:20],
        "suspicious_by": suspicious[:20], "clean_by": clean[:20], "link": f"{base_url.rstrip('/')}/jobs/{job_id}" if job_id else "",
    }}


def lookup(kind: str, value: str) -> dict:
    path, body = request_body(kind, value)
    status, raw = _call("POST", path, body)
    answer = (raw.get("results") or [{}])[0] if path.startswith("/api/playbook") and isinstance(raw, dict) else raw
    if status not in (200, 201) or not isinstance(answer, dict) or not answer.get("job_id"):
        errors = next((x.get("errors") for x in (answer, raw) if isinstance(x, dict) and x.get("errors")), None)
        raise EnrichError(f"IntelOwl did not start a job (HTTP {status}){f': {errors}' if errors else ''}")
    job_id = answer["job_id"]
    deadline = time.monotonic() + POLL_SECONDS
    job: dict = {}
    while time.monotonic() < deadline:
        time.sleep(5)
        status, job = _call("GET", f"/api/jobs/{job_id}")
        if status == 200 and isinstance(job, dict) and job.get("status") in DONE:
            break
    if not isinstance(job, dict) or job.get("status") not in DONE:
        result = summarise({"id": job_id, "status": "running", "analyzer_reports": (job or {}).get("analyzer_reports") or []}, get_settings().intelowl_url)
        result["summary"]["note"] = "Still running in IntelOwl; open the job there for the rest"
        return result
    return summarise(job, get_settings().intelowl_url)


def probe() -> dict:
    from app.enrich.providers import _probe

    status, body = _call("GET", "/api/jobs?page_size=1", timeout=30)
    if status != 200:
        raise EnrichError(f"IntelOwl answered HTTP {status}")
    return _probe(True, f"Answered: IntelOwl at {host()} accepted the key")
