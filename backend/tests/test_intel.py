"""Release 1.1 intelligence logic: ATT&CK, resolution helpers, quality, lookalikes, priority, exposure, STIX, providers."""
import json
from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace

from app import mfa
from app.enrich import providers
from app.extract.entities import EntityMatcher, KnownEntity, distinctive
from app.extract.redact import redact
from app.extract.risk import score_risk
from app.intel import attack, priority, quality, stix
from app.intel.lookalike import lookalike_reason
from app.notify.integrations import DeliveryError, build_request, check_destination
from app.search.query import parse_query, to_bool_query
from app.worker.matching import DocView, alert_category, match_watch
from app.worker.parsers import parse_cisa_kev, parse_ioc_feed, parse_telegram_public


def test_attack_catalogue_is_bundled_and_consistent():
    data = attack.catalog()
    assert len(data["techniques"]) > 500 and len(data["groups"]) > 100 and data["version"]
    known = attack.techniques()
    assert known["T1486"]["name"] == "Data Encrypted for Impact" and "impact" in known["T1486"]["tactics"]
    apt28 = next(g for g in data["groups"] if g["name"] == "APT28")
    assert {"Fancy Bear", "Sofacy"} <= set(apt28["aliases"]) and "T1566.001" in apt28["techniques"]
    assert all(t in known for g in data["groups"] for t in g["techniques"])


def test_techniques_from_explicit_ids_and_behaviour():
    found = attack.extract_techniques("Akira ransomware hits a bank", "Used stolen credentials over VPN, ran PowerShell, deleted backups. See T1486, T9999.")
    assert found["T1486"] == 95 and "T9999" not in found
    assert {"T1078", "T1059.001", "T1490"} <= set(found)
    assert attack.extract_techniques("Quarterly results", "Revenue grew four percent.") == {}


def test_imported_names_that_could_be_words_need_context():
    assert distinctive("APT28") and distinctive("TrickBot") and distinctive("Sandworm Team") and not distinctive("Turla") and not distinctive("Carbon")
    matcher = EntityMatcher([KnownEntity(1, "actor", "Turla", ("Snake", "Venomous Bear"), True, True), KnownEntity(2, "malware", "Carbon", (), True, True)])
    assert matcher.find("Carbon emissions fell while the snake slept") == {}
    assert matcher.find("The Turla group deployed the Carbon backdoor malware") == {1: 1, 2: 1}
    assert 1 in matcher.find("Venomous Bear was active again")


def test_admiralty_grading_and_verification_states():
    source = SimpleNamespace(trust=80, reliability="")
    assert quality.reliability(source) == "B" and quality.admiralty(source, "corroborated") == "B2" and quality.admiralty(source, "unverified") == "B6"
    assert quality.reliability(SimpleNamespace(trust=10, reliability="A")) == "A"  # the operator's grade wins
    assert quality.verification_for(80, 0) == "reported" and quality.verification_for(30, 0) == "unverified"
    assert quality.verification_for(30, 2) == "corroborated" and quality.verification_for(30, 0, "confirmed") == "confirmed"


def test_lookalike_domains():
    brand = "safaricom.co.ke"
    assert lookalike_reason("safaricom.co.ke", brand) is None and lookalike_reason("selfcare.safaricom.co.ke", brand) is None
    assert "different top-level" in lookalike_reason("safaricom.com", brand)
    assert "look-alike characters" in lookalike_reason("safaric0m.co.ke", brand)
    assert "characters away" in lookalike_reason("safaricon.co.ke", brand)
    assert "combined with other words" in lookalike_reason("safaricom-rewards.com", brand)
    assert "attached" in lookalike_reason("safaricomlogin.net", brand)
    assert lookalike_reason("example.org", brand) is None and lookalike_reason("kenyapower.co.ke", brand) is None
    assert lookalike_reason("equitybank-ke.com", "Equitybank") is not None  # a bare brand name works too


def view(**kw):
    base = dict(title="t", text="body", threat_type="phishing", severity="medium", confidence=80, has_credentials=False)
    return DocView(**{**base, **kw})


def test_asset_watch_kinds():
    phish = view(iocs={"domain": {"safaric0m.co.ke": "login at safaric0m.co.ke"}})
    hit = match_watch("domain", "safaricom.co.ke", phish, lookalikes=True)
    assert hit.lookalike and alert_category("domain", phish, hit) == "lookalike"
    assert match_watch("domain", "safaricom.co.ke", phish) is None  # only owned assets get lookalike detection
    assert match_watch("brand", "safaricom.co.ke", phish).lookalike
    vuln = view(threat_type="vulnerability", text="A flaw in Fortinet FortiGate is being exploited", iocs={"cve": {"CVE-2024-21762": "x"}})
    tech = match_watch("technology", "FortiGate", vuln)
    assert tech and alert_category("technology", vuln, tech) == "vulnerability"
    assert match_watch("technology", "FortiGate", view(text="We sell FortiGate licences")) is None
    assert match_watch("executive", "Jane Wanjiru", view(text="CFO Jane Wanjiru was named in the leak")) is not None
    assert match_watch("vendor", "Acme Payroll", view(text="x", organizations={"acme payroll"})) is not None


def test_alert_priority_reflects_context_not_just_risk():
    common = dict(risk=60, confidence=80, category="compromise", corroboration=0, verification="reported", age_days=1)
    crown, crown_factors = priority.alert_priority(credential_exposed=True, criticality=5, **common)
    minor, _ = priority.alert_priority(credential_exposed=False, criticality=1, **common)
    assert crown > minor + 20 and any("criticality 5/5" in f["factor"] for f in crown_factors)
    stale, _ = priority.alert_priority(credential_exposed=False, criticality=3, **{**common, "age_days": 400})
    fresh, _ = priority.alert_priority(credential_exposed=False, criticality=3, **common)
    assert stale < fresh - 20
    doubtful, _ = priority.alert_priority(credential_exposed=False, criticality=3, **{**common, "verification": "unverified"})
    assert doubtful < fresh


def test_vulnerability_priority_is_about_threat_and_exposure_not_cvss_alone():
    quiet = dict(kev=False, kev_added=None, ransomware_use=False, epss=0.001, mention_count=0, exposed_assets=0, watched_technology=False)
    theoretical, _ = priority.vulnerability_priority(cvss=9.8, **quiet)
    real, factors = priority.vulnerability_priority(cvss=7.5, **{**quiet, "kev": True, "kev_added": date.today(), "epss": 0.9, "exposed_assets": 2})
    assert theoretical <= 12 and real >= 80 and factors[0]["factor"].startswith("Present on 2")


def test_asset_risk_explains_itself():
    score, factors = priority.asset_risk(ports=[22, 443, 3389], vulns=["CVE-2024-1", "CVE-2024-2"], kev_vulns=["CVE-2024-1"], feed_hits=[], tags=[], criticality=4)
    assert score >= 60 and any("Remote Desktop (3389)" in f["factor"] for f in factors) and any("actively exploited" in f["factor"] for f in factors)
    assert priority.asset_risk(ports=[443], vulns=[], kev_vulns=[], feed_hits=[], tags=[], criticality=5) == (0, [])


def test_risk_gains_new_explainable_factors():
    base = dict(threat_type="data_breach", confidence=80, source_trust=70, network="surface", exposure={}, ioc_count=3, has_actor=False, has_victim=True,
                in_focus_country=False, reference_time=datetime.now(timezone.utc) - timedelta(days=20))
    plain, _, _ = score_risk(**base)
    richer, _, factors = score_risk(**base, corroboration=2, feed_listed=True, criticality=5, in_focus_sector=True)
    assert richer > plain and {"Corroborated by 2 other sources", "An indicator is listed by a threat feed"} <= {f["factor"] for f in factors}
    assert score_risk(**base) == score_risk(**base, corroboration=0)  # backward compatible


def test_exposure_records_never_keep_the_secret():
    text, exp = redact("URL: https://vpn.corp.co.ke/login\nUsername: jdoe\nPassword: Hunter2!!\njane@corp.co.ke:Summer2024!\n"
                       "key AKIAIOSFODNN7EXAMPLE and ghp_abcdefghijklmnopqrstuvwxyz0123456789")
    assert not any(s in text for s in ("Hunter2!!", "Summer2024!", "AKIAIOSFODNN7EXAMPLE", "ghp_abcdefghijkl"))
    kinds = {r["kind"]: r for r in exp.records}
    assert kinds["stealer_log"]["identity"] == "jdoe" and kinds["stealer_log"]["service"] == "vpn.corp.co.ke" and kinds["stealer_log"]["password_exposed"]
    assert kinds["credential"]["identity"] == "jane@corp.co.ke" and kinds["credential"]["domain"] == "corp.co.ke" and not kinds["credential"]["fingerprint"]
    assert kinds["cloud_secret"]["secret_type"] == "aws_access_key" and len(kinds["cloud_secret"]["fingerprint"]) == 16
    assert kinds["token"]["secret_type"] == "github_token"
    assert not any(secret in json.dumps(exp.records) for secret in ("Hunter2", "Summer2024", "AKIA", "ghp_"))
    assert exp.as_dict()["stealer_logs"] == 1 and exp.credential_pairs == 1


def test_new_connectors_parse_public_posts_and_feeds():
    page = """<div class="tgme_channel_info_header_title">Threat Feed KE</div>
    <div class="tgme_widget_message" data-post="threatfeedke/42"><div class="tgme_widget_message_text">New leak: bank database for sale<br>contact @seller</div>
    <time datetime="2026-10-01T10:00:00+00:00"></time></div><div class="tgme_widget_message" data-post="threatfeedke/43"><div class="tgme_widget_message_text">ok</div></div>"""
    items = parse_telegram_public(page, "https://t.me/s/threatfeedke").items
    assert len(items) == 1 and items[0].key == "threatfeedke/42" and items[0].url == "https://t.me/threatfeedke/42"
    assert items[0].title.startswith("Threat Feed KE: New leak") and items[0].published_at.year == 2026
    feed = parse_ioc_feed("# comment\n185.220.101.4\nhttp://evil.example.com/login\n10.0.0.1\nnot an indicator\n185.220.101.4\n", {})
    assert feed.feed_iocs == [("ip", "185.220.101.4"), ("url", "http://evil.example.com/login")]
    assert parse_ioc_feed("185.220.101.4\nhttp://evil.example.com/x\n", {"ioc_type": "ip"}).feed_iocs == [("ip", "185.220.101.4")]
    kev = parse_cisa_kev(json.dumps({"vulnerabilities": [{"cveID": "CVE-2026-0001", "vulnerabilityName": "X RCE", "vendorProject": "X", "product": "Y",
                                                           "dateAdded": "2026-10-01", "dueDate": "2026-10-22", "knownRansomwareCampaignUse": "Known"}]}), "u", days=3650)
    assert kev.vulnerabilities[0] == {"cve": "CVE-2026-0001", "title": "X RCE", "vendor": "X", "product": "Y", "description": "", "kev_added": "2026-10-01",
                                      "kev_due": "2026-10-22", "ransomware_use": True}


def test_query_language_knows_techniques_and_verification():
    body = to_bool_query(parse_query("technique:t1566 verified:corroborated tactic:impact"))["bool"]["filter"]
    assert {"term": {"verification": "corroborated"}} in body and {"term": {"tactics": "impact"}} in body
    assert any("prefix" in json.dumps(f) and "T1566." in json.dumps(f) for f in body)
    assert any(i["kind"] == "warning" for i in parse_query("verified:maybe").interpretation)


def test_stix_round_trip():
    case = {"id": 7, "title": "Case", "description": "d", "iocs": [{"type": "domain", "value": "evil.example.com"}, {"type": "cve", "value": "CVE-2024-3400"},
                                                                     {"type": "hash", "value": "a" * 64}, {"type": "username", "value": "x"}],
            "entities": [{"type": "actor", "name": "APT28", "aliases": ["Fancy Bear"]}, {"type": "technique", "name": "T1566 Phishing", "meta": {"attack_id": "T1566", "tactics": ["initial-access"]}}]}
    bundle = stix.case_bundle(case)
    types = [o["type"] for o in bundle["objects"]]
    assert types == ["report", "indicator", "vulnerability", "indicator", "threat-actor", "attack-pattern"]
    pattern = next(o for o in bundle["objects"] if o["type"] == "attack-pattern")
    assert pattern["name"] == "Phishing" and pattern["external_references"][0]["external_id"] == "T1566"
    assert stix.case_bundle(case)["objects"][1]["id"] == bundle["objects"][1]["id"]  # deterministic identifiers
    assert "'SHA-256'" in bundle["objects"][3]["pattern"]
    bundle["objects"].append(stix.relationship("uses", bundle["objects"][4]["id"], bundle["objects"][5]["id"], 85))
    back = stix.summarise_import(bundle)
    assert ("domain", "evil.example.com") in back["indicators"] and ("hash", "a" * 64) in back["indicators"] and back["cves"] == ["CVE-2024-3400"]
    assert {(e["kind"], e["name"]) for e in back["entities"]} == {("actor", "APT28"), ("technique", "T1566")}
    assert back["relationships"][0][1] == "uses" and back["title"] == "Case"


def test_provider_response_parsers():
    vt = providers.parse_virustotal(200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 12, "suspicious": 1, "harmless": 60, "undetected": 10},
                                                                   "reputation": -40, "tags": ["phishing"]}}})
    assert vt["verdict"] == "malicious" and vt["summary"]["malicious"] == 12 and vt["score"] > 10
    assert providers.parse_virustotal(404, None)["verdict"] == "unknown"
    assert providers.parse_virustotal(200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 70}}}})["verdict"] == "clean"
    sh = providers.parse_shodan(200, {"ports": [443, 22], "org": "Example Ltd", "vulns": ["CVE-2024-2", "CVE-2024-1"], "tags": []})
    assert sh["summary"]["ports"] == [22, 443] and sh["summary"]["vulns"] == ["CVE-2024-1", "CVE-2024-2"]
    assert providers.parse_abuseipdb(200, {"data": {"abuseConfidenceScore": 90, "totalReports": 40}})["verdict"] == "malicious"
    assert providers.parse_greynoise(200, {"classification": "benign", "riot": True})["verdict"] == "clean"
    idb = providers.parse_internetdb(200, {"ports": [80], "cpes": ["cpe:/a:nginx"], "tags": ["compromised"], "vulns": ["CVE-2021-1"], "hostnames": []})
    assert idb["verdict"] == "suspicious" and providers.parse_internetdb(404, {"detail": "No information available"})["summary"]["note"]
    assert providers.parse_epss({"data": [{"cve": "CVE-2024-3400", "epss": "0.94", "percentile": "0.99"}]}) == {"CVE-2024-3400": (0.94, 0.99)}
    nvd = providers.parse_nvd({"vulnerabilities": [{"cve": {"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "vectorString": "CVSS:3.1/AV:N"}}]},
                                                             "descriptions": [{"lang": "en", "value": "bad"}], "published": "2024-04-12T00:00:00"}}]})
    assert nvd == {"cvss": 10.0, "cvss_vector": "CVSS:3.1/AV:N", "description": "bad", "published": "2024-04-12"}
    hosts, _ = providers.parse_certspotter([{"dns_names": ["*.corp.co.ke", "vpn.corp.co.ke", "other.example.com"], "issuer": {"friendly_name": "LE"}}], "corp.co.ke")
    assert hosts == ["corp.co.ke", "vpn.corp.co.ke"]
    names = {p["name"]: p for p in providers.catalogue()}
    assert names["internetdb"]["enabled"] and not names["virustotal"]["enabled"] and names["hibp"]["tier"] == "planned"


ALERT = {"id": 1, "severity": "high", "priority": 80, "category": "compromise", "category_label": "Possible compromise", "matched": "ceo[@]corp[.]co[.]ke",
         "title": "Combo list", "origin": "Watchlist: Corporate domain", "snippet": "ceo[@]corp[.]co[.]ke:[REDACTED]", "link": "https://kivuli.example/findings/1"}


def test_integration_payloads():
    import hashlib
    import hmac

    url, headers, body, auth = build_request("webhook", "https://hooks.example.com/x", {}, "s3cret", ALERT)
    assert headers["X-Kivuli-Signature"] == "sha256=" + hmac.new(b"s3cret", body, hashlib.sha256).hexdigest() and json.loads(body)["alert"]["priority"] == 80
    assert "X-Kivuli-Signature" not in build_request("webhook", "https://hooks.example.com/x", {}, "", ALERT)[1]
    assert json.loads(build_request("slack", "https://hooks.slack.com/services/x", {}, "", ALERT)[2])["blocks"][0]["type"] == "header"
    assert json.loads(build_request("teams", "https://x.webhook.office.com/y", {}, "", ALERT)[2])["attachments"][0]["contentType"].endswith("card.adaptive")
    url, headers, body, _ = build_request("splunk_hec", "https://splunk.example.com:8088", {"index": "sec"}, "tok", ALERT)
    assert url.endswith("/services/collector/event") and headers["Authorization"] == "Splunk tok" and json.loads(body)["index"] == "sec"
    url, _, body, auth = build_request("jira", "https://corp.atlassian.net/", {"project": "SEC", "user": "a@corp.co.ke"}, "tok", ALERT)
    assert url == "https://corp.atlassian.net/rest/api/2/issue" and auth == ("a@corp.co.ke", "tok") and json.loads(body)["fields"]["project"]["key"] == "SEC"
    url, _, body, _ = build_request("servicenow", "https://corp.service-now.com", {"user": "svc"}, "pw", ALERT)
    assert url.endswith("/api/now/table/incident") and json.loads(body)["urgency"] == "2"


def test_webhook_destinations_cannot_point_inwards():
    for bad in ("http://hooks.example.com/x", "https://127.0.0.1/x", "https://10.0.0.5/hook", "https://169.254.169.254/latest", "https://user:pw@example.com/"):
        try:
            check_destination(bad)
            raise AssertionError(f"{bad} was allowed")
        except DeliveryError:
            pass


def test_totp_matches_rfc_6238_and_rejects_replay_window():
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # ASCII "12345678901234567890"
    assert mfa._code(secret, 59 // 30) == "287082" and mfa.verify(secret, "287082", at=59) == 1
    assert mfa.verify(secret, "287082", at=59 + 120) is None and mfa.verify(secret, "12345", at=59) is None
    codes = mfa.new_recovery_codes()
    assert len(set(codes)) == 10 and mfa.hash_recovery_code(codes[0].upper()) == mfa.hash_recovery_code(codes[0])
    assert "secret=" + secret in mfa.provisioning_uri(secret, "a@b.co", "Kivuli")


# ── Provider keys managed from the console, and connection tests ────────────

def _use_keys(monkeypatch, console: dict | None = None, env: dict | None = None, config: dict | None = None):
    """Pretend the Redis mirror holds ``console`` and the environment holds ``env``."""
    from app.config import get_settings
    from app.enrich import keys

    monkeypatch.setattr(keys, "_load", lambda: (dict(console or {}), dict(config or {})))
    keys._cache.update(at=0.0, unreadable=set())
    for name, setting in keys.ENV_SETTING.items():
        monkeypatch.setattr(get_settings(), setting, (env or {}).get(name, ""), raising=False)
    return keys


def test_console_key_takes_precedence_over_env(monkeypatch):
    keys = _use_keys(monkeypatch, console={"virustotal": "console-key"}, env={"virustotal": "env-key", "shodan": "env-shodan"}, config={"anthropic": {"model": "claude-sonnet-5-5"}})
    assert keys.get("virustotal") == "console-key" and keys.source("virustotal") == "console"
    assert keys.get("shodan") == "env-shodan" and keys.source("shodan") == "env"
    assert keys.get("abuseipdb") == "" and keys.source("abuseipdb") == "none"
    assert keys.ai_model() == "claude-sonnet-5-5"
    names = {p["name"]: p for p in providers.catalogue()}
    assert names["virustotal"]["enabled"] and names["virustotal"]["key_source"] == "console" and not names["abuseipdb"]["enabled"]
    assert names["nvd"]["enabled"] and names["nvd"]["optional_key"] and names["nvd"]["tier"] == "free"  # NVD works without its key
    assert names["epss"]["testable"] and names["internetdb"]["key_source"] == "not_needed"
    assert [p.name for p in providers.for_kind("cve")] == []  # EPSS and NVD score vulnerabilities; they are not indicator lookups


def test_provider_keys_are_sealed_with_their_own_key(monkeypatch):
    from app import crypto
    from app.config import get_settings

    monkeypatch.setattr(get_settings(), "provider_keys_key", "unit-test-provider-key", raising=False)
    token = crypto.seal("vt-secret-0123456789")
    assert "vt-secret" not in token and crypto.unseal(token) == "vt-secret-0123456789" and crypto.seal("") == ""
    monkeypatch.setattr(get_settings(), "provider_keys_key", "a-different-key", raising=False)
    try:
        crypto.unseal(token)
        raise AssertionError("a rotated key must not decrypt old ciphertext")
    except RuntimeError as exc:
        assert "PROVIDER_KEYS_KEY has changed" in str(exc)


def test_connection_tests_say_what_is_wrong(monkeypatch):
    from app.enrich.http import EnrichError

    _use_keys(monkeypatch, console={"virustotal": "k" * 64, "shodan": "s" * 32})
    assert providers.run_probe("abuseipdb") == {"ok": False, "message": "No API key is set for this provider", "detail": {}}
    assert not providers.run_probe("hibp")["ok"]  # planned providers have nothing to test

    answers = {"status": 401, "body": {"error": {"code": "WrongCredentialsError"}}}
    monkeypatch.setattr(providers, "api_request", lambda url, **kw: (answers["status"], answers["body"]))
    rejected = providers.run_probe("virustotal")
    assert not rejected["ok"] and "rejected the API key (HTTP 401)" in rejected["message"] and rejected["detail"]["reason"] == "key_rejected"
    answers.update(status=429)
    assert providers.run_probe("virustotal")["detail"]["reason"] == "quota"
    answers.update(status=200, body={"data": {"attributes": {"as_owner": "GOOGLE"}}})
    assert providers.run_probe("virustotal") == {"ok": True, "message": "Key accepted: VirusTotal returned a report", "detail": {"as_owner": "GOOGLE"}}
    answers.update(status=200, body={"plan": "dev", "query_credits": 97, "scan_credits": 100})
    shodan = providers.run_probe("shodan")
    assert shodan["ok"] and "97 query credits left" in shodan["message"] and shodan["detail"]["plan"] == "dev"

    def refused(url, **kw):
        raise EnrichError("egress proxy refused the request (is the host in EGRESS_ALLOW_HOSTS?): 403")
    monkeypatch.setattr(providers, "api_request", refused)
    blocked = providers.run_probe("internetdb")
    assert not blocked["ok"] and "Add internetdb.shodan.io to EGRESS_ALLOW_HOSTS" in blocked["message"] and blocked["detail"]["reason"] == "egress"


def test_a_rejected_key_is_an_error_not_an_empty_result(monkeypatch):
    _use_keys(monkeypatch, console={"abuseipdb": "a" * 80})
    monkeypatch.setattr(providers, "api_request", lambda url, **kw: (401, {"errors": [{"detail": "Authentication failed."}]}))
    try:
        providers.abuseipdb("ip", "8.8.8.8")
        raise AssertionError("a 401 must not be reported as 'no data'")
    except providers.KeyRejected as exc:
        assert "AbuseIPDB rejected the API key" in str(exc)


def test_ai_self_test_without_a_key(monkeypatch):
    from app.ai import analyst

    _use_keys(monkeypatch)
    assert not analyst.enabled()
    assert analyst.selftest() == {"ok": False, "detail": {"model": "claude-opus-5-5"}, "message": "No Anthropic API key is set"}


def test_enqueue_accepts_task_arguments_called_name(monkeypatch):
    from app.worker import celery_app as module

    sent = {}
    monkeypatch.setattr(module.celery_app, "send_task", lambda task, kwargs=None, countdown=None: sent.update(task=task, kwargs=kwargs, countdown=countdown))
    module.enqueue("enrich.test_provider", job_id="j1", name="virustotal")
    assert sent == {"task": "enrich.test_provider", "kwargs": {"job_id": "j1", "name": "virustotal"}, "countdown": None}


def test_greynoise_is_tested_on_the_endpoint_that_checks_the_key(monkeypatch):
    _use_keys(monkeypatch, console={"greynoise": "g" * 40})
    asked = []

    def answer(url, **kw):
        asked.append(url)
        # The community lookup answers anyone, key or no key; only /ping says whether the key is valid.
        return (401, {"message": "unauthorized"}) if url.endswith("/ping") else (404, {"message": "IP not observed scanning the internet."})
    monkeypatch.setattr(providers, "api_request", answer)
    result = providers.run_probe("greynoise")
    assert asked == ["https://api.greynoise.io/ping"] and not result["ok"] and result["detail"]["reason"] == "key_rejected"
    monkeypatch.setattr(providers, "api_request", lambda url, **kw: (200, {"message": "pong", "offering": "community", "expiration": "2027-01-01"}))
    assert providers.run_probe("greynoise")["message"] == "Key accepted: GreyNoise plan “community”"
