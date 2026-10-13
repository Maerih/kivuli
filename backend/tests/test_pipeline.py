"""Parsers, fetch policy and watchlist matching - none of which need a database."""
import json

from app.crawl.fetcher import same_site, validate_url
from app.egress_proxy import allowed
from app.notify.mailer import defang_text
from app.reports.render import to_stix
from app.search.index import parent_domains
from app.worker.matching import DocView, alert_category, alert_severity, match_watch
from app.worker.parsers import parse_cisa_kev, parse_html, parse_ransomlook_group, parse_ransomware_live, parse_rss

ONION = "b" * 56 + ".onion"


def test_url_policy_refuses_everything_that_is_not_a_public_site():
    assert validate_url(f"http://{ONION}/")[:1] == (True,) and validate_url(f"http://{ONION}/")[3] == "onion"
    assert validate_url("https://www.example.com/feed")[3] == "surface"
    for bad in ("http://127.0.0.1/", "http://10.0.0.5/admin", "http://[::1]/", "http://redis:6379/", "http://db.internal/",
                "ftp://example.com/", "file:///etc/passwd", "http://user:pw@example.com/", "http://short.onion/", "https://example.com:22/"):
        assert validate_url(bad)[0] is False, bad


def test_redirects_must_stay_on_the_same_site():
    assert same_site("www.example.co.ke", "cdn.example.co.ke")
    assert not same_site("example.co.ke", "evil.co.ke")


def test_egress_allowlist_is_exact_unless_dotted():
    allow = ["api.ransomware.live", ".cisa.gov"]
    assert allowed("api.ransomware.live", allow) and allowed("www.cisa.gov", allow) and allowed("cisa.gov", allow)
    assert not allowed("ransomware.live", allow) and not allowed("evil-cisa.gov", allow) and not allowed("api.ransomware.live.evil.com", allow)


def test_html_parser_extracts_text_links_and_candidates_without_scripts():
    html = f"""<html><head><title>Leaks</title><script>steal()</script></head><body><h1>New victim</h1>
      <p>Acme Ltd data published.</p><a href="/post/2">next</a><a href="/files/dump.zip">dump</a><a href="/login">login</a>
      <a href="http://{ONION}/">mirror</a><a href="https://clearnet.example.com/">x</a></body></html>"""
    out = parse_html(html, "http://" + "c" * 56 + ".onion/", "c" * 56 + ".onion")
    assert out.items[0].title == "Leaks" and "Acme Ltd data published." in out.items[0].text
    assert "steal()" not in out.items[0].text
    assert out.links == ["http://" + "c" * 56 + ".onion/post/2"]
    assert [d["url"] for d in out.discovered] == [f"http://{ONION}/"]


def test_login_and_captcha_walls_are_reported_not_collected():
    out = parse_html('<html><body><form><input name="u"><input type="password" name="p"></form></body></html>', f"http://{ONION}/", ONION)
    assert out.gated.startswith("login required") and not out.items
    out = parse_html("<html><body>Please solve the CAPTCHA to continue</body></html>", f"http://{ONION}/", ONION)
    assert out.gated.startswith("CAPTCHA") and not out.items


def test_ransomware_live_rows_become_structured_findings():
    rows = [{"victim": "Majani Insurance Brokers", "group": "qilin", "country": "KE", "activity": "Financial Services",
             "discovered": "2026-09-25T13:24:43+00:00", "attackdate": "2026-09-25T13:01:42+00:00", "domain": "www.majaninsure.com",
             "claim_url": f"http://{ONION}/blog?id=1", "url": "https://www.ransomware.live/id/abc", "description": "N/A",
             "screenshot": "https://images.example/x.png"}]
    item = parse_ransomware_live(json.dumps(rows), "https://api.ransomware.live/v2/recentvictims").items[0]
    assert item.title == "Majani Insurance Brokers listed by Qilin"
    assert item.actor == "Qilin" and item.victim == "Majani Insurance Brokers" and item.countries == ["KE"]
    assert item.hint_type == "ransomware" and item.namespace == "ransomware_live"
    assert ("domain", "www.majaninsure.com") in item.extra_iocs and ("onion", ONION) in item.extra_iocs
    assert "screenshot" not in item.raw and "N/A" not in item.text
    renamed = parse_ransomware_live(json.dumps([{**rows[0], "group": "Vexy Ransomware", "activity": "Other"}]), "https://x").items[0]
    assert renamed.actor == "Vexy" and renamed.sectors == [] and not any(t == "username" for t, _ in renamed.extra_iocs)


def test_group_profiles_yield_candidates_but_skip_file_servers_and_captcha():
    profile = [{"meta": "A group.", "captcha": False, "locations": [
        {"fqdn": ONION, "available": True}, {"fqdn": "d" * 56 + ".onion", "available": True, "fs": True}, {"fqdn": "bad.onion"}]}]
    out = parse_ransomlook_group(json.dumps(profile), "https://www.ransomlook.io/api/group/akira")
    assert [d["url"] for d in out.discovered] == [f"http://{ONION}/"] and out.actor_profiles == {"akira": "A group."}
    assert not parse_ransomlook_group(json.dumps([{"captcha": True, "locations": profile[0]["locations"]}]), "https://x/api/group/y").discovered


def test_rss_and_kev_parsers():
    feed = """<?xml version="1.0"?><rss version="2.0"><channel><title>t</title><item><title>Bank breach</title>
      <link>https://news.example.com/a</link><description>&lt;p&gt;Records &lt;b&gt;leaked&lt;/b&gt;&lt;/p&gt;</description>
      <pubDate>Tue, 06 Oct 2026 10:00:00 GMT</pubDate></item></channel></rss>"""
    item = parse_rss(feed, "https://news.example.com/feed").items[0]
    assert item.title == "Bank breach" and "leaked" in item.text and "<b>" not in item.text and item.published_at.year == 2026
    kev = {"vulnerabilities": [{"cveID": "CVE-2026-0001", "vulnerabilityName": "X RCE", "dateAdded": "2026-10-01", "vendorProject": "X",
                                "product": "Y", "shortDescription": "d", "requiredAction": "patch", "knownRansomwareCampaignUse": "Known"},
                               {"cveID": "CVE-2019-0001", "vulnerabilityName": "old", "dateAdded": "2019-01-01"}]}
    out = parse_cisa_kev(json.dumps(kev), "https://www.cisa.gov/kev.json", days=3650)
    assert set(out.kev_ids) == {"CVE-2026-0001", "CVE-2019-0001"}
    assert any(i.key == "CVE-2026-0001" and i.hint_type == "vulnerability" for i in out.items)


def view(**kw):
    base = dict(title="Combo list", text="dump of accounts", threat_type="credential_leak", severity="medium", confidence=80, has_credentials=True)
    return DocView(**{**base, **kw})


def test_domain_watch_matches_subdomains_mailboxes_and_flags_exposed_passwords():
    v = view(iocs={"email": {"jane@mail.corp.co.ke": "jane@mail.corp.co.ke:[REDACTED] bob@other.com:[REDACTED]"}, "domain": {"vpn.corp.co.ke": "host vpn.corp.co.ke"}})
    m = match_watch("domain", "corp.co.ke", v)
    assert m.matched == "jane@mail.corp.co.ke" and m.credential_exposed
    assert alert_category("domain", v, m) == "compromise" and alert_severity("compromise", v, m) == "high"
    assert match_watch("domain", "notcorp.co.ke", v) is None and match_watch("domain", "co.ke", view(iocs={})) is None


def test_keyword_ip_and_entity_watches():
    v = view(title="Leak", text="Data from Kenya  Power staff portal, 41.90.64.7 exposed", threat_type="data_breach", has_credentials=False,
             iocs={"ip": {"41.90.64.7": "41.90.64.7 exposed"}}, actors={"lockbit", "lockbit 3.0"})
    assert match_watch("keyword", "kenya power", v).matched.lower().startswith("kenya")
    assert match_watch("keyword", "enya pow", v) is None
    assert match_watch("ip", "41.90.64.0/20", v).matched == "41.90.64.7" and match_watch("ip", "8.8.8.0/24", v) is None
    assert match_watch("actor", "LockBit 3.0", v) is not None
    m = match_watch("keyword", "kenya power", v)
    assert alert_category("keyword", v, m) == "mention"


def test_helpers_for_index_email_and_reports():
    assert parent_domains("mail.portal.kra.go.ke") == ["mail.portal.kra.go.ke", "portal.kra.go.ke", "kra.go.ke"]
    assert defang_text("see https://evil.example.com/x or mail a@b.co.ke") == "see hxxps[://]evil[.]example[.]com/x or mail a[@]b[.]co[.]ke"
    bundle = to_stix({"id": 1, "title": "T", "description": "", "iocs": [{"type": "domain", "value": "evil.example.com"}, {"type": "username", "value": "x"}],
                      "entities": [{"type": "actor", "name": "LockBit"}]})
    types = [o["type"] for o in bundle["objects"]]
    assert types == ["report", "indicator", "threat-actor"] and len(bundle["objects"][0]["object_refs"]) == 2
