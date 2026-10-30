"""The analyst query language."""
import json

from app.search.query import parse_query, to_bool_query


def kinds(parsed):
    return [(i["kind"], i["label"]) for i in parsed.interpretation]


def dump(parsed):
    return json.dumps(to_bool_query(parsed))


def test_free_text_understands_countries_and_broad_terms():
    parsed = parse_query("cyber attack Kenya")
    assert ("country", "Country: Kenya") in kinds(parsed)
    assert [k for k, _ in kinds(parsed)].count("broad") == 2
    # Only the country is required; "cyber" and "attack" just improve ranking.
    assert len(parsed.must) == 1 and len(parsed.should) == 2
    assert '"countries": {"value": "KE"' in dump(parsed)


def test_strict_mode_requires_every_term():
    parsed = parse_query("cyber attack Kenya", strict=True)
    assert len(parsed.must) == 3 and not parsed.should


def test_multi_word_countries_and_wordlike_codes():
    assert ("country", "Country: South Africa") in kinds(parse_query("ransomware South Africa"))
    assert not any(k == "country" for k, _ in kinds(parse_query("ransomware IN banks")))
    assert ("country", "Country: Kenya") in kinds(parse_query("KE ransomware"))


def test_bare_indicators_are_recognised_even_when_defanged():
    parsed = parse_query("example[.]co[.]ke 41.90.64.0/20 jane@corp.com CVE-2024-3400")
    labels = [label for _, label in kinds(parsed)]
    assert labels == ["Domain: example.co.ke", "Network: 41.90.64.0/20", "Email: jane@corp.com", "CVE: CVE-2024-3400"]
    body = dump(parsed)
    assert '"domain_suffixes"' in body and '"email_domains"' in body and '"ioc_ip": "41.90.64.0/20"' in body


def test_field_operators_filters_and_negation():
    parsed = parse_query('actor:lockbit country:KE type:ransomware -type:phishing risk:>70 has:creds "initial access"')
    body = to_bool_query(parsed)["bool"]
    assert {"term": {"countries": "KE"}} in body["filter"]
    assert {"term": {"threat_types": "ransomware"}} in body["filter"]
    assert {"range": {"risk_score": {"gt": 70}}} in body["filter"]
    assert {"term": {"has_credentials": True}} in body["filter"]
    assert body["must_not"] == [{"term": {"threat_types": "phishing"}}]
    assert ("exclude", "Not Type: Phishing") in kinds(parsed)
    assert len(body["must"]) == 2  # actor and the quoted phrase


def test_or_groups_alternatives_including_filters():
    parsed = parse_query("lockbit OR akira")
    assert len(parsed.must) == 1 and len(parsed.must[0]["bool"]["should"]) == 2
    parsed = parse_query("type:ransomware OR type:phishing")
    assert not parsed.filters and len(parsed.must[0]["bool"]["should"]) == 2


def test_unknown_operators_and_urls_fall_back_to_text():
    parsed = parse_query("https://example.com/path foo:bar")
    assert ("ioc", "URL: https://example.com/path") in kinds(parsed)
    assert ("text", "foo:bar") in kinds(parsed)


def test_relative_dates_ranges_and_bad_values():
    parsed = parse_query("after:30d before:2026-06-01 risk:40..80 country:nowhere")
    assert sum(1 for f in parsed.filters if "range" in f) == 3
    assert any(k == "warning" for k, _ in kinds(parsed))


def test_empty_query_matches_everything():
    assert to_bool_query(parse_query(""))["bool"]["must"] == [{"match_all": {}}]


def test_parser_never_raises_on_garbage():
    for raw in ['"unterminated', "-", ":::", "a:b:c:d", "risk:>>", "((((", "OR OR OR", "x" * 5000, "\x00\x01"]:
        to_bool_query(parse_query(raw))


def test_contact_handle_operators():
    parsed = parse_query("jabber:seller@exploit.im edb:51234")
    assert ("ioc", "Jabber/XMPP: seller@exploit.im") in kinds(parsed)
    assert ("ioc", "Exploit-DB: EDB-51234") in kinds(parsed)
    assert '"ioc_handles": "jabber:seller@exploit.im"' in dump(parsed)
    assert '"tox:abc*"' in dump(parse_query("tox:ABC*"))
