"""The research workstation: query language additions, ranking explanations, language and relevance detection, the abuse blocklist."""
import hashlib
import json

from app.crawl import blocklist
from app.extract.lang import detect_language
from app.extract.relevance import page_title as _page_title
from app.extract.relevance import research_relevance
from app.search import service
from app.search.query import parse_query, to_bool_query
from app.worker.parsers import parse_onion_blocklist


def _flat(parsed) -> str:
    return json.dumps(to_bool_query(parsed))


def test_boolean_keywords():
    spelled = parse_query('ransomware AND Kenya NOT advertisement')
    dashed = parse_query('ransomware Kenya -advertisement')
    assert [i["label"] for i in spelled.interpretation] == [i["label"] for i in dashed.interpretation]
    assert len(spelled.must_not) == 1 and len(spelled.must) == 2
    either = parse_query('"company.com" OR company')
    assert len(either.must) == 1 and len(either.must[0]["bool"]["should"]) == 2
    assert len(parse_query("NOT").must) == 1  # a lone NOT is just a word


def test_regular_expressions_wildcards_and_new_filters():
    regex = parse_query("/cve-2026-[0-9]+/")
    assert '"regexp"' in _flat(regex) and regex.interpretation[0]["label"] == "/cve-2026-[0-9]+/"
    assert parse_query("/(unclosed/").interpretation[0]["kind"] == "warning"
    assert '"wildcard"' in _flat(parse_query("ransom*"))
    body = to_bool_query(parse_query("lang:russian kind:leak site:example.onion inurl:thread network:tor"))["bool"]["filter"]
    assert {"term": {"lang": "ru"}} in body and {"term": {"source_category": "ransomware_leak_site"}} in body and {"term": {"network": "onion"}} in body
    assert any("wildcard" in f and "url" in f["wildcard"] for f in body)
    assert parse_query("lang:klingon").interpretation[0]["kind"] == "warning"
    similar = parse_query("similar:9e5abc42-4361-4e9c-bee1-2e563f87346b")
    assert similar.similar_to == "9e5abc42-4361-4e9c-bee1-2e563f87346b" and "more_like_this" in _flat(similar)


def test_results_say_why_they_matched():
    parsed = parse_query('"cyber attack" Kenya leaked')
    names = [json.dumps(c) for c in parsed.must]
    assert all('"_name": "q' in n for n in names)  # every scoring clause is named after its line in "Understood as"
    hit = {"matched_queries": ["q0", "q1", "q9"], "highlight": {"title": ["x"]}}
    src = {"corroboration": 2, "seen_at": 5, "risk_score": 88, "source_trust": 90}
    why = service._why(hit, src, parsed.interpretation)
    labels = [w["label"] for w in why]
    assert labels[:2] == ["“cyber attack”", "Country: Kenya"] and "Match in the title" in labels
    assert "Corroborated by 2 other sources" in labels and "Same content seen at 5 sources" in labels and "High risk (88)" in labels and "Reliable source" in labels
    out = service._hit({"_id": "a", "_score": 4.0, "_source": {"title": "t"}}, parsed.interpretation, 8.0)
    assert out["relevance"] == 50 and out["why"] == []


def test_ranking_uses_more_than_keyword_match():
    functions = json.dumps(service._ranked({"match_all": {}})["function_score"]["functions"])
    for signal in ("risk_score", "date", "source_trust", "corroboration", "seen_at", "version_count"):
        assert signal in functions


def test_language_detection():
    assert detect_language("We have published the data of the company because they did not pay and this is what will happen to all of you") == "en"
    assert detect_language("Мы опубликовали данные компании после отказа платить выкуп. Все файлы доступны для скачивания") == "ru"
    assert detect_language("Los datos de la empresa han sido publicados porque no pagaron el rescate en el plazo que les dimos para ello") == "es"
    assert detect_language("Kampuni hii imevamiwa na data zake zimewekwa wazi kwa sababu hawakulipa kwa wakati na hii ni onyo kwa wengine pia") == "sw"
    assert detect_language("x1 9f 00") == "" and detect_language("") == ""


def test_site_relevance_and_titles():
    assert research_relevance("Akira ransomware leaks - victims") >= 6 and research_relevance("DarkForum - hacking, leaks, databases") >= 6
    assert research_relevance("Buy cannabis online shop") == 0 and research_relevance("") == 0
    assert research_relevance("", "listed by RansomLook for qilin") >= 3
    assert _page_title("<html><head><TITLE>\n  Qilin &amp; friends <b>blog</b> </TITLE></head>") == "Qilin & friends blog"
    assert _page_title("no title here") == "" and len(_page_title("<title>" + "x" * 900 + "</title>")) == 200


class _FakeRedis:
    def __init__(self, members):
        self.members, self.asked = set(members), []

    def pipeline(self, transaction=False):
        return self

    def sismember(self, key, value):
        self.asked.append(value)

    def execute(self):
        answers, self.asked = [v in self.members for v in self.asked], []
        return answers


def test_abuse_blocklist_matches_hashes_never_addresses():
    banned = "a" * 56 + ".onion"
    listed = hashlib.md5(banned.encode()).hexdigest()
    parsed = parse_onion_blocklist(f"{listed}\nnot-a-hash\n{'b' * 32}\n{listed}\n")
    assert parsed.blocklist == [listed, "b" * 32] and parsed.items == []
    redis = _FakeRedis(parsed.blocklist)
    assert blocklist.is_blocked(redis, banned) and blocklist.is_blocked(redis, "forum." + banned)
    assert not blocklist.is_blocked(redis, "c" * 56 + ".onion") and not blocklist.is_blocked(redis, "example.com")
    # A list that hashes the address without its suffix is honoured too.
    assert blocklist.is_blocked(_FakeRedis([hashlib.md5(("a" * 56).encode()).hexdigest()]), banned)


def test_collection_settings_are_validated():
    from app.intel import settings_store

    class Db:
        row = None

        def get(self, model, key):
            return self.row

        def add(self, row):
            Db.row = row

    db = Db()
    settings_store._cache.clear()
    assert settings_store.get(db)["auto_approve"] == "leak_sites"
    saved = settings_store.put(db, "collection", {"auto_approve": "manual", "research_max_depth": 3, "unknown": 1}, 7)
    assert saved["auto_approve"] == "manual" and saved["research_max_depth"] == 3 and "unknown" not in saved and db.row.updated_by == 7
    for bad in ({"auto_approve": "everything"}, {"research_max_depth": 99}, {"max_onion_sources": True}, {"research_max_pages": "many"}):
        try:
            settings_store.put(db, "collection", bad, 7)
            raise AssertionError(f"{bad} was accepted")
        except ValueError:
            pass
    settings_store._cache.clear()


def test_deepdark_catalog_parses_and_filters():
    from app.worker.parsers import parse_deepdark_catalog

    md = """# forums
|Name|Status|Note|
| ------ | ------ | ------ |
|[Live Forum](http://liveabc234abc234abc234abc234abc234abc234abc234abc234ad.onion/)|ONLINE|carding|
|[Dead Forum](http://deadxyz567xyz567xyz567xyz567xyz567xyz567xyz567xyz567yz.onion/)|OFFLINE||
|[Clearnet Board](https://board.example.com/)|ONLINE||
|[Invite](https://t.me/+secretInvite)|ONLINE||
|[Dup](http://liveabc234abc234abc234abc234abc234abc234abc234abc234ad.onion/x)|ONLINE||
"""
    out = parse_deepdark_catalog(md, {"list": "forum"})
    urls = {d["url"] for d in out.discovered}
    assert any("liveabc234" in u for u in urls)          # live onion kept
    assert any("board.example.com" in u for u in urls)   # clearnet kept
    assert not any("deadxyz567" in u for u in urls)      # OFFLINE dropped
    assert not any("t.me/+" in u for u in urls)          # invite link dropped
    assert len(out.discovered) == 2                       # the duplicate host is not filed twice
    assert all(d["category"] == "forum" for d in out.discovered)
    assert all("login or invitation likely required" in d["context"] for d in out.discovered)
    assert "deepdarkCTI forum" in out.discovered[0]["context"]


def test_deepdark_catalog_maps_categories():
    from app.worker.parsers import parse_deepdark_catalog

    row = "|[X](http://abcde234abcde234abcde234abcde234abcde234abcde234abcde2ad.onion/)|ONLINE|"
    assert parse_deepdark_catalog("|h|s|\n|---|---|\n" + row, {"list": "ransomware_gang"}).discovered[0]["category"] == "ransomware_leak_site"
    assert parse_deepdark_catalog("|h|s|\n|---|---|\n" + row, {"list": "markets"}).discovered[0]["category"] == "marketplace"


def test_contact_handle_indicator_types():
    from app.extract.iocs import detect_indicator, extract_iocs

    tox = "A" * 76
    text = (f"Tox: {tox} Session 05{'b' * 64} Matrix @lockbit:matrix.org "
            "Discord discord.gg/AbCd1234 xmpp: support@thesecure.biz exploit EDB-ID: 50123 "
            "and a real mailbox victim@corp.co.ke")
    vals = {(i.type, i.value) for i in extract_iocs(text)[0]}
    assert ("tox", tox) in vals
    assert ("session", "05" + "b" * 64) in vals
    assert ("matrix", "@lockbit:matrix.org") in vals
    assert ("discord", "discord.gg/AbCd1234") in vals
    assert ("jabber", "support@thesecure.biz") in vals        # the labelled xmpp handle, not read as a plain email
    assert ("edb", "EDB-50123") in vals
    assert ("email", "victim@corp.co.ke") in vals             # a genuine email is still an email
    assert not any(t == "domain" and v in ("discord.gg", "matrix.org") for t, v in vals)  # no noise domains
    assert detect_indicator(tox) == ("tox", tox)
    assert detect_indicator("@x:matrix.org") == ("matrix", "@x:matrix.org")
    assert detect_indicator("EDB-50123") == ("edb", "EDB-50123")
