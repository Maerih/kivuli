"""Extraction, redaction and classification - the logic everything downstream trusts."""
from app.extract.classify import classify
from app.extract.entities import EntityMatcher, KnownEntity, propose_organizations
from app.extract.geo import country_from_term, detect_countries
from app.extract.iocs import defang, detect_indicator, extract_iocs, refang, registered_domain
from app.extract.redact import redact
from app.extract.risk import score_risk
from app.extract.safety import is_fetchable_link, is_prohibited
from app.extract.textutil import hamming, simhash64, simhash_bands


def iocs(text):
    found, _ = extract_iocs(refang(text))
    return {(i.type, i.value) for i in found}


def test_refang_and_defang_round_trip():
    assert refang("hxxps://evil[.]example[.]com/a") == "https://evil.example.com/a"
    assert refang("admin[at]corp[dot]co[.]ke") == "admin@corp.co.ke"
    assert defang("https://evil.example.com") == "hxxps[://]evil[.]example[.]com"


def test_extracts_core_indicator_types():
    found = iocs(
        "C2 at hxxp://185.220.101.4/gate.php and mail.kra.go.ke, contact ops@victim.co.ke. "
        "Exploits CVE-2024-3400. sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "
        "wallet bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
    )
    assert ("ip", "185.220.101.4") in found
    assert ("url", "http://185.220.101.4/gate.php") in found
    assert ("domain", "mail.kra.go.ke") in found
    assert ("email", "ops@victim.co.ke") in found
    assert ("cve", "CVE-2024-3400") in found
    assert ("hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") in found
    assert ("crypto", "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh") in found


def test_onion_addresses_must_be_valid_v3():
    good = "a" * 56 + ".onion"
    found = iocs(f"mirror http://{good}/blog and fake.onion and short{'b' * 10}.onion")
    assert ("onion", good) in found
    assert not any(t == "onion" and v != good for t, v in found)


def test_ignores_private_addresses_filenames_and_sentence_joins():
    found = iocs("Internal 192.168.1.10 and 10.0.0.1. See report.zip and readme.md. It finished.It was late. Version 2.4.1 shipped.")
    assert not any(t == "ip" for t, _ in found)
    assert not any(t == "domain" for t, _ in found)


def test_bitcoin_addresses_are_checksum_validated():
    assert ("crypto", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") in iocs("pay 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa now")
    assert not any(t == "crypto" for t, _ in iocs("id 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"))


def test_registered_domain_understands_multi_part_suffixes():
    assert registered_domain("mail.portal.kra.go.ke") == "kra.go.ke"
    assert registered_domain("www.example.com") == "example.com"


def test_detect_indicator_classifies_search_tokens():
    assert detect_indicator("example[.]co[.]ke") == ("domain", "example.co.ke")
    assert detect_indicator("41.90.0.0/16") == ("cidr", "41.90.0.0/16")
    assert detect_indicator("cve-2023-34362") == ("cve", "CVE-2023-34362")
    assert detect_indicator("Jane.Doe@Corp.com") == ("email", "jane.doe@corp.com")
    assert detect_indicator("ransomware") is None


def test_redaction_masks_passwords_but_keeps_the_account():
    text, exposure = redact("jane@corp.co.ke:Summer2024!\nbob@corp.co.ke | hunter2\npassword = s3cr3t-value\ncontact: info@corp.co.ke for details")
    assert "Summer2024!" not in text and "hunter2" not in text and "s3cr3t-value" not in text
    assert "jane@corp.co.ke" in text and "info@corp.co.ke for details" in text
    assert exposure.credential_pairs == 2 and exposure.secrets == 1
    assert exposure.accounts == ["jane@corp.co.ke", "bob@corp.co.ke"]


def test_redaction_masks_keys_and_valid_card_numbers_only():
    text, exposure = redact("-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\ncard 4111 1111 1111 1111 ref 1234 5678 9012 3456")
    assert "MIIabc" not in text and exposure.private_keys == 1
    assert "4111 1111 1111 1111" not in text and "****1111" in text
    assert "1234 5678 9012 3456" in text and exposure.cards == 1


def test_country_detection_uses_names_demonyms_cities_and_cctlds():
    assert detect_countries("Attackers hit a Nairobi hospital; Kenyan regulators responded.")[0] == "KE"
    assert detect_countries("Leak contains portal.health.go.ke records", ["portal.health.go.ke"]) == ["KE"]
    assert detect_countries("Hosted on example.io", ["example.io"]) == []
    assert country_from_term("kenya") == "KE" and country_from_term("South Africa") == "ZA" and country_from_term("xyz") is None


def test_classification_and_source_hints():
    kind, _, conf = classify("Akira ransomware gang lists new victim", "The ransomware group threatens that data will be published unless ransom is paid.")
    assert kind == "ransomware" and conf >= 50
    kind, _, _ = classify("Selling RDP access", "Initial access to a corporate network, domain admin, revenue: $40M")
    assert kind == "access_sale"
    kind, _, conf = classify("Weekly newsletter", "Our team went hiking last weekend.")
    assert kind == "other" and conf < 40
    assert classify("Acme Ltd", "listed", hint="ransomware")[0] == "ransomware"


def test_entity_matcher_requires_context_for_ordinary_words():
    matcher = EntityMatcher([KnownEntity(1, "actor", "Play", (), True), KnownEntity(2, "actor", "LockBit", ("LockBit 3.0",), True),
                             KnownEntity(3, "organization", "Majani Insurance Brokers", (), False)])
    assert matcher.find("Children play outside while LockBit 3.0 strikes again") == {2: 2}
    assert 1 in matcher.find("The Play ransomware group claimed the breach")
    assert 3 in matcher.find("Data from majani insurance brokers was published")


def test_organisation_proposals_are_conservative():
    names = propose_organizations("The breach affected Kenya Airways and the Ministry of Health. The group said nothing else.")
    assert "Kenya Airways" in names and "Ministry of Health" in names
    assert not any(n.lower().startswith("the ") for n in names)


def test_risk_score_is_explained_and_bounded():
    score, severity, factors = score_risk(threat_type="ransomware", confidence=90, source_trust=80, network="onion", exposure={"credential_pairs": 250},
                                          ioc_count=12, has_actor=True, has_victim=True, in_focus_country=True, reference_time=None, watchlist_hit=True)
    assert 80 <= score <= 100 and severity == "critical"
    assert sum(f["points"] for f in factors) >= score - 2
    low, low_sev, _ = score_risk(threat_type="other", confidence=20, source_trust=50, network="surface", exposure={}, ioc_count=0,
                                 has_actor=False, has_victim=False, in_focus_country=False, reference_time=None)
    assert low < 20 and low_sev == "info"


def test_simhash_detects_near_duplicates():
    base = " ".join(f"token{i}" for i in range(5000))
    near = base.replace("token2500 ", "edited2500 ")
    other = " ".join(f"other{i}" for i in range(5000))
    assert hamming(simhash64(base), simhash64(near)) <= 3
    assert hamming(simhash64(base), simhash64(other)) > 10
    # Within three bits, at least one of the four bands is identical - which is what the lookup relies on.
    assert any(a == b for a, b in zip(simhash_bands(simhash64(base)), simhash_bands(simhash64(near))))


def test_crawler_never_follows_downloads_or_account_actions():
    assert is_fetchable_link("http://x.onion/blog/post-12")
    assert not is_fetchable_link("http://x.onion/files/dump.7z")
    assert not is_fetchable_link("http://x.onion/login?next=/")
    assert not is_fetchable_link("http://x.onion/download/123")


def test_guardrail_distinguishes_advertising_from_reporting():
    assert is_prohibited("cp links collection", "pthc videos and pedo forum")
    assert not is_prohibited("Europol arrests", "Police arrested the admin of a child porn site after a takedown.")
    assert not is_prohibited("LockBit lists insurer", "The ransomware group published stolen files.")
