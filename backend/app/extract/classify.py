"""Rule-based threat-type classification with an explainable confidence score."""
import re

THREAT_TYPES = {
    "ransomware": "Ransomware / extortion",
    "data_breach": "Data breach / leak",
    "credential_leak": "Credential exposure",
    "access_sale": "Initial access sale",
    "defacement": "Compromised / defaced site",
    "malware": "Malware",
    "phishing": "Phishing",
    "ddos": "DDoS",
    "vulnerability": "Vulnerability / exploit",
    "fraud": "Fraud / carding",
    "hacktivism": "Hacktivism",
    "other": "Other",
}

_RULES: dict[str, list[tuple[str, int]]] = {
    "ransomware": [
        (r"\bransomware\b", 5), (r"\bransom\b", 3), (r"\bextort\w*", 4), (r"\bleak site\b", 3),
        (r"\bdata will be (?:published|leaked|released)\b", 4), (r"\bencrypt(?:ed|ion|or)\b", 2),
        (r"\bdecrypt(?:or|ion)\b", 3), (r"\bnegotiat\w+", 2), (r"\b(?:payment|ransom) deadline\b", 3),
        (r"\blocker\b", 2), (r"\bdouble extortion\b", 3), (r"\bvictims?\b", 1),
    ],
    "data_breach": [
        (r"\bdata breach\b", 5), (r"\bbreach(?:ed|es)?\b", 3), (r"\bleak(?:ed|s|ing)?\b", 3),
        (r"\b(?:database|db|sql) dump\b", 4), (r"\bdatabase\b", 2), (r"\bexfiltrat\w+", 3),
        (r"\bstolen (?:data|files|records|documents)\b", 4), (r"\bpersonal (?:data|information)\b|\bpii\b", 2),
        (r"\b\d[\d,.]*\s?(?:k|m|gb|tb|million|thousand)?\s+(?:of\s+)?(?:records|rows|users|customers|accounts|lines|files)\b", 3),
        (r"\bdump(?:ed)?\b", 2), (r"\bdata (?:for sale|sale)\b", 4),
    ],
    "credential_leak": [
        (r"\bcombo ?lists?\b", 5), (r"\bstealer logs?\b", 5), (r"\binfostealer\b", 4), (r"\bcredentials?\b", 3),
        (r"\b(?:e?mail|user|login):pass(?:word)?\b", 5), (r"\bmail access\b", 4), (r"\bpasswords?\b", 2),
        (r"\bcredential stuffing\b", 4), (r"\blogs? cloud\b", 3), (r"\[REDACTED\]", 2), (r"\bhashed passwords?\b", 3),
    ],
    "access_sale": [
        (r"\binitial access\b", 5), (r"\b(?:rdp|vpn|citrix|shell|webshell|rdweb|fortinet|ssh|cpanel) access\b", 5),
        (r"\b(?:selling|sell|sale of) (?:network |corp(?:orate)? )?access\b", 5), (r"\bdomain admin\b", 4),
        (r"\baccess to (?:a |the )?(?:network|company|corporate|bank|government)\b", 4), (r"\baccess broker\b", 5),
        (r"\brevenue\s*[:>$]", 2),
    ],
    "defacement": [
        (r"\bdefac(?:ed|ement|ing)\b", 5), (r"\bhacked by\b", 5), (r"\bpwn(?:ed|d)\b", 3),
        (r"\b(?:web)?sites? (?:was |were |has been |have been )?(?:hacked|compromised|defaced|taken over)\b", 5),
        (r"\bcompromised (?:web)?(?:site|server|host)s?\b", 4), (r"\bmirror\b", 1),
    ],
    "malware": [
        (r"\bmalware\b", 4), (r"\btrojan\b", 3), (r"\bbotnet\b", 4), (r"\bloader\b", 2), (r"\bstealer\b", 3),
        (r"\bbackdoor\b", 3), (r"\bcommand[- ]and[- ]control\b|\bc2\b", 3), (r"\bcrypter\b", 3), (r"\bpayload\b", 2),
        (r"\bspyware\b", 4), (r"\bwiper\b", 4), (r"\brootkit\b", 4), (r"\bkeylogger\b", 4),
    ],
    "phishing": [
        (r"\bphish\w*", 5), (r"\bscam page\b", 4), (r"\bspoof(?:ed|ing)\b", 2), (r"\bfake (?:login|site|page|app)\b", 4),
        (r"\bsmishing\b|\bvishing\b", 4), (r"\bbusiness email compromise\b|\bbec\b", 4), (r"\bphishing kit\b", 5),
    ],
    "ddos": [
        (r"\bddos\b", 5), (r"\bdenial[- ]of[- ]service\b", 5), (r"\bstresser\b|\bbooter\b", 4), (r"\bflood(?:ing)?\b", 1),
        (r"\b(?:knocked|taken) offline\b", 3),
    ],
    "vulnerability": [
        (r"\bcve-\d{4}-\d+", 4), (r"\b(?:0|zero)[- ]?day\b", 5), (r"\bexploit(?:ed|ation|s)?\b", 3),
        (r"\bvulnerabilit(?:y|ies)\b", 4), (r"\bremote code execution\b|\brce\b", 4), (r"\bproof[- ]of[- ]concept\b|\bpoc\b", 2),
        (r"\bprivilege escalation\b", 3), (r"\bsql injection\b|\bsqli\b", 3), (r"\bpatch(?:ed|es)?\b", 1),
    ],
    "fraud": [
        (r"\bcarding\b", 5), (r"\bcvv\b", 4), (r"\bfullz\b", 5), (r"\bdumps? (?:with|\+) pin\b", 5), (r"\bbank logs?\b", 4),
        (r"\bcredit cards?\b", 2), (r"\bcash ?out\b", 3), (r"\bsim swap\w*", 4), (r"\bfraud\w*", 2), (r"\bREDACTED CARD\b", 4),
    ],
    "hacktivism": [
        (r"\bhacktivis\w+", 5), (r"#op[a-z]\w+", 3), (r"\bin (?:protest|solidarity|retaliation)\b", 3),
        (r"\bcyber army\b", 4), (r"\bwe are legion\b", 4), (r"\bexpect us\b", 3),
    ],
}

_COMPILED = {kind: [(re.compile(p, re.I), w) for p, w in rules] for kind, rules in _RULES.items()}
_MIN_SCORE = 4.0


def classify(title: str, text: str, hint: str | None = None) -> tuple[str, list[str], int]:
    """Return (primary type, all plausible types, confidence 0-100).

    ``hint`` is a type asserted by a structured source (e.g. a ransomware tracker);
    it wins outright, because the source already did the classification.
    """
    sample = text[:60_000]
    scores: dict[str, float] = {}
    for kind, rules in _COMPILED.items():
        score = 0.0
        for pattern, weight in rules:
            hits = min(len(pattern.findall(sample)), 3)
            if hits:
                score += weight * (1 + 0.25 * (hits - 1))
            if pattern.search(title):
                score += weight
        if score:
            scores[kind] = score

    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    if hint and hint in THREAT_TYPES:
        others = [k for k, s in ranked if k != hint and s >= _MIN_SCORE][:3]
        return hint, [hint, *others], 90
    if not ranked or ranked[0][1] < _MIN_SCORE:
        return "other", ["other"], 25 if ranked else 15

    top_kind, top_score = ranked[0]
    margin = top_score - (ranked[1][1] if len(ranked) > 1 else 0)
    confidence = int(max(30, min(92, 35 + top_score * 2.5 + margin * 2)))
    plausible = [k for k, s in ranked if s >= max(_MIN_SCORE, top_score * 0.5)][:4]
    return top_kind, plausible, confidence
