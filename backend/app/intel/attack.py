"""MITRE ATT&CK: the bundled catalogue and technique recognition.

Techniques are recognised two ways. An explicit identifier (T1566.001) is taken
at face value. Otherwise a small set of behaviour phrases maps to the technique
they describe; these are deliberately conservative and carry lower confidence.
"""
import json
import os
import re
from functools import lru_cache

_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "attack.json")
RE_TECHNIQUE_ID = re.compile(r"\bT(\d{4})(?:\.(\d{3}))?\b")

# (pattern, technique id, confidence)
_BEHAVIOURS: list[tuple[str, str, int]] = [
    (r"\bransomware\b|\bfiles? (?:were|are|was) encrypted\b|\bencrypt(?:ed|ing) (?:the )?(?:network|servers|systems|files)\b", "T1486", 70),
    (r"\bdouble extortion\b|\bleak site\b|\bdata will be (?:published|leaked)\b|\bexfiltrat\w+", "T1567", 55),
    (r"\bspear[- ]?phish\w*", "T1566.001", 65),
    (r"\bphishing (?:email|campaign|link|page|kit)s?\b|\bphish(?:ing|ed)\b", "T1566", 60),
    (r"\bstolen credentials\b|\bcompromised (?:credentials|accounts?)\b|\bvalid accounts?\b|\bcredential stuffing\b", "T1078", 55),
    (r"\bbrute[- ]?forc\w+|\bpassword spray\w*", "T1110", 65),
    (r"\bexploit\w* (?:a |the )?(?:vulnerabilit\w+|flaw|bug|zero[- ]day)\b.{0,60}\b(?:vpn|firewall|gateway|appliance|server|web|public[- ]facing)\b|\bpublic[- ]facing application\b", "T1190", 60),
    (r"\b(?:rdp|remote desktop)\b", "T1021.001", 55),
    (r"\bexternal remote services?\b|\bvpn (?:access|credentials|compromise)\b|\bcitrix access\b", "T1133", 55),
    (r"\bsupply[- ]chain (?:attack|compromise)\b|\btrojani[sz]ed (?:update|installer|package)\b", "T1195", 65),
    (r"\bweb ?shell\b", "T1505.003", 70),
    (r"\bdefac(?:ed|ement|ing)\b", "T1491", 70),
    (r"\bddos\b|\bdenial[- ]of[- ]service\b", "T1498", 70),
    (r"\b(?:info)?stealer logs?\b|\binfostealer\b|\bbrowser (?:passwords|credentials|cookies)\b", "T1555.003", 60),
    (r"\bsession (?:cookie|token)s? (?:theft|stolen|hijack\w*)\b|\bcookie theft\b", "T1539", 65),
    (r"\bmimikatz\b|\blsass\b|\bcredential dump\w*", "T1003", 70),
    (r"\bcobalt strike\b|\bbeacon(?:ing)?\b.{0,40}\bc2\b|\bcommand[- ]and[- ]control\b", "T1071", 50),
    (r"\bpowershell\b", "T1059.001", 55),
    (r"\bscheduled task\b", "T1053.005", 65),
    (r"\bdata (?:wiper|destruction)\b|\bwiper malware\b|\bwiped (?:data|systems|servers)\b", "T1485", 65),
    (r"\bsim[- ]?swap\w*", "T1451", 55),
    (r"\bmfa (?:fatigue|bombing)\b|\bpush bombing\b", "T1621", 70),
    (r"\bbusiness email compromise\b|\bbec (?:attack|scam|fraud)\b", "T1534", 55),
    (r"\bdrive[- ]by (?:download|compromise)\b|\bwatering[- ]hole\b", "T1189", 65),
    (r"\bmalicious (?:attachment|document|macro)s?\b", "T1204.002", 60),
    (r"\bprivilege escalation\b", "T1068", 50),
    (r"\blateral movement\b", "T1021", 45),
    (r"\bdns tunnel\w*", "T1071.004", 70),
    (r"\bcryptominer\b|\bcrypto[- ]?jacking\b|\bcrypto(?:currency)? mining malware\b", "T1496", 65),
    (r"\bdisabl\w+ (?:antivirus|edr|defender|security tools?)\b|\bbyovd\b", "T1562.001", 60),
    (r"\bshadow cop(?:y|ies)\b|\binhibit system recovery\b|\bdeleted backups\b", "T1490", 70),
    (r"\bdatabase dump\b|\bsql dump\b|\bdumped (?:the )?database\b", "T1005", 45),
    (r"\bsql injection\b|\bsqli\b", "T1190", 55),
    (r"\binitial access broker\b|\bselling (?:network |corp(?:orate)? )?access\b", "T1650", 60),
    (r"\btyposquat\w*|\blookalike domain\b", "T1583.001", 60),
]
_COMPILED = [(re.compile(pattern, re.I | re.S), technique, confidence) for pattern, technique, confidence in _BEHAVIOURS]


@lru_cache
def catalog() -> dict:
    with open(_PATH, encoding="utf-8") as fh:
        return json.load(fh)


@lru_cache
def techniques() -> dict[str, dict]:
    return {t["id"]: t for t in catalog()["techniques"]}


def technique_label(technique_id: str) -> str:
    technique = techniques().get(technique_id)
    return f"{technique_id} {technique['name']}" if technique else technique_id


def extract_techniques(title: str, text: str, limit: int = 12) -> dict[str, int]:
    """Return {technique id: confidence} for techniques evidenced in the text."""
    known = techniques()
    sample = f"{title}\n{text[:80_000]}"
    found: dict[str, int] = {}
    for match in RE_TECHNIQUE_ID.finditer(sample):
        technique_id = f"T{match.group(1)}" + (f".{match.group(2)}" if match.group(2) else "")
        if technique_id in known:
            found[technique_id] = 95
    for pattern, technique_id, confidence in _COMPILED:
        if technique_id in known and technique_id not in found and pattern.search(sample):
            found[technique_id] = confidence
    ranked = sorted(found.items(), key=lambda kv: kv[1], reverse=True)[:limit]
    return dict(ranked)
