"""How relevant a site's own description of itself looks to security research.

Used on a site's landing-page title when it is first checked, so a researcher
reviewing discovered onion sites can tell a leak blog from a shop selling
something unrelated, and so the collection policy can act on it.
"""
import html
import re

_STRONG = re.compile(r"\b(ransom\w*|leak\w*|breach\w*|extort\w*|hack\w*|exploit\w*|malware|stealer|botnet|carding|cve|0day|zero.?day|dump\w*|"
                     r"databases?|combo\w*|credential\w*|logs?|access broker|initial access|ddos|phish\w*|defac\w*|cyber\w*|infosec|pentest\w*|"
                     r"vulnerabilit\w+|threat|apt\d*|rats?|trojan|spyware|doxx?\w*|whistleblow\w*|взлом\w*|утечк\w*|слив\w*|хак\w*)\b", re.I)
_CONTEXT = re.compile(r"\b(forum|board|blog|news|market\w*|shop|store|paste\w*|wiki|index|archive|team|group|gang|data|files?|victims?|"
                      r"companies|clients|press|security|форум|рынок)\b", re.I)
_UNRELATED = re.compile(r"\b(casino|bet\w*|porn\w*|escort\w*|drugs?|weed|cannabis|cocaine|pills?|pharmac\w*|steroid\w*|counterfeit|"
                        r"fake (?:id|passport)|hitman|gun\w*|weapon\w*|bitcoin (?:doubler|multiplier|generator)|lottery|dating)\b", re.I)


def research_relevance(title: str, context: str = "") -> int:
    """0 (nothing suggests it) to 10 (clearly security-research material)."""
    text = f"{title} {context}"[:600]
    score = 3 * len({m.lower() for m in _STRONG.findall(text)}) + len({m.lower() for m in _CONTEXT.findall(text)})
    if _UNRELATED.search(text):
        score -= 4
    return max(0, min(10, score))


_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def page_title(body: str) -> str:
    """What a page calls itself, as plain text: tags stripped, entities decoded, length capped."""
    match = _TITLE.search(body or "")
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", match.group(1))).split())[:200] if match else ""
