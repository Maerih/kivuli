"""Lightweight language identification for collected text.

Good enough to filter a search by language and to tell a researcher what they
are about to open. Scripts are recognised by their characters; languages in the
Latin script by their most common function words. No model, no dependency.
"""
import re

_SCRIPTS = (("ru", re.compile(r"[Ѐ-ӿ]")), ("zh", re.compile(r"[一-鿿]")), ("ar", re.compile(r"[؀-ۿ]")),
            ("ja", re.compile(r"[぀-ヿ]")), ("ko", re.compile(r"[가-힯]")), ("he", re.compile(r"[֐-׿]")),
            ("th", re.compile(r"[฀-๿]")), ("fa", re.compile(r"[پچژگ]")))
_STOPWORDS = {
    "en": "the and of to in is that for with this on are was have not you from your will we our all can has",
    "es": "de la que el en los del las por un para con una su al lo como más pero sus le ya este",
    "fr": "le de la les et des en un une du que est pour dans qui sur pas au plus par avec ce sont",
    "de": "der die und in den von zu das mit sich des auf für ist im dem nicht ein eine als auch es",
    "pt": "de que não o a do da em um para com uma os no se na por mais as dos como mas foi ao",
    "it": "di che la il per un in del è non le una si con dei alla più da sono gli nel questo",
    "nl": "de van het een en in is dat op te zijn met voor niet aan er ook als bij maar om",
    "tr": "bir ve bu için ile de da çok daha olarak gibi en kadar ancak ise veya her olan",
    "sw": "ya na wa kwa ni za katika la kuwa hii kama pia au yake hiyo wake sana hata baada",
    "id": "yang dan di ini itu dengan untuk dari tidak dalam akan pada juga ke saya ada bisa",
    "pl": "nie się na jest że do to jak ale po co tak za od jego czy tylko przez przy już",
}
_WORDS = {lang: frozenset(words.split()) for lang, words in _STOPWORDS.items()}
_TOKEN = re.compile(r"[^\W\d_]{2,}", re.UNICODE)

LANGUAGE_NAMES = {"en": "English", "ru": "Russian", "zh": "Chinese", "ar": "Arabic", "ja": "Japanese", "ko": "Korean", "he": "Hebrew", "th": "Thai",
                  "fa": "Persian", "es": "Spanish", "fr": "French", "de": "German", "pt": "Portuguese", "it": "Italian", "nl": "Dutch", "tr": "Turkish",
                  "sw": "Swahili", "id": "Indonesian", "pl": "Polish"}


def detect_language(text: str) -> str:
    """Return an ISO 639-1 code, or an empty string when the text is too short or mixed to call."""
    sample = (text or "")[:6000]
    letters = sum(1 for c in sample if c.isalpha())
    if letters < 40:
        return ""
    for code, pattern in _SCRIPTS:
        # Persian is checked after Arabic and only wins on its own letters.
        if code == "fa":
            continue
        if len(pattern.findall(sample)) / letters > 0.3:
            if code == "ar" and len(_SCRIPTS[-1][1].findall(sample)) / letters > 0.02:
                return "fa"
            return code
    tokens = [t.lower() for t in _TOKEN.findall(sample)]
    if len(tokens) < 12:
        return ""
    scores = {lang: sum(1 for t in tokens if t in words) for lang, words in _WORDS.items()}
    best = max(scores, key=scores.get)
    ranked = sorted(scores.values(), reverse=True)
    if scores[best] / len(tokens) < 0.06 or (len(ranked) > 1 and ranked[0] < ranked[1] * 1.25):
        return ""
    return best
