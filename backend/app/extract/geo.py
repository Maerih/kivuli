"""Country detection from names, demonyms, major cities and country-code domains."""
import re
from functools import lru_cache

import pycountry

# Names too ambiguous to trust in free text (US state, surname, first name, ransomware brand...).
_AMBIGUOUS = {"Georgia", "Jersey", "Chad", "Jordan", "Cuba", "Guernsey", "Monaco", "Reunion", "Réunion"}
# ccTLDs sold as generic domains; a hit says nothing about the country.
_GENERIC_CCTLDS = {"io", "co", "me", "tv", "cc", "ai", "to", "ly", "fm", "am", "gg", "sh", "ws", "nu", "tk", "ml", "ga", "cf", "gq", "st", "la", "su", "eu", "app", "is", "im", "so", "vc", "ac", "bz", "pw"}
_CCTLD_FIX = {"uk": "GB"}

# Common names, demonyms and a few major cities. East Africa is covered in more depth.
_EXTRA: dict[str, list[str]] = {
    "KE": ["Kenyan", "Kenyans", "Nairobi", "Mombasa", "Kisumu", "Nakuru", "Eldoret"],
    "UG": ["Ugandan", "Kampala"],
    "TZ": ["Tanzania", "Tanzanian", "Dar es Salaam", "Dodoma", "Zanzibar"],
    "RW": ["Rwandan", "Kigali"],
    "ET": ["Ethiopian", "Addis Ababa"],
    "SO": ["Somali", "Mogadishu"],
    "SS": ["South Sudanese", "Juba"],
    "BI": ["Burundian", "Bujumbura"],
    "CD": ["DR Congo", "DRC", "Democratic Republic of Congo", "Congolese", "Kinshasa"],
    "NG": ["Nigerian", "Lagos", "Abuja"],
    "GH": ["Ghanaian", "Accra"],
    "ZA": ["South African", "Johannesburg", "Cape Town", "Pretoria"],
    "EG": ["Egyptian", "Cairo"],
    "MA": ["Moroccan"],
    "CI": ["Ivory Coast", "Ivorian"],
    "US": ["United States", "USA", "U.S.", "American"],
    "GB": ["United Kingdom", "UK", "Britain", "British", "England", "Scotland", "Wales"],
    "RU": ["Russia", "Russian"],
    "CN": ["China", "Chinese"],
    "IR": ["Iran", "Iranian"],
    "KP": ["North Korea", "North Korean", "DPRK"],
    "KR": ["South Korea", "South Korean"],
    "IN": ["Indian"],
    "PK": ["Pakistani"],
    "DE": ["German"],
    "FR": ["French"],
    "IT": ["Italian"],
    "ES": ["Spanish"],
    "NL": ["Dutch", "The Netherlands"],
    "BR": ["Brazilian"],
    "CA": ["Canadian"],
    "AU": ["Australian"],
    "JP": ["Japanese"],
    "IL": ["Israeli"],
    "UA": ["Ukrainian"],
    "TR": ["Turkey", "Turkish", "Türkiye"],
    "SA": ["Saudi"],
    "AE": ["UAE", "Emirati", "Dubai", "Abu Dhabi"],
    "VN": ["Vietnam", "Vietnamese"],
    "TW": ["Taiwan", "Taiwanese"],
    "SY": ["Syria", "Syrian"],
    "VE": ["Venezuela", "Venezuelan"],
    "BO": ["Bolivia"],
    "MD": ["Moldova"],
    "LA": ["Laos"],
    "CZ": ["Czech Republic", "Czech"],
    "MX": ["Mexican"],
    "ID": ["Indonesian"],
    "PH": ["Philippine", "Filipino"],
    "TH": ["Thai"],
    "MY": ["Malaysian"],
    "SG": ["Singaporean"],
}


@lru_cache
def _tables() -> tuple[dict[str, str], re.Pattern, dict[str, str]]:
    name_to_code: dict[str, str] = {}
    display: dict[str, str] = {}
    for country in pycountry.countries:
        code = country.alpha_2
        names = {country.name, getattr(country, "common_name", None), getattr(country, "official_name", None)}
        display[code] = getattr(country, "common_name", None) or country.name.split(",")[0]
        for name in names:
            if name and "," not in name and name not in _AMBIGUOUS:
                name_to_code[name] = code
    for code, extras in _EXTRA.items():
        for name in extras:
            name_to_code[name] = code
        if code in ("TZ", "RU", "IR", "KP", "KR", "TR", "VN", "TW", "SY", "VE", "BO", "MD", "LA", "CZ"):
            display[code] = extras[0]
    alternation = "|".join(re.escape(n) for n in sorted(name_to_code, key=len, reverse=True))
    pattern = re.compile(rf"(?<![\w-])(?:{alternation})(?![\w-])")
    return name_to_code, pattern, display


def country_name(code: str) -> str:
    return _tables()[2].get(code.upper(), code.upper())


def country_numeric(code: str) -> str:
    """ISO 3166 numeric code ("404" for KE), which world map data uses to identify countries."""
    country = pycountry.countries.get(alpha_2=code.upper())
    return country.numeric if country else ""


def all_countries() -> dict[str, str]:
    return dict(_tables()[2])


def country_from_term(term: str) -> str | None:
    """Resolve a user-typed term ("kenya", "KE", "Kenyan") to an ISO code."""
    term = term.strip()
    if not term:
        return None
    name_to_code, _, display = _tables()
    if len(term) == 2 and term.upper() in display and term.isupper():
        return term.upper()
    lowered = term.lower()
    for name, code in name_to_code.items():
        if name.lower() == lowered:
            return code
    return None


def country_terms(code: str) -> list[str]:
    """Text forms worth matching for a country: names, demonyms and cities."""
    name_to_code, _, _ = _tables()
    return sorted({name for name, c in name_to_code.items() if c == code}, key=len)


def detect_countries(text: str, domains: list[str] | None = None, limit: int = 6) -> list[str]:
    """Countries a document is about, strongest evidence first."""
    name_to_code, pattern, display = _tables()
    scores: dict[str, float] = {}
    for match in pattern.finditer(text[:200_000]):
        code = name_to_code[match.group(0)]
        scores[code] = scores.get(code, 0) + 1.0
    for domain in domains or []:
        tld = domain.rsplit(".", 1)[-1].lower()
        if len(tld) != 2 or tld in _GENERIC_CCTLDS:
            continue
        code = _CCTLD_FIX.get(tld, tld.upper())
        if code in display:
            scores[code] = scores.get(code, 0) + 1.0
    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    if not ranked:
        return []
    # Drop passing mentions when one country clearly dominates a long document.
    floor = 1.0 if ranked[0][1] < 6 else ranked[0][1] * 0.15
    return [code for code, score in ranked if score >= floor][:limit]
