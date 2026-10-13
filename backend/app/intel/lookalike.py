"""Lookalike-domain detection for brand protection.

Given a domain seen in collected intelligence and a domain (or brand name) the
organisation owns, decide whether the first imitates the second, and say why.
"""
import re

from app.extract.iocs import registered_domain

_HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("cl", "d"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"), ("7", "t"), ("8", "b"), ("|", "l")]
_AFFIXES = ("login", "secure", "account", "verify", "update", "support", "portal", "online", "pay", "payment", "auth", "sso",
            "mail", "webmail", "service", "help", "id", "my", "app", "bank", "wallet", "official", "ke")


def _label(domain: str) -> tuple[str, str]:
    base = registered_domain(domain) or domain.lower()
    name, _, suffix = base.partition(".")
    return name, suffix


def _skeleton(name: str) -> str:
    for src, dst in _HOMOGLYPHS:
        name = name.replace(src, dst)
    return name.replace("-", "")


def _distance(a: str, b: str, cap: int = 3) -> int:
    """Damerau-Levenshtein distance, abandoned early once it exceeds ``cap``."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    previous2: list[int] = []
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            value = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                value = min(value, previous2[j - 2] + 1)
            current.append(value)
        if min(current) > cap:
            return cap + 1
        previous2, previous = previous, current
    return previous[-1]


def lookalike_reason(candidate: str, brand: str) -> str | None:
    """Why ``candidate`` looks like an imitation of ``brand`` (a domain or a bare name), or None."""
    candidate = candidate.lower().strip(".")
    brand = brand.lower().strip(". ")
    brand_is_domain = "." in brand
    brand_name, brand_suffix = _label(brand) if brand_is_domain else (re.sub(r"[^a-z0-9]", "", brand), "")
    name, suffix = _label(candidate)
    if len(brand_name) < 4 or not name:
        return None
    if brand_is_domain and (candidate == brand or candidate.endswith("." + (registered_domain(brand) or brand))):
        return None  # the brand's own domain or a subdomain of it
    if candidate.startswith("xn--") or ".xn--" in candidate:
        if _distance(_skeleton(re.sub(r"[^a-z0-9]", "", name.replace("xn--", ""))), brand_name, 2) <= 2:
            return "internationalised (punycode) name resembling the brand"
    if name == brand_name:
        return f"same name on a different top-level domain (.{suffix})" if brand_is_domain and suffix != brand_suffix else None
    if _skeleton(name) == _skeleton(brand_name):
        return "look-alike characters (e.g. 0 for o, rn for m)"
    limit = 1 if len(brand_name) < 9 else 2
    if len(brand_name) >= 5 and _distance(name, brand_name, limit) <= limit:
        return "one or two characters away from the brand name"
    tokens = [t for t in re.split(r"[-_.]", name) if t]
    if len(brand_name) >= 5 and brand_name in tokens and len(tokens) > 1:
        return "brand name combined with other words"
    if len(brand_name) >= 6:
        for affix in _AFFIXES:
            if name in (brand_name + affix, affix + brand_name):
                return f"brand name with \"{affix}\" attached"
    return None
