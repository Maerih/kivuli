"""Settings an administrator changes in the console. PostgreSQL is the record; every reader sees a change within seconds."""
import time

from sqlalchemy.orm import Session

from app.models import AppSetting, utcnow

AUTO_APPROVE = {
    "manual": "Nothing is collected until a researcher approves the site",
    "leak_sites": "Ransomware and extortion leak sites listed by victim trackers are collected as soon as they respond",
    "relevant": "Leak sites, plus any discovered onion site whose own title is clearly about security research",
}
DEFAULTS: dict[str, dict] = {
    "collection": {
        "auto_approve": "leak_sites",
        "relevance_threshold": 4,  # of 10, for the "relevant" policy
        "max_onion_sources": 400,  # ceiling on automatically approved onion sources
        "discovery_groups_per_run": 10,
        "research_max_depth": 4,
        "research_max_pages": 300,
    },
}
_LIMITS = {"relevance_threshold": (1, 10), "max_onion_sources": (0, 5000), "discovery_groups_per_run": (1, 40), "research_max_depth": (1, 6),
           "research_max_pages": (5, 2000)}
_cache: dict[str, tuple[float, dict]] = {}


def get(db: Session, key: str = "collection") -> dict:
    cached = _cache.get(key)
    if cached and time.monotonic() - cached[0] < 10:
        return cached[1]
    row = db.get(AppSetting, key)
    value = {**DEFAULTS[key], **((row.value if row else None) or {})}
    _cache[key] = (time.monotonic(), value)
    return value


def put(db: Session, key: str, values: dict, user_id: int | None) -> dict:
    """Validate and store. Unknown names are ignored; out-of-range numbers are refused."""
    current = dict(get(db, key))
    for name, value in values.items():
        if name not in DEFAULTS[key] or value is None:
            continue
        if name == "auto_approve":
            if value not in AUTO_APPROVE:
                raise ValueError("auto_approve must be manual, leak_sites or relevant")
        else:
            low, high = _LIMITS[name]
            if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
                raise ValueError(f"{name} must be a whole number from {low} to {high}")
        current[name] = value
    row = db.get(AppSetting, key)
    if row is None:
        row = AppSetting(key=key)
        db.add(row)
    row.value, row.updated_by, row.updated_at = current, user_id, utcnow()
    _cache.pop(key, None)
    return current
