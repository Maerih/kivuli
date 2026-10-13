"""Text normalisation, hashing and near-duplicate fingerprints."""
import hashlib
import re
import unicodedata

_WS = re.compile(r"[ \t\f\v ]+")
_BLANK_LINES = re.compile(r"\n\s*\n\s*(?:\n\s*)+")
_WORD = re.compile(r"[a-z0-9]{2,}")


def normalize_text(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).replace("\r\n", "\n").replace("\r", "\n").replace("\x00", "")
    text = "\n".join(_WS.sub(" ", line).strip() for line in text.split("\n"))
    return _BLANK_LINES.sub("\n\n", text).strip()


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    return hashlib.sha256(data).hexdigest()


def slugify(value: str) -> str:
    value = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:200] or "unnamed"


def summarize(text: str, limit: int = 320) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[:limit].rsplit(" ", 1)[0] + "…"


def simhash64(text: str) -> int:
    """64-bit SimHash over word trigrams. Similar pages differ in only a few bits."""
    words = _WORD.findall(text.lower())
    if len(words) < 3:
        shingles = words or [""]
    else:
        shingles = [" ".join(words[i : i + 3]) for i in range(len(words) - 2)]
    weights = [0] * 64
    for shingle in set(shingles):
        h = int.from_bytes(hashlib.blake2b(shingle.encode(), digest_size=8).digest(), "big")
        for bit in range(64):
            weights[bit] += 1 if (h >> bit) & 1 else -1
    value = 0
    for bit in range(64):
        if weights[bit] > 0:
            value |= 1 << bit
    return value


def simhash_bands(value: int) -> tuple[int, int, int, int]:
    """Four 16-bit bands. Two hashes within 3 bits of each other share at least one."""
    return tuple((value >> shift) & 0xFFFF for shift in (0, 16, 32, 48))  # type: ignore[return-value]


def to_signed64(value: int) -> int:
    return value - (1 << 64) if value >= (1 << 63) else value


def from_signed64(value: int) -> int:
    return value + (1 << 64) if value < 0 else value


def hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def line_diff_stats(old: str, new: str) -> dict:
    old_lines = {line for line in old.split("\n") if line.strip()}
    new_lines = {line for line in new.split("\n") if line.strip()}
    added, removed = new_lines - old_lines, old_lines - new_lines
    union = len(old_lines | new_lines) or 1
    return {
        "added_lines": len(added),
        "removed_lines": len(removed),
        "similarity": round(len(old_lines & new_lines) / union, 3),
        "added_sample": sorted(added, key=len, reverse=True)[:5],
        "removed_sample": sorted(removed, key=len, reverse=True)[:5],
    }
