"""Collection guardrails.

The crawler exists to find evidence of compromise, not to mirror the dark web.
Pages that advertise child sexual abuse material are never stored or indexed, and
the source that served them is blocked so it is never fetched again.
"""
import re

# Deliberately narrow: markers that advertise this material, not words a news
# article or a law-enforcement notice about it would be limited to.
_ABUSE_MARKERS = re.compile(
    r"\b(?:child\s*porn\w*|cp\s+(?:links?|videos?|forum|collection)|pedo(?:phile|philia)?\s+(?:forum|links?|videos?|community)"
    r"|pthc|hurtcore|jailbait\s+(?:pics?|videos?|forum)|preteen\s+(?:porn|sex|nude)|loli(?:con|ta)\s+(?:porn|videos?|links?))\b",
    re.I,
)
_REPORTING_CONTEXT = re.compile(r"\b(?:arrest\w*|sentenced|indict\w*|convicted|europol|interpol|fbi|takedown|seized|charged|prosecut\w*)\b", re.I)


def is_prohibited(title: str, text: str) -> bool:
    sample = f"{title}\n{text[:20000]}"
    hits = len(_ABUSE_MARKERS.findall(sample))
    if hits == 0:
        return False
    # Journalism and law-enforcement reporting mentions the subject without advertising it.
    if hits <= 2 and _REPORTING_CONTEXT.search(sample):
        return False
    return True


_BINARY_EXT = re.compile(
    r"\.(?:zip|rar|7z|tar|gz|tgz|bz2|xz|iso|img|exe|msi|dll|bin|apk|dmg|sql|bak|dump|csv|xlsx?|docx?|pptx?|pdf|"
    r"jpe?g|png|gif|webp|bmp|svg|ico|mp[34]|avi|mkv|mov|webm|wav|flac|torrent|css|js|woff2?|ttf|eot)(?:$|[?#])",
    re.I,
)
_ACTION_PATH = re.compile(
    r"(?:^|[/?&=_.-])(?:login|logout|signin|signup|sign-up|register|registration|captcha|download|attachment|file|"
    r"cart|checkout|order|buy|payment|pay|deposit|password|reset|delete|remove|unsubscribe|vote|post-reply|newreply)(?:[/?&=_.-]|$)",
    re.I,
)


def is_fetchable_link(url: str) -> bool:
    """Only follow links to readable pages: never files, and never anything that
    looks like an account action, a purchase or a download."""
    return not _BINARY_EXT.search(url) and not _ACTION_PATH.search(url.split("://", 1)[-1])
