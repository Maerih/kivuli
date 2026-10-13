"""Secret redaction and exposure records.

Leak pages carry other people's passwords, keys and card numbers. The platform's
job is to tell a defender *that* an account or key is exposed, not to become a
second copy of the stolen secret - so secrets are masked before anything is
stored, indexed or emailed. The hash of the unredacted capture is kept as
evidence, and each exposure is recorded as a fact: who, where, what kind.

High-entropy keys and tokens also get a short SHA-256 fingerprint, so an owner
can check "is this my key?" without the key ever being kept. Passwords are never
fingerprinted: a hash of a human-chosen password can be guessed.
"""
import hashlib
import re
from dataclasses import dataclass, field

MASK = "[REDACTED]"
MAX_RECORDS = 2000

_EMAIL = r"[a-z0-9][a-z0-9._%+-]{0,63}@(?:[a-z0-9-]+\.)+[a-z]{2,24}"
RE_COMBO = re.compile(rf"(?i)(?<![\w.+%-])({_EMAIL})([ \t]*[:;|][ \t]*)([^\s:;|]{{3,128}})")
# Infostealer logs list one credential per block: where it is used, who, and the password.
RE_STEALER = re.compile(
    r"(?im)^[ \t]*(?:url|host|site|link)[ \t]*[:=][ \t]*(\S+)[ \t]*\r?\n"
    r"[ \t]*(?:user(?:name)?|login|e?mail)[ \t]*[:=][ \t]*(\S+)[ \t]*\r?\n"
    r"[ \t]*(?:pass(?:word)?|pwd)[ \t]*[:=][ \t]*(\S+)"
)
RE_LABELLED = re.compile(
    r"(?i)\b(pass(?:word|wd)?|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|token|bearer)"
    r"(\s*[:=]\s*|\s+is\s+)(['\"]?)([^\s'\"<>]{3,256})"
)
RE_PRIVATE_KEY = re.compile(r"-----BEGIN ([A-Z ]*)PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)
RE_CARD = re.compile(r"(?<![\d.])(?:\d[ -]?){12,18}\d(?![\d.])")

# (name, exposure kind, pattern). Formats are the vendors' published key shapes.
_TOKENS: list[tuple[str, str, re.Pattern]] = [
    ("aws_access_key", "cloud_secret", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", "token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ("github_fine_grained_token", "token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,255}\b")),
    ("gitlab_token", "token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("slack_token", "token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", "api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe_live_key", "api_key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{24,}\b")),
    ("sendgrid_key", "api_key", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")),
    ("azure_storage_key", "cloud_secret", re.compile(r"(?i)\bAccountKey=[A-Za-z0-9+/]{80,}={0,2}")),
    ("jwt", "token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
]

# Words that follow "email:" in prose rather than in a credential dump.
_NOT_A_PASSWORD = {"http", "https", "www", "the", "and", "for", "please", "contact", "email", "phone", "tel", "none", "null", "n/a"}
_LABEL_KIND = {"api": "api_key", "access": "api_key", "token": "token", "auth": "token", "bearer": "token", "secret": "api_key"}


@dataclass
class Exposure:
    credential_pairs: int = 0
    secrets: int = 0
    private_keys: int = 0
    cards: int = 0
    stealer_logs: int = 0
    accounts: list[str] = field(default_factory=list)  # addresses seen with a password
    records: list[dict] = field(default_factory=list)  # one per exposed identity or secret

    @property
    def any(self) -> bool:
        return bool(self.credential_pairs or self.secrets or self.private_keys or self.cards or self.stealer_logs)

    def as_dict(self) -> dict:
        return {
            "credential_pairs": self.credential_pairs,
            "secrets": self.secrets,
            "private_keys": self.private_keys,
            "cards": self.cards,
            "stealer_logs": self.stealer_logs,
        }

    def record(self, kind: str, *, identity: str = "", domain: str = "", service: str = "", secret_type: str = "",
               fingerprint: str = "", password_exposed: bool = False) -> None:
        if len(self.records) < MAX_RECORDS:
            self.records.append({"kind": kind, "identity": identity[:320], "domain": domain[:255].lower(), "service": service[:255].lower(),
                                 "secret_type": secret_type, "fingerprint": fingerprint, "password_exposed": password_exposed})


def fingerprint(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8", "replace")).hexdigest()[:16]


def _host(url: str) -> str:
    return re.sub(r"^[a-z][a-z0-9+.-]*://", "", url.strip(), flags=re.I).split("/")[0].split("@")[-1].split(":")[0].lower()


def _luhn_ok(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def redact(text: str) -> tuple[str, Exposure]:
    """Mask secrets in ``text`` and report what was exposed."""
    exp = Exposure()

    def private_key(m: re.Match) -> str:
        exp.private_keys += 1
        label = (m.group(1).strip().lower() or "generic").replace(" ", "_")
        exp.record("private_key", secret_type=f"{label}_private_key", fingerprint=fingerprint(re.sub(r"\s+", "", m.group(0))))
        return "[REDACTED PRIVATE KEY]"

    def stealer(m: re.Match) -> str:
        url, user = m.group(1), m.group(2)
        exp.stealer_logs += 1
        host = _host(url)
        domain = user.rsplit("@", 1)[-1] if "@" in user else host
        exp.record("stealer_log", identity=user.lower(), domain=domain, service=host, password_exposed=True)
        return m.group(0)[: m.start(3) - m.start(0)] + MASK

    def combo(m: re.Match) -> str:
        candidate = m.group(3)
        if candidate == MASK or candidate.lower().strip(".,") in _NOT_A_PASSWORD or candidate.lower().startswith(("http://", "https://", "//")):
            return m.group(0)
        exp.credential_pairs += 1
        account = m.group(1).lower()
        if len(exp.accounts) < 1000:
            exp.accounts.append(account)
        exp.record("credential", identity=account, domain=account.rsplit("@", 1)[-1], password_exposed=True)
        return f"{m.group(1)}{m.group(2)}{MASK}"

    def token(name: str, kind: str):
        def replace(m: re.Match) -> str:
            exp.secrets += 1
            exp.record(kind, secret_type=name, fingerprint=fingerprint(m.group(0)))
            return MASK
        return replace

    def labelled(m: re.Match) -> str:
        value = m.group(4)
        if value == MASK or value.startswith("[REDACTED") or value.lower() in _NOT_A_PASSWORD:
            return m.group(0)
        exp.secrets += 1
        label = m.group(1).lower()
        kind = next((k for prefix, k in _LABEL_KIND.items() if label.startswith(prefix)), "")
        if kind:  # a key or token, not a human password
            exp.record(kind, secret_type=f"labelled_{label.replace('-', '_')}", fingerprint=fingerprint(value) if len(value) >= 16 else "")
        return f"{m.group(1)}{m.group(2)}{m.group(3)}{MASK}"

    def card(m: re.Match) -> str:
        digits = re.sub(r"\D", "", m.group(0))
        if not (13 <= len(digits) <= 19) or len(set(digits)) < 2 or not _luhn_ok(digits):
            return m.group(0)
        exp.cards += 1
        exp.record("card", secret_type="payment_card", identity=f"****{digits[-4:]}")
        return f"[REDACTED CARD ****{digits[-4:]}]"

    text = RE_PRIVATE_KEY.sub(private_key, text)
    text = RE_STEALER.sub(stealer, text)
    text = RE_COMBO.sub(combo, text)
    for name, kind, pattern in _TOKENS:
        text = pattern.sub(token(name, kind), text)
    text = RE_LABELLED.sub(labelled, text)
    text = RE_CARD.sub(card, text)
    return text, exp
