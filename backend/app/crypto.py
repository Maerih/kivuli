"""Encryption of secrets at rest (integration credentials, MFA seeds).

The key lives in the environment, never in the database, so a database dump on
its own does not disclose third-party credentials.
"""
import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from app.config import get_settings


def _fernet(setting: str = "secrets_key") -> Fernet:
    key = getattr(get_settings(), setting)
    if not key:
        raise RuntimeError(f"{setting.upper()} is not set; run ./ctl.sh start to generate it")
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest()))


def encrypt(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode() if plaintext else ""


def decrypt(token: str) -> str:
    if not token:
        return ""
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken:
        raise RuntimeError("stored secret cannot be decrypted: SECRETS_KEY has changed") from None


# Provider API keys use their own key, so the enricher (which must read them) never
# holds the key that protects two-step sign-in seeds and alert-destination secrets.

def seal(plaintext: str) -> str:
    return _fernet("provider_keys_key").encrypt(plaintext.encode()).decode() if plaintext else ""


def unseal(token: str) -> str:
    if not token:
        return ""
    try:
        return _fernet("provider_keys_key").decrypt(token.encode()).decode()
    except InvalidToken:
        raise RuntimeError("stored provider key cannot be decrypted: PROVIDER_KEYS_KEY has changed") from None
