"""Authentication, role checks and the audit trail."""
import base64
import hashlib
import re
import secrets
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import Argon2Error, InvalidHashError
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.models import ROLES, ApiKey, AuditLog, User, utcnow

COOKIE_NAME = "kivuli_session"
CSRF_HEADER = "x-kivuli-csrf"
_hasher = PasswordHasher()
_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,24}$")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (Argon2Error, InvalidHashError):
        return False


def password_problem(password: str) -> str | None:
    if len(password) < 12:
        return "Password must be at least 12 characters."
    if password.lower() == password or not re.search(r"\d", password):
        return "Password must mix upper and lower case and include a digit."
    return None


def valid_email(address: str) -> bool:
    return bool(_EMAIL.match(address))


def create_token(user: User) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload = {"sub": str(user.id), "iat": now, "exp": now + timedelta(minutes=settings.session_ttl_minutes)}
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    return (forwarded.split(",")[0].strip() or (request.client.host if request.client else ""))[:64]


API_KEY_PREFIX = "kv_"
_SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


def new_api_key() -> tuple[str, str, str]:
    """Return (full key, display prefix, hash). Only the hash is stored."""
    key = API_KEY_PREFIX + secrets.token_urlsafe(32)
    return key, key[:11], hashlib.sha256(key.encode()).hexdigest()


def _presented_key(request: Request) -> str | None:
    """An API key from Authorization: Bearer <key>, or HTTP Basic with the key as the password (TAXII clients)."""
    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() == "bearer":
        return value.strip()
    if scheme.lower() == "basic":
        try:
            return base64.b64decode(value).decode().partition(":")[2]
        except (ValueError, UnicodeDecodeError):
            return ""
    return None


def _user_for_key(request: Request, db: Session, key: str) -> User:
    row = db.query(ApiKey).filter(ApiKey.key_hash == hashlib.sha256(key.encode()).hexdigest()).one_or_none() if key.startswith(API_KEY_PREFIX) else None
    now = utcnow()
    if row is None or row.revoked or (row.expires_at and row.expires_at < now):
        raise HTTPException(401, "Invalid or expired API key", headers={"WWW-Authenticate": "Bearer"})
    if request.method not in _SAFE_METHODS and "write" not in (row.scopes or []):
        raise HTTPException(403, "This API key is read-only")
    user = db.get(User, row.user_id)
    if user is None or not user.is_active:
        raise HTTPException(401, "The owner of this API key is disabled")
    if row.last_used_at is None or now - row.last_used_at > timedelta(minutes=5):
        row.last_used_at = now
        db.commit()
    request.state.user, request.state.api_key = user, row
    return user


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    # A request that presents an API key is authenticated by that key alone; the
    # session cookie is ignored, so key-based calls are never exposed to CSRF.
    key = _presented_key(request)
    if key is not None:
        return _user_for_key(request, db, key)
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(401, "Not signed in")
    try:
        payload = jwt.decode(token, get_settings().jwt_secret, algorithms=["HS256"])
        user = db.get(User, int(payload["sub"]))
    except (jwt.PyJWTError, KeyError, ValueError):
        raise HTTPException(401, "Session expired") from None
    if user is None or not user.is_active:
        raise HTTPException(401, "Account disabled")
    request.state.user = user
    return user


def require(role: str):
    """Dependency factory: the caller must hold ``role`` or a higher one."""
    needed = ROLES.index(role)

    def dependency(user: User = Depends(current_user)) -> User:
        if ROLES.index(user.role) < needed:
            raise HTTPException(403, f"This action needs the {role} role")
        return user

    return dependency


viewer = require("viewer")
analyst = require("analyst")
admin = require("admin")


def audit(db: Session, request: Request | None, user: User | None, action: str, object_type: str = "", object_id: object = "", /, **detail) -> None:
    """Append to the audit trail. The fixed arguments are positional-only so that
    detail keys such as ``object_type`` can never collide with them."""
    db.add(AuditLog(
        user_id=user.id if user else None, user_email=user.email if user else "", action=action, object_type=object_type,
        object_id=str(object_id)[:64], ip=client_ip(request) if request else "", detail=detail,
    ))
