import time
from datetime import timedelta

import redis
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import crypto, mfa
from app.config import get_settings
from app.db import get_db
from app.models import User, utcnow
from app.security import (COOKIE_NAME, audit, client_ip, create_token, current_user, hash_password, password_problem, verify_password)

router = APIRouter(tags=["auth"])
settings = get_settings()
_redis = redis.Redis.from_url(settings.redis_url, decode_responses=True)

MAX_FAILED_LOGINS = 5
LOCK_MINUTES = 15
# Verified against when the account does not exist, so response time does not reveal which emails are registered.
_DUMMY_HASH = hash_password("not-a-real-password")


class LoginIn(BaseModel):
    email: str
    password: str
    code: str = ""  # authenticator or recovery code, when MFA is on


class CodeIn(BaseModel):
    code: str
    password: str = ""


class PasswordIn(BaseModel):
    current_password: str
    new_password: str


def user_out(user: User) -> dict:
    return {"id": user.id, "email": user.email, "name": user.name, "role": user.role, "mfa_enabled": user.mfa_enabled,
            "mfa_setup_required": settings.require_mfa and user.role == "admin" and not user.mfa_enabled}


def _second_factor_ok(user: User, code: str) -> bool:
    """Check an authenticator code (once per time step) or burn a recovery code."""
    step = mfa.verify(crypto.decrypt(user.mfa_secret), code)
    if step is not None:
        try:
            return bool(_redis.set(f"kivuli:mfa:{user.id}:{step}", "1", nx=True, ex=120))  # refuse a replayed code
        except redis.RedisError:
            return True
    hashed = mfa.hash_recovery_code(code)
    if hashed in (user.recovery_codes or []):
        user.recovery_codes = [c for c in user.recovery_codes if c != hashed]
        return True
    return False


@router.post("/auth/login")
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    ip = client_ip(request)
    try:
        key = f"kivuli:rl:login:{ip}:{int(time.time() // 60)}"
        if _redis.incr(key) > settings.login_rate_limit_per_minute:
            raise HTTPException(429, "Too many sign-in attempts. Try again in a minute.")
        _redis.expire(key, 90)
    except redis.RedisError:
        pass

    email = body.email.strip().lower()
    user = db.scalar(select(User).where(func.lower(User.email) == email))
    now = utcnow()
    if user is None:
        verify_password(_DUMMY_HASH, body.password)
        audit(db, request, None, "auth.login_failed", "user", "", email=email[:254], reason="unknown account")
        db.commit()
        raise HTTPException(401, "Incorrect email or password")
    if user.locked_until and user.locked_until > now:
        audit(db, request, user, "auth.login_blocked", "user", user.id, reason="locked")
        db.commit()
        raise HTTPException(423, "Account temporarily locked after repeated failures. Try again later.")
    if not user.is_active or not verify_password(user.password_hash, body.password):
        user.failed_logins += 1
        if user.failed_logins >= MAX_FAILED_LOGINS:
            user.locked_until = now + timedelta(minutes=LOCK_MINUTES)
            user.failed_logins = 0
        audit(db, request, user, "auth.login_failed", "user", user.id, reason="bad password" if user.is_active else "disabled")
        db.commit()
        raise HTTPException(401, "Incorrect email or password")

    if user.mfa_enabled:
        if not body.code.strip():
            # Not counted as a failure: the client simply has not asked for the code yet.
            raise HTTPException(401, "mfa_required")
        if not _second_factor_ok(user, body.code):
            user.failed_logins += 1
            if user.failed_logins >= MAX_FAILED_LOGINS:
                user.locked_until = now + timedelta(minutes=LOCK_MINUTES)
                user.failed_logins = 0
            audit(db, request, user, "auth.login_failed", "user", user.id, reason="bad second factor")
            db.commit()
            raise HTTPException(401, "Incorrect verification code")

    user.failed_logins, user.locked_until, user.last_login_at = 0, None, now
    audit(db, request, user, "auth.login", "user", user.id, mfa=user.mfa_enabled)
    db.commit()
    response.set_cookie(COOKIE_NAME, create_token(user), max_age=settings.session_ttl_minutes * 60, httponly=True,
                        samesite="strict", secure=settings.cookie_secure, path="/")
    return user_out(user)


@router.post("/auth/logout")
def logout(request: Request, response: Response, user: User = Depends(current_user), db: Session = Depends(get_db)):
    audit(db, request, user, "auth.logout", "user", user.id)
    db.commit()
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}


@router.get("/auth/me")
def me(user: User = Depends(current_user)):
    return user_out(user)


@router.post("/auth/password")
def change_password(body: PasswordIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if not verify_password(user.password_hash, body.current_password):
        raise HTTPException(400, "Current password is incorrect")
    if problem := password_problem(body.new_password):
        raise HTTPException(400, problem)
    user = db.get(User, user.id)
    user.password_hash = hash_password(body.new_password)
    audit(db, request, user, "auth.password_changed", "user", user.id)
    db.commit()
    return {"ok": True}


@router.post("/auth/mfa/setup")
def mfa_setup(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Start enrolment: issue a secret and its QR code. MFA is not active until a code is confirmed."""
    import io

    import segno

    user = db.get(User, user.id)
    if user.mfa_enabled:
        raise HTTPException(409, "MFA is already enabled; disable it first to re-enrol")
    secret = mfa.new_secret()
    user.mfa_secret = crypto.encrypt(secret)
    uri = mfa.provisioning_uri(secret, user.email, settings.app_name)
    buffer = io.BytesIO()
    segno.make(uri, error="m").save(buffer, kind="svg", scale=4, border=2, xmldecl=False, svgns=True)
    audit(db, request, user, "auth.mfa_setup", "user", user.id)
    db.commit()
    return {"secret": secret, "uri": uri, "qr_svg": buffer.getvalue().decode()}


@router.post("/auth/mfa/enable")
def mfa_enable(body: CodeIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    user = db.get(User, user.id)
    if user.mfa_enabled or not user.mfa_secret:
        raise HTTPException(409, "Start enrolment first")
    if mfa.verify(crypto.decrypt(user.mfa_secret), body.code) is None:
        raise HTTPException(400, "That code is not correct. Check the time on your device and try again.")
    codes = mfa.new_recovery_codes()
    user.mfa_enabled, user.recovery_codes = True, [mfa.hash_recovery_code(c) for c in codes]
    audit(db, request, user, "auth.mfa_enabled", "user", user.id)
    db.commit()
    return {"ok": True, "recovery_codes": codes}


@router.post("/auth/mfa/disable")
def mfa_disable(body: CodeIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    user = db.get(User, user.id)
    if not verify_password(user.password_hash, body.password) or not _second_factor_ok(user, body.code):
        raise HTTPException(400, "Password or verification code is incorrect")
    user.mfa_enabled, user.mfa_secret, user.recovery_codes = False, "", []
    audit(db, request, user, "auth.mfa_disabled", "user", user.id)
    db.commit()
    return {"ok": True}
