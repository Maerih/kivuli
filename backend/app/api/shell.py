"""The server shell: a browser terminal on the VPS, behind Kivuli's sign-in.

The terminal itself is WeTTY, a web SSH client in its own container; it logs in
to the host's SSH server with the username and password typed in the browser,
every session. Kivuli adds the gate in front of it. Caddy asks
GET /api/shell/authorize before every request to /shell, and that answers yes
only when all of these hold:

  * the shell is switched on (SHELL_ENABLED, set by ./ctl.sh shell on);
  * the request carries a browser session, not an API key;
  * the user is an administrator with two-step sign-in turned on;
  * that same browser session opened the shell in the console
    (POST /api/shell/open, audited) within the last GRANT_HOURS. The grant is
    keyed to a hash of the session token, so another session of the same
    account, or a new one after signing out, has to open it again.

A stolen session alone therefore reaches only the SSH login prompt, and every
opening is in the audit log.
"""
import hashlib

import redis
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.models import User
from app.security import COOKIE_NAME, _presented_key, admin, audit, current_user

router = APIRouter(tags=["admin"])
settings = get_settings()
_redis = redis.Redis.from_url(settings.redis_url, decode_responses=True)
GRANT_KEY = "kivuli:shell:grant:{}:{}"
GRANT_HOURS = 12


def _grant(request: Request, user: User) -> str:
    """The grant key for this user and this browser session (a hash of its token, never the token)."""
    token = request.cookies.get(COOKIE_NAME, "")
    return GRANT_KEY.format(user.id, hashlib.sha256(token.encode()).hexdigest()[:32])


def _why_not(user: User) -> str:
    """Why this user may not open the shell, or "" when they may."""
    if not settings.shell_enabled:
        return "The server shell is off. Turn it on with ./ctl.sh shell on (HTTPS must be on first)."
    if user.role != "admin":
        return "Only administrators can open the server shell."
    if not user.mfa_enabled:
        return "Turn on two-step sign-in for your account first (Settings > Security)."
    return ""


@router.get("/shell/status")
def status(request: Request, user: User = Depends(admin)):
    """Whether the server shell is available to this administrator, and if not, why."""
    reason = _why_not(user)
    return {"enabled": settings.shell_enabled, "allowed": not reason, "reason": reason, "open": bool(_redis.exists(_grant(request, user))),
            "grant_hours": GRANT_HOURS, "ssh_host": settings.shell_ssh_host, "ssh_port": settings.shell_ssh_port}


@router.post("/shell/open")
def open_shell(request: Request, db: Session = Depends(get_db), user: User = Depends(admin)):
    """Allow this administrator's browser to reach the terminal for the next GRANT_HOURS. Audited."""
    if _presented_key(request) is not None:
        raise HTTPException(403, "The server shell is for signed-in browsers, not API keys")
    if reason := _why_not(user):
        raise HTTPException(403, reason)
    if not request.cookies.get(COOKIE_NAME):
        raise HTTPException(403, "Open the server shell from a signed-in browser")
    _redis.set(_grant(request, user), "1", ex=GRANT_HOURS * 3600)
    audit(db, request, user, "shell.open", "shell", "server", hours=GRANT_HOURS)
    db.commit()
    return {"ok": True, "path": "/shell/", "hours": GRANT_HOURS}


@router.post("/shell/close")
def close_shell(request: Request, db: Session = Depends(get_db), user: User = Depends(admin)):
    """End access now. Sessions already in the terminal end when the page is closed."""
    _redis.delete(_grant(request, user))
    audit(db, request, user, "shell.close", "shell", "server")
    db.commit()
    return {"ok": True}


@router.get("/shell/authorize", include_in_schema=False)
def authorize(request: Request, db: Session = Depends(get_db)):
    """Asked by Caddy (forward_auth) before every request to /shell. 204 lets it through."""
    if _presented_key(request) is not None:
        raise HTTPException(403, "Not with an API key")
    user = current_user(request, db)
    if _why_not(user) or not _redis.exists(_grant(request, user)):
        raise HTTPException(403, "Not allowed")
    return Response(status_code=204, headers={"X-Kivuli-User": user.email})
