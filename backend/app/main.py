"""HTTP API. Served only to the web container on the internal application network."""
import logging
import time

import redis
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.api import admin, ai, attack, auth, cases, chain, exposure, findings, integrations, intel, reports, research, rules, paths, patterns, search, shell, sources, taxii, timeline, tools, watch
from app import runtime
from app.config import get_settings
from app.models import User
from app.db import get_db
from app.security import CSRF_HEADER, client_ip, current_user, viewer

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("kivuli.api")
settings = get_settings()
_redis = redis.Redis.from_url(settings.redis_url, decode_responses=True)

# The schema and its interactive view are for signed-in users and API keys only (served below), not the open internet.
app = FastAPI(title=f"{settings.app_name} API", version="1.1.0", docs_url=None, openapi_url=None, redoc_url=None)


class _Skip(Exception):
    """Leave the rate limiter for this request."""


@app.middleware("http")
async def guard(request: Request, call_next):
    runtime.sync()  # console settings, within seconds of a change
    path = request.url.path
    if path.startswith("/api") and path != "/api/healthz":
        # A browser cannot add a custom header to a cross-site form post, so requiring
        # one on every state-changing request defeats CSRF against the session cookie.
        if request.method not in ("GET", "HEAD", "OPTIONS") and CSRF_HEADER not in request.headers and "authorization" not in request.headers:
            return JSONResponse({"detail": "Missing CSRF header"}, status_code=403)
        try:
            # The server shell's gate is asked on every terminal request; it carries no credentials to guess,
            # and counting it would let heavy console use cut the terminal off.
            if path == "/api/shell/authorize":
                raise _Skip
            key = f"kivuli:rl:{client_ip(request)}:{int(time.time() // 60)}"
            hits = _redis.incr(key)
            if hits == 1:
                _redis.expire(key, 90)
            if hits > settings.rate_limit_per_minute:
                return JSONResponse({"detail": "Rate limit exceeded. Slow down and retry in a minute."}, status_code=429, headers={"Retry-After": "60"})
        except _Skip:
            pass
        except redis.RedisError:
            log.warning("rate limiter unavailable")
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.get("/api/openapi.json", include_in_schema=False)
def openapi_schema(user: User = Depends(viewer)):
    return app.openapi()


@app.get("/api/docs", include_in_schema=False)
def api_docs(request: Request, db: Session = Depends(get_db)):
    # A page people open in a browser: send them to sign in and back, rather than show a bare 401.
    try:
        current_user(request, db)
    except HTTPException:
        return RedirectResponse("/login?next=/api/docs", status_code=303)
    return get_swagger_ui_html(openapi_url="/api/openapi.json", title=f"{settings.app_name} API")


@app.get("/api/healthz", include_in_schema=False)
def healthz():
    return {"ok": True}


for module in (auth, search, findings, intel, watch, research, sources, cases, admin, exposure, attack, chain, rules, integrations, taxii, ai, reports, tools, timeline, patterns, shell, paths):
    app.include_router(module.router, prefix="/api")
