"""HTTP API. Served only to the web container on the internal application network."""
import logging
import time

import redis
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.api import admin, ai, attack, auth, cases, exposure, findings, integrations, intel, reports, research, rules, search, sources, taxii, watch
from app.config import get_settings
from app.security import CSRF_HEADER, client_ip

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("kivuli.api")
settings = get_settings()
_redis = redis.Redis.from_url(settings.redis_url, decode_responses=True)

app = FastAPI(title=f"{settings.app_name} API", version="1.1.0", docs_url="/api/docs", openapi_url="/api/openapi.json", redoc_url=None)


@app.middleware("http")
async def guard(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api") and path != "/api/healthz":
        # A browser cannot add a custom header to a cross-site form post, so requiring
        # one on every state-changing request defeats CSRF against the session cookie.
        if request.method not in ("GET", "HEAD", "OPTIONS") and CSRF_HEADER not in request.headers and "authorization" not in request.headers:
            return JSONResponse({"detail": "Missing CSRF header"}, status_code=403)
        try:
            key = f"kivuli:rl:{client_ip(request)}:{int(time.time() // 60)}"
            hits = _redis.incr(key)
            if hits == 1:
                _redis.expire(key, 90)
            if hits > settings.rate_limit_per_minute:
                return JSONResponse({"detail": "Rate limit exceeded. Slow down and retry in a minute."}, status_code=429, headers={"Retry-After": "60"})
        except redis.RedisError:
            log.warning("rate limiter unavailable")
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.get("/api/healthz", include_in_schema=False)
def healthz():
    return {"ok": True}


for module in (auth, search, findings, intel, watch, research, sources, cases, admin, exposure, attack, rules, integrations, taxii, ai, reports):
    app.include_router(module.router, prefix="/api")
