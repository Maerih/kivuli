# ── Dependencies ────────────────────────────────────────────────────────────
# Installed from requirements.lock (exact pins). If backend/wheelhouse/ has been
# filled by tools/fetch_deps.py - which ./ctl.sh does before building - the
# install is offline, from wheels already verified against PyPI's SHA-256.
# With an empty wheelhouse pip downloads the same pinned versions itself.
FROM python:3.12-slim AS deps
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_DEFAULT_TIMEOUT=120
COPY requirements.lock /tmp/requirements.lock
COPY wheelhouse/ /wheels/
RUN python -m venv /opt/venv \
    && if ls /wheels/*.whl >/dev/null 2>&1; then \
         /opt/venv/bin/pip install --no-index --find-links /wheels --no-deps -r /tmp/requirements.lock; \
       else \
         /opt/venv/bin/pip install --retries 10 --no-deps -r /tmp/requirements.lock; \
       fi \
    && /opt/venv/bin/pip check

# ── Runtime ─────────────────────────────────────────────────────────────────
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH

# Unprivileged runtime user. Every role (api, workers, proxy) runs as this user
# on a read-only root filesystem.
RUN useradd --system --uid 10001 --home-dir /srv --shell /usr/sbin/nologin kivuli \
    && mkdir -p /evidence && chown kivuli /evidence

COPY --from=deps /opt/venv /opt/venv
WORKDIR /srv
COPY --chown=kivuli . .

USER kivuli
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
