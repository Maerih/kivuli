# Disposable JavaScript rendering for pages that are empty without it.
#
# This container runs a real browser against hostile pages, so it is built to be
# thrown away: it has no secrets, no volumes and no internet route. It sits only
# on the internal crawl network, where the sole ways out are the Tor gateway and
# the allow-listing egress proxy. Every page gets a new browser process and a new
# profile in tmpfs, deleted when the page is done.
FROM alpine:3.20
RUN apk add --no-cache chromium python3 \
    && adduser -D -H -u 10002 -s /sbin/nologin render
COPY server.py /srv/server.py
USER render
ENV HOME=/tmp
EXPOSE 9300
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=5 \
    CMD wget -q -O /dev/null http://127.0.0.1:9300/health || exit 1
CMD ["python3", "/srv/server.py"]
