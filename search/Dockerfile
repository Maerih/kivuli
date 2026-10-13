# OpenSearch, minimal distribution (engine + bundled JDK, no plugins).
#
# It has no security plugin, so it must never be published or attached to a
# network other than the internal "data" network - which is how the compose file
# wires it. For a multi-host deployment, swap this for the official image with
# the security plugin and set OPENSEARCH_URL / OPENSEARCH_USER / OPENSEARCH_PASSWORD.
FROM python:3.12-slim AS fetch
ARG OPENSEARCH_VERSION=2.19.1
COPY fetch.py /fetch.py
RUN python /fetch.py "$OPENSEARCH_VERSION" /tmp/opensearch.tar.gz \
    && mkdir -p /opt/opensearch \
    && tar -xzf /tmp/opensearch.tar.gz -C /opt/opensearch --strip-components=1 \
    && rm /tmp/opensearch.tar.gz

FROM debian:bookworm-slim
RUN useradd --system --uid 10002 --home-dir /usr/share/opensearch --shell /usr/sbin/nologin opensearch
COPY --from=fetch --chown=opensearch /opt/opensearch /usr/share/opensearch
COPY --chown=opensearch opensearch.yml /usr/share/opensearch/config/opensearch.yml
RUN mkdir -p /usr/share/opensearch/data /usr/share/opensearch/logs \
    && chown opensearch /usr/share/opensearch/data /usr/share/opensearch/logs
USER opensearch
WORKDIR /usr/share/opensearch
ENV OPENSEARCH_JAVA_OPTS="-Xms1g -Xmx1g" \
    OPENSEARCH_PATH_CONF=/usr/share/opensearch/config
EXPOSE 9200
CMD ["/usr/share/opensearch/bin/opensearch"]
