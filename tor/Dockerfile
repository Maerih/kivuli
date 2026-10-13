FROM alpine:3.20
RUN apk add --no-cache tor \
    && mkdir -p /var/lib/tor && chown -R tor /var/lib/tor && chmod 700 /var/lib/tor
COPY torrc /etc/tor/torrc
USER tor
EXPOSE 9050
# Healthy once the SOCKS port accepts connections; circuit health is reported
# separately by the crawler's own Tor check (see System > Health in the console).
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=5 \
    CMD nc -z 127.0.0.1 9050 || exit 1
CMD ["tor", "-f", "/etc/tor/torrc"]
