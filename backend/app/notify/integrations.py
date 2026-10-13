"""Outbound integrations: push alerts to chat, SIEM, SOAR and ticketing.

Runs in the notify container (the only role with outbound access besides the
enricher). Destinations are checked before every send: HTTPS, a public address
unless the operator allowed private ones, and never a redirect.
"""
import hashlib
import hmac
import ipaddress
import json
import socket
from urllib.parse import urlsplit

import httpx

from app.config import get_settings

KINDS = {
    "webhook": "Generic webhook (signed JSON)",
    "slack": "Slack incoming webhook",
    "teams": "Microsoft Teams workflow webhook",
    "splunk_hec": "Splunk HTTP Event Collector",
    "jira": "Jira issue",
    "servicenow": "ServiceNow incident",
}
# Kinds whose URL is itself a credential and is therefore stored encrypted.
URL_IS_SECRET = ("slack", "teams")
_SEVERITY_COLOUR = {"critical": "attention", "high": "warning", "medium": "accent", "low": "default", "info": "default"}


class DeliveryError(Exception):
    pass


def check_destination(url: str) -> None:
    """Refuse destinations a webhook must never reach (SSRF guard)."""
    settings = get_settings()
    parts = urlsplit(url)
    if parts.scheme != "https" and not (settings.integrations_allow_private and parts.scheme == "http"):
        raise DeliveryError("destination must use HTTPS")
    host = parts.hostname or ""
    if not host or parts.username or parts.password:
        raise DeliveryError("destination URL is not valid")
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(host, parts.port or 443, type=socket.SOCK_STREAM)}
    except socket.gaierror:
        raise DeliveryError(f"destination host {host} does not resolve") from None
    if not settings.integrations_allow_private and not all(ipaddress.ip_address(a).is_global for a in addresses):
        raise DeliveryError("destination resolves to a private or reserved address (set INTEGRATIONS_ALLOW_PRIVATE=true to allow an internal SIEM)")


def _text(alert: dict) -> str:
    lines = [f"[{alert['severity'].upper()}] {alert['category_label']}: {alert['matched']}", alert["title"], alert["origin"],
             f"Priority {alert['priority']}/100", alert["snippet"], alert["link"]]
    return "\n".join(line for line in lines if line)


def build_request(kind: str, url: str, config: dict, secret: str, alert: dict) -> tuple[str, dict, bytes, tuple[str, str] | None]:
    """Return (url, headers, body, basic-auth) for one alert. Pure: no network."""
    headers = {"Content-Type": "application/json", "User-Agent": "Kivuli-Integrations/1.1"}
    auth = None
    if kind == "webhook":
        body = json.dumps({"event": "alert.created", "alert": alert}, separators=(",", ":"), sort_keys=True).encode()
        headers["X-Kivuli-Event"] = "alert.created"
        if secret:
            headers["X-Kivuli-Signature"] = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        return url, headers, body, auth
    if kind == "slack":
        payload = {"text": f"{alert['severity'].upper()}: {alert['category_label']} - {alert['matched']}", "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": f"{alert['severity'].upper()} · {alert['category_label']}"[:150]}},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*{alert['matched']}*\n{alert['title']}\n_{alert['origin']} · priority {alert['priority']}/100_"[:2900]}},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"```{alert['snippet'][:900]}```"}},
            {"type": "actions", "elements": [{"type": "button", "text": {"type": "plain_text", "text": "Open in Kivuli"}, "url": alert["link"]}]},
        ]}
        return url, headers, json.dumps(payload).encode(), auth
    if kind == "teams":
        card = {"type": "AdaptiveCard", "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "version": "1.4", "body": [
            {"type": "TextBlock", "size": "Medium", "weight": "Bolder", "color": _SEVERITY_COLOUR.get(alert["severity"], "default"),
             "text": f"{alert['severity'].upper()} · {alert['category_label']}"},
            {"type": "TextBlock", "weight": "Bolder", "wrap": True, "text": alert["matched"]},
            {"type": "TextBlock", "wrap": True, "text": alert["title"]},
            {"type": "FactSet", "facts": [{"title": "Raised by", "value": alert["origin"]}, {"title": "Priority", "value": f"{alert['priority']}/100"}]},
            {"type": "TextBlock", "wrap": True, "isSubtle": True, "fontType": "Monospace", "text": alert["snippet"][:900]},
        ], "actions": [{"type": "Action.OpenUrl", "title": "Open in Kivuli", "url": alert["link"]}]}
        payload = {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]}
        return url, headers, json.dumps(payload).encode(), auth
    if kind == "splunk_hec":
        endpoint = url.rstrip("/") if "/services/collector" in url else url.rstrip("/") + "/services/collector/event"
        headers["Authorization"] = f"Splunk {secret}"
        payload = {"event": alert, "sourcetype": config.get("sourcetype") or "kivuli:alert", "source": "kivuli"}
        if config.get("index"):
            payload["index"] = config["index"]
        return endpoint, headers, json.dumps(payload).encode(), auth
    if kind == "jira":
        payload = {"fields": {"project": {"key": config.get("project", "")}, "issuetype": {"name": config.get("issue_type") or "Task"},
                              "summary": f"[{alert['severity'].upper()}] {alert['category_label']}: {alert['matched']}"[:250],
                              "description": _text(alert), "labels": ["kivuli", alert["category"]]}}
        return url.rstrip("/") + "/rest/api/2/issue", headers, json.dumps(payload).encode(), (config.get("user", ""), secret)
    if kind == "servicenow":
        urgency = {"critical": "1", "high": "2"}.get(alert["severity"], "3")
        payload = {"short_description": f"{alert['category_label']}: {alert['matched']}"[:160], "description": _text(alert), "urgency": urgency,
                   "impact": urgency, "category": config.get("category") or "Security"}
        return url.rstrip("/") + f"/api/now/table/{config.get('table') or 'incident'}", headers, json.dumps(payload).encode(), (config.get("user", ""), secret)
    raise DeliveryError(f"unknown integration kind {kind}")


def deliver(kind: str, url: str, config: dict, secret: str, alert: dict) -> int:
    """Send one alert. Returns the HTTP status; raises DeliveryError on any failure."""
    target, headers, body, auth = build_request(kind, url, config, secret, alert)
    check_destination(target)
    try:
        with httpx.Client(follow_redirects=False, timeout=15.0, trust_env=False) as client:
            response = client.post(target, headers=headers, content=body, auth=auth)
    except httpx.HTTPError as exc:
        raise DeliveryError(f"{type(exc).__name__}: {str(exc)[:160]}".rstrip(": ")) from None
    if response.status_code >= 300:
        raise DeliveryError(f"destination answered HTTP {response.status_code}: {response.text[:160]}")
    return response.status_code
