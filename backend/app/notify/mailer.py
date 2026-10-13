"""Alert email: composition and SMTP delivery.

Messages are safe to forward: indicators are defanged so mail gateways and
recipients cannot follow them by accident, and passwords never appear because
they were redacted before the finding was stored.
"""
import html
import re
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from app.config import get_settings
from app.extract.classify import THREAT_TYPES
from app.extract.iocs import RE_DOMAIN, RE_EMAIL, RE_URL, defang

SEVERITY_COLORS = {"critical": "#b42318", "high": "#c4320a", "medium": "#b54708", "low": "#175cd3", "info": "#475467"}
CATEGORY_LABELS = {"compromise": "Possible compromise", "mention": "Keyword / indicator match", "rule": "Detection rule",
                   "attack_surface": "Attack surface", "vulnerability": "Vulnerability affecting your technology",
                   "lookalike": "Lookalike domain", "exposure": "Identity exposure"}


def defang_text(text: str) -> str:
    for pattern in (RE_URL, RE_EMAIL, RE_DOMAIN):
        text = pattern.sub(lambda m: defang(m.group(0)), text)
    # A snippet can cut a URL short; make sure no bare scheme survives to be auto-linked.
    text = re.sub(r"\bhttp(s?)://", r"hxxp\1[://]", text, flags=re.I)
    return re.sub(r"(\[\.\]){2,}", "[.]", text)


def send(recipients: list[str], subject: str, text_body: str, html_body: str) -> None:
    """Deliver one message. Raises on failure so the caller can log and retry."""
    settings = get_settings()
    message = EmailMessage()
    message["Subject"] = subject[:240]
    message["From"] = settings.smtp_from
    message["To"] = ", ".join(recipients)
    message["Date"] = formatdate(localtime=False)
    message["Message-ID"] = make_msgid(domain="kivuli.local")
    message["Auto-Submitted"] = "auto-generated"
    message["X-Auto-Response-Suppress"] = "All"
    message.set_content(text_body)
    message.add_alternative(html_body, subtype="html")

    mode = settings.smtp_tls.lower()
    context = ssl.create_default_context()
    if mode == "ssl":
        server: smtplib.SMTP = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=30, context=context)
    else:
        server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=30)
    with server:
        server.ehlo()
        if mode == "starttls":
            server.starttls(context=context)
            server.ehlo()
        if settings.smtp_username:
            server.login(settings.smtp_username, settings.smtp_password)
        server.send_message(message)


def _alert_view(alert) -> dict:
    """Everything a message needs about one alert, whatever raised it (watchlist, rule or the attack-surface monitor)."""
    doc, watch, rule = alert.document, alert.watchlist, alert.rule
    settings = get_settings()
    base = settings.public_url.rstrip("/")
    if watch is not None:
        origin = f"Watchlist: {watch.name} ({watch.kind}: {defang_text(watch.value)})"
    elif rule is not None:
        origin = f"Rule: {rule.name}"
    else:
        origin = "Platform monitor"
    if doc is not None:
        meta = " · ".join([THREAT_TYPES.get(doc.threat_type, doc.threat_type), f"risk {doc.risk_score}/100",
                           f"{doc.source.name} ({'Tor hidden service' if doc.network == 'onion' else 'surface web'})",
                           f"first seen {doc.first_seen_at:%Y-%m-%d %H:%M} UTC", doc.verification])
    else:
        meta = f"raised {alert.created_at:%Y-%m-%d %H:%M} UTC"
    return {
        "severity": alert.severity,
        "category": CATEGORY_LABELS.get(alert.category, alert.category),
        "matched": defang_text(alert.matched),
        "title": defang_text(alert.title or (doc.title if doc is not None else alert.matched))[:200],
        "origin_line": origin,
        "meta_line": meta,
        "priority": alert.priority,
        "snippet": defang_text(alert.snippet)[:600],
        "link": f"{base}/findings/{doc.id}" if doc is not None else f"{base}/alerts",
        "has_finding": doc is not None,
        "historic": alert.reason == "retro",
    }


def compose_alerts(alerts: list, digest: bool = False) -> tuple[str, str, str]:
    """Return (subject, text, html) for a batch of alerts addressed to one recipient."""
    settings = get_settings()
    order = ["critical", "high", "medium", "low", "info"]
    alerts = sorted(alerts, key=lambda a: (order.index(a.severity), a.created_at))
    views = [_alert_view(a) for a in alerts]
    shown = views[: settings.email_max_alerts_per_message]
    hidden = len(views) - len(shown)
    compromises = sum(1 for a in alerts if a.category == "compromise")
    top = views[0]
    app = settings.app_name
    alerts_url = f"{settings.public_url.rstrip('/')}/alerts"

    if digest:
        subject = f"[{app}] Daily digest: {len(views)} alert{'s' if len(views) != 1 else ''}" + (f", {compromises} possible compromise" if compromises else "")
    elif len(views) == 1:
        subject = f"[{app}] {top['severity'].upper()} · {top['category']}: {top['matched']} · {top['title'][:70]}"
    else:
        subject = f"[{app}] {len(views)} new alerts" + (f" ({compromises} possible compromise)" if compromises else "") + f" · highest {top['severity'].upper()}"

    lines = [f"{app}: {'daily digest' if digest else 'new alerts'} ({len(views)})", ""]
    for v in shown:
        lines += [
            f"[{v['severity'].upper()}] {v['category']}: {v['matched']}",
            f"  Raised by:  {v['origin_line']}",
            f"  Finding:    {v['title']}",
            f"  Priority:   {v['priority']}/100  |  {v['meta_line']}",
            f"  Context:    {v['snippet']}",
            f"  Open:       {v['link']}",
            "",
        ]
    if hidden:
        lines += [f"...and {hidden} more: {alerts_url}", ""]
    lines += ["Indicators are defanged. Passwords and secrets are never included in alert email.", f"Manage alerts: {alerts_url}"]
    text_body = "\n".join(lines)

    e = html.escape
    cards = []
    for v in shown:
        color = SEVERITY_COLORS.get(v["severity"], "#475467")
        cards.append(f"""
        <tr><td style="padding:0 0 14px 0">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e4e7ec;border-left:4px solid {color};border-radius:6px">
            <tr><td style="padding:14px 16px;font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;color:#101828">
              <div style="font-size:11px;font-weight:700;letter-spacing:.06em;color:{color};text-transform:uppercase">{e(v['severity'])} &middot; {e(v['category'])}{' &middot; historic match' if v['historic'] else ''}</div>
              <div style="font-size:16px;font-weight:600;margin:6px 0 2px 0;word-break:break-word">{e(v['matched'])}</div>
              <div style="font-size:13px;color:#475467;margin-bottom:10px">{e(v['origin_line'])}</div>
              <div style="font-size:14px;font-weight:600;margin-bottom:4px;word-break:break-word">{e(v['title'])}</div>
              <div style="font-size:13px;color:#475467;margin-bottom:10px">priority {v['priority']}/100 &middot; {e(v['meta_line'])}</div>
              <div style="font-size:13px;line-height:1.5;color:#344054;background:#f9fafb;border-radius:4px;padding:10px 12px;font-family:ui-monospace,Menlo,Consolas,monospace;word-break:break-word">{e(v['snippet'])}</div>
              <div style="margin-top:12px"><a href="{e(v['link'])}" style="display:inline-block;background:#101828;color:#ffffff;text-decoration:none;font-size:13px;font-weight:600;padding:8px 14px;border-radius:6px">{'Open finding' if v['has_finding'] else 'Open alert queue'}</a></div>
            </td></tr>
          </table>
        </td></tr>""")
    more = f'<tr><td style="padding:0 0 14px 0;font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;font-size:13px;color:#475467">&hellip;and {hidden} more in the <a href="{e(alerts_url)}" style="color:#175cd3">alert queue</a>.</td></tr>' if hidden else ""
    heading = "Daily digest" if digest else ("New alert" if len(views) == 1 else f"{len(views)} new alerts")
    html_body = f"""<!doctype html>
<html><body style="margin:0;padding:0;background:#f2f4f7">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f2f4f7"><tr><td align="center" style="padding:24px 12px">
  <table role="presentation" width="640" cellpadding="0" cellspacing="0" style="max-width:640px;width:100%;background:#ffffff;border-radius:10px">
    <tr><td style="padding:22px 24px 6px 24px;font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif">
      <div style="font-size:12px;font-weight:700;letter-spacing:.08em;color:#667085;text-transform:uppercase">{e(app)} threat intelligence</div>
      <div style="font-size:21px;font-weight:700;color:#101828;margin-top:4px">{e(heading)}</div>
      <div style="font-size:13px;color:#475467;margin-top:4px">{compromises} possible compromise &middot; {len(views) - compromises} keyword or indicator match</div>
    </td></tr>
    <tr><td style="padding:14px 24px 4px 24px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0">{''.join(cards)}{more}</table></td></tr>
    <tr><td style="padding:6px 24px 22px 24px;font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;font-size:12px;line-height:1.5;color:#667085">
      Indicators are defanged. Passwords and secrets are never included in alert email.<br>
      You are receiving this because you are a recipient on these watchlists. <a href="{e(alerts_url)}" style="color:#175cd3">Manage alerts</a>
    </td></tr>
  </table>
</td></tr></table>
</body></html>"""
    return subject, text_body, html_body


def compose_test() -> tuple[str, str, str]:
    settings = get_settings()
    subject = f"[{settings.app_name}] Test message"
    text = f"This is a test message from {settings.app_name}. If you can read it, alert email is configured correctly.\n\n{settings.public_url}"
    body = f"""<!doctype html><html><body style="font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;color:#101828">
<p style="font-size:16px;font-weight:600">{html.escape(settings.app_name)}: test message</p>
<p style="font-size:14px;color:#475467">If you can read this, alert email is configured correctly.</p>
<p style="font-size:13px"><a href="{html.escape(settings.public_url)}">{html.escape(settings.public_url)}</a></p></body></html>"""
    return subject, text, body
