"""Connector parsers: turn a fetched payload into normalised items.

Runs in the pipeline container, which has no network access. Parsing is static:
HTML is read as a tree and reduced to text; nothing is rendered or executed.
"""
import json
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from urllib.parse import urldefrag, urljoin, urlsplit

import feedparser
from dateutil import parser as dateparser
from selectolax.parser import HTMLParser

from app.extract.iocs import detect_indicator, is_onion_v3
from app.extract.safety import is_fetchable_link

CONNECTORS = {
    "html": "Web page (crawled)",
    "rss": "RSS / Atom feed",
    "ransomware_live": "Ransomware.live API",
    "ransomlook_recent": "RansomLook recent posts API",
    "ransomlook_group": "RansomLook group profile (source discovery)",
    "cisa_kev": "CISA Known Exploited Vulnerabilities",
    "telegram_public": "Public Telegram channel",
    "ioc_feed": "Indicator feed (plain text list)",
    "onion_blocklist": "Safety blocklist (hashes of banned onion services)",
    "deepdark_catalog": "deepdarkCTI source catalogue (discovers sources)",
}


@dataclass
class ParsedItem:
    key: str
    url: str
    title: str
    text: str
    raw: str = ""
    namespace: str = ""  # shared key space across sources of the same family
    published_at: datetime | None = None
    hint_type: str | None = None
    actor: str | None = None
    victim: str | None = None
    countries: list[str] = field(default_factory=list)
    sectors: list[str] = field(default_factory=list)
    extra_iocs: list[tuple[str, str]] = field(default_factory=list)
    meta: dict = field(default_factory=dict)


@dataclass
class ParseOutput:
    items: list[ParsedItem] = field(default_factory=list)
    links: list[str] = field(default_factory=list)  # in-scope pages to crawl next
    discovered: list[dict] = field(default_factory=list)  # candidate sources
    gated: str = ""  # set when the page is a login or CAPTCHA wall
    note: str = ""
    kev_ids: list[str] = field(default_factory=list)
    actor_profiles: dict[str, str] = field(default_factory=dict)
    feed_iocs: list[tuple[str, str]] = field(default_factory=list)  # indicators listed by a threat feed
    vulnerabilities: list[dict] = field(default_factory=list)  # catalogue rows for the vulnerability table
    blocklist: list[str] = field(default_factory=list)  # MD5 hashes of onion domains that must never be fetched


def _when(value) -> datetime | None:
    if not value:
        return None
    try:
        parsed = dateparser.parse(str(value))
    except (ValueError, OverflowError, TypeError):
        return None
    if parsed is None:
        return None
    parsed = parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return parsed if datetime(2000, 1, 1, tzinfo=timezone.utc) < parsed < datetime.now(timezone.utc) + timedelta(days=2) else None


def html_to_text(html: str) -> tuple[str, str, HTMLParser]:
    tree = HTMLParser(html)
    title_node = tree.css_first("title")
    title = title_node.text(strip=True) if title_node else ""
    for node in tree.css("script, style, noscript, template, svg, iframe, object, embed, head, nav, footer"):
        node.decompose()
    root = tree.body or tree.root
    text = root.text(separator="\n", strip=True) if root else ""
    return title, text, tree


_WALL = re.compile(r"captcha|are you (?:a )?human|verify you are human|ddos[- ]?guard|checking your browser|anti[- ]?bot|queue position", re.I)


def parse_html(body: str, final_url: str, source_host: str) -> ParseOutput:
    out = ParseOutput()
    raw_tree = HTMLParser(body)
    has_password = raw_tree.css_first('input[type="password"]') is not None
    published = None
    for selector, attr in (('meta[property="article:published_time"]', "content"), ("time[datetime]", "datetime"), ('meta[name="date"]', "content")):
        node = raw_tree.css_first(selector)
        if node and (published := _when(node.attributes.get(attr))):
            break

    anchors: list[tuple[str, str]] = []
    for a in raw_tree.css("a[href]"):
        href = (a.attributes.get("href") or "").strip()
        if href and not href.startswith(("#", "javascript:", "mailto:", "magnet:", "tel:", "data:")):
            anchors.append((href, a.text(strip=True)[:120]))

    title, text, _ = html_to_text(body)

    # Walls are reported, never worked around: no logins, no CAPTCHA solving.
    if len(text) < 1500:
        if has_password:
            out.gated = "login required - not collected"
            return out
        if _WALL.search(text) or _WALL.search(title):
            out.gated = "CAPTCHA or anti-bot wall - not collected"
            return out

    seen: set[str] = set()
    off_site: dict[str, str] = {}
    for href, label in anchors:
        absolute, _ = urldefrag(urljoin(final_url, href))
        host = (urlsplit(absolute).hostname or "").lower()
        if not host or absolute in seen:
            continue
        seen.add(absolute)
        if host == source_host:
            if is_fetchable_link(absolute) and absolute.rstrip("/") != final_url.rstrip("/"):
                out.links.append(absolute)
        elif host.endswith(".onion") and is_onion_v3(host) and host not in off_site:
            off_site[host] = label
    out.discovered = [{"url": f"http://{host}/", "name": label or host[:16] + "…", "context": f"linked from {final_url}"} for host, label in off_site.items()]

    key, _ = urldefrag(final_url)
    out.items.append(ParsedItem(key=key, url=final_url, title=title, text=text, raw=body, published_at=published))
    return out


def parse_rss(body: str, feed_url: str) -> ParseOutput:
    out = ParseOutput()
    feed = feedparser.parse(body)
    for entry in feed.entries[:200]:
        link = entry.get("link") or feed_url
        html = ""
        if entry.get("content"):
            html = " ".join(c.get("value", "") for c in entry.content)
        html = html or entry.get("summary", "") or entry.get("description", "")
        _, text, _ = html_to_text(f"<body>{html}</body>") if html else ("", "", None)
        title = HTMLParser(f"<body>{entry.get('title', '')}</body>").text(strip=True)
        tags = [t.get("term", "") for t in entry.get("tags", []) if t.get("term")]
        if tags:
            text = f"{text}\n\nTopics: {', '.join(tags[:12])}"
        published = _when(entry.get("published") or entry.get("updated"))
        out.items.append(ParsedItem(
            key=entry.get("id") or link, url=link, title=title, text=text or title,
            raw=json.dumps({"title": title, "link": link, "summary": html}, sort_keys=True), published_at=published,
        ))
    if not feed.entries:
        out.note = "feed had no entries"
    return out


def _clean(value) -> str:
    value = str(value or "").strip()
    return "" if value.lower() in ("n/a", "na", "none", "null", "-", "unknown", "not found", "tba", "to be announced...", "other") else value


def _claim_iocs(url: str) -> list[tuple[str, str]]:
    host = (urlsplit(url).hostname or "").lower() if url.startswith("http") else ""
    if host.endswith(".onion") and is_onion_v3(host):
        return [("onion", host), ("url", url[:1024])]
    return []


def _ransom_item(*, family: str, group: str, victim: str, discovered, published, description: str, country: str,
                 sector: str, website: str, claim_url: str, permalink: str, feed_url: str, extra: dict, raw: dict) -> ParsedItem | None:
    # Trackers disagree on naming ("vexy" vs "Vexy Ransomware"); keep one name per group.
    slug = re.sub(r"\s+ransomware(?:\s+group)?$", "", _clean(group), flags=re.I) or _clean(group)
    victim = _clean(victim)
    if not slug or not victim:
        return None
    # Trackers publish group names as lower-case slugs ("qilin"); show them as names.
    group = slug.title() if slug.islower() else slug
    description, country, sector, website = _clean(description), _clean(country).upper(), _clean(sector), _clean(website).lower()
    website = re.sub(r"^https?://", "", website).split("/")[0]
    when = _when(published) or _when(discovered)
    lines = [f"The {group} ransomware group has listed {victim} as a victim on its leak site.", ""]
    lines.append(f"Victim: {victim}")
    lines.append(f"Threat actor: {group}")
    if country:
        lines.append(f"Country: {country}")
    if sector:
        lines.append(f"Sector: {sector}")
    if website:
        lines.append(f"Victim website: {website}")
    if when:
        lines.append(f"Claim published: {when:%Y-%m-%d}")
    for label, value in extra.items():
        if _clean(value):
            lines.append(f"{label}: {_clean(value)}")
    if claim_url.startswith("http"):
        lines.append(f"Leak post: {claim_url}")
    if description:
        lines += ["", description]
    iocs = _claim_iocs(claim_url)
    if website and "." in website:
        iocs.append(("domain", website))
    day = (when or datetime.now(timezone.utc)).strftime("%Y-%m")
    return ParsedItem(
        key=f"{slug.lower()}|{victim.lower()}|{day}", namespace=family, url=permalink or feed_url,
        title=f"{victim} listed by {group}", text="\n".join(lines), raw=json.dumps(raw, sort_keys=True, default=str),
        published_at=when, hint_type="ransomware", actor=group, victim=victim,
        countries=[country] if len(country) == 2 else [], sectors=[sector] if sector else [], extra_iocs=iocs,
        meta={"tracker": family, "tracker_group": slug, "victim_website": website},
    )


def parse_ransomware_live(body: str, feed_url: str) -> ParseOutput:
    out = ParseOutput()
    data = json.loads(body)
    if not isinstance(data, list):
        out.note = "unexpected response shape"
        return out
    for row in data[:500]:
        if not isinstance(row, dict):
            continue
        item = _ransom_item(
            family="ransomware_live", group=row.get("group") or row.get("group_name"), victim=row.get("victim") or row.get("post_title"),
            discovered=row.get("discovered"), published=row.get("attackdate") or row.get("published"),
            description=row.get("description"), country=row.get("country"), sector=row.get("activity"),
            website=row.get("domain") or row.get("website"), claim_url=str(row.get("claim_url") or row.get("post_url") or ""),
            permalink=str(row.get("url") or ""), feed_url=feed_url,
            extra={"Data size": row.get("data_size"), "Ransom demand": row.get("ransom")},
            raw={k: v for k, v in row.items() if k != "screenshot"},
        )
        if item:
            out.items.append(item)
    return out


def parse_ransomlook_recent(body: str, feed_url: str) -> ParseOutput:
    out = ParseOutput()
    data = json.loads(body)
    if not isinstance(data, list):
        out.note = "unexpected response shape"
        return out
    for row in data[:500]:
        if not isinstance(row, dict):
            continue
        group = _clean(row.get("group_name"))
        item = _ransom_item(
            family="ransomlook", group=group, victim=row.get("post_title"), discovered=row.get("discovered"), published=None,
            description=row.get("description"), country="", sector="", website="", claim_url="",
            permalink=f"https://www.ransomlook.io/group/{group}" if group else "", feed_url=feed_url, extra={},
            # Screenshots and magnet links to the stolen data are deliberately not kept.
            raw={k: v for k, v in row.items() if k in ("post_title", "discovered", "description", "group_name")},
        )
        if item:
            out.items.append(item)
    return out


def parse_ransomlook_group(body: str, feed_url: str) -> ParseOutput:
    """Leak-site locations for one group, as candidate sources for an analyst to review."""
    out = ParseOutput()
    group = feed_url.rstrip("/").rsplit("/", 1)[-1]
    profile: dict = {}
    try:
        data = json.loads(body)
        profile = data[0] if isinstance(data, list) and data and isinstance(data[0], dict) else {}
        locations = profile.get("locations") or []
    except ValueError:
        # Profiles embed large screenshots and may exceed the size limit; the
        # locations block sits at the start, so recover it from the truncated text.
        locations = [
            {"fqdn": m.group(1), "available": m.group(2) == "true"}
            for m in re.finditer(r'"fqdn":\s*"([^"]+)".{0,200}?"available":\s*(true|false)', body[:400_000], re.S)
        ]
    if profile.get("captcha"):
        out.note = "group site is behind a CAPTCHA - not proposed"
        return out
    if description := _clean(profile.get("meta")):
        out.actor_profiles[group] = description[:4000]
    for loc in locations:
        if not isinstance(loc, dict):
            continue
        host = str(loc.get("fqdn") or "").lower()
        # File servers, chat panels and admin panels are not readable leak blogs.
        if not is_onion_v3(host) or loc.get("fs") or loc.get("chat") or loc.get("admin") or loc.get("private"):
            continue
        out.discovered.append({
            "url": f"http://{host}/", "name": f"{group} leak site", "category": "ransomware_leak_site",
            "context": f"listed by RansomLook for {group}" + ("" if loc.get("available") else " (reported offline)"),
            "actor": group,
        })
    return out


def parse_cisa_kev(body: str, feed_url: str, days: int = 60) -> ParseOutput:
    out = ParseOutput()
    data = json.loads(body)
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    for row in data.get("vulnerabilities", []):
        cve = str(row.get("cveID", "")).upper()
        if not cve.startswith("CVE-"):
            continue
        out.kev_ids.append(cve)
        out.vulnerabilities.append({
            "cve": cve, "title": str(row.get("vulnerabilityName", ""))[:500], "vendor": str(row.get("vendorProject", ""))[:200],
            "product": str(row.get("product", ""))[:200], "description": str(row.get("shortDescription", ""))[:2000],
            "kev_added": str(row.get("dateAdded", ""))[:10], "kev_due": str(row.get("dueDate", ""))[:10],
            "ransomware_use": str(row.get("knownRansomwareCampaignUse", "")).lower() == "known",
        })
        added = _when(row.get("dateAdded"))
        if not added or added < cutoff:
            continue
        ransomware = str(row.get("knownRansomwareCampaignUse", "")).lower() == "known"
        text = "\n".join(filter(None, [
            f"{cve} is on the CISA Known Exploited Vulnerabilities catalogue: it is being exploited in the wild.",
            "",
            f"Vendor: {row.get('vendorProject', '')}",
            f"Product: {row.get('product', '')}",
            f"Added to catalogue: {row.get('dateAdded', '')}",
            f"Remediation due (US federal agencies): {row.get('dueDate', '')}",
            "Known to be used in ransomware campaigns." if ransomware else "",
            "",
            row.get("shortDescription", ""),
            "",
            f"Required action: {row.get('requiredAction', '')}",
        ]))
        out.items.append(ParsedItem(
            key=cve, namespace="cisa_kev", url=f"https://nvd.nist.gov/vuln/detail/{cve}",
            title=f"{cve}: {row.get('vulnerabilityName', 'Known exploited vulnerability')}", text=text,
            raw=json.dumps(row, sort_keys=True), published_at=added, hint_type="vulnerability",
            extra_iocs=[("cve", cve)], meta={"kev": True, "ransomware_use": ransomware},
        ))
    return out


def parse_telegram_public(body: str, final_url: str) -> ParseOutput:
    """Posts from a public channel's web preview (t.me/s/<channel>). No account, no API, no private chats."""
    out = ParseOutput()
    tree = HTMLParser(body)
    header = tree.css_first(".tgme_channel_info_header_title")
    channel = header.text(strip=True) if header else final_url.rstrip("/").rsplit("/", 1)[-1]
    for message in tree.css("div.tgme_widget_message[data-post]"):
        post = message.attributes.get("data-post") or ""
        text_node = message.css_first(".tgme_widget_message_text")
        text = text_node.text(separator="\n", strip=True) if text_node else ""
        if not post or len(text) < 20:
            continue  # media-only posts carry nothing to index
        stamp = message.css_first("time[datetime]")
        first_line = text.split("\n", 1)[0][:90]
        out.items.append(ParsedItem(
            key=post, namespace="telegram", url=f"https://t.me/{post}", title=f"{channel}: {first_line}", text=text,
            raw=json.dumps({"post": post, "text": text}, sort_keys=True),
            published_at=_when(stamp.attributes.get("datetime")) if stamp else None, meta={"channel": channel, "platform": "telegram"},
        ))
    if not out.items:
        out.note = "no public posts found (is the channel public and is the URL t.me/s/<channel>?)"
    return out


def parse_ioc_feed(body: str, config: dict) -> ParseOutput:
    """A plain-text threat feed: one indicator per line. Indicators are recorded, never contacted."""
    out = ParseOutput()
    wanted = config.get("ioc_type") or ""
    seen: set[tuple[str, str]] = set()
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        token = re.split(r"[\s,;|]", line, 1)[0].strip("\"'")
        found = detect_indicator(token)
        if not found or found[0] == "cidr" or (wanted and found[0] != wanted):
            continue
        if found[0] == "ip" and not ipaddress.ip_address(found[1]).is_global:
            continue  # a feed that lists a private or reserved address is wrong about it
        if found not in seen:
            seen.add(found)
            out.feed_iocs.append(found)
        if len(out.feed_iocs) >= 20_000:
            break
    out.note = f"{len(out.feed_iocs)} indicators listed"
    return out


def parse_onion_blocklist(body: str) -> ParseOutput:
    """Ahmia's published list of banned onion services: one MD5 hash of a domain per line."""
    out = ParseOutput()
    out.blocklist = list(dict.fromkeys(re.findall(r"^[a-f0-9]{32}$", body, re.M)))
    out.note = f"{len(out.blocklist)} banned onion services listed"
    return out


# deepdarkCTI (fastfire/deepdarkCTI, GPL-3.0): curated lists of dark-web sources, as markdown tables.
# We read the list and file each live entry as a *discovered source* for review; nothing is collected
# until approved. Credentials columns (some forum lists carry shared logins) are ignored entirely.
_MD_LINK = re.compile(r"\[([^\]]*)\]\((https?://[^)\s]+)\)")
_MD_BARE = re.compile(r"(https?://[^\s|)]+)")
_LIST_CATEGORY = {"ransomware_gang": "ransomware_leak_site", "forum": "forum", "markets": "marketplace",
                  "telegram_threat_actors": "other", "telegram_infostealer": "other", "search_engines": "other"}
_DEAD = {"offline", "expired", "dead", "down", "removed", "seized", "closed", "scam", "exit"}


def parse_deepdark_catalog(body: str, config: dict) -> ParseOutput:
    out = ParseOutput()
    list_name = (config or {}).get("list", "")
    category = _LIST_CATEGORY.get(list_name, "other")
    seen: set[str] = set()
    for line in body.splitlines():
        line = line.strip()
        if not line.startswith("|") or set(line) <= set("|-: "):
            continue  # not a data row, or the header separator
        cells = [c.strip() for c in line.strip("|").split("|")]
        if not cells:
            continue
        link = _MD_LINK.search(cells[0])
        label, url = (link.group(1).strip(), link.group(2)) if link else ("", "")
        if not url:
            bare = _MD_BARE.search(cells[0])
            url = bare.group(1) if bare else ""
        if not url:
            continue
        status = cells[1].lower() if len(cells) > 1 else ""
        if any(d in status for d in _DEAD):
            continue  # do not file dead links
        # t.me/+invite links need an account and cannot be read; skip them as sources.
        if "/t.me/+" in url or "t.me/joinchat" in url:
            continue
        host = url.split("://", 1)[-1].split("/")[0].lower()
        if not host or host in seen:
            continue
        seen.add(host)
        # Context: the list it came from, plus any threat-actor / attack-type columns.
        extra = [c for c in cells[2:5] if c and not c.startswith(("http", "[", "ONLINE", "online"))][:2]
        context = f"deepdarkCTI {list_name.replace('_', ' ')}" + (f": {', '.join(extra)}" if extra else "")
        if category in ("forum", "marketplace"):
            context += " (login or invitation likely required)"
        out.discovered.append({"url": url, "name": label or host[:40], "category": category, "context": context[:480]})
        if len(out.discovered) >= 2000:
            break
    out.note = f"{len(out.discovered)} sources listed from deepdarkCTI/{list_name}"
    return out


def parse(connector: str, body: str, final_url: str, source_host: str, config: dict | None = None) -> ParseOutput:
    config = config or {}
    if connector == "onion_blocklist":
        return parse_onion_blocklist(body)
    if connector == "deepdark_catalog":
        return parse_deepdark_catalog(body, config)
    if connector == "telegram_public":
        return parse_telegram_public(body, final_url)
    if connector == "ioc_feed":
        return parse_ioc_feed(body, config)
    if connector == "rss":
        return parse_rss(body, final_url)
    if connector == "ransomware_live":
        return parse_ransomware_live(body, final_url)
    if connector == "ransomlook_recent":
        return parse_ransomlook_recent(body, final_url)
    if connector == "ransomlook_group":
        return parse_ransomlook_group(body, final_url)
    if connector == "cisa_kev":
        return parse_cisa_kev(body, final_url, int(config.get("days", 60)))
    return parse_html(body, final_url, source_host)
