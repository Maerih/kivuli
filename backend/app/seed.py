"""First-run data: the bootstrap admin, the entity gazetteer and the default sources."""
import logging

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.crawl.fetcher import validate_url
from app.extract.entities import CURATED_ACTORS, CURATED_MALWARE
from app.extract.geo import country_name
from app.extract.textutil import slugify
from app.models import Entity, Source, User
from app.security import hash_password

log = logging.getLogger(__name__)

# Public, structured clearnet feeds: approved out of the box. Everything onion is
# discovered or added later and waits for an analyst to approve it.
#   (name, url, connector, category, trust, interval minutes, config)
DEFAULT_SOURCES = [
    ("Ransomware.live: recent victims", "https://api.ransomware.live/v2/recentvictims", "ransomware_live", "tracker", 80, 60, {}),
    ("RansomLook: recent posts", "https://www.ransomlook.io/api/recent", "ransomlook_recent", "tracker", 75, 90, {}),
    ("CISA Known Exploited Vulnerabilities", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "cisa_kev", "vuln_feed", 95, 720, {"max_bytes": 6_000_000, "days": 60}),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/", "rss", "news", 75, 60, {}),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews", "rss", "news", 65, 90, {}),
    ("DataBreaches.net", "https://databreaches.net/feed/", "rss", "news", 75, 120, {}),
    ("Security Affairs", "https://securityaffairs.com/feed", "rss", "news", 70, 120, {}),
    ("The Record", "https://therecord.media/feed", "rss", "news", 80, 120, {}),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/", "rss", "blog", 85, 360, {}),
    ("HackRead", "https://hackread.com/feed/", "rss", "news", 60, 120, {}),
]

# Added in 1.1. Inserted once on upgrade as well as on fresh installs.
#   (name, url, connector, category, trust, interval minutes, config, status)
ADDED_SOURCES = [
    ("Feodo Tracker: botnet C2 addresses", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "ioc_feed", "tracker", 85, 360,
     {"tag": "botnet-c2", "ioc_type": "ip"}, "approved"),
    ("OpenPhish: phishing URLs", "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt", "ioc_feed", "tracker", 75, 360,
     {"tag": "phishing", "ioc_type": "url", "max_bytes": 6_000_000}, "approved"),
    ("CISA cybersecurity advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml", "rss", "vuln_feed", 95, 360, {}, "approved"),
    # Not intelligence but a safety control: onion services Ahmia has banned for abuse material, as hashes. Nothing on it is ever fetched.
    ("Ahmia: banned onion services (safety blocklist)", "https://ahmia.fi/blacklist/banned/", "onion_blocklist", "other", 95, 1440,
     {"max_bytes": 4_000_000}, "approved"),
    # deepdarkCTI (fastfire/deepdarkCTI, GPL-3.0): curated catalogues of dark-web sources. These do not collect
    # intelligence themselves; each run files the listed sites as *discovered sources* for a researcher to approve.
    ("deepdarkCTI: ransomware leak sites", "https://raw.githubusercontent.com/fastfire/deepdarkCTI/main/ransomware_gang.md",
     "deepdark_catalog", "other", 70, 1440, {"list": "ransomware_gang", "max_bytes": 4_000_000}, "approved"),
    ("deepdarkCTI: forums", "https://raw.githubusercontent.com/fastfire/deepdarkCTI/main/forum.md",
     "deepdark_catalog", "other", 70, 1440, {"list": "forum", "max_bytes": 4_000_000}, "approved"),
    ("deepdarkCTI: markets", "https://raw.githubusercontent.com/fastfire/deepdarkCTI/main/markets.md",
     "deepdark_catalog", "other", 70, 1440, {"list": "markets", "max_bytes": 4_000_000}, "approved"),
    # Vendor threat-research blogs: where teams such as Unit 42 publish what their telemetry, incident
    # response and malware analysis found. Every feed was checked to answer Kivuli's own user agent directly.
    *[(name, url, "rss", "blog", trust, 360, {"max_bytes": 3_000_000}, "approved") for name, url, trust in (
        ("Unit 42 (Palo Alto Networks)", "https://unit42.paloaltonetworks.com/feed/", 90),
        ("Check Point Research", "https://research.checkpoint.com/feed/", 85),
        ("Kaspersky Securelist", "https://securelist.com/feed/", 85),
        ("ESET WeLiveSecurity", "https://www.welivesecurity.com/en/rss/feed/", 85),
        ("SentinelLabs", "https://www.sentinelone.com/labs/feed/", 85),
        ("Proofpoint Threat Insight", "https://www.proofpoint.com/us/threat-insight-blog.xml", 85),
        ("Recorded Future", "https://www.recordedfuture.com/feed", 85),
        ("The DFIR Report", "https://thedfirreport.com/feed/", 90),
        ("Volexity", "https://www.volexity.com/feed/", 85),
        ("Huntress", "https://www.huntress.com/blog/rss.xml", 80),
        ("Zscaler ThreatLabz", "https://www.zscaler.com/blogs/feeds/security-research", 80),
        ("Fortinet FortiGuard Labs", "https://feeds.fortinet.com/fortinet/blog/threat-research", 80),
        ("Trend Micro Research", "https://feeds.feedburner.com/TrendMicroResearch", 80),
        ("CrowdStrike", "https://www.crowdstrike.com/en-us/blog/feed", 85),
        ("Rapid7", "https://www.rapid7.com/rss.xml", 75),
    )],
]


def seed_admin(db: Session) -> None:
    settings = get_settings()
    if db.scalar(select(func.count()).select_from(User)):
        return
    if not settings.bootstrap_admin_email or not settings.bootstrap_admin_password:
        log.warning("no users exist and BOOTSTRAP_ADMIN_EMAIL/PASSWORD are not set; create one with: manage create-user")
        return
    db.add(User(email=settings.bootstrap_admin_email.lower(), name="Administrator", role="admin",
                password_hash=hash_password(settings.bootstrap_admin_password)))
    log.info("created bootstrap admin %s", settings.bootstrap_admin_email)


def seed_entities(db: Session) -> None:
    existing = {(t, s) for t, s in db.execute(select(Entity.type, Entity.slug))}
    for kind, rows in (("actor", CURATED_ACTORS), ("malware", CURATED_MALWARE)):
        for name, aliases in rows:
            if (kind, slugify(name)) not in existing:
                db.add(Entity(type=kind, name=name, slug=slugify(name), aliases=aliases, curated=True))


def seed_sources(db: Session) -> None:
    if db.scalar(select(func.count()).select_from(Source)):
        return
    settings = get_settings()
    rows = list(DEFAULT_SOURCES)
    for code in settings.focus_country_list:
        rows.insert(1, (f"Ransomware.live: {country_name(code)} victims", f"https://api.ransomware.live/v2/countryvictims/{code}",
                        "ransomware_live", "tracker", 80, 180, {}))
    for name, url, connector, category, trust, interval, config in rows:
        ok, _reason, host, network = validate_url(url)
        if ok:
            db.add(Source(name=name, url=url, host=host, network=network, connector=connector, route="direct", category=category,
                          status="approved", trust=trust, crawl_interval_minutes=interval, max_depth=0, max_pages=1, config=config))


def seed_added_sources(db: Session) -> None:
    """Sources introduced by a later release. Skipped if the URL is already there, in whatever state."""
    existing = set(db.scalars(select(Source.url)))
    for name, url, connector, category, trust, interval, config, status in ADDED_SOURCES:
        ok, _reason, host, network = validate_url(url)
        if ok and url not in existing:
            db.add(Source(name=name, url=url, host=host, network=network, connector=connector, route="direct", category=category, status=status,
                          trust=trust, crawl_interval_minutes=interval, max_depth=0, max_pages=1, config=config))


def seed_knowledge(db: Session) -> None:
    """Load MITRE ATT&CK once per catalogue version; it is the reference set entity resolution works against."""
    from app.intel import attack
    from app.intel.relationships import seed_attack

    version = attack.catalog()["version"]
    marker = db.scalar(select(Entity).where(Entity.type == "technique", Entity.slug == "t1486"))
    if marker is not None and (marker.meta or {}).get("catalog") == version:
        return
    seed_attack(db)
    marker = db.scalar(select(Entity).where(Entity.type == "technique", Entity.slug == "t1486"))
    if marker is not None:
        marker.meta = {**(marker.meta or {}), "catalog": version}


def run(db: Session) -> None:
    seed_admin(db)
    seed_entities(db)
    seed_sources(db)
    seed_added_sources(db)
    seed_knowledge(db)
