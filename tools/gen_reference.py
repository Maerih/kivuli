"""Generate docs/REFERENCE.md from the running code: HTTP API, data model, configuration, scheduled work and enumerations.

Run inside the api container so it describes exactly what is deployed:

    ./ctl.sh docker compose exec -T api python - < tools/gen_reference.py > docs/REFERENCE.md
"""
import inspect
import re
from datetime import datetime, timezone

from fastapi.routing import APIRoute

import app.main as main
from app import models, security
from app.config import Settings
from app.enrich import providers
from app.extract.classify import THREAT_TYPES
from app.extract.iocs import IOC_TYPES
from app.extract.lang import LANGUAGE_NAMES
from app.intel import quality, settings_store
from app.notify.integrations import KINDS as INTEGRATION_KINDS
from app.search.query import FIELD_ALIASES, HAS_FLAGS
from app.worker.celery_app import celery_app
from app.worker.parsers import CONNECTORS

# Descriptions for operations whose handler has no docstring. A docstring, where there is one, wins.
DESCRIPTIONS = {
    ("GET", "/audit"): "The audit log, newest first; filter by action prefix and user.",
    ("GET", "/dashboard"): "Figures behind the Trends page: volumes, types, countries, actors, sectors, timeline, what is rising, exposure counts.",
    ("GET", "/system/email-log"): "The last 50 alert emails and whether each was delivered.",
    ("GET", "/system/health"): "Health of the database, search index, queues and Tor gateway, crawl activity, email settings, collection policy flags and data-quality figures.",
    ("POST", "/system/test-email"): "Queue a test message to one address.",
    ("GET", "/users"): "Every account with its role, state and whether two-step sign-in is on.",
    ("POST", "/users"): "Create an account.",
    ("PATCH", "/users/{user_id}"): "Change a role, enable or disable, reset a password, or reset two-step sign-in.",
    ("GET", "/users/directory"): "Names of active users, for assigning cases and alerts.",
    ("GET", "/ai/jobs/{job_id}"): "Progress and result of an AI request. Only its owner or an admin can read it.",
    ("GET", "/ai/status"): "Whether the AI analyst is switched on, and the model in use.",
    ("POST", "/ai/summarize"): "Summarise one finding. Returns the stored summary if there is one, otherwise starts a job.",
    ("GET", "/attack/techniques/{technique_id}"): "One ATT&CK technique: description, sub-techniques, findings tagged with it, and the groups and malware known to use it.",
    ("POST", "/relationships"): "Record a relationship between two entities, with a confidence. The analyst is stored as its source.",
    ("DELETE", "/relationships/{relationship_id}"): "Remove a relationship.",
    ("POST", "/auth/login"): "Sign in with email and password, plus a code when two-step sign-in is on. Sets the session cookie. Rate limited; five failures lock the account.",
    ("POST", "/auth/logout"): "End the session.",
    ("GET", "/auth/me"): "The signed-in user.",
    ("POST", "/auth/mfa/enable"): "Confirm enrolment with a code from the authenticator app. Returns ten single-use recovery codes, once.",
    ("POST", "/auth/mfa/disable"): "Turn two-step sign-in off. Needs the password and a current code or recovery code.",
    ("POST", "/auth/password"): "Change your own password.",
    ("GET", "/cases"): "Every investigation with its status, priority, owner and item count.",
    ("POST", "/cases"): "Open an investigation.",
    ("GET", "/cases/{case_id}"): "An investigation with its findings, the indicators and entities across them, preserved evidence, saved hunts, crawls and notes.",
    ("PATCH", "/cases/{case_id}"): "Change title, summary, status, priority, sharing level (TLP) or owner.",
    ("DELETE", "/cases/{case_id}"): "Delete an investigation. The findings themselves are kept.",
    ("POST", "/cases/{case_id}/items"): "Attach a finding, indicator, entity, saved hunt (a query) or graph bookmark.",
    ("DELETE", "/cases/{case_id}/items/{item_id}"): "Detach an item.",
    ("GET", "/cases/{case_id}/report"): "Export: `format=html` (printable report), `json`, `csv` (indicators) or `stix` (STIX 2.1 bundle).",
    ("GET", "/attack-surface"): "Hosts discovered for owned assets, with open ports, known vulnerabilities and explained risk, plus a summary and the owned assets themselves.",
    ("GET", "/exposures"): "Exposed accounts and secrets; filter by kind, status, domain, text, or only those on domains you watch.",
    ("GET", "/exposures/export"): "The same list as CSV. Never contains a secret.",
    ("POST", "/exposures/status"): "Mark exposures open, remediated, ignored or false positive.",
    ("GET", "/vulnerabilities"): "The vulnerability catalogue ranked by priority, exploit likelihood, recency, severity or mentions.",
    ("GET", "/vulnerabilities/{cve}"): "One CVE: scores, why it ranks where it does, findings that mention it, related entities, and owned hosts reported with it.",
    ("GET", "/findings/{doc_id}"): "A finding in full: text, classification, explained risk, indicators, entities, versions, alerts, cases, duplicates, related findings, techniques, exposure records, verification.",
    ("PATCH", "/findings/{doc_id}"): "Set triage status, tags, or mark as confirmed by an analyst.",
    ("DELETE", "/findings/{doc_id}/entities/{entity_id}"): "Remove a wrongly attached entity from a finding.",
    ("GET", "/findings/{doc_id}/versions/{version}"): "The stored text of one capture.",
    ("GET", "/findings/{doc_id}/diff"): "Line-by-line difference between two captures.",
    ("GET", "/findings/{doc_id}/evidence"): "The evidence chain for a finding, re-verified on request: every capture's hashes, chain hash and signature.",
    ("GET", "/notes"): "Notes on a finding, case, entity, indicator or source.",
    ("POST", "/notes"): "Add a note.",
    ("DELETE", "/notes/{note_id}"): "Delete your own note (admins: any).",
    ("GET", "/integrations"): "Alert destinations and the kinds available.",
    ("POST", "/integrations"): "Add an alert destination. Its token or webhook address is stored encrypted.",
    ("PATCH", "/integrations/{integration_id}"): "Change, pause or resume a destination.",
    ("DELETE", "/integrations/{integration_id}"): "Remove a destination.",
    ("POST", "/integrations/{integration_id}/test"): "Send a test alert. The outcome appears in the destination's deliveries.",
    ("GET", "/integrations/{integration_id}/deliveries"): "The last 50 delivery attempts and their results.",
    ("GET", "/iocs/{ioc_id}/enrichment"): "What providers said about an indicator, the feeds that list it, and whether it is marked benign.",
    ("GET", "/providers/tests/{job_id}"): "Progress and result of a provider connection test.",
    ("GET", "/entities"): "Actors, organisations, malware, campaigns, incidents and techniques; filter by type and text.",
    ("POST", "/entities"): "Create an actor, organisation, malware family or campaign.",
    ("GET", "/entities/{entity_id}"): "An entity: profile, activity over time, findings, related entities, indicators, countries and sectors.",
    ("PATCH", "/entities/{entity_id}"): "Edit name, aliases or description.",
    ("GET", "/iocs"): "Indicators; filter by type and text.",
    ("GET", "/iocs/{ioc_id}"): "An indicator: where it appears with surrounding text, associated entities, and indicators seen with it.",
    ("GET", "/graph"): "The relationship graph around one node (`entity:ID`, `ioc:ID` or `finding:UUID`): co-occurrence and stated relationships.",
    ("GET", "/reports/executive"): "A plain-language summary of a period for leadership: `format=html` (printable) or `json`.",
    ("GET", "/collection/status"): "Tor connection, collectors answering, sources by state, queue depth, pages indexed, last collection, failed fetches, blocklist state and the policy in force.",
    ("GET", "/crawls"): "Research crawls, newest first, with progress.",
    ("POST", "/crawls/{job_id}/stop"): "Stop queuing further pages for a crawl. Pages already being fetched finish.",
    ("GET", "/settings/collection"): "The collection policy and research-crawl limits.",
    ("PUT", "/settings/collection"): "Change the collection policy or limits. Waiting sites are re-checked against the new policy.",
    ("GET", "/rules"): "Detection rules with how often each has fired.",
    ("POST", "/rules"): "Create a detection rule from a search.",
    ("PATCH", "/rules/{rule_id}"): "Change, pause or resume a rule.",
    ("DELETE", "/rules/{rule_id}"): "Delete a rule and its alerts.",
    ("POST", "/rules/{rule_id}/run"): "Evaluate a rule now instead of waiting for the five-minute cycle.",
    ("GET", "/saved-searches"): "Your saved searches.",
    ("POST", "/saved-searches"): "Save the current query and filters under a name.",
    ("DELETE", "/saved-searches/{search_id}"): "Delete a saved search.",
    ("GET", "/search"): "Search everything collected. Returns ranked results with highlights, why each matched, facets, a timeline, the sources carrying the results and how the query was understood.",
    ("GET", "/search/suggest"): "Type-ahead: operators, countries, entities, indicators and finding titles.",
    ("GET", "/search/export"): "The results of a search as CSV or JSON (up to 5,000).",
    ("GET", "/meta"): "Labels and fixed lists the console needs: threat types, countries, operators, techniques, languages and so on.",
    ("GET", "/sources"): "Sources, optionally through an explorer view: `new`, `offline`, `changed`, `referenced`, `relevant`.",
    ("POST", "/sources"): "Add a source by address. Added as a candidate unless `approve` is set.",
    ("PATCH", "/sources/{source_id}"): "Approve, pause or block a source, or change how it is crawled.",
    ("DELETE", "/sources/{source_id}"): "Delete a source that has no findings. One with findings can only be paused or blocked, so evidence is kept.",
    ("POST", "/sources/{source_id}/crawl"): "Crawl an active source now.",
    ("POST", "/sources/{source_id}/verify"): "Check now whether a source answers.",
    ("GET", "/sources/{source_id}/log"): "Recent fetches for a source: address, result, size, timing, what was new.",
    ("POST", "/sources/discover"): "Look up where ransomware groups publish (one named group, or the most recently active) and file the sites as discovered sources.",
    ("GET", "/taxii2/"): "TAXII 2.1 discovery document.",
    ("GET", "/taxii2/root/"): "TAXII API root.",
    ("GET", "/taxii2/root/collections/"): "The three collections: indicators, high-risk indicators, and actors/malware/techniques.",
    ("GET", "/taxii2/root/collections/{collection_id}/"): "One collection.",
    ("GET", "/taxii2/root/collections/{collection_id}/objects/"): "STIX 2.1 objects in a collection, paged; `added_after`, `limit` and `next` as in the TAXII specification.",
    ("GET", "/taxii2/root/collections/{collection_id}/manifest/"): "Identifiers and dates of the objects in a collection.",
    ("GET", "/alerts"): "The alert queue with counts by status, severity and category. Ordered by priority unless `sort=newest`.",
    ("PATCH", "/alerts/{alert_id}"): "Change an alert's status or assign it.",
    ("POST", "/alerts/bulk"): "Change the status of many alerts at once.",
    ("GET", "/watchlists"): "Everything being watched, with open alert and match counts.",
    ("POST", "/watchlists"): "Watch a value. Existing intelligence is checked at once; an owned domain or IP range also starts passive attack-surface discovery.",
    ("PATCH", "/watchlists/{watch_id}"): "Change label, email settings, ownership, criticality, or pause it.",
    ("DELETE", "/watchlists/{watch_id}"): "Stop watching. Its alerts are removed.",
    ("POST", "/watchlists/{watch_id}/hunt"): "Re-check everything already collected against this entry.",
    ("GET", "/healthz"): "Liveness probe for the container.",
    ("GET", "/metrics"): "Prometheus metrics. Scrape with an API key.",
}


ROLE_OF = {security.viewer: "viewer", security.analyst: "analyst", security.admin: "admin", security.current_user: "signed in"}
out: list[str] = []
w = out.append


def first_line(doc: str | None) -> str:
    return " ".join((doc or "").strip().split("\n\n")[0].split()) if doc else ""


def describe(method: str, route: APIRoute) -> str:
    path = route.path.removeprefix("/api")
    return first_line(route.endpoint.__doc__) or DESCRIPTIONS.get((method, path)) or DESCRIPTIONS.get((method, path + "/")) or route.name.replace("_", " ").capitalize()


def role_for(route: APIRoute) -> str:
    found = set()

    def walk(dep):
        if dep.call in ROLE_OF:
            found.add(ROLE_OF[dep.call])
        for sub in dep.dependencies:
            walk(sub)
    walk(route.dependant)
    for name in ("admin", "analyst", "viewer", "signed in"):
        if name in found:
            return name
    return "public"


w("# Reference (generated)\n")
w(f"Generated from the running code on {datetime.now(timezone.utc):%Y-%m-%d} by `tools/gen_reference.py`. Do not edit by hand; regenerate after a change:\n")
w("```bash\n./ctl.sh docker compose exec -T api python - < tools/gen_reference.py > docs/REFERENCE.md\n```\n")
w("Contents: [HTTP API](#http-api) · [Data model](#data-model) · [Configuration](#configuration) · [Scheduled work and tasks](#scheduled-work-and-tasks) · [Enumerations](#enumerations)\n")

# ── HTTP API ──
w("## HTTP API\n")
w("All paths are under `/api`. A request is authenticated by the session cookie (console) or by `Authorization: Bearer <api key>`. "
  "Roles nest: an admin can do everything an analyst can, an analyst everything a viewer can. A read-only API key is refused on anything but GET. "
  "State-changing requests from the console must carry the header `X-Kivuli-CSRF: 1`.\n")
def all_routes() -> list[APIRoute]:
    """Every API route, including those FastAPI keeps inside an included router."""
    found: list[APIRoute] = []
    for route in main.app.routes:
        nested = getattr(getattr(route, "original_router", None), "routes", None)
        found += [r for r in (nested if nested is not None else [route]) if isinstance(r, APIRoute)]
    return found


groups: dict[str, list] = {}
for route in all_routes():
    if route.include_in_schema:
        groups.setdefault((route.tags or ["platform"])[0], []).append(route)
hidden = [r for r in all_routes() if not r.include_in_schema]
total = 0
for tag in sorted(groups):
    w(f"### {tag}\n")
    w("| Method | Path | Role | What it does |")
    w("|---|---|---|---|")
    for route in sorted(groups[tag], key=lambda r: (r.path, sorted(r.methods))):
        for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
            total += 1
            w(f"| {method} | `{route.path.removeprefix('/api')}` | {role_for(route)} | {describe(method, route)} |")
    w("")
hidden = [r for r in hidden if not r.path.startswith("/taxii2")]
w("Every TAXII path also answers without its trailing slash, because reverse proxies often strip it.\n")
if hidden:
    w("### not in the OpenAPI schema\n")
    w("| Method | Path | Role | What it does |")
    w("|---|---|---|---|")
    seen = set()
    for route in sorted(hidden, key=lambda r: r.path):
        for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
            if (method, route.path) in seen:
                continue
            seen.add((method, route.path))
            total += 1
            w(f"| {method} | `{route.path.removeprefix('/api')}` | {role_for(route)} | {describe(method, route)} |")
    w("")
w(f"{total} operations. The machine-readable schema is served at `/api/openapi.json` and an interactive view at `/api/docs`.\n")

# ── Data model ──
w("## Data model\n")
w("PostgreSQL is the system of record. Every table, with its columns. `PK` primary key, `FK` foreign key (with what happens on delete), `idx` indexed, `uniq` unique, `null` nullable.\n")
for table in sorted(models.Base.metadata.tables.values(), key=lambda t: t.name):
    cls = next((c for c in models.Base.registry.mappers if c.local_table is table), None)
    doc = first_line(cls.class_.__doc__) if cls is not None else ""
    w(f"### `{table.name}`\n")
    if doc:
        w(doc + "\n")
    w("| Column | Type | Notes |")
    w("|---|---|---|")
    for col in table.columns:
        notes = []
        if col.primary_key:
            notes.append("PK")
        for fk in col.foreign_keys:
            notes.append(f"FK {fk.column.table.name}.{fk.column.name}" + (f" ({fk.ondelete.lower()})" if fk.ondelete else ""))
        if col.unique:
            notes.append("uniq")
        if col.index:
            notes.append("idx")
        if col.nullable and not col.primary_key:
            notes.append("null")
        kind = re.sub(r"\(\)$", "", str(col.type).replace("VARCHAR", "varchar").replace("TIMESTAMP", "timestamptz").replace("INTEGER", "integer").replace("BOOLEAN", "boolean").replace("TEXT", "text").replace("BIGINT", "bigint"))
        w(f"| `{col.name}` | {kind} | {', '.join(notes)} |")
    extra = [f"unique ({', '.join(c.name for c in con.columns)})" for con in table.constraints if con.__class__.__name__ == "UniqueConstraint" and len(con.columns) > 1]
    if extra:
        w("\n" + "; ".join(extra) + ".")
    w("")

# ── Configuration ──
w("## Configuration\n")
w("Environment settings, read from `.env` by `./ctl.sh` and passed to the containers that need them. Each container receives only its own. "
  "Secrets are generated on first start. Settings marked *console* can also be changed in the console, which then takes precedence.\n")
SETTINGS = {
    "APP_NAME": "Name shown in the console and in alert email.",
    "ROLE": "Which role a backend container plays (api, crawler, pipeline, enricher, notify, beat, egress). Set by docker-compose, not by you.",
    "PUBLIC_URL": "Address researchers use to reach the console. Links in alert email and the TAXII discovery document point here.",
    "DATABASE_URL": "PostgreSQL connection. Built by docker-compose from POSTGRES_PASSWORD.",
    "OPENSEARCH_URL": "Search node address.", "OPENSEARCH_USER": "Search node user, if it has authentication.", "OPENSEARCH_PASSWORD": "Search node password, if it has authentication.",
    "OPENSEARCH_INDEX": "Name of the findings index.",
    "REDIS_URL": "Queue and cache connection. Built by docker-compose from REDIS_PASSWORD.",
    "JWT_SECRET": "Signs session cookies. Generated.",
    "SESSION_TTL_MINUTES": "How long a console session lasts.",
    "COOKIE_SECURE": "Set to true when the console is served over HTTPS.",
    "RATE_LIMIT_PER_MINUTE": "API requests allowed per client address per minute.",
    "LOGIN_RATE_LIMIT_PER_MINUTE": "Sign-in attempts allowed per client address per minute.",
    "BOOTSTRAP_ADMIN_EMAIL": "First administrator, created once when there are no users.", "BOOTSTRAP_ADMIN_PASSWORD": "That administrator's initial password. Generated.",
    "EVIDENCE_HMAC_KEY": "Signs the evidence chain. Generated. Back it up: without it stored evidence cannot be verified.",
    "EVIDENCE_STORE_RAW": "Also keep the unredacted capture on the evidence volume. Off: turning it on makes the system a store of stolen credentials.",
    "EVIDENCE_DIR": "Where raw captures are written inside the container.",
    "REDACT_SECRETS": "Mask passwords, keys and card numbers before anything is stored, indexed or emailed.",
    "TOR_SOCKS_URL": "The Tor gateway's SOCKS address.", "EGRESS_PROXY_URL": "The allow-listing egress proxy.",
    "RENDER_URL": "The JavaScript renderer (crawler only).", "RENDER_TIMEOUT_SECONDS": "Seconds allowed to render one page in the headless browser.",
    "TOR_USER_AGENT": "User-Agent sent through Tor (that of Tor Browser, so the crawler does not stand out).",
    "DIRECT_USER_AGENT": "User-Agent sent to clearnet feeds and providers (identifies the platform honestly).",
    "CRAWL_MAX_BYTES": "Largest page body read. Larger responses are cut off.", "CRAWL_TIMEOUT_SECONDS": "Longest wait for one page.",
    "CRAWL_HOST_DELAY_SECONDS": "Pause between two requests to the same host, across all crawler processes.",
    "CRAWL_MAX_REDIRECTS": "Redirect hops followed. Each must stay on the same site and is re-validated.",
    "EGRESS_ALLOW_HOSTS": "Clearnet hosts that may be reached directly over HTTPS. Everything else, and every onion site, goes through Tor. A leading dot allows subdomains. Deliberately not editable in the console.",
    "FOCUS_COUNTRIES": "ISO country codes you care most about. Findings about them score higher.",
    "FOCUS_SECTORS": "Industries you care most about, as trackers name them.",
    "DISCOVER_ONION_LINKS": "Record onion sites linked from crawled pages as discovered sources.",
    "MAX_CANDIDATES_PER_CRAWL": "Most discovered sources filed from one page.",
    "LIVENESS_INTERVAL_HOURS": "How often discovered and paused sources are re-checked.",
    "EMAIL_ENABLED": "Send alert email at all.", "SMTP_HOST": "Mail relay. The bundled test inbox by default.", "SMTP_PORT": "Mail relay port.",
    "SMTP_USERNAME": "Mail relay user.", "SMTP_PASSWORD": "Mail relay password.", "SMTP_TLS": "none, starttls or ssl.", "SMTP_FROM": "Sender shown on alert email.",
    "ALERT_EMAIL_TO": "Default recipients for watchlists and rules that name none.", "DIGEST_HOUR_UTC": "Hour at which daily digests are sent.",
    "EMAIL_MAX_ALERTS_PER_MESSAGE": "Alerts batched into one message.",
    "SECRETS_KEY": "Encrypts alert-destination credentials and two-step sign-in seeds in the database. Generated. Back it up.",
    "PROVIDER_KEYS_KEY": "Encrypts provider API keys entered in the console. Held only by the api and enricher containers. Generated. Back it up.",
    "REQUIRE_MFA": "Prompt administrators who have not enrolled two-step sign-in.",
    "INTEGRATIONS_ALLOW_PRIVATE": "Allow alert destinations on private addresses (an internal SIEM). Off so the console cannot be pointed at internal services by mistake.",
    "VIRUSTOTAL_API_KEY": "VirusTotal key.", "SHODAN_API_KEY": "Shodan key.", "ABUSEIPDB_API_KEY": "AbuseIPDB key.", "GREYNOISE_API_KEY": "GreyNoise key.",
    "NVD_API_KEY": "Optional NVD key; raises the rate limit.", "ANTHROPIC_API_KEY": "Anthropic key; switches the AI analyst on.", "AI_MODEL": "Model the AI analyst uses.",
    "ASM_MAX_HOSTS": "Most hosts tracked per owned domain.", "ASM_INTERVAL_DAYS": "How often owned assets are re-checked.",
}
GENERATED = {"JWT_SECRET", "EVIDENCE_HMAC_KEY", "SECRETS_KEY", "PROVIDER_KEYS_KEY", "BOOTSTRAP_ADMIN_PASSWORD"}
console = {"VIRUSTOTAL_API_KEY", "SHODAN_API_KEY", "ABUSEIPDB_API_KEY", "GREYNOISE_API_KEY", "NVD_API_KEY", "ANTHROPIC_API_KEY", "AI_MODEL"}
w("| Variable | Default | What it controls |")
w("|---|---|---|")
for name, field in Settings.model_fields.items():
    env = name.upper()
    default = field.default
    shown = "*generated*" if env in GENERATED else f"`{default}`" if default not in ("", None) else "*empty*"
    w(f"| `{env}` | {shown} | {SETTINGS.get(env, '')}{' *Also settable in the console.*' if env in console else ''} |")
w("")
w("Read only by docker-compose and `ctl.sh`, not by the application:\n")
w("| Variable | Default | What it controls |")
w("|---|---|---|")
for env, default, text in (("POSTGRES_PASSWORD", "*generated*", "Database password."), ("REDIS_PASSWORD", "*generated*", "Queue password."),
                           ("WEB_PORT", "`28941`", "Port the console is published on, on 127.0.0.1 only."),
                           ("MAILPIT_PORT", "`28942`", "Port of the bundled test inbox, on 127.0.0.1 only."),
                           ("SEARCH_HEAP", "`768m`", "Memory given to the search node."), ("CRAWLER_CONCURRENCY", "`6`", "Simultaneous fetches."),
                           ("PIPELINE_CONCURRENCY", "`4`", "Simultaneous pages being processed.")):
    w(f"| `{env}` | {default} | {text} |")
w("")
w("### Settings changed in the console\n")
w("Stored in the `app_settings` table (collection policy) and `provider_keys` table (provider keys and the AI model).\n")
w("| Setting | Default | Allowed |")
w("|---|---|---|")
limits = settings_store._LIMITS
for name, default in settings_store.DEFAULTS["collection"].items():
    allowed = " / ".join(settings_store.AUTO_APPROVE) if name == "auto_approve" else f"{limits[name][0]} to {limits[name][1]}"
    w(f"| `collection.{name}` | `{default}` | {allowed} |")
w("")

# ── Scheduled work and tasks ──
w("## Scheduled work and tasks\n")
w("The `beat` container fires these; the named worker role runs them.\n")
w("| Schedule | Task | Runs in |")
w("|---|---|---|")
queue_of = {"crawl": "crawler", "pipeline": "pipeline", "notify": "notify", "enrich": "enricher", "ai": "enricher"}
for name, entry in sorted(celery_app.conf.beat_schedule.items(), key=lambda kv: kv[1]["task"]):
    schedule = entry["schedule"]
    every = f"every {int(schedule)} s" if isinstance(schedule, (int, float)) else f"cron: minute {schedule._orig_minute}, hour {schedule._orig_hour} UTC"
    w(f"| {every} | `{entry['task']}` | {queue_of.get(entry['task'].split('.')[0], '?')} |")
w("")
w("Task routing: " + ", ".join(f"`{pattern}` → queue `{target['queue']}`" for pattern, target in celery_app.conf.task_routes.items()) + ".\n")

# ── Enumerations ──
w("## Enumerations\n")


def table(title: str, rows, header=("Value", "Meaning")):
    w(f"### {title}\n")
    w(f"| {header[0]} | {header[1]} |")
    w("|---|---|")
    for key, value in rows:
        w(f"| `{key}` | {value} |")
    w("")


table("Threat types", THREAT_TYPES.items())
w("### Other fixed values\n")
for label, values in (("Severities", models.SEVERITIES), ("Finding statuses", models.FINDING_STATUSES), ("Alert statuses", models.ALERT_STATUSES),
                      ("Source statuses", models.SOURCE_STATUSES), ("Indicator types", IOC_TYPES), ("Entity types", models.ENTITY_TYPES),
                      ("Watchlist kinds", models.WATCH_KINDS), ("Verification states", models.VERIFICATION), ("Relationship kinds", models.RELATIONSHIP_KINDS),
                      ("Exposure kinds", models.EXPOSURE_KINDS), ("Exposure statuses", models.EXPOSURE_STATUSES), ("Rule kinds", models.RULE_KINDS),
                      ("Crawl job statuses", models.CRAWL_JOB_STATUSES), ("User roles", ("viewer", "analyst", "admin"))):
    w(f"- **{label}:** " + ", ".join(f"`{v}`" for v in values))
w("")
table("Source connectors", CONNECTORS.items())
table("Alert destinations", INTEGRATION_KINDS.items())
table("Source reliability (Admiralty letter)", quality.RELIABILITY.items(), ("Grade", "Meaning"))
table("Information credibility (Admiralty digit)", quality.CREDIBILITY.items(), ("Grade", "Meaning"))
table("Verification states", quality.VERIFICATION_LABELS.items(), ("State", "Meaning"))
w("### Enrichment providers\n")
w("| Provider | Tier | Asks about | Hosts contacted | Key setting |")
w("|---|---|---|---|---|")
for p in providers.PROVIDERS:
    w(f"| {p.label} | {p.tier}{' (key optional)' if p.optional_key else ''} | {', '.join(p.kinds)} | {', '.join(p.hosts) or '-'} | {('`' + p.key_setting.upper() + '`') if p.key_setting else '-'} |")
w("")
aliases: dict[str, list[str]] = {}
for alias, canonical in FIELD_ALIASES.items():
    aliases.setdefault(canonical, []).append(alias)
table("Search operators and their aliases", [(canonical + ":", ", ".join(f"`{a}:`" for a in sorted(names))) for canonical, names in sorted(aliases.items())], ("Operator", "Accepted spellings"))
table("`has:` flags", [(k, "") for k in sorted(HAS_FLAGS)], ("Flag", ""))
table("Languages recognised", LANGUAGE_NAMES.items(), ("Code", "Language"))
print("\n".join(out))
