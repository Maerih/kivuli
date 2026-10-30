# Technical reference

How the platform is built and why. For day-to-day use see
[USER-GUIDE.md](USER-GUIDE.md). The exact API, tables, settings and schedules
are in [REFERENCE.md](REFERENCE.md), which is generated from the running code;
this document explains them.

## Contents

1. [Design principles](#1-design-principles)
2. [System overview](#2-system-overview)
3. [Containers, networks and volumes](#3-containers-networks-and-volumes)
4. [Collection](#4-collection)
5. [The processing pipeline](#5-the-processing-pipeline)
6. [Extraction](#6-extraction)
7. [Scoring](#7-scoring)
8. [History, de-duplication and evidence](#8-history-de-duplication-and-evidence)
9. [Search](#9-search)
10. [Alerting](#10-alerting)
11. [Enrichment and the AI analyst](#11-enrichment-and-the-ai-analyst)
12. [Exposure intelligence](#12-exposure-intelligence)
13. [Intelligence graph, STIX and TAXII](#13-intelligence-graph-stix-and-taxii)
14. [Access control](#14-access-control)
15. [The console](#15-the-console)
16. [Configuration](#16-configuration)
17. [Operations](#17-operations)
18. [Testing](#18-testing)
19. [Extending](#19-extending)
20. [Repository layout](#20-repository-layout)
21. [Technical limits](#21-technical-limits)

---

## 1. Design principles

1. **The thing that reads hostile content can do nothing else.** The crawler
   has no database credentials, no signing keys and no route to the internet
   except through two gateways. Parsing happens in a container with no network
   at all.
2. **Read only, text only.** GET requests; no forms, logins, cookies, scripts
   or downloads. Nothing discovered is contacted except to read a page.
3. **Do not become a store of stolen secrets.** Passwords, keys and card
   numbers are masked before anything is stored, indexed or emailed. A short
   fingerprint is kept so the same secret can be recognised again.
4. **PostgreSQL is the record; everything else can be rebuilt.** The search
   index is derived (`./ctl.sh reindex`). Redis holds queues and short-lived
   state.
5. **Every score explains itself.** Risk, priority and relevance are sums of
   named factors that are stored and shown.
6. **The application cannot widen its own reach.** Which clearnet hosts may be
   contacted is operator configuration outside the application.
7. **No infrastructure that is not needed.** One relational database, one
   search node, one queue. Relationships live in PostgreSQL, not a graph
   database; there is no vector store and no streaming platform.
8. **Changes are additive.** Schema migrations only add; they are idempotent
   and run on start.

## 2. System overview

```
 researcher ──> web (Next.js) ──> api (FastAPI) ──┬──> postgres   system of record
                                                  ├──> search     OpenSearch, derived index
                                                  └──> redis      queues, short-lived state
                                                         │
          beat ── schedules ──> pipeline  <── results ───┤
                                (parse, redact,          │
                                 extract, score,         ▼
                                 match, index)        crawler ──> tor ────> Tor network
                                    │                         └─> egress ─> allow-listed HTTPS
                                    │                 enricher ──────┘
                                    ▼
                                 notify ──> SMTP relay, alert destinations
```

| Layer | Technology |
|---|---|
| Console | Next.js 15, React 19, TypeScript 5, Tailwind CSS 3, SWR, d3-force, lucide-react |
| API | FastAPI 0.142, Pydantic 2, SQLAlchemy 2.0 (synchronous), psycopg 3, Uvicorn |
| Workers | Celery 5.6 on Redis, one image, five roles |
| Database | PostgreSQL 16, migrations with Alembic |
| Search | OpenSearch 2.19 (minimal distribution, no security plugin, internal network only) |
| Queue | Redis 7 |
| Tor | Tor on Alpine 3.20, client only |
| Fetching | httpx 0.28; HTML parsed with selectolax; feeds with feedparser |
| Security | argon2-cffi (passwords), PyJWT (sessions, HS256), cryptography/Fernet (secrets at rest), stdlib TOTP |
| AI (optional) | Anthropic Python SDK 1.11 |
| Runtime | Rootless Docker kept inside the project folder; Python 3.12; Node 22 |

All backend roles share one image, `kivuli-backend`. The role is chosen by the
`ROLE` variable and decides which task modules are loaded, so a role cannot run
another role's tasks even if asked to.

## 3. Containers, networks and volumes

### Containers

| Container | Role | Networks | Holds |
|---|---|---|---|
| `web` | Console and reverse proxy to the API. Publishes `127.0.0.1:28941` | app, public | nothing |
| `api` | HTTP API. Runs migrations and seeding on start | app, data, queue | database and index credentials, session key, both encryption keys |
| `pipeline` | Parses, redacts, extracts, scores, matches, indexes | data, queue | database and index credentials, evidence key |
| `crawler` | Fetches pages | crawl, crawlq | nothing but the queue password |
| `render` | Headless Chromium for sources marked "Render JavaScript" | crawl | nothing |
| `enricher` | Asks enrichment providers and the AI API | crawl, crawlq | provider keys (from `.env`), the key that decrypts console-entered provider keys |
| `notify` | Sends email and alerts to destinations | data, queue, mail, mail_out | database credentials, SMTP password, secrets key |
| `beat` | Fires scheduled tasks | queue | queue password |
| `tor` | SOCKS gateway to Tor | crawl, tor_out | Tor state |
| `egress` | Allow-listing HTTPS proxy | crawl, clear_out | the allow-list |
| `postgres` | Database | data | data |
| `search` | OpenSearch | data | index |
| `redis` | Queues | queue, crawlq | queue |
| `mailpit` | Test inbox. Publishes `127.0.0.1:28942` | mail, public | test mail |

Every backend container runs as an unprivileged user on a read-only root
filesystem with all capabilities dropped and `no-new-privileges`. The crawler
and enricher are limited to 1 GB of memory, the renderer to 1.5 GB.

### Networks

Ten networks; six are `internal` (no route out).

| Network | Internal | Joins |
|---|---|---|
| `app` | yes | web ↔ api |
| `data` | yes | api, pipeline, notify ↔ postgres, search |
| `queue` | yes | api, pipeline, notify, beat ↔ redis |
| `crawlq` | yes | crawler, enricher ↔ redis |
| `crawl` | yes | crawler, enricher, render ↔ tor, egress |
| `mail` | yes | notify ↔ mailpit |
| `public` | no | web, mailpit (published ports) |
| `tor_out` | no | tor → internet |
| `clear_out` | no | egress → internet |
| `mail_out` | no | notify → mail relay, alert destinations |

Consequences worth stating:

- The crawler and the enricher can reach only Redis, the Tor gateway and the
  egress proxy. They have no route to the database, the index, the API or the
  internet.
- The pipeline, which parses hostile content, has no route to the internet at
  all.
- Only `web` and `mailpit` publish ports, and only on 127.0.0.1.

**Known trust boundary.** The crawler and enricher share the Redis broker with
the other workers, because that is how they hand results over. A fully
compromised crawler could enqueue tasks for other roles. It still could not
read the database or reach the internet directly. For a hostile-network
deployment, give each its own Redis user restricted with ACLs.

### Volumes

`pgdata` (database), `searchdata` (index, rebuildable), `redisdata` (queues,
blocklist copy), `tordata` (Tor state), `evidence` (raw captures, only when
`EVIDENCE_STORE_RAW=true`).

## 4. Collection

### 4.1 Sources and connectors

A source is a row in `sources`: an address, a connector, a route, a status and
a schedule.

| Connector | Reads |
|---|---|
| `html` | A site, crawled page by page. The only connector that follows links |
| `rss` | An RSS or Atom feed |
| `ransomware_live` | The ransomware.live victim API |
| `ransomlook_recent` | RansomLook's recent posts API |
| `ransomlook_group` | A RansomLook group profile. Used only for discovery |
| `cisa_kev` | CISA's Known Exploited Vulnerabilities catalogue |
| `telegram_public` | The public web preview of a Telegram channel (`t.me/s/…`) |
| `ioc_feed` | A plain-text indicator list, one per line |
| `onion_blocklist` | Ahmia's list of banned onion services, as hashes (a safety control, not intelligence) |

Status: `candidate` (discovered, not collected), `approved` (collected on a
schedule), `paused` (not monitored), `blocked` (never contacted).

Route: `tor` (through the Tor gateway) or `direct` (through the egress proxy;
HTTPS only; the host must be on `EGRESS_ALLOW_HOSTS`). Onion sites always use
Tor. Research crawls always use Tor.

### 4.2 Scheduling

`pipeline.schedule_due` runs every minute and starts a crawl for each approved
source whose interval has elapsed. A failing source is retried progressively
less often: the interval is multiplied by 2 for each consecutive failure, up to
16 times.

`pipeline.liveness_sweep` runs every 30 minutes and re-checks discovered and
paused sources that have not been checked within `LIVENESS_INTERVAL_HOURS`.

### 4.3 The fetcher

`app/crawl/fetcher.py`. One function, one policy:

- **Address validation before anything is sent.** `http` or `https` only; a
  host name is required; no embedded credentials; no IP literals; no
  single-label or internal names; an onion host must be a valid v3 address.
- **GET only.** No request body, no cookies kept between requests.
- **Content types.** Only HTML, XHTML, plain text, JSON, XML and feeds. Anything
  else is refused when the response headers arrive, before the body is read:
  `refused: content type application/zip is not collected`.
- **Limits.** `CRAWL_MAX_BYTES` (2 MB by default; a source can raise it),
  `CRAWL_TIMEOUT_SECONDS` (75), at most `CRAWL_MAX_REDIRECTS` (3) redirect hops,
  each re-validated and each required to stay on the same site.
- **Politeness.** One request per host every `CRAWL_HOST_DELAY_SECONDS` (3),
  enforced across all crawler processes with a Redis key per host.
- **Retries.** Transient failures (common on Tor) get two more attempts, twenty
  and forty seconds later; a liveness check gets one.
- **Identity.** Through Tor the crawler sends Tor Browser's User-Agent so it
  does not stand out. To clearnet feeds and providers it identifies itself
  honestly.

Links are filtered before they are followed (`app/extract/safety.py`): never a
file (archives, documents, images, media, executables, dumps, style sheets,
scripts) and never anything that looks like an account action, a purchase or a
download (`login`, `register`, `captcha`, `download`, `cart`, `checkout`,
`payment`, `delete`, …).

A page that is a login form or an anti-bot wall is recorded as such
(`login required - not collected`, `CAPTCHA or anti-bot wall - not collected`)
and nothing is stored from it.

### 4.3a JavaScript rendering

`render/server.py` and `app/crawl/render.py`. Opt-in per source (`render_js`
in the source's config; *Render JavaScript* in the console). When it is on, the
crawler validates the URL with the fetcher's rules and asks the `render`
container for the page; liveness probes still use a plain fetch.

- **One browser per page.** Each request starts a new headless Chromium with a
  new profile in tmpfs, dumps the DOM after scripts ran (`--dump-dom` with a
  virtual-time budget), kills the process group and deletes the profile. At
  most `RENDER_CONCURRENCY` pages at once; `RENDER_TIMEOUT_SECONDS` each.
- **Every request through a proxy.** Onion sites and the Tor route use
  `socks5://tor:9050`; the direct route uses the egress proxy, so the
  allow-list applies to every sub-request a page's scripts make. Local name
  resolution is mapped to nothing, the loopback bypass is removed, and WebRTC is
  limited to proxied traffic. The container is only on the internal `crawl`
  network, so it has no route out even if the browser ignored all of that.
- **Nothing extra is loaded or kept.** No images, remote fonts, plugins,
  extensions, downloads, sync, crash reports or component updates.
- **The result is an ordinary fetch result** (`text/html`, recorded as HTTP 200,
  header `x-kivuli-rendered: javascript`), so parsing, link-following,
  extraction and versioning are unchanged.
- **Trade-off.** Chromium's own sandbox is off (`--no-sandbox`): it needs
  user-namespace privileges the hardened container does not grant. The
  container is the boundary instead: read-only root, all capabilities dropped,
  unprivileged user, no secrets, no database, queue or API access.

### 4.4 The Tor gateway

`tor/torrc`: client only (`ClientOnly 1`); `SafeSocks 1` so a request by raw IP
address is refused (no DNS leak); `IsolateDestAddr` so each destination gets
its own circuit; SOCKS accepted from private ranges only. `crawl.tor_check`
runs every five minutes, fetches the Tor Project's check service through the
gateway and publishes whether the exit really is Tor; the console shows that
result.

### 4.5 The egress proxy

`app/egress_proxy.py`: a small CONNECT-only proxy. It tunnels HTTPS to hosts on
`EGRESS_ALLOW_HOSTS` and refuses everything else. A leading dot in the list
allows subdomains. The list is read from the environment of the proxy's own
container, so nothing in the application can change it.

### 4.6 Discovery

New sources are found three ways. Each is filed with `status = candidate`.

1. **Victim trackers.** `pipeline.discover_sources` (nightly at 03:20 UTC, ten
   minutes after a first start with no onion sources, or on demand) takes the
   ransomware groups most recently named by either tracker, asks RansomLook
   where each publishes, and files the onion addresses it lists. Groups whose
   site is behind a CAPTCHA, and locations that are file servers, chat panels
   or admin panels, are skipped. Each group is looked up at most once a week.
2. **Links.** When a crawled page links to another onion service, that service
   is filed (`DISCOVER_ONION_LINKS`, at most `MAX_CANDIDATES_PER_CRAWL` per
   page) and the link is recorded in `source_links`.
3. **Research crawls.** The same link discovery, for whatever a researcher
   chooses to crawl.

A site on the abuse blocklist is not filed at all.

Every newly filed site is checked immediately: one request that keeps the
status code and the page's `<title>` and nothing else. From the title the site
gets a language and a **relevance** score (0 to 10, `app/extract/relevance.py`):
three points for each distinct security term (ransom, leak, breach, exploit,
stealer, dump, credential, …), one for each context term (forum, market, blog,
paste, …), minus four if it reads as something unrelated (casino, drugs,
weapons, …). The content guardrail is applied to the title; a prohibited title
blocks the site before it is ever crawled.

### 4.7 The collection policy

`app_settings["collection"]`, edited in the console. When a discovered onion
site answers its check, `apply_collection_policy` decides whether to approve it:

| `auto_approve` | Approved automatically |
|---|---|
| `manual` | nothing |
| `leak_sites` (default) | sites a victim tracker lists as a ransomware leak site |
| `relevant` | those, plus any site whose relevance is at or above `relevance_threshold` |

Never beyond `max_onion_sources` approved onion sources. The reason is written
to the source's notes. Changing the policy re-applies it to every waiting site.

### 4.8 Research crawls

`app/intel/crawls.py`. A researcher supplies a starting address, a depth and a
page limit; that is the authorisation for that site.

- The address is validated as in 4.3 and checked against the blocklist.
- The source for that host is found or created (`paused` unless *keep
  monitoring* was ticked).
- A `crawl_jobs` row is created with a fresh `run_id`.
- The crawl carries its own limits in each task (`max_depth`, `max_pages`),
  capped by `research_max_depth` and `research_max_pages`. A scheduled crawl
  uses the source's own limits instead.
- **Boundary.** Only links on the same host are followed. Links to other onion
  services become discovered sources.
- **Duplicate addresses.** A Redis set per run (`kivuli:run:<id>:seen`) holds
  every address queued; an address is queued once, and the set's size is the
  page budget.
- **Tree.** Each child task carries the address of the page that linked to it,
  stored in `crawl_log.parent_url`. The live view is built from `crawl_log`.
- **Completion.** A counter per run is incremented for every page queued and
  decremented when the pipeline has dealt with that page, whatever the outcome.
  At zero the job is marked done. A job with no activity for twelve minutes is
  closed when next read, so a crashed worker cannot leave one running forever.
- **Stop.** Sets a flag; no further pages are queued.
- At most twelve research crawls run at once.

### 4.9 The abuse blocklist

`app/crawl/blocklist.py`. Ahmia, the Tor search engine, publishes the MD5
hashes of onion domains it has banned for child sexual abuse material. A
built-in source fetches that list daily; the pipeline replaces a Redis set with
it atomically. Hashes only: the addresses are never stored.

It is enforced in three places, so no path around it exists:

1. a listed site is never filed as a discovered source;
2. a research crawl of a listed site is refused;
3. the crawler itself checks before every fetch and refuses, whoever asked. The
   source is then marked blocked.

A subdomain of a listed service counts as that service.

## 5. The processing pipeline

`pipeline.ingest_fetch` receives each fetched page. For every item on it
(`app/worker/ingest.py`), in order:

| # | Stage | What happens |
|---|---|---|
| 1 | Normalise | Defanged text is re-fanged (`hxxp`, `[.]`), whitespace normalised. Items with almost no text are dropped |
| 2 | Guardrail | Text advertising child sexual abuse material is dropped and the source is blocked. Reporting about arrests and takedowns is not mistaken for it |
| 3 | Redact | Passwords, keys, tokens and card numbers are masked; exposure records are produced (6.2) |
| 4 | Identify | `doc_key` (source or feed family + item key), content SHA-256, 64-bit SimHash |
| 5 | Unchanged? | Same content hash as the stored version: only `last_seen` moves |
| 6 | Indicators | Domains, onion addresses, URLs, IPs, emails, hashes, CVEs, wallets, usernames, each with the text around it (6.1) |
| 7 | Countries | From names, demonyms, cities and country-code domains |
| 8 | Classify | Threat type, secondary types and a confidence (6.4) |
| 9 | Techniques | ATT&CK technique identifiers (6.5) |
| 10 | Entities | Actor and victim asserted by the source; known entities recognised in the text; organisations proposed by pattern (6.3) |
| 11 | Language | ISO code from scripts and common words (6.6) |
| 12 | Duplicate? | Exact content hash, then SimHash within 4 bits, against originals (8.2) |
| 13 | Version | A new `document_versions` row with the hash chain and signature (8.3) |
| 14 | Corroboration | Other independent sources reporting the same incident raise the verification state (7.5) |
| 15 | Risk | Score, severity and factors (7.1) |
| 16 | Exposure records | One row per exposed account or secret (12.1) |
| 17 | Relationships | "actor targets victim", "actor uses technique" (13.1) |
| 18 | Watchlists | Each active entry is matched; alerts are raised (10.1) |
| 19 | Index | The finding is written to OpenSearch; if it is a copy, the original is re-indexed so its "seen at" count is right |

Then, for the page as a whole: links are queued (within the depth and page
limits), other onion sites are filed, source-to-source links are recorded, and
the crawl log entry is completed with what was new, changed and unchanged.

Feeds use the same stages with structured input: a tracker row names its actor
and victim directly, a KEV row becomes a vulnerability, an indicator feed
updates `iocs.feeds`.

## 6. Extraction

### 6.1 Indicators (`app/extract/iocs.py`)

| Type | Notes |
|---|---|
| `domain` | Validated against the public suffix list. File names that look like domains (`report.zip`), and two-letter words that are also country codes, are rejected |
| `onion` | v3 addresses only (56 characters) |
| `url` | `http` and `https` |
| `ip` | Public addresses only; private, reserved and loopback are discarded |
| `email` | |
| `hash` | MD5, SHA-1, SHA-256 |
| `cve` | Normalised to `CVE-YYYY-NNNN` |
| `crypto` | Bitcoin (checksum verified), Ethereum, Monero |
| `username` | Telegram handles (`t.me/…`), `@handles`, and labelled handles ("Telegram: …", "contact: …") |

At most 400 of each type per page (a combo list can hold a hundred thousand
addresses); the finding records which types were truncated. Each indicator
keeps the text around it. Indicators are **recorded, never resolved or
contacted**.

### 6.2 Redaction (`app/extract/redact.py`)

Applied before storage when `REDACT_SECRETS=true` (the default).

| Pattern | Becomes | Exposure record |
|---|---|---|
| `email:password` (also `;` and `\|`) | `email:[REDACTED]` | credential: the mailbox and its domain, "password exposed" |
| Stealer-log triple (`URL:` / `Username:` / `Password:`) | password masked | stealer_log: the user, the service host |
| Labelled secrets (`password = …`, `api_key: …`, `token: …`) | value masked | api_key or token |
| Vendor tokens: AWS access key, GitHub (classic and fine-grained), GitLab, Slack, Google API key, Stripe live key, SendGrid, Azure storage key, JWT | masked | cloud_secret or token, with the vendor type and a fingerprint |
| PEM private keys | masked | private_key |
| Card numbers (Luhn-valid) | masked | card |

A **fingerprint** is the first 16 hexadecimal characters of the secret's
SHA-256: enough to recognise the same secret in another leak, useless for
recovering it. Passwords get no fingerprint. The SHA-256 of the original,
unredacted capture is kept as evidence. At most 2,000 records per page.

### 6.3 Entities (`app/extract/entities.py`)

Known entities (actors, malware, campaigns, organisations, with their aliases)
are matched in text by token. A name that could be an ordinary word ("Carbon",
"Turla") matches only next to context words such as "group", "ransomware",
"malware", "backdoor". Names imported from ATT&CK are subject to that rule;
names with a distinctive shape ("APT28", "TrickBot") are not.

Organisations are also proposed from capitalised names with a company suffix
("… Ltd", "… Bank", "… University") or a prefix ("Ministry of …"). This is
conservative on purpose.

Tracker rows state their actor and victim outright; those are attached with
high confidence and an *incident* entity ("Actor / Victim") joins them.

### 6.4 Classification (`app/extract/classify.py`)

Rule-based. Each threat type has weighted patterns. A pattern contributes its
weight when it matches the text (a little more for a second and third match)
and again when it matches the title. The highest score wins if it reaches 4;
otherwise the type is `other`. Confidence is `35 + 2.5 × score + 2 × margin`
over the runner-up, kept between 30 and 92. Types scoring at least half the
winner's score are kept as secondary types.

A type asserted by a structured source (a ransomware tracker row), or implied
by the source's category (a leak site, a vulnerability feed), wins outright
with confidence 90: the source already did the classification.

### 6.5 ATT&CK techniques (`app/intel/attack.py`)

The MITRE ATT&CK Enterprise catalogue (v19.2: 697 techniques, 176 groups, 825
software entries, 15 tactics) ships as a 462 KB derivative,
`app/data/attack.json`, built by `tools/build_attack_catalog.py`. A finding is
tagged when it names a technique identifier that exists in the catalogue
(confidence 95) or matches one of about 35 behaviour patterns ("deleted
backups" → T1490, "stolen credentials … VPN" → T1078). Precision over coverage.

### 6.6 Language (`app/extract/lang.py`)

A heuristic, no model. Scripts are recognised by their characters (Cyrillic →
`ru`, Han → `zh`, Arabic → `ar` or `fa`, and so on); Latin-script languages by
their most common function words (English, Spanish, French, German,
Portuguese, Italian, Dutch, Turkish, Swahili, Indonesian, Polish). Short or
mixed text returns nothing. It cannot tell Belarusian from Russian or Catalan
from Spanish.

### 6.7 Investigation tools (`app/tools/`, `app/api/tools.py`)

Analyst-pasted text, processed in the API container with no network access
used. Inputs are capped (256 KB of headers, 512 KB of payload) and the
content is never stored; the audit log records the tool and the input size.

- **`headers.analyse`** parses the header block with the standard library
  parser (`headersonly`), reverses the `Received` chain into delivery order,
  takes the first globally routable address as the origin, reads SPF, DKIM and
  DMARC from `Authentication-Results` (then `ARC-Authentication-Results`, then
  `Received-SPF`), and compares registered domains of From, Return-Path,
  Reply-To, Sender, DKIM `d=` and Message-ID.
- **`decoder.decode`** applies at most 12 steps; each step is the first of
  an ordered list of transformations that yields readable text (UTF-16LE or
  UTF-8, or Latin-1 only when it is mostly ASCII). Decompression uses
  `zlib.decompressobj` with a 2 MB output cap, so a compression bomb stops at
  the cap. Hex is only accepted when it contains the digits 2-7, the high
  nibble of printable ASCII. A layer equal to an earlier one ends the loop.
  Behaviours are regular expressions over every layer.
- **Verdict** (`GET /tools/verdict`) reads the `iocs`, `document_iocs`,
  `watchlists`, `enrichments` and `chain_addresses` rows for the detected type
  and value; `POST /tools/verdict` queues `enrich.subject` for IPs, domains,
  URLs and hashes. Precedence: benign mark, then feeds or a malicious provider
  answer, then a suspicious answer, then appearances in findings (*seen*), then
  clean answers. Which providers are switched on comes from the status the
  enricher publishes, since only it holds the keys.

## 7. Scoring

### 7.1 Finding risk (`app/extract/risk.py`)

A sum of named factors, then scaled by classification confidence, clamped to
0-100. Stored with the finding and shown in full.

| Factor | Points |
|---|---|
| Threat type | ransomware 55, access sale 55, credential leak 50, data breach 50, malware / phishing / defacement / fraud 35, DDoS / vulnerability / hacktivism 30, other 10 |
| Source reliability | (trust − 50) ÷ 5, so −10 to +10 |
| Seen on a Tor hidden service | +5 |
| Exposed credentials | +10, or +15 for 100 pairs or more |
| Exposed keys or secrets | +10 |
| Payment card data | +8 |
| Indicator density | up to +8 (one point per five indicators) |
| Attributed to a tracked actor | +6 |
| Names a victim organisation | +6 |
| Concerns a focus country | +8 |
| Concerns a focus sector | +5 |
| References a known-exploited vulnerability | +5 |
| Matches a watchlist | +15 |
| Asset criticality (when not 3) | (criticality − 3) × 5 |
| Corroborated by other sources | 3 + 2 per source, up to +8 |
| An indicator is listed by a threat feed | +6 |
| Several attack techniques described (3 or more) | +3 |
| Reported in the last 7 days | +6 |
| More than six months old / more than a year old | −15 / −25 |

**Confidence scaling.** The sum is multiplied by `0.6 + 0.4 × confidence`, so a
low-confidence classification cannot produce a high score on its own. The
difference is shown as its own line.

**Severity** follows the score: 80 and above critical, 60 high, 40 medium, 20
low, otherwise info.

### 7.2 Alert priority (`app/intel/priority.py`)

How urgently an alert deserves attention. It starts from the finding's risk and
adds what the watchlist knows that the finding does not.

| Factor | Points |
|---|---|
| Risk of the underlying finding | risk × 0.55 |
| A monitored asset in a leak, extortion post or dump | +14 |
| Directly concerns your own exposure (attack surface, vulnerability) | +12 |
| Domain imitating your brand | +10 |
| A password was exposed with the account | +12 |
| Asset criticality | (criticality − 3) × 6 |
| Confirmed by an analyst / corroborated | +8 / 4 + 2 per source up to +8 |
| Single unverified source | −8 |
| Low classification confidence (under 50%) | −6 |
| Reported in the last 48 hours | +8 |
| More than a month old / more than six months old | −8 / −20 |
| A rule marks it critical while the finding's risk is under 60 | +20 |

### 7.3 Vulnerability priority

| Factor | Points |
|---|---|
| Present on your internet-facing hosts | 25 + 2 per host, up to 35 |
| Known to be exploited (CISA KEV) | +30 |
| Used in ransomware campaigns | +10 |
| EPSS ≥ 50% / ≥ 10% / ≥ 1% | +18 / +10 / +4 |
| Affects a technology you said you use | +15 |
| Mentioned in collected findings | 3 + 1.5 per finding, up to 12 |
| CVSS ≥ 9 / ≥ 7 / ≥ 4 | +10 / +6 / +2 |
| Added to the exploited list in the last 30 days | +6 |

A theoretical CVSS 9.8 with no exploitation ranks far below a CVSS 7.5 that is
being exploited and is present on an owned host.

### 7.4 Asset risk

For a host on the attack surface: software with actively exploited
vulnerabilities (40 + 5 each, up to 55), other known vulnerabilities (6 + 2
each, up to 20), sensitive services exposed (FTP, Telnet, SMB, RDP, databases,
Docker API, …: 14 + 6 each, up to 30), its address on a threat feed (+30),
flagged as compromised by the scan-data provider (+30), more than twelve open
ports (+6). When any of those applies, criticality adds (criticality − 3) × 5.
A host with nothing reported scores 0 whatever its criticality.

### 7.5 Verification and the Admiralty code (`app/intel/quality.py`)

| State | Set when |
|---|---|
| `unverified` | One source with trust under 60 |
| `reported` | One source with trust of 60 or more |
| `corroborated` | At least one other *independent* source reports the same incident. Two feeds of the same tracker count as one source |
| `confirmed` | An analyst pressed Confirm. Only an analyst sets or clears it |

**Reliability** (the letter) is the operator's explicit grade for the source,
or derived from its trust: 90+ A, 75+ B, 60+ C, 40+ D, 20+ E, else F.
**Credibility** (the digit) follows the verification state: confirmed 1,
corroborated 2, reported 3, unverified 6.

### 7.6 Search relevance

See 9.3.

## 8. History, de-duplication and evidence

### 8.1 Versions

A finding is identified by `doc_key`. Each time its content hash changes, a new
immutable `document_versions` row is written with the full text and a summary
of the change (lines added and removed, similarity, indicators that appeared or
disappeared). The finding row always reflects the latest version. Any two
versions can be compared line by line.

**Observations.** `crawl_log` records every fetch of every address. The History
tab groups the fetches of a finding's address by day and derives a status:

| Status | Rule |
|---|---|
| `online` | Seen on the most recent crawl |
| `removed` | The last fetch of that address answered 404 or 410 |
| `missing` | The site has been crawled since, and the page was no longer reachable from it (not seen for three crawl intervals, minimum twelve hours) |
| `source_offline` | The whole site is not answering |
| `unreachable` | The last fetch failed for another reason |
| `feed` | It came from a feed, which is read as a list, not re-fetched as a page |

Nothing is deleted when a page disappears.

### 8.2 De-duplication

Three layers:

1. **Address.** Within one crawl, an address is fetched once.
2. **Identity.** The same item from the same source or feed family is the same
   finding (`doc_key`), however often it is seen.
3. **Content.** A new finding whose content hash equals an existing original is
   its duplicate. Failing that, for texts of 400 characters or more, a 64-bit
   SimHash within 4 bits of an existing original marks it a near-duplicate.
   Candidates are found without scanning: the hash is split into four 16-bit
   bands, each indexed, and two hashes within 4 bits must share a band.

A duplicate is stored (it is evidence that the content appeared elsewhere),
excluded from search unless asked for, and does not alert if the original
already alerted for that watchlist. The original's `seen_at` count rises.

### 8.3 Evidence chain

For each capture:

```
chain_hash = SHA-256( prev_chain_hash | document_id | version | url |
                      captured_at | raw_sha256 | content_sha256 )
signature  = HMAC-SHA-256( EVIDENCE_HMAC_KEY, chain_hash )
```

`raw_sha256` is the hash of the original response body, before redaction;
`content_sha256` of the stored text. Editing or removing any stored version
breaks every later link, and the key is not in the database, so tampering is
detectable. The Evidence tab recomputes the chain on request.

**Preserving evidence** adds a `case_items` row of type `evidence` whose
reference is `<finding id>:<version>`, with the researcher and the time. It
points at an immutable version, so what was preserved cannot drift.

## 9. Search

### 9.1 The index

One OpenSearch index, `kivuli-findings`, one document per finding, rebuilt from
PostgreSQL at any time. Fields, in groups:

- **Text**: `title`, `content` (analysed with stemming and synonyms) and
  `title.exact`, `content.exact` (no stemming) for phrases and typo correction.
- **Names**: `actors`, `organizations`, `malware`, `campaigns`, each as an exact
  keyword, a lower-cased keyword and searchable text.
- **Indicators**: one keyword field per type (`ioc_domain`, `ioc_email`,
  `ioc_ip` as an IP type for CIDR queries, …), `ioc_all` for "paste anything"
  and wildcards, and `domain_suffixes` / `email_domains`, which hold every
  parent domain so a search for `example.co.ke` finds `mail.example.co.ke` and
  every mailbox under it.
- **Facets and filters**: threat types, severity, countries, sectors, network,
  source name / category / id / trust, host, language, tags, status,
  techniques, tactics, verification, Admiralty grade.
- **Numbers and dates**: risk, confidence, corroboration, `seen_at`, version
  count, indicator and credential counts; event date, first seen, last seen,
  last changed.

The full text of `content` and the indicator lists are excluded from what a
search returns; results carry highlights instead.

### 9.2 The query language (`app/search/query.py`)

A hand-written parser, not OpenSearch's query-string syntax, so that a pasted
indicator or a country name means what the researcher expects. It tokenises on
whitespace (respecting quotes), then for each token, in this order:

1. `NOT` / `!` negates the next token; a leading `-` negates its own.
2. `field:value` with a known field becomes a field clause; an unknown prefix
   (`https://…`, `12:30`) is treated as text.
3. A quoted string is an exact phrase.
4. `OR` / `|` joins the previous clause and the next into a group; `AND` is
   accepted and is the default.
5. Stop words are dropped.
6. One to three consecutive words that name a country become a country clause:
   tagged with that country, or mentioning it.
7. `/…/` is a regular expression over words in the title, the content and the
   indicators. Lucene matches a pattern against a whole term, so it cannot span
   spaces. Patterns over 120 characters, or that do not compile, are refused.
8. A token with `*` or `?` is a wildcard over indicators and hosts; a trailing
   `*` also does a prefix match on text.
9. A token that looks like an indicator (domain, email, IP or CIDR, hash, CVE,
   wallet, URL, onion address; defanged forms accepted) becomes an exact
   indicator clause. A domain also matches its subdomains and mailboxes.
10. A word that names a threat type ("ransomware", "phishing", "leak") matches
    as text or as that classification.
11. A broad word ("cyber", "attack", "hack", "threat", "security", "darkweb",
    "news", "latest", …) only improves ranking; it is not required unless
    *Require every term* is on.
12. Anything else is a text term: stemmed, typo-tolerant, across title,
    content and names.

The result is an OpenSearch `bool` query: required clauses in `must`, exact
filters in `filter` (they do not affect ranking), exclusions in `must_not`,
ranking-only clauses in `should`. Each line of *Understood as* corresponds to
one clause; every scoring clause is named after its line (`q0`, `q1`, …).

`similar:<id>` becomes a `more_like_this` query on title and content, excluding
the finding itself.

### 9.3 Ranking and "why matched"

When sorted by relevance, the text score is multiplied by a sum of small
functions, so none can outvote a good match:

```
score = text_score × ( 1
                     + 0.006 × risk
                     + 0.6 × recency          (Gaussian, half-weight at 45 days, flat for 3)
                     + 0.003 × source_trust
                     + 0.08 × ln(1 + corroboration)
                     + 0.06 × ln(1 + seen_at)
                     + 0.04 × ln(1 + version_count) )
```

A country clause scores a constant, so a finding tagged with the country ranks
the same whether or not its text spells the name out, and risk and recency
decide the order.

**Relevance** shown to the researcher is the score as a percentage of the best
score in that search.

**Why matched** is built per result from OpenSearch's `matched_queries` (the
named clauses, mapped back to their *Understood as* line), plus "match in the
title" when the title was highlighted, plus the ranking signals that applied
(corroborated, seen at several sources, risk of 70 or more, source trust of 80
or more).

### 9.4 What else a search returns

Facets for every filter; a timeline (auto-sized histogram); the count with
credentials; a spelling suggestion when a term finds fewer than three results;
and `sources`, the sources carrying the results, from an aggregation on
`source_id`. The console separately asks `/sources/suggest` for known sites not
being collected whose name, title or discovery context matches the query.

### 9.5 Highlights are not HTML

OpenSearch marks matches with private sentinel characters. The API splits each
fragment into parts, `{t: text, h: highlighted}`, and the console renders them
as text nodes. Crawled content therefore cannot inject markup through a
highlight.

## 10. Alerting

### 10.1 Watchlist matching (`app/worker/matching.py`)

Each new or changed finding is matched against every active entry.

| Kind | Match |
|---|---|
| keyword | Whole-word match in title or text |
| domain | The domain, a subdomain, or a mailbox under it, among the indicators. For an owned domain, also look-alikes |
| email, ip (address or CIDR), cve, hash, crypto, username | Among the indicators |
| organization, vendor | A recognised organisation, or the name in text |
| actor | A recognised actor |
| brand | The name in text, or a look-alike domain |
| technology | The name in text, in a finding classified as a vulnerability or naming a CVE |
| executive | The full name in text |

**Look-alikes** (`app/intel/lookalike.py`): the same name under a different
top-level domain; the name after look-alike characters are normalised (`0`→`o`,
`rn`→`m`, `1`→`l`, …); within two edits of the name; the name joined to a
luring word (`-login`, `secure-`, `-verify`, …); the name with words attached.
Subdomains of the real domain are not look-alikes.

The category follows from what matched and where: `compromise` when an owned
asset appears in a leak, extortion post or credential dump; `lookalike`;
`vulnerability`; otherwise `mention`.

An entry's minimum severity is applied. A duplicate finding does not alert if
its original already alerted for that entry.

### 10.2 Detection rules

`pipeline.evaluate_rules` runs every five minutes.

| Kind | Fires |
|---|---|
| `query` | Once for each finding matching the search, collected since the rule last ran. Never for history: creating a rule does not flood the queue |
| `threshold` | Once per window, when matches in the window reach the threshold |
| `spike` | Once per window, when matches reach the rule's number (at least three) and are at least three times the average of the seven windows before |

Rule alerts on volume have no single finding behind them. Every alert has a
`dedupe_key` with a unique index, so the same event cannot alert twice.

### 10.3 Email

`notify.dispatch_alerts` runs every minute: unsent alerts whose owner (the
watchlist or the rule) asks for immediate email are grouped by recipient and
sent, at most `EMAIL_MAX_ALERTS_PER_MESSAGE` per message. `notify.send_digest`
does the same daily for owners set to digest. Indicators in the message are
defanged; the snippet is the redacted text. If the relay rejects a message,
sending pauses for ten minutes and the alerts stay queued. Every message is
logged in `email_log`.

### 10.4 Alert destinations (`app/notify/integrations.py`)

`notify.dispatch_integrations` runs every minute. Each active destination
receives each open alert created after the destination was, once, if the
alert's severity and category pass its filters.

| Kind | Request |
|---|---|
| `webhook` | JSON `{event, alert}`; with a secret, the header `X-Kivuli-Signature: sha256=<HMAC-SHA-256 of the body>` |
| `slack` | Block Kit message to an incoming-webhook address |
| `teams` | Adaptive Card to a workflow webhook address |
| `splunk_hec` | Event to `/services/collector/event`, `Authorization: Splunk <token>` |
| `jira` | Issue via `/rest/api/2/issue`, basic authentication |
| `servicenow` | Incident via the Table API, basic authentication |

**Destination guard.** Before every send the address is resolved and refused if
it is not HTTPS, carries embedded credentials, or points at a private,
loopback, link-local or reserved address (`INTEGRATIONS_ALLOW_PRIVATE=true`
lifts that for an internal SIEM). Redirects are not followed. Tokens and
chat-webhook addresses are stored encrypted with `SECRETS_KEY`. After ten
consecutive failures a destination is paused.

## 11. Enrichment and the AI analyst

### 11.1 The enricher

A worker role of its own, on the same isolated networks as the crawler. It is
the only container that can read provider keys; it has no database access and
never parses crawled content. Results go back to the pipeline over the queue.

Enrichment asks a provider **about** an indicator or an owned asset. The
indicator itself is never contacted.

| Provider | Key | Used for |
|---|---|---|
| Shodan InternetDB | none | Open ports, software, known vulnerabilities of an address |
| RIPEstat | none | Announcing network and holder |
| Public DNS (Google DoH) | none | A, MX, NS records |
| Certificate transparency (Cert Spotter, falling back to crt.sh) | none | Host names of a domain |
| FIRST EPSS | none | Exploit likelihood of CVEs |
| NVD | optional | CVSS severity and descriptions |
| VirusTotal | required | Reputation of files, URLs, domains, addresses |
| Shodan | required | Full host record |
| AbuseIPDB | required | Abuse reports for an address |
| GreyNoise | required | Internet background noise, known-benign services |

A provider's answer of 401 or 403 is raised as "rejected the API key" and 429
as "quota used up", so neither is ever mistaken for "no data".

### 11.2 Provider keys set in the console

`app/intel/provider_store.py`, `app/enrich/keys.py`.

- The API encrypts a key with `PROVIDER_KEYS_KEY` (Fernet) and stores it in
  `provider_keys`. Only its last four characters are kept readable.
- The same ciphertext is mirrored to a Redis hash. The mirror is rewritten on
  every change, on API start and every five minutes, so losing Redis loses
  nothing.
- The enricher, which cannot reach the database, reads the mirror and decrypts
  with the same key. It caches for twenty seconds.
- A key set in the console takes precedence over one in `.env`.
- `PROVIDER_KEYS_KEY` is separate from `SECRETS_KEY`, so the enricher never
  holds the key that protects two-step sign-in seeds and alert-destination
  credentials.

### 11.3 Connection tests

`enrich.test_provider` makes one real, minimal request about a harmless
subject (8.8.8.8, example.com, CVE-2021-44228) and reports in words an operator
can act on: working; key rejected; quota used up; blocked by the egress
allow-list (naming the host to add); unreachable.

Each provider is tested on the call that actually validates its key. GreyNoise
is tested on `/ping`, because its lookup endpoint answers with or without a
valid key. Shodan is tested on `/api-info`, which also returns the plan and the
credits left.

The console starts a test, polls its job in Redis, and the last result is
stored so it survives a reload.

### 11.4 The AI analyst (`app/ai/analyst.py`)

Optional; off without an Anthropic key. Rules it is built on:

- **Grounded.** The model sees only findings the platform retrieved for the
  request, already redacted, as numbered, delimited blocks.
- **No tools.** It cannot browse, fetch, search or act.
- **Untrusted input.** Collected content is hostile. The system prompt says to
  treat everything inside the sources as data, never as instructions.
- **Cited.** Every answer must cite `[S1]`, `[S2]`. Citations that do not
  correspond to a supplied source are dropped before the answer is returned.
- **Structured.** Each request asks for JSON matching a schema.
- **Honest about gaps.** An answer includes a confidence and what the sources
  do not cover.

The API never calls the model. "Ask" is three queued steps: the enricher
translates the question into a search (`ai.ask`); the pipeline, which has the
data, retrieves the best matches (`pipeline.ai_retrieve`); the enricher answers
from them (`ai.answer`). Summaries and briefs are one step. The console polls
the job.

The connection test looks the model up (free), then sends one tiny structured
request through the same code path the analyst uses, so "working" means the
feature works.

Without a key, "Ask" falls back to the query interpreter and nothing leaves the
platform.

## 12. Exposure intelligence

### 12.1 Identity exposure

One `exposures` row per account or secret per finding: kind, identity,
mailbox domain, service host, secret type, fingerprint, whether a password was
exposed, and a remediation status (`open`, `remediated`, `ignored`,
`false_positive`). "Yours" means the mailbox domain or service host falls under
a domain you watch.

### 12.2 Attack surface (passive)

Only for watchlist entries marked as owned, of kind domain or IP.

1. `enrich.asm_discover`: host names of the domain from certificate
   transparency.
2. `enrich.asm_host`, per host: resolve over public DNS; for up to three
   addresses, ask InternetDB for open ports, software and known
   vulnerabilities; ask RIPEstat for the network.
3. The pipeline stores the host in `assets`, scores it (7.4) and raises
   alerts for an actively exploited vulnerability, a sensitive service exposed,
   or an address listed by a threat feed.

Re-run every `ASM_INTERVAL_DAYS`, at most `ASM_MAX_HOSTS` hosts per domain.
**Nothing is scanned or probed**: every fact comes from a public dataset.
Vulnerabilities come from banner matching in that data and are unverified.

### 12.3 Vulnerabilities

- The KEV connector upserts the exploited-vulnerability catalogue.
- `pipeline.refresh_vulnerabilities` (hourly, after each KEV sync, and shortly
  after start) counts mentions in collected findings, counts owned hosts
  reported with each CVE, re-scores (7.3), and queues up to 800 CVEs for EPSS
  and the top eight for NVD severity, most relevant first.

## 13. Intelligence graph, STIX and TAXII

### 13.1 Relationships

`relationships`: source entity, target entity, kind (`uses`, `targets`,
`attributed_to`, `exploits`, `delivers`, `related_to`), confidence, where the
statement came from, first and last seen. Sources of statements: the ATT&CK
catalogue (groups use techniques and software; confidence 85), collected
reporting (a tracker row says an actor targets a victim, 80; a finding
attributed to an actor describes a technique, 55), analysts, and STIX imports
(70).

The graph view combines these with co-occurrence: two things are linked when
they appear in the same findings, weighted by how many. Indicators marked
benign are left out.

### 13.2 Entity resolution

Names are resolved against existing entities and their aliases by slug. The
ATT&CK catalogue is loaded once per catalogue version as the reference set.
Analysts can merge two records: findings and relationships move to the kept
record, the dropped name becomes an alias, affected findings are re-indexed.

### 13.3 STIX 2.1 (`app/intel/stix.py`)

Export: an investigation becomes a bundle with a report, indicators (with STIX
patterns), vulnerabilities, threat actors, malware, attack patterns and
relationships. Identifiers are deterministic (UUIDv5), so re-exporting the same
thing yields the same identifiers.

Import: actors, malware, campaigns, techniques, indicators and relationships
are merged into what is known. The bundle itself becomes a finding, so its
origin is traceable. ATT&CK techniques are matched to the bundled catalogue by
identifier; unknown ones are skipped, not invented. Up to 10 MB.

### 13.4 TAXII 2.1 (`app/api/taxii.py`)

Read-only. Three collections: indicators, high-risk indicators, and actors /
malware / techniques. Paged with `added_after`, `limit` and `next` as in the
specification. Authenticated with an API key as a bearer token, or as the
password of HTTP Basic with any user name. Every path answers with and without
its trailing slash.

## 13a. Blockchain tracing

`app/chain/`, with the enricher doing the fetching. An address is recognised and
normalised (`addresses.py`: shape plus a base58check or EIP-55 check), then the
enricher reads a public explorer through the egress proxy — Blockstream for
Bitcoin, BlockCypher for Ethereum, TronGrid for TRON/USDT — none needing a key.
Each explorer's response is reduced to one shape (`providers.py`): balance,
totals, first and last activity, and counterparties as aggregated flows, with
Bitcoin's co-spent inputs recorded for clustering. The enricher hands the result
to `pipeline.store_chain`, which labels the address (`labels.py`: a small
verified list of OFAC and exchange addresses, then whether it appears in a
collected finding, then a shape heuristic), and stores it in `chain_addresses`
with the flows in `chain_edges`. The graph an analyst sees is the address, its
direct counterparties and the edges among them; expanding a node looks its
counterparties up, which fills the graph in. Everything is read-only public
chain data; no key is held, nothing is signed or broadcast. Monero and other
chains are recognised but have no on-chain lookup.

## 14. Access control

| Control | Implementation |
|---|---|
| Passwords | Argon2id. Twelve characters minimum, mixed case and a digit |
| Sessions | Signed JWT (HS256) in an `httpOnly`, `SameSite=Strict` cookie, valid `SESSION_TTL_MINUTES` |
| CSRF | Every state-changing request must carry `X-Kivuli-CSRF: 1`, which a cross-site form cannot set |
| Rate limits | Per client address: `RATE_LIMIT_PER_MINUTE` overall, `LOGIN_RATE_LIMIT_PER_MINUTE` for sign-in |
| Lockout | Five failed sign-ins lock the account for fifteen minutes. A wrong second factor counts |
| Two-step sign-in | TOTP (RFC 6238, 30-second steps, one step of tolerance). Ten single-use recovery codes, stored hashed. The seed is encrypted. An admin can reset it for a user |
| Roles | viewer ⊂ analyst ⊂ admin, enforced per endpoint |
| API keys | `kv_…`, shown once, stored as SHA-256. Act as their owner. Scope read, or read and write. Optional expiry. Cannot create keys |
| Key or cookie, never both | A request with an `Authorization` header is authenticated by that key alone; the cookie is ignored and the CSRF header is not required |
| Audit log | Sign-ins, failures, exports, evidence views, crawls, and every change, with who, when and from where |
| Secrets at rest | Fernet with keys from the environment, never the database |

Each container receives only the environment variables its role needs.

## 15. The console

Next.js App Router, client-rendered pages over the API through a same-origin
rewrite (`/api/*` → the API container), so the browser never needs a second
origin.

Safety properties:

- Captured text is always rendered as text. No collected value is ever passed
  to `dangerouslySetInnerHTML`.
- Indicators are defanged for display and are never links to themselves.
- Search highlights arrive as structured parts (9.5).
- A strict Content-Security-Policy: scripts, styles, fonts and connections from
  the same origin only; no framing.
- The console never talks to Tor, to a provider or to a collected site. It
  asks the API, which asks the workers.

Colour is by role (page, surface, ink, accent, status) with light and dark
values. Status is always an icon and a word, never colour alone.

## 16. Configuration

Three places, by who may change what:

| Where | What | Who |
|---|---|---|
| `.env` | Secrets, addresses, limits, the egress allow-list | The operator of the machine |
| `app_settings` table | Collection policy and research-crawl limits | Console administrators |
| `provider_keys` table | Provider API keys and the AI model | Console administrators |

`./ctl.sh` creates `.env` on first start with generated secrets, and on every
start adds any setting introduced by a newer release (it prints which). It
never changes a value you set.

The egress allow-list is deliberately not in the console: a compromise of the
console must not be able to open a route out.

Every setting is listed in [REFERENCE.md](REFERENCE.md#configuration).

## 17. Operations

### 17.1 Commands

```
./ctl.sh start | stop | restart | status
./ctl.sh logs [service]        follow logs (api, crawler, pipeline, enricher, notify, web, tor, egress, …)
./ctl.sh build [image]         rebuild and redeploy (backend, web, tor, search)
./ctl.sh crawl                 crawl every active source now
./ctl.sh reindex               rebuild the search index from PostgreSQL
./ctl.sh upgrade-intel         re-derive techniques, language, verification and exposure for older findings
./ctl.sh backup [dir]          database dump, evidence and .env into a dated folder
./ctl.sh restore <folder>      restore a backup (asks first), then reindex
./ctl.sh test                  backend test suite
./ctl.sh lock                  re-pin backend dependencies after editing requirements.txt
./ctl.sh manage <command>      e.g. create-user analyst@example.com analyst
./ctl.sh docker <args>         the bundled Docker, for anything else
./ctl.sh destroy               remove everything, including collected data
```

### 17.2 Runtime

Docker runs rootless from inside the project folder (`.runtime/`), started as a
transient user service. Nothing is installed system-wide and no sudo is needed.
The bundled Docker has no buildx, so images are built with plain `docker build`
rather than `docker compose build`.

**Code is baked into the images**, and containers have read-only root
filesystems. A change to backend or console code needs
`./ctl.sh build backend` or `./ctl.sh build web`.

### 17.3 Dependencies

Pinned to exact versions (`backend/requirements.lock`,
`frontend/package-lock.json`). `tools/fetch_deps.py` downloads them over many
parallel connections and verifies each against its published checksum (PyPI
SHA-256, npm SHA-512); the image builds install from that offline. This exists
because some networks throttle single connections to package CDNs.

### 17.4 Start-up sequence

The API container, on start: takes a database advisory lock, runs migrations,
ensures the search index and extends its mapping, seeds built-in sources and
the ATT&CK catalogue, publishes provider keys to Redis, and queues
vulnerability ranking and (with no onion source on file) discovery.

### 17.5 Upgrading

`./ctl.sh backup`, then `./ctl.sh build`. Migrations run in place. Run
`./ctl.sh upgrade-intel` when a release adds derived fields, and
`./ctl.sh reindex` when it adds index fields.

### 17.6 Backup and restore

A backup is a custom-format `pg_dump`, a tarball of the evidence volume and a
copy of `.env`, in a folder only you can read. It contains every secret; keep
it encrypted. `EVIDENCE_HMAC_KEY`, `SECRETS_KEY` and `PROVIDER_KEYS_KEY` are
needed to verify evidence and read stored credentials.

### 17.7 Scaling

Every role is stateless apart from the three data stores. Crawler, pipeline,
enricher and notify scale by replica count (`CRAWLER_CONCURRENCY` and
`PIPELINE_CONCURRENCY` set processes per container). The per-host delay is
enforced in Redis, so more crawlers do not hit one site harder. The compose
services map one-to-one onto Kubernetes Deployments, with the networks becoming
NetworkPolicies.

### 17.8 Observability

- Console: *Collection & crawls* and *System > Health*.
- `GET /api/metrics`: Prometheus text. Gauges: findings by severity and by
  verification, alerts and open alerts, sources and failing sources, open
  exposures, assets, vulnerabilities on owned hosts, fetches in 24 hours, queue
  depth, Tor state, email back-off. Scrape with an API key.
- `./ctl.sh logs <service>`.
- The audit log.

### 17.9 Troubleshooting

| Symptom | Look at |
|---|---|
| Tor connection OFFLINE | `./ctl.sh logs tor`. It needs a minute to bootstrap after a start |
| Nothing collected from Tor | *Source explorer*: are any onion sources Active? *Collection policy*: is it *Never*? |
| A source shows "Host is not in EGRESS_ALLOW_HOSTS" | Add the host to `.env`, `./ctl.sh restart`, or switch the source to the Tor route |
| A provider test says "blocked by the egress allow-list" | Same |
| Many failed fetches | Normal on Tor in moderation. A source failing repeatedly backs off by itself |
| A research crawl stays at "Waiting for the first page" | Onion sites can take a minute. It closes itself after twelve minutes of silence |
| Search results look stale after an upgrade | `./ctl.sh reindex` |
| Collectors below 4/4 | `./ctl.sh status`, then `./ctl.sh logs <role>` |
| Alert email not arriving | *System > Email alerts*: the log shows each attempt and its error |
| Builds crawl on a slow link | Expected: `tools/fetch_deps.py` resumes; do not wrap builds in a short timeout |

## 18. Testing

`./ctl.sh test` runs the backend suite inside the backend image, with no
network and no services: 71 tests of the pure logic.

| File | Covers |
|---|---|
| `test_extract.py` | Indicators and their validation, defanging, redaction, countries, classification, entities, risk, text utilities |
| `test_query.py` | The query language: free text, countries, indicators, operators, negation, OR groups, dates and ranges, garbage input |
| `test_pipeline.py` | Address policy, redirects, the egress allow-list, the HTML, feed and tracker parsers, login and CAPTCHA walls, watchlist matching |
| `test_intel.py` | ATT&CK, look-alikes, priority, exposure records, Admiralty grading, STIX, provider parsers and connection tests, integration payloads, the destination guard, TOTP, provider-key handling |
| `test_research.py` | Boolean keywords, regular expressions, new filters, "why matched", ranking signals, language and relevance, the blocklist, collection settings |

The console is type-checked (`tsc --noEmit`) and built as part of the image
build. Behaviour that needs services was validated live; what was and was not
is recorded in [COVERAGE.md](COVERAGE.md).

## 19. Extending

**A connector.** Write `parse_<name>(body, …) -> ParseOutput` in
`app/worker/parsers.py`, register it in `CONNECTORS` and in `parse()`, and add
it to `USER_CONNECTORS` in `app/api/sources.py` if researchers may choose it.
Its host must be on the egress allow-list for the direct route.

**An enrichment provider.** In `app/enrich/providers.py`: a pure
`parse_<name>` function, a fetch function, a probe that calls the endpoint
which validates the key, and an entry in `PROVIDERS`. For a keyed provider add
the setting to `Settings` and to `ENV_SETTING` in `app/enrich/keys.py`. The
console picks it up.

**A search operator.** Add its spellings to `FIELD_ALIASES` and a branch in
`_field_clause` in `app/search/query.py`; add it to `OPERATOR_HELP` in
`app/api/search.py`. If it needs a new index field, add it to the mapping and
to `build_index_doc`, then reindex.

**A watchlist kind.** Add it to `WATCH_KINDS`, a branch in `match_watch`, a
branch in `watch_query` (for retro-hunts), and a label in the console's
`WATCH_LABELS`.

**A schema change.** A new Alembic revision that only adds, written to be
idempotent (`ADD COLUMN IF NOT EXISTS`, `create_all(checkfirst=True)`), because
the baseline creates tables from the current models.

Regenerate [REFERENCE.md](REFERENCE.md) afterwards.

## 20. Repository layout

```
backend/
  app/
    api/         HTTP API, one module per area (see REFERENCE.md)
    worker/      Celery tasks by role: crawl_, pipeline_, intel_, enrich_, notify_; parsers; ingest; matching
    crawl/       the fetcher and the abuse blocklist
    extract/     indicators, redaction, entities, countries, language, classification, risk, relevance, safety
    intel/       ATT&CK, relationships, verification, look-alikes, priority, STIX, research crawls, settings, provider keys
    enrich/      provider HTTP client, providers, key resolution
    ai/          the grounded AI analyst
    search/      index definition, query language, search service
    notify/      alert email and outbound destinations
    reports/     case report rendering
    data/        the compact ATT&CK catalogue
    models.py    every table
    config.py    every environment setting
    security.py  passwords, sessions, roles, API keys, audit
    crypto.py    encryption of secrets at rest
    mfa.py       TOTP
    seed.py      built-in sources, the first administrator, ATT&CK
    manage.py    init, create-user, crawl-all, reindex, upgrade-intel
    egress_proxy.py
  alembic/versions/   0001 baseline … 0004 research workstation
  tests/
frontend/
  src/app/(console)/  one folder per screen
  src/components/     ui (primitives), bits (domain components), shell, charts
  src/lib/            api client and types, formatting
docs/           this documentation
tools/          fetch_deps.py, build_attack_catalog.py, gen_reference.py
tor/  search/   gateway and search-node images
docker-compose.yml  .env.example  ctl.sh
```

## 21. Technical limits

- **Static fetching.** No JavaScript is run, so a site that renders its content
  with scripts yields little. No screenshots.
- **Regular expressions** match one word at a time.
- **Language detection** is a heuristic over 19 languages.
- **Classification, technique tagging and organisation recognition** are
  rule-based and favour precision.
- **Search depth**: paging stops at 10,000 results; exports at 5,000.
- **Indicator caps**: 400 per type per page; 2,000 exposure records per page.
- **One search node, one database, one Redis.** No replication.
- **One crawler container** by default. Hundreds of sources and millions of
  pages are not tested.
- **The shared broker** (section 3).
- **OpenSearch has no authentication.** Acceptable only because it is confined
  to an internal network.
