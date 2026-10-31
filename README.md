# Kivuli

An internal dark-web security-research workstation for authorised, defensive
work. One interface to discover, collect, search, monitor and investigate what
is published on Tor, without hopping between Tor Browser, onion directories,
scripts and separate tools. *Kivuli* is Swahili for "shadow"; rename it with
`APP_NAME` in `.env`.

**Full documentation is in [docs/](docs/README.md):** a user guide, a technical
reference, a statement of what is and is not covered, and an API and data
reference generated from the running code.

Analysts search across collected dark-web and surface-web intelligence, watch
their own assets, and get an email when a watched domain, mailbox or keyword
turns up in a leak, an extortion post or a credential dump. Release 1.1 adds
the exposure side of the picture: which of your accounts are in leaks, what an
outsider can see of your attack surface, and which vulnerabilities attackers are
actually using. What changed, what was tested and what was not is in
[docs/GAP-ANALYSIS.md](docs/GAP-ANALYSIS.md).

```bash
./ctl.sh start
```

The first start builds four images and takes a while on a slow connection.
It prints the console address (http://localhost:28941) and where to find the
generated admin password. Alert email goes to a bundled test inbox at
http://localhost:28942 until you configure a real relay.

Everything runs in rootless Docker kept inside this folder (`.runtime/`). Nothing
is installed system-wide and no sudo is needed; `./ctl.sh destroy` plus deleting
the folder removes all of it.

## The research workflow

**Search first.** The home screen is a search box over everything collected:
type `cyber attack kenya`, `company.com`, `leaked credentials` or
`username@example.com`. You do not need to know an onion address. Results say
*why* they matched, how relevant they are, when they were first and last seen
and which source they came from; each has Open, Crawl, Source, Similar, History,
Connections and Add to investigation.

**Discovery is automatic.** Onion sites are found three ways: victim trackers
list ransomware groups' leak sites, crawled pages link to other onion services,
and research crawls record every site they come across. Each new site is checked
at once (does it answer, what does it call itself, how relevant is that to
security research) and appears in the **Source explorer**.

**What gets collected is a policy you set** (Collection & crawls > Collection
policy):

- *Leak sites* (the default): leak sites listed by victim trackers are collected
  as soon as they respond. Everything else waits in the explorer for a click.
- *Leak sites and relevant sites*: also sites whose own title is clearly about
  security research.
- *Never*: nothing is collected until someone approves it.

**Research crawl.** Give a starting URL and a depth (0 to the limit an
administrator sets), press *Start research crawl*, and watch the pages appear
level by level with the page that led to each. A crawl stays on the site it
started on; other sites it finds become discovered sources. Supplying the URL is
the authorisation for that site.

**Everything collected stays searchable.** Each page is stored with its text,
indicators, entities, language, hashes and every later version. If a page or a
whole site disappears, the stored copies and their history remain: the History
tab shows when it was seen, when it changed and whether it is still there.

**Source profiles** show an onion service's address, first and last
observation, availability day by day, the pages found there, what it links to
and what links to it, the actors named on it, crawl history and research notes.

**Preserve evidence** pins the exact capture of a page, with its hashes, your
name and the time, to an investigation.

**Collection status** is always visible: Tor connection, collectors answering,
active and offline sources, crawl queue, pages indexed, last collection and
failed fetches.

### Safety controls that are always on

- **Abuse blocklist.** Ahmia's published list of onion services banned for
  child sexual abuse material (about 60,000, as hashes only) is refreshed daily.
  Nothing on it is ever filed, probed or fetched, under any policy.
- **Text only, read only.** GET requests through Tor; no logins, no CAPTCHA
  solving, no forms, no scripts. Archives, images, media and attachments are
  refused before the body is read, so leaked data dumps are never downloaded.
- **A content guardrail** drops prohibited pages and blocks the site that served
  them; it also checks a site's title before it is ever crawled.
- **Secrets are redacted** before storage, so the platform records that an
  account is exposed without keeping the password.
- Nothing discovered is contacted except to read the page: no scanning, no
  interaction, no purchases.

## What it does

| | |
|---|---|
| **Search** | Free text, pasted indicators (defanged is fine), field operators, facets, typo tolerance, synonyms, type-ahead, saved searches, CSV/JSON export |
| **Collection** | Tor hidden services through an isolated gateway; clearnet feeds through an allowlisting proxy; continuous scheduling with back-off |
| **Discovery** | Ransomware leak sites from the public RansomLook tracker, and onion links seen on crawled pages - all filed as *candidates* until an analyst approves them |
| **Link verification** | Every source is health-checked; candidates and paused sources are re-probed on a schedule |
| **Extraction** | Domains, onion addresses, URLs, IPs, emails, hashes, CVEs, crypto wallets, usernames; threat actors, malware, organisations, incidents; countries and sectors |
| **Deduplication** | By URL, by exact content hash, and by SimHash for near-copies |
| **History** | Every change to a page is a new version with a diff, so you can see when something first appeared and how it changed |
| **Evidence** | Timestamp, source URL, response metadata and SHA-256 per capture, in an HMAC-signed hash chain that the console re-verifies on demand |
| **Watchlists and alerts** | Keyword, domain, email, IP/CIDR, organisation, actor, CVE, hash, wallet, username; retro-hunt over existing data; triage queue |
| **Email** | Immediate or daily-digest alert mail per watchlist, batched per recipient, indicators defanged |
| **Risk** | 0-100 score with every point attributed to a named factor |
| **Cases** | Group findings, indicators and entities; notes; TLP; export as printable HTML, JSON, indicator CSV or a STIX 2.1 bundle |
| **Relationships** | Interactive graph of what appears together, plus stated relationships (uses, targets, attributed to…) with a confidence and a source |
| **ATT&CK** | Findings tagged with MITRE ATT&CK techniques; a matrix of what is being observed; groups and software from the ATT&CK catalogue with what they use |
| **Verification** | Every finding is unverified, reported, corroborated or confirmed, with an Admiralty grade; corroboration is detected across independent sources |
| **Identity exposure** | Which accounts, sessions and keys appear in leaks and stealer logs, with a remediation workflow. Secrets are fingerprinted and discarded |
| **Attack surface** | Passive discovery for the assets you declare: hosts from certificate logs and DNS, open ports and known vulnerabilities from public scan data |
| **Vulnerabilities** | Ranked by exploitation (CISA KEV), likelihood (EPSS), mentions in collected intelligence and presence on your hosts, not by CVSS alone |
| **Detection rules** | Turn any search into an alert: on every match, on volume, or on a spike |
| **Integrations** | Alerts to a signed webhook, Slack, Teams, Splunk, Jira or ServiceNow; indicator enrichment; TAXII 2.1 and STIX 2.1; API keys; Prometheus metrics |
| **AI analyst (optional)** | Questions answered from collected findings with citations, finding summaries, report drafts. Off unless you add a key |
| **Access control** | Viewer / analyst / admin roles, two-step sign-in, account lockout, audit log of every sign-in, export, evidence view and change |

## Searching

Type what you would say out loud. The query is interpreted, and the console
shows you how:

| You type | What happens |
|---|---|
| `cyber attack Kenya` | Findings tagged Kenya (by name, demonym, city or `.ke` domain). "cyber" and "attack" only influence ranking, because nearly every finding is one |
| `example[.]co[.]ke` | Recognised as a domain: matches it, every subdomain, and every mailbox under it |
| `jane@corp.com`, `41.90.64.0/20`, `CVE-2024-3400`, a hash, a wallet | Recognised as indicators and matched exactly |
| `"initial access" bank` | Exact phrase plus a term |
| `actor:lockbit country:KE after:30d` | Field operators (the search page lists all of them) |
| `type:ransomware -type:phishing risk:>70 has:creds` | Negation, ranges, flags |
| `lockbit OR akira` | Alternatives |
| `technique:T1566 tactic:initial-access` | ATT&CK technique (sub-techniques included) and tactic |
| `verified:corroborated` | Only what more than one independent source reports |
| `ransomware AND Kenya NOT advertisement` | `AND`, `OR`, `NOT` spelled out |
| `ransom*`, `/cve-2026-[0-9]+/` | Wildcards, and regular expressions (matched against whole words) |
| `network:tor kind:leak lang:russian` | Tor sources only, by source type (leak, forum, market, paste, news), by language |
| `site:example.onion inurl:thread` | One onion service; text in the page address |
| `similar:<finding id>` | Findings whose wording resembles one you chose (the *Similar* button) |

Turn on *Require every term* for strict matching. Ranking multiplies how well
the text matches by risk, recency, how reliable the source is, how many
independent sources report the same thing, how many sources carry the same
content and how often the page has changed. Identical content collected from
several sources is shown once, marked "seen at N sources".

**Ask a question** (under the search box) turns a question into a search,
retrieves the best-matching findings and answers from those alone, citing each
one. It needs the optional AI analyst; without it the question runs through the
query interpreter and you get the matching findings.

## Your exposure

Mark a watchlist entry as **an asset we own** and give it a criticality from 1
to 5. That one flag does four things:

- **Look-alike detection** for a domain or brand: `examp1e.co.ke`,
  `example-login.com` and the like raise their own alert category.
- **Passive attack-surface discovery** for a domain or IP range. The platform
  asks certificate-transparency logs, public DNS and Shodan's InternetDB about
  the asset. It never connects to, scans or probes anything. Only assets you
  declare are looked up.
- **Priority.** Alerts and risk scores weigh criticality, so a leak touching a
  crown-jewel system outranks the same leak against a test domain.
- **"Yours" in Identity exposure**, separating your accounts from everyone
  else's in the same dump.

Also worth adding: the **technology** you run (alerts when an exploited
vulnerability names it), **vendors** you depend on, **executives**, and your
**brand**.

Every score in the console opens into the factors that produced it.

## Alerts and email

1. **Watchlists > Add entry.** Pick a kind (start with your domain), choose
   *Immediately* or *Daily digest*, and optionally name recipients.
2. When a new finding matches, an alert is raised and mailed within a minute.
   A match on an asset you own inside a leak, ransomware post or credential dump
   is flagged **Possible compromise**; if a password was exposed next to a watched
   mailbox, the alert says so.
3. **System > Email alerts** shows the relay in use, a log of every message, and
   a *Send test* button.

To deliver to real mailboxes, set these in `.env` and run `./ctl.sh restart`:

```ini
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_TLS=starttls          # or ssl / none
SMTP_USERNAME=alerts@example.com
SMTP_PASSWORD=...
SMTP_FROM=Kivuli Alerts <alerts@example.com>
ALERT_EMAIL_TO=soc@example.com      # default recipients
PUBLIC_URL=https://kivuli.example.com   # links in the email point here
```

If the relay rejects a message, sending pauses for ten minutes and the alerts
stay queued; nothing is dropped.

**Detection rules** cover what a single watched value cannot. Write any search,
see how often it would have fired, and choose: alert on every new match, when
matches in a window reach a threshold, or when they spike above the recent
average. Rules email the same way watchlists do.

**Destinations** (Integrations > Alert destinations) receive every new alert at
or above a severity, in addition to email. Webhook requests are signed
(`X-Kivuli-Signature: sha256=…`, HMAC of the body). Destinations must be public
HTTPS addresses; internal ones are refused unless `INTEGRATIONS_ALLOW_PRIVATE=true`.

## Integrations

**Enrichment** asks third-party services *about* an indicator or an owned
asset. Six free providers work out of the box; the commercial ones switch on
when you give them a key.

Set keys in the console: **Integrations > Enrichment and AI > Set key**. Saving
a key makes one real request to that provider with it and tells you, on the
same screen, whether the provider accepted it or exactly why not (key rejected,
quota used up, host blocked by the egress allow-list, service unreachable).
Every provider, free ones included, has a **Test** button that does the same at
any time, and the last result stays on the page.

| Provider | Key | Covers |
|---|---|---|
| Shodan InternetDB, RIPEstat, public DNS, certificate transparency, FIRST EPSS | none | Addresses, domains, CVEs |
| NVD | optional (raises the rate limit) | CVSS severity and descriptions |
| VirusTotal | required | Files, URLs, domains, addresses |
| Shodan | required | Full host records |
| AbuseIPDB | required | Abuse reports for addresses |
| GreyNoise | required | Internet noise and known-benign services |

Keys can also be put in `.env` (`VIRUSTOTAL_API_KEY` and so on); a key entered
in the console takes precedence. Console keys are encrypted in the database
with `PROVIDER_KEYS_KEY`, are never shown again (only the last four characters,
to administrators), and are readable only by the enrichment worker. Have I Been
Pwned, urlscan.io, SecurityTrails and Censys are listed as planned and are not
implemented.

What stays in `.env` on purpose is `EGRESS_ALLOW_HOSTS`: which hosts the
platform may contact at all. The application cannot widen its own network
access, so a compromise of the console cannot open a route out. The hosts of
every built-in provider are already on the list, and a test tells you when one
is missing.

**AI analyst.** Add an Anthropic API key in the same place and choose the model
there. The test looks the model up and then sends one tiny request of exactly
the kind the analyst makes, so "Working" means the real feature works.
Understand what turning it on does: the text of the findings relevant to a
request is sent to the Anthropic API. Secrets are already redacted from that
text, but the rest of what you collected is in it. The model gets no tools,
cannot browse or act, and is told to treat finding text as untrusted data;
citations that do not correspond to a retrieved finding are discarded. With no
key, nothing leaves the platform.

**Alert destinations** are tested the same way: adding one, or pressing
**Test**, sends a test alert and shows whether the destination accepted it.

**TAXII 2.1 and API keys.** Create a key under Integrations > API, TAXII and
STIX. A key acts as the user who made it, read-only unless you choose otherwise,
and is shown once.

```bash
curl -H "Authorization: Bearer $KIVULI_KEY" "http://localhost:28941/api/search?q=type:ransomware+country:KE"
```

TAXII discovery is at `/api/taxii2/` with three collections (indicators,
high-risk indicators, actors/malware/techniques); HTTP Basic works with any
username and the key as the password. STIX 2.1 bundles can be imported on the
same page and exported from any case. Prometheus metrics are at `/api/metrics`.

## Architecture

```
 analyst ──> web (Next.js) ──> api (FastAPI) ──┬──> postgres   system of record
                                               ├──> search     OpenSearch, derived index
                                               └──> redis      queues
                                                      │
        beat ── schedules ──> pipeline  <── results ──┤
                              (parse, extract,        │
                               dedupe, score,         ▼
                               match, index)       crawler ──> tor ────> Tor network
                                  │                        └─> egress ─> allowlisted HTTPS
                                  │                enricher ──────┘
                                  ▼
                               notify ──> SMTP relay, alert destinations
```

Four worker roles share one image and four queues, and never import each
other's code:

- **crawler** fetches. It holds no database credentials and no signing keys.
- **pipeline** parses and stores. It has no internet access at all.
- **enricher** talks to enrichment providers and the AI API. It is the only
  container that can read their API keys: keys entered in the console reach it
  encrypted, through the queue's Redis, and only it can decrypt them. It has no
  database access, never parses crawled content, and can reach nothing but the
  allowlisting egress proxy.
- **notify** is the only container that can reach a mail relay or an alert
  destination.

PostgreSQL is authoritative; the OpenSearch index can be rebuilt at any time
with `./ctl.sh reindex`.

## Security model

**Network isolation.** The compose file defines ten networks; six are
`internal`. The crawler - the only component that reads hostile content - sits
on two internal networks and has no route to the internet, the database, the
index or the API. The enricher sits on the same two networks under the same
restriction. It can only ask the Tor gateway or the egress proxy to fetch,
and hand the result to the queue. Only `web` and the test inbox publish ports,
and only on 127.0.0.1. (`notify` does have outbound access: it has to reach your
mail relay.)

**Egress control.** Onion traffic leaves through Tor (client-only, `SafeSocks`,
so no DNS leaks and no raw-IP requests). Clearnet traffic leaves through a proxy
that tunnels HTTPS to the hosts in `EGRESS_ALLOW_HOSTS` and nothing else. That
list is operator configuration: the application cannot widen its own egress.

**Collection is read-only and text-only.** GET requests only; no forms, logins
or cookies. Anything that is not HTML, text, JSON or a feed is refused before the
body is read, so archives, dumps and media are never downloaded. Links that look
like downloads or account actions are never followed. Login and CAPTCHA walls
are reported, not worked around. Size, time and per-host rate limits apply.

**Nothing discovered is ever contacted.** Indicators are recorded, never
resolved or probed. URLs must be hostnames (no IP literals, no internal names),
and each redirect hop is re-validated and must stay on the same site.

**Untrusted content is inert.** Pages are parsed as a static tree in a container
with no network. JavaScript runs only for sources you mark "Render JavaScript",
and then only in a disposable headless browser that has no internet route of its
own (Tor or the allow-listing proxy only), no secrets, and a fresh profile per
page. The console renders
captured text as text - search highlights travel as structured parts, not HTML -
and indicators are shown defanged and are never links.

**Secrets in leaks are redacted** before storage, indexing and email
(`REDACT_SECRETS=true`). The platform tells you an account is exposed; it does
not keep a second copy of the stolen password. The SHA-256 of the original
capture is preserved for evidence.

**A content guardrail** drops pages advertising child sexual abuse material and
permanently blocks the source that served them.

**Console.** Argon2 password hashing, optional two-step sign-in (TOTP with
single-use recovery codes; `REQUIRE_MFA=true` prompts admins who have not
enrolled), httpOnly SameSite=Strict session cookie, a required custom header on
every state-changing request (CSRF), per-IP rate limits, lockout after five
failed sign-ins, a strict Content-Security-Policy, and an audit log.

**API keys** are stored as SHA-256 hashes, carry a read or read/write scope,
can expire, and cannot be used to create further keys.

**Enrichment is passive and bounded.** Lookups go to the providers you allow,
through the same egress proxy as collection. Attack-surface discovery runs only
for assets you have declared as owned and only against public datasets.

**Containers** run as unprivileged users on read-only root filesystems with all
capabilities dropped and `no-new-privileges`.

**Secrets** are generated on first start into `.env` (mode 600) and each
container receives only the variables its role needs. Tokens and webhook URLs
you enter for alert destinations, and two-step sign-in secrets, are encrypted in
the database with `SECRETS_KEY`. Provider API keys entered in the console are
encrypted with a separate key, `PROVIDER_KEYS_KEY`, so the enrichment worker
that has to read them never holds the key protecting everything else.

**Dependencies** are pinned to exact versions (`backend/requirements.lock`,
`frontend/package-lock.json`) and verified before installation: Python wheels
against PyPI's published SHA-256, npm packages against the SHA-512 integrity
values in the lock file.

**Known trust boundary.** The crawler and the enricher share the Redis broker
with the other workers, because that is how they hand results over. A fully
compromised crawler or enricher could therefore enqueue tasks for them. It still
could not read the database or reach the internet directly, but for a
hostile-network deployment give each its own Redis user restricted with ACLs,
or a separate broker for results.

## Operating it

```
./ctl.sh start | stop | restart | status
./ctl.sh update                pull from git, rebuild, restart
./ctl.sh https <domain> <email> | off   HTTPS with Let's Encrypt in front of the console
./ctl.sh doctor                health check: containers, API, Tor, disk, HTTPS
./ctl.sh logs [service]        crawler, pipeline, notify, api, web, tor, egress, ...
./ctl.sh build [image]         rebuild after a code change (backend, web, tor, search)
./ctl.sh crawl                 crawl every active source now (research crawls are started in the console)
./ctl.sh reindex               rebuild the search index from PostgreSQL
./ctl.sh test                  backend test suite
./ctl.sh lock                  re-pin backend dependencies after editing requirements.txt
./ctl.sh manage create-user analyst@example.com analyst
./ctl.sh backup [dir] [--keep N]   database dump, evidence and .env into a dated folder; prune to N
./ctl.sh autostart on|off      start at boot and back up daily (systemd)
./ctl.sh restore <folder>      restore a backup (asks first), then reindex
./ctl.sh upgrade-intel         re-derive techniques, verification and exposure for older findings
./ctl.sh destroy               remove everything, including collected data
```

**Upgrading from 1.0.** `./ctl.sh backup`, then `./ctl.sh build`. The database
is migrated in place, missing settings are added to `.env` (it tells you which),
and the new enricher starts. Run `./ctl.sh upgrade-intel` once to tag existing
findings.

Adding a source: **Sources > Add source**. Onion sites always go through Tor. A
clearnet site can go through Tor too; for the *direct* route its host must be in
`EGRESS_ALLOW_HOSTS`.

`./ctl.sh backup` writes the database, the evidence volume and `.env` to a
folder readable only by you. Keep it encrypted: it contains `EVIDENCE_HMAC_KEY`
(without which stored evidence can no longer be verified), `SECRETS_KEY` and
`PROVIDER_KEYS_KEY` (without which stored integration secrets and provider keys
cannot be read).

**Slow first build?** Some networks throttle individual connections to package
CDNs, which makes `pip` and `npm` crawl. `./ctl.sh` therefore runs
`tools/fetch_deps.py` first: it downloads the pinned Python wheels and npm
packages from PyPI and the npm registry over many parallel connections, checks
each against its published checksum, and the image builds install from that
offline. The Tor image installs one Alpine package and may still take a while
the first time; later starts reuse the cached layers.

## Running it on a VPS

The full guide (installation, configuration, management, backups, updates,
troubleshooting, security) is [docs/OPERATIONS.md](docs/OPERATIONS.md); next
steps are in [docs/ROADMAP.md](docs/ROADMAP.md).

**The easy way: `install.sh`.** It looks at the server first and works around
what is already there, so other websites keep running untouched:

```
git clone https://github.com/Maerih/kivuli.git /opt/kivuli && cd /opt/kivuli
sudo ./install.sh --check --domain kivuli.example.org                       # look only, change nothing
sudo ./install.sh --domain kivuli.example.org --email you@example.org       # install
```

It checks RAM, disk, Docker, the firewall and that the domain's DNS points at
this server, then picks how to serve Kivuli:

| On ports 80/443 | What install.sh does |
|---|---|
| nothing | Kivuli's own HTTPS (Caddy, Let's Encrypt) |
| nginx | adds one site file for Kivuli's domain, gets its certificate with certbot; other sites untouched (the server shell works here too) |
| Apache | adds one site file for Kivuli's domain, gets its certificate with certbot; other sites untouched |
| anything else (Traefik, Caddy, a Docker container) | leaves it alone and prints what to add to it |

Kivuli itself opens nothing to the outside: the console listens on
`127.0.0.1:28941` (the test inbox on 28942, the server shell on 28943, or the
next free ports), uncommon on purpose so they do not collide with other
applications. It refuses to touch a site for the same domain that it did not
write, and installs start-at-boot and daily backups unless `--no-autostart`.

**By hand**, the same steps:

```
git clone git@github.com:Maerih/kivuli.git && cd kivuli
KIVULI_DOCKER=system ./ctl.sh start            # or plain ./ctl.sh start for folder-local rootless Docker
./ctl.sh https intel.example.org you@example.org   # HTTPS with a Let's Encrypt certificate
./ctl.sh doctor                                 # containers, API, Tor, disk, HTTPS
sudo KIVULI_DOCKER=system ./ctl.sh autostart on # start at boot, back up daily at 03:30 (newest 14 kept)
./ctl.sh update                                 # later: pull from GitHub, rebuild, restart
```

Container logs are rotated (5 files of 20 MB per container), so a server left
running does not fill its disk with logs. `./ctl.sh backup --keep N` deletes
all but the newest N backups it made; the daily timer uses `--keep 14`. Copy
backups off the server too: they hold the database and the keys to read it.

`./ctl.sh https` needs the domain's DNS to point at the server and ports 80
and 443 open. It starts Caddy in front of the console, sets
`PUBLIC_URL=https://<domain>` and `COOKIE_SECURE=true`, and keeps the console
itself on 127.0.0.1, so only Caddy faces the internet. `./ctl.sh https off`
goes back to localhost only. Rootless Docker cannot listen on ports below 1024
unless `net.ipv4.ip_unprivileged_port_start` allows it; with
`KIVULI_DOCKER=system` it can. `./ctl.sh update` refuses to run over local
changes to tracked files. Back up before upgrading: `./ctl.sh backup`.

**Server shell.** `./ctl.sh shell on` (after HTTPS) adds a terminal on the
server itself under *Research > Command line > Server shell*. It is WeTTY, a
browser SSH client in its own container with no published port; Caddy puts
every request to `/shell` to Kivuli first, which lets through only an
administrator with two-step sign-in who pressed *Open server shell* (audited,
valid 12 hours). The server's own SSH login is then asked every session, so
SSH password login must be allowed for that user, and `SHELL_SSH_PORT` must
match your SSH port. No Kivuli container gets access to the host.
`./ctl.sh shell off` removes it.

## Before exposing it beyond localhost

- Put the console behind TLS (`./ctl.sh https <domain> <email>`), which sets `COOKIE_SECURE=true` and `PUBLIC_URL`.
- Replace the bundled search image (`search/Dockerfile`, OpenSearch minimal
  distribution, no auth - acceptable only because it is confined to an internal
  network) with the official image and its security plugin if the search node
  will ever share a network with anything else.
- Remove the `mailpit` service once a real relay is configured.
- Turn on two-step sign-in for every account and set `REQUIRE_MFA=true`.
- Review `EGRESS_ALLOW_HOSTS` and remove providers you do not use.
- Move secrets from `.env` to your orchestrator's secret store.

## Deliberate limits

- **Search covers what has been collected**, not the live dark web. Coverage
  grows with the sources being collected and the crawls you run.
- **JavaScript only where you ask for it, and no screenshots.** Pages are
  fetched and parsed statically unless a source is marked "Render JavaScript";
  either way the stored snapshot is the page's text and a hash, never an image.
- **No images or attachments**, by design: on these sites they are where illegal
  material and malware live.
- **No onion search-engine scraping.** Engines such as Ahmia gate automated
  queries with tokens; the platform does not work around that. Discovery comes
  from RansomLook, from links on pages you already collect, and from sources you
  add.
- **No access to closed forums or markets.** Anything behind a login, an
  invitation or a CAPTCHA is reported as such and not collected. Publicly
  readable forum, market and paste pages are collected like any other page.
- **Language detection is a heuristic** (scripts and common words): good for
  filtering, not for close calls between related languages.
- Organisation recognition in free text is pattern-based and conservative; named
  victims from tracker feeds are exact.
- **Attack-surface data is second-hand.** Ports and vulnerabilities come from
  public scan datasets and banner matching. Treat them as leads to confirm, not
  as scan results.
- **ATT&CK tagging is rule-based**: explicit technique IDs and a set of
  behaviour patterns. It favours precision over coverage.
- **Telegram** means the public web preview of public channels. Nothing that
  needs an account is collected.
- **Single tenant, no SSO.** See the roadmap in docs/GAP-ANALYSIS.md.

## Layout

```
backend/app/
  extract/    indicators, redaction and exposure records, entities, countries, classification, risk
  intel/      ATT&CK, relationships, verification, look-alikes, priority, STIX
  enrich/     enrichment providers
  ai/         grounded AI analyst
  search/     index definition, query language, ranking and facets
  worker/     crawler, pipeline, enricher and notify tasks; parsers; ingest; matching
  crawl/      the hardened fetcher and the abuse blocklist
  notify/     alert email and outbound destinations
  reports/    case report rendering
  api/        HTTP API
  data/       compact ATT&CK catalogue
  egress_proxy.py
frontend/     Next.js console
docs/         gap analysis, what 1.1 delivered, roadmap
tools/fetch_deps.py            parallel, checksum-verified dependency download
tools/build_attack_catalog.py  rebuilds the ATT&CK catalogue from MITRE's STIX bundle
tor/          Tor gateway image
search/       OpenSearch image
docker-compose.yml, .env.example, ctl.sh
```

Scaling out: every role is stateless apart from the three data stores, so the
crawler, pipeline, enricher and notify services scale horizontally by replica
count, and the compose services map one-to-one onto Kubernetes Deployments with
the networks becoming NetworkPolicies.

## Attribution

The ATT&CK catalogue in `backend/app/data/attack.json` is derived from MITRE
ATT&CK®, © The MITRE Corporation, reproduced under the ATT&CK terms of use
(https://attack.mitre.org/resources/terms-of-use/). EPSS scores are from FIRST;
the exploited-vulnerability catalogue is from CISA.
