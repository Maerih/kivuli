# Capability audit and roadmap

Audit of release 1.0 against a modern CTI / threat-exposure platform, and the
plan that release 1.1 implements. Written before any 1.1 code was changed; the
"Delivered in 1.1" section at the end records what actually shipped.

## 1. What release 1.0 is

| Layer | Implementation |
|---|---|
| Console | Next.js 15 / React 19 / Tailwind. 14 pages: overview, search, finding, alerts, watchlists, cases, entities, indicators, graph, sources, system |
| API | FastAPI, 60 routes, cookie session (JWT), CSRF header, RBAC (viewer / analyst / admin), audit log, rate limits |
| Workers | Celery on Redis, three roles on three queues: `crawler` (fetch), `pipeline` (parse, store), `notify` (mail) |
| Storage | PostgreSQL (19 tables, system of record), OpenSearch (derived index), Redis (queues) |
| Collection | Tor gateway, allowlisting egress proxy; connectors: `html`, `rss`, `ransomware_live`, `ransomlook_recent`, `ransomlook_group`, `cisa_kev` |
| Pipeline | normalise → guardrail → redact → fingerprint → dedupe/version → extract → classify → match watchlists → score → evidence chain → index |
| Deployment | Docker Compose, 10 networks (6 internal), rootless, read-only containers |

Lifecycle coverage in 1.0:

| Stage | 1.0 |
|---|---|
| Collect | Yes (6 connectors, Tor + clearnet) |
| Validate | Yes (URL policy, liveness, content-type and size limits, guardrail) |
| Normalise | Yes |
| Deduplicate | Yes (key, hash, SimHash) |
| Extract | Partial: indicators, actors, malware, organisations, countries. No TTPs, technologies, exposure records |
| Enrich | **No** |
| Resolve | Partial: aliases for ~60 curated actors only; no merge, no typed relationships |
| Correlate | Partial: co-occurrence only |
| Score | Yes, explainable, but blind to asset criticality, exploitability and corroboration |
| Investigate | Yes (cases, notes, graph) but no timeline or saved hunts |
| Alert | Partial: watchlist matches only |
| Report | Partial: technical case report only |
| Respond | **No** (email only; no webhooks, ticketing, SIEM or feeds out) |

## 2. Gap analysis

Status: **E** exists, **P** partial, **M** missing. Decision: **1.1** implement
now, **Later** roadmap, **Keep** no change needed.

| # | Capability | 1.0 | What exists / what is missing | Decision |
|---|---|---|---|---|
| 1 | Unified search | E | Query language, facets, fuzzy, synonyms, indicator recognition | Keep; add technique/verification filters |
| 2 | Intelligence graph | P | Co-occurrence neighbourhood only; no typed edges, confidence or provenance | 1.1 |
| 3 | Dark-web intelligence | E | Tor crawl, leak-site discovery, candidate approval | Keep |
| 4 | Clear-web / OSINT | P | News RSS, trackers, KEV. No threat feeds | 1.1 (indicator feeds) |
| 5 | Public messaging | M | Nothing | 1.1 (public Telegram channel previews) |
| 6 | Source provenance | P | Trust 0-100, crawl log, liveness. No standard reliability grading | 1.1 (Admiralty code) |
| 7 | Entity extraction | P | No TTPs | 1.1 (ATT&CK techniques) |
| 8 | Entity resolution | P | Aliases for curated actors only; no merge | 1.1 (ATT&CK groups, merge) |
| 9 | Threat-actor intelligence | P | Profile page from findings; no TTPs, software, references | 1.1 |
| 10 | Campaigns | P | Analyst-created, linkable | Keep |
| 11 | Malware intelligence | P | 28 curated families | 1.1 (ATT&CK software) |
| 12 | MITRE ATT&CK | M | Nothing | 1.1 |
| 13 | IOC intelligence | P | Extraction, pivots. No reputation, no benign list | 1.1 |
| 14 | Infrastructure | M | Nothing | 1.1 (ports, services, ASN via passive sources) |
| 15 | DNS / WHOIS / passive DNS | M | Nothing | 1.1 DNS; WHOIS and passive DNS Later (need keyed providers or per-registry egress) |
| 16 | Certificates | M | Nothing | 1.1 (certificate transparency) |
| 17 | ASN / BGP | M | Nothing | 1.1 (RIPEstat) |
| 18 | Credential exposure | P | Detected and redacted; shown per finding only | 1.1 (exposure records) |
| 19 | Infostealer intelligence | P | Classified; stealer-log triplets not parsed | 1.1 |
| 20 | Organisation monitoring | P | Flat watchlists, no criticality | 1.1 (asset inventory) |
| 21 | Brand monitoring | M | Keyword only | 1.1 (lookalike domains) |
| 22 | Employee exposure | P | Domain watch catches mailboxes | 1.1 (per-account view) |
| 23 | Attack surface | M | Nothing | 1.1 (passive) |
| 24 | Vulnerability intelligence | P | KEV as findings; no CVE record, EPSS or CVSS | 1.1 |
| 25 | Ransomware intelligence | E | Trackers, groups, victims, incidents | Keep |
| 26 | Phishing intelligence | P | Classification only | 1.1 (feeds, lookalikes) |
| 27 | BEC / fraud | P | Classification only | Later |
| 28 | Risk scoring | E | Explainable; missing factors | 1.1 (extend) |
| 29 | Risk-based alerting | P | Minimum severity only | 1.1 (priority, rules) |
| 30 | AI threat analyst | M | No AI anywhere | 1.1 (grounded, cited) |
| 31 | Natural-language hunting | P | Parser understands countries and broad terms | 1.1 (translation to query) |
| 32 | Hunting workspace | P | Saved searches | 1.1 (hunts saved to cases) |
| 33 | Case management | E | Cases, items, notes, TLP, reports | Keep |
| 34 | Investigation timeline | M | Nothing | 1.1 |
| 35 | Evidence management | E | Hash chain, HMAC, verification | Keep |
| 36 | Confidence scoring | P | Classification confidence only | 1.1 (verification state) |
| 37 | Source reliability | P | Numeric trust | 1.1 (A-F) |
| 38 | Correlation | P | Co-occurrence | 1.1 (corroboration, feed and asset correlation) |
| 39 | Automated enrichment | M | Nothing | 1.1 (provider framework) |
| 40 | Geographic intelligence | E | Detection, facet, focus countries | Keep |
| 41 | Trends and analytics | P | Dashboard | 1.1 (movers) |
| 42 | Watchlists | E | Ten kinds, retro-hunt | Keep, extend |
| 43 | Continuous monitoring | E | Scheduler, back-off | Keep |
| 44 | Threat reports | P | Case report | Keep |
| 45 | Executive reporting | M | Nothing | 1.1 |
| 46 | Technical reporting | E | Case report, CSV, STIX | Keep |
| 47 | STIX 2.x | P | Minimal export, no import | 1.1 |
| 48 | TAXII 2.x | M | Nothing | 1.1 (read-only server) |
| 49 | SIEM | M | Nothing | 1.1 (Splunk HEC, generic webhook, TAXII) |
| 50 | SOAR | M | Nothing | 1.1 (signed webhooks) |
| 51 | EDR / XDR | M | Nothing | Later (indicator push; TAXII covers pull) |
| 52 | IAM | M | Nothing | Later (forced reset on exposure) |
| 53 | Ticketing | M | Nothing | 1.1 (Jira, ServiceNow) |
| 54 | REST API | P | Session cookie only | 1.1 (API keys) |
| 55 | Webhooks | M | Nothing | 1.1 |
| 56 | Multi-tenancy | M | Single tenant | Later (see 4) |
| 57 | RBAC | E | Three roles | Keep |
| 58 | MFA / SSO | M | Password only | 1.1 TOTP; OIDC Later |
| 59 | Audit logging | E | Every sign-in, export, change | Keep |
| 60 | Secure evidence storage | E | Chain, optional raw store | Keep; encryption at rest Later |
| 61 | AI-assisted correlation | M | Nothing | 1.1 (within the analyst) |
| 62 | Semantic / vector search | M | Lexical only | Later (see 4) |
| 63 | Graph investigation | P | View only | 1.1 (filters, typed edges, bookmarks) |
| 64 | Automated prioritisation | P | Risk only | 1.1 (alert and vulnerability priority) |
| 65 | Analyst collaboration | P | Notes, assignment | Keep |
| 66 | Real-time pipeline | E | Queue-driven, minute-level | Keep |
| 67 | Data quality | P | Dedupe, guardrail | 1.1 (verification, benign list, quality metrics) |
| 68 | Observability | P | Health page | 1.1 (Prometheus metrics) |
| 69 | Horizontal scale | E | Stateless roles | Keep |
| 70 | High availability | M | Single node of each store | Later |
| 71 | Disaster recovery | M | No backup tooling | 1.1 (backup / restore) |

Additional gaps found that were not on the list:

- **Benign-indicator handling.** Real data showed common domains (e.g. a
  business directory) ranking as top indicators. 1.1 adds a benign flag that
  removes an indicator from correlation.
- **Lookalike-domain detection** for brand protection. 1.1.
- **Secret fingerprints.** Exposed keys cannot be stored, but a SHA-256
  fingerprint lets an owner confirm "is this my key?". 1.1.
- **Secrets at rest** for integration credentials. 1.1 (encrypted with a key
  outside the database).
- Later: takedown workflow, Sigma/YARA extraction, MISP sync, retention
  policies, priority intelligence requirements, analyst feedback loop.

## 3. Design decisions for 1.1

**No new infrastructure.** Everything fits PostgreSQL, OpenSearch, Redis and
Celery. Specifically not added, and why:

- *Graph database.* Relationships are a typed edge table; neighbourhood queries
  over thousands of entities are indexed joins. Revisit beyond ~10M edges.
- *Vector database / embeddings.* Needs either the full OpenSearch image with
  k-NN or pgvector plus an embedding model. Natural-language translation to
  the existing query language covers most of the need at no infrastructure cost.
- *Kafka.* Redis queues handle the volume; ingestion is idempotent.
- *Kubernetes.* Compose services already map one-to-one to Deployments.

**One new worker role, `enricher`.** Enrichment and AI calls need outbound
access and hold third-party API keys. The crawler must keep holding no secrets,
and the API must keep having no egress, so these calls run in their own
container that reaches only the allowlisting proxy. It never parses crawled
content.

**Enrichment is passive.** Providers are asked *about* an indicator; the
indicator itself is still never contacted. Attack-surface discovery uses
certificate transparency, public DNS-over-HTTPS and Shodan InternetDB: no
scanning. It runs only for assets the operator declares as their own.

**AI is grounded and optional.** Without an API key every AI feature is
disabled and nothing leaves the platform. With one, the model only ever sees
retrieved, already-redacted findings, has no tools, and must cite finding
identifiers; citations that were not supplied are discarded. Crawled text is
treated as untrusted data in the prompt.

**Backward compatibility.** Schema changes are additive (new tables, new
columns with defaults, two columns relaxed to nullable) in migration `0002`.
Existing routes keep their shapes; new fields are added. Existing findings are
re-scored and re-indexed in place.

## 4. Roadmap

### Already implemented (1.0, kept)
Search and query language, Tor/clearnet collection with isolation, leak-site
discovery with approval, extraction, dedupe, versioning, evidence chain, risk
scoring, watchlists with retro-hunt, email alerts and digest, cases and
technical reports, RBAC, audit log, redaction, guardrail.

### Implemented in 1.1
See "Delivered in 1.1" below.

### Recommended next
| Item | Why it was not done now |
|---|---|
| Semantic search | Needs k-NN or pgvector plus an embedding model; measurable benefit only once the corpus is large and multilingual |
| Multi-tenancy | Touches every table and query (tenant key + row-level security). Run one deployment per tenant until then |
| SSO / OIDC | The API has no egress by design; needs an identity-proxy sidecar or a dedicated allowlisted route |
| WHOIS and passive DNS | RDAP redirects to per-registry hosts, which the egress policy refuses; passive DNS needs a keyed provider |
| EDR / XDR indicator push, IAM actions | Vendor-specific; TAXII, webhooks and CSV cover pull-based use today |
| File attachments on cases | Needs malware-safe upload handling and scanning |
| High availability | PostgreSQL replication, multi-node OpenSearch, Redis Sentinel |
| Evidence encryption at rest, object storage | Volume-level encryption is the pragmatic interim |
| Redis ACLs per worker role | Closes the shared-broker trust boundary noted in the README |
| JavaScript rendering | Only inside a disposable, network-isolated sandbox |
| Takedown workflow, Sigma/YARA extraction, MISP sync, retention policies | Valuable, lower priority |

## 5. Delivered in 1.1

Deployed onto the running 1.0 installation and its data (about 420 findings at
the time) without a reset. A backup was taken first with the new `./ctl.sh backup`.

### What shipped

| Area | Capability |
|---|---|
| Intelligence graph | Typed relationships (`uses`, `targets`, `attributed_to`, `exploits`, `delivers`, `related_to`) with confidence, source and first/last seen; MITRE ATT&CK Enterprise v19.2 bundled (697 techniques, 176 groups, 785 software after alias merging, 5,557 relationships); technique tagging of findings; ATT&CK matrix; analyst-added relationships; entity merge with duplicate suggestions; graph shows stated relationships, type filters and bookmarks |
| Search | `technique:` / `ttp:`, `tactic:`, `verified:` operators and facets; "Ask a question" with cited answers (AI optional, falls back to the query interpreter) |
| Collection | Public Telegram channel previews and plain-text indicator feeds as connectors; three more built-in sources (Feodo Tracker, OpenPhish, CISA advisories) |
| Data quality | Verification states (unverified, reported, corroborated, confirmed), Admiralty grading, corroboration across sources, benign-indicator marking, quality figures on the System page and in metrics |
| Risk | New explainable factors: corroboration, threat-feed listing, asset criticality, focus sector. Alert priority separate from finding risk, with its own breakdown |
| Organisation monitoring | Owned assets with criticality and business unit; brand, technology, vendor and executive watch kinds; look-alike domain detection |
| Attack surface | Passive discovery for declared assets only: certificate transparency, public DNS, Shodan InternetDB. Risky ports, known vulnerabilities, per-host explained risk, alerts |
| Vulnerabilities | CISA KEV catalogue, EPSS, NVD severity for the highest-ranked, mentions in collected intelligence, presence on owned hosts, explained priority |
| Identity exposure | Per-account and per-secret records from leaks and stealer logs, vendor token recognition, fingerprints instead of secrets, remediation workflow, CSV export |
| Hunting and cases | Saved hunts and graph bookmarks in cases, case timeline, executive brief, AI draft of a case summary or actor profile |
| Alerting | Detection rules (every match, volume threshold, spike) with preview; alerts from rules and from the attack surface; destinations: signed webhook, Slack, Teams, Splunk HEC, Jira, ServiceNow |
| Sharing | TAXII 2.1 server (three collections), STIX 2.1 import, richer STIX export, API keys with read or read/write scope, Prometheus metrics |
| Enrichment | Isolated `enricher` worker. Free: InternetDB, RIPEstat, DNS-over-HTTPS, certificate transparency, EPSS, NVD. Keyed and off until configured: VirusTotal, Shodan, AbuseIPDB, GreyNoise. Listed as planned: HIBP, urlscan.io, SecurityTrails, Censys |
| Platform security | TOTP two-step sign-in with recovery codes, admin reset, optional prompt for admins who have not enrolled; secrets for integrations encrypted at rest; SSRF guard on outbound destinations; backup and restore commands |

### How it was validated

- **56 unit tests** (38 from 1.0 unchanged, 18 new) covering technique extraction,
  look-alike detection, priority scoring, exposure records, Admiralty grading,
  STIX round trip, provider response parsing, integration payloads, the
  destination guard, TOTP, the new connectors and the new query operators.
- **Migration on live data**: `0002` applied to the 1.0 database in place; the
  search mapping was extended without a reindex; `./ctl.sh upgrade-intel` tagged
  techniques on 420 findings and marked 104 as corroborated.
- **End to end with synthetic data** (a fictitious bank, removed afterwards): a
  leak with credential pairs, a stealer-log record and a cloud key produced a
  "possible compromise" alert at priority 93 with its factors, four exposure
  records and no secret anywhere in the stored text, the API responses or the
  CSV export. A look-alike domain, a technology watch and an executive watch each
  raised the expected alert. A query rule and a threshold rule fired, including
  one alert with no single finding behind it. The alert email was delivered to
  the test inbox.
- **Live passive lookups through the egress proxy**: KEV sync (1,734 CVEs), EPSS
  scores, NVD severity, attack-surface discovery for `example.com`, InternetDB and
  RIPEstat for one address.
- **API keys and TAXII**: bearer and basic authentication, read-only scope
  refused on writes, no key of either scope can create keys, revocation, paging,
  manifests, and TAXII URLs answered through the console's proxy without a
  redirect, with or without the trailing slash.
- **Two-step sign-in**: enrolment, wrong code, correct code, recovery code and
  its single use, admin reset. The QR code renders under the console's
  Content-Security-Policy.
- **Webhook delivery**: a real HTTP delivery to a listener inside the notify
  container, with the HMAC signature verified on receipt, the Splunk HEC path and
  header, and failure handling. Delivery to a link-local address was refused.
- **Console**: every new page and every changed page opened in a browser against
  real data. The sign-in code step and the add/edit dialogs were type-checked and
  exercised through the API, not clicked through.

### Not verified against a live service

Say so rather than assume:

- **The AI analyst.** No `ANTHROPIC_API_KEY` was available. The request path,
  the grounding prompt, citation validation and the disabled-state fallback are
  in place and the fallback was exercised; no model answer has been seen.
- **VirusTotal, Shodan, AbuseIPDB, GreyNoise.** Their response parsers are unit
  tested against the documented formats; no real key was used.
- **Slack, Teams, Jira and ServiceNow.** Payloads are unit tested. Only the
  generic webhook and Splunk HEC shapes were delivered over HTTP, to a local listener.
- **The Telegram connector** was tested on a sample page, not on a live channel.
- **Spike rules** share the evaluated code path of threshold rules but were not
  made to fire.
- **Restore.** The backup was produced and confirmed readable by `pg_restore`;
  a restore over the live database was not run.

### Defects found by this validation and fixed

- Indicator feeds accepted private and reserved addresses.
- The ATT&CK matrix query failed on PostgreSQL (grouping by a parameterised JSON key).
- The dashboard assumed every alert has a watchlist and a finding.
- CSV exports prefixed empty cells with an apostrophe (the formula-injection
  guard matched the empty string). This was also present in the 1.0 search export.
- STIX import dropped ATT&CK techniques and their relationships.
- TAXII URLs redirected to an internal host name when reached through the console.
- Vulnerability ranking waited up to an hour after start; mention counts were
  never reset when the mentioning finding was removed.

### Compatibility notes

- `GET /alerts`: `watchlist` and `finding` may now be `null` (rule and
  attack-surface alerts); `origin`, `title`, `priority`, `factors` are new. The
  default order is by priority; pass `sort=newest` for the old order.
- An API request carrying an `Authorization` header is authenticated by that
  key alone; the session cookie is ignored for it.
- `.env` gains new settings on upgrade (`./ctl.sh` adds the missing ones and
  reports them) and the egress allow-list gains the hosts of the new built-in
  feeds and providers. Remove any you do not want; the feature that needs a
  host says so when it is missing.

## 6. Addendum: provider and AI keys from the console

Requested after 1.1 shipped: API integrations must be configurable from the
front end, and the platform must confirm against the provider itself whether a
key works.

- **Set, replace and remove keys in the console** for VirusTotal, Shodan,
  AbuseIPDB, GreyNoise, NVD and Anthropic, and choose the AI model. Keys are
  encrypted with a dedicated `PROVIDER_KEYS_KEY`, stored in PostgreSQL, mirrored
  as ciphertext to Redis and decrypted only by the enricher. A console key takes
  precedence over `.env`; removing it brings the `.env` key back into force.
- **Connection tests.** Saving a key runs a real request to the provider and the
  console shows the verdict; every provider (free ones too) and every alert
  destination has a Test button. Results distinguish a rejected key, exhausted
  quota, a host missing from the egress allow-list, and an unreachable service.
- **A rejected key is now an error everywhere**, not "no data": indicator
  lookups with a bad key report the rejection.
- The egress allow-list deliberately stays in `.env`.

Validated live: all six free providers answered through the egress proxy. A
deliberately invalid key was saved for each keyed service through the same API
the console uses, and each provider's own server rejected it (VirusTotal,
Shodan, AbuseIPDB and GreyNoise with HTTP 401, NVD with 404, Anthropic with an
authentication error); the console showed "Not working" with the reason. No
plaintext key appeared in the database, the Redis mirror or any API response.
The same flow was clicked through in the browser for VirusTotal and for an alert
destination. All test keys were removed afterwards.

Still not seen: a **valid** key being accepted. The success path is covered by
unit tests against the providers' documented responses, but no real key was
available. Two defects were found and fixed on the way: test jobs were never
queued (a task argument named `name` clashed with the queue helper), and the
GreyNoise test used a lookup endpoint that answers with any key, so it would have
reported an invalid key as working; it now uses the endpoint that checks the key.

## 7. Addendum: the dark-web research workstation

The platform was re-centred on one job: letting an authorised researcher find
dark-web intelligence without knowing where it lives. It is an internal tool;
nothing here was built for tenants, billing or public distribution.

A finding first: before this work the running system had **no onion sources at
all**. Tor worked, but only clearnet feeds were seeded, discovery ran once a
night and had not run since the last reset, and anything it found waited for
approval. That is fixed below.

### Built, against the brief

| Brief | State |
|---|---|
| 1, 19 Search at the centre; command centre | Home is a search box, collection status strip, recent Tor intelligence, critical findings, new matches, watched keywords, new sources, active research. The old chart dashboard moved to Trends |
| 2 Search engine | Already: full text, phrases, OR, negation, fields, dates, fuzzy matching, wildcards, facets, saved searches. Added: `AND`/`NOT` keywords, regular expressions, language, source type, site, address and similar-content filters |
| 3 Automatic discovery; query → source → page → entity → source | Tracker listings from both victim trackers, links on crawled pages, research crawls. Search shows the sources carrying the results and known-but-uncollected sites that match |
| 4 Controlled Tor collection layer | Unchanged isolation (console never touches Tor); a collection policy an administrator sets in the console decides what is collected automatically |
| 5 Dark-web crawler; research crawl | Start URL + depth + page limit; same-site boundary; URL and content de-duplication; retries; parent tracking; live view of pages by depth; stop; optional monitoring afterwards |
| 6 Open-in-research workflow | Open, Crawl, Source, Similar, History, Connections, Add to investigation on every result |
| 7 Index everything | Text, links between sources, timestamps, first/last seen, hashes, HTTP metadata, language, entities, indicators. Not images or attachments (see below) |
| 8 Historical search | Versions and diffs existed; added per-page observations (seen, changed, failed, by day) and a status: online, no longer on the site, removed, source offline |
| 9 Ranking and "why matched" | Ranking adds source reliability, corroboration, same-content count and change frequency to relevance, risk and recency. Each result lists the query parts it matched and what lifted it |
| 10, 11 Entities and pivoting | Existing extraction; every indicator and entity now has search-everywhere and connections pivots |
| 12 Source explorer and profiles | Views: active, discovered, new, recently changed, most referenced, offline, paused, blocked. Profile: address, first/last observed, availability by day, pages, related sources (links in and out), actors and entities, crawl history, notes |
| 13, 14 Watchlists; quiet alerts | Existing watchlists, rules and duplicate suppression (a copy of something that already alerted does not alert again); search results show how many sources carry the same content |
| 16, 17 Workspace; evidence | Investigations hold findings, indicators, entities, saved hunts, graph bookmarks, research crawls, a timeline and preserved evidence (exact capture, hashes, who, when) |
| 18 Collection health | Tor, collectors answering, sources by state, queue, pages indexed, last collection, failed fetches, blocklist state |
| 21 One platform | One console; nothing new to run |

### Not built, or only partly

- **Screenshots, images, attachments** (7, 16, 17): deliberately not collected.
  The snapshot is text plus hashes.
- **Sites behind logins, invitations or CAPTCHAs** (1): out of scope. Publicly
  readable forum, market and paste pages are collected; most established forums
  and markets are not publicly readable.
- **Searching the live dark web or onion search engines** (1, 3): search covers
  what the platform has collected.
- **Source nodes in the graph** (15): source-to-source links are in the source
  profile, not yet in the relationship graph.
- **People, Telegram handles and file names as their own entity types** (10):
  handles are covered by usernames; people only through executive watchlists.
- **Alert events** (14): duplicates are suppressed and counted; alerts are not
  yet regrouped into a single "event" object.
- **AI research commands** (20): the cited question-answering from 1.1 is
  unchanged and still untested for want of a key.
- **Clustering of actors and campaigns, advanced entity resolution** (22, P2).
- **Scale**: one crawler container. The roles scale by replica count; the
  figures in the brief (hundreds of sources, millions of pages) are not tested.

### Validated live

- The default policy approved the eight tracker-listed leak sites that answered;
  54 pages were collected through Tor within minutes and are searchable.
- The abuse blocklist loaded 59,973 hashes; links to archives on a leak site
  were refused ("content type application/zip is not collected").
- A research crawl of a benign onion site (the Tor Project's) at depth 1 read 6
  pages in 30 seconds, with depth and parent recorded; internal, IP-literal and
  non-HTTP addresses were refused. Its data was removed afterwards.
- Search over the Tor data: `network:tor kind:leak`, `AND`/`NOT`, a regular
  expression, `lang:`, `site:`, `inurl:`, `similar:`, relevance and "why matched".
- Source profile, page observations, evidence preservation, investigation-linked
  crawls, and every new screen in a browser.
- 71 unit tests.
