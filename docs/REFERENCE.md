# Reference (generated)

Generated from the running code on 2026-10-31 by `tools/gen_reference.py`. Do not edit by hand; regenerate after a change:

```bash
./ctl.sh docker compose exec -T api python - < tools/gen_reference.py > docs/REFERENCE.md
```

Contents: [HTTP API](#http-api) · [Data model](#data-model) · [Configuration](#configuration) · [Scheduled work and tasks](#scheduled-work-and-tasks) · [Enumerations](#enumerations)

## HTTP API

All paths are under `/api`. A request is authenticated by the session cookie (console) or by `Authorization: Bearer <api key>`. Roles nest: an admin can do everything an analyst can, an analyst everything a viewer can. A read-only API key is refused on anything but GET. State-changing requests from the console must carry the header `X-Kivuli-CSRF: 1`.

### admin

| Method | Path | Role | What it does |
|---|---|---|---|
| GET | `/audit` | admin | The audit log, newest first; filter by action prefix and user. |
| GET | `/dashboard` | viewer | Figures behind the Trends page: volumes, types, countries, actors, sectors, timeline, what is rising, exposure counts. |
| POST | `/shell/close` | admin | End access now. Sessions already in the terminal end when the page is closed. |
| POST | `/shell/open` | admin | Allow this administrator's browser to reach the terminal for the next GRANT_HOURS. Audited. |
| GET | `/shell/status` | admin | Whether the server shell is available to this administrator, and if not, why. |
| GET | `/system/email-log` | analyst | The last 50 alert emails and whether each was delivered. |
| GET | `/system/health` | analyst | Health of the database, search index, queues and Tor gateway, crawl activity, email settings, collection policy flags and data-quality figures. |
| GET | `/system/settings` | admin | Settings an administrator can change here instead of `.env`, with the value in effect and where it comes from. |
| PUT | `/system/settings` | admin | Update console settings |
| POST | `/system/test-email` | admin | Queue a test message to one address. |
| GET | `/users` | admin | Every account with its role, state and whether two-step sign-in is on. |
| POST | `/users` | admin | Create an account. |
| GET | `/users/directory` | viewer | Names only, for assignment menus. |
| PATCH | `/users/{user_id}` | admin | Change a role, enable or disable, reset a password, or reset two-step sign-in. |

### ai

| Method | Path | Role | What it does |
|---|---|---|---|
| POST | `/ai/ask` | viewer | Answer a question from collected intelligence, with citations. |
| POST | `/ai/brief` | analyst | Draft an executive summary for a case, or a profile for an actor, from its findings. |
| GET | `/ai/jobs/{job_id}` | viewer | Progress and result of an AI request. Only its owner or an admin can read it. |
| GET | `/ai/status` | viewer | Whether the AI analyst is switched on, and the model in use. |
| POST | `/ai/summarize` | viewer | Summarise one finding. Returns the stored summary if there is one, otherwise starts a job. |

### attack

| Method | Path | Role | What it does |
|---|---|---|---|
| GET | `/attack/matrix` | viewer | ATT&CK techniques by tactic, with how often each appears in collected intelligence. |
| GET | `/attack/techniques/{technique_id}` | viewer | One ATT&CK technique: description, sub-techniques, findings tagged with it, and the groups and malware known to use it. |
| GET | `/entities/{entity_id}/duplicates` | viewer | Other entities of the same type whose name is very close: candidates for a merge. |
| POST | `/entities/{entity_id}/merge` | analyst | Resolve two records of the same real-world entity into one. The merged name becomes an alias. |
| GET | `/entities/{entity_id}/relationships` | viewer | Typed, sourced relationships of an entity, in both directions. |
| POST | `/relationships` | analyst | Record a relationship between two entities, with a confidence. The analyst is stored as its source. |
| DELETE | `/relationships/{relationship_id}` | analyst | Remove a relationship. |

### auth

| Method | Path | Role | What it does |
|---|---|---|---|
| POST | `/auth/login` | public | Sign in with email and password, plus a code when two-step sign-in is on. Sets the session cookie. Rate limited; five failures lock the account. |
| POST | `/auth/logout` | signed in | End the session. |
| GET | `/auth/me` | signed in | The signed-in user. |
| POST | `/auth/mfa/disable` | signed in | Turn two-step sign-in off. Needs the password and a current code or recovery code. |
| POST | `/auth/mfa/enable` | signed in | Confirm enrolment with a code from the authenticator app. Returns ten single-use recovery codes, once. |
| POST | `/auth/mfa/setup` | signed in | Start enrolment: issue a secret and its QR code. MFA is not active until a code is confirmed. |
| POST | `/auth/password` | signed in | Change your own password. |

### cases

| Method | Path | Role | What it does |
|---|---|---|---|
| GET | `/cases` | viewer | Every investigation with its status, priority, owner and item count. |
| POST | `/cases` | analyst | Open an investigation. |
| DELETE | `/cases/{case_id}` | admin | Delete an investigation. The findings themselves are kept. |
| GET | `/cases/{case_id}` | viewer | An investigation with its findings, the indicators and entities across them, preserved evidence, saved hunts, crawls and notes. |
| PATCH | `/cases/{case_id}` | analyst | Change title, summary, status, priority, sharing level (TLP) or owner. |
| POST | `/cases/{case_id}/items` | analyst | Attach a finding, indicator, entity, saved hunt (a query) or graph bookmark. |
| DELETE | `/cases/{case_id}/items/{item_id}` | analyst | Detach an item. |
| GET | `/cases/{case_id}/report` | viewer | Export: `format=html` (printable report), `json`, `csv` (indicators) or `stix` (STIX 2.1 bundle). |
| GET | `/cases/{case_id}/timeline` | viewer | Everything that happened in an investigation, in order: what the sources reported, what was collected, what alerted, and what analysts did. |

### chain

| Method | Path | Role | What it does |
|---|---|---|---|
| GET | `/chain/jobs/{job_id}` | viewer | Job |
| POST | `/chain/lookup` | analyst | Look an address up on-chain. Returns a job to poll; the result lands in the graph. |
| GET | `/chain/{address}` | viewer | A looked-up address, the flow around it, and where it appears in collected intelligence. |
| POST | `/chain/{address}/case` | analyst | Pin a wallet (and the trace rooted at it) to an investigation. |
| POST | `/chain/{address}/expand` | analyst | Look up the counterparties of an address that have not been looked up yet: the next hop. |

### exposure

| Method | Path | Role | What it does |
|---|---|---|---|
| GET | `/attack-surface` | viewer | Hosts discovered for owned assets, with open ports, known vulnerabilities and explained risk, plus a summary and the owned assets themselves. |
| POST | `/attack-surface/scan` | analyst | Start passive discovery for an owned asset: certificate logs, public DNS and scan-data lookups. Nothing is probed. |
| GET | `/exposures` | viewer | Exposed accounts and secrets; filter by kind, status, domain, text, or only those on domains you watch. |
| GET | `/exposures/export` | viewer | The same list as CSV. Never contains a secret. |
| POST | `/exposures/status` | analyst | Mark exposures open, remediated, ignored or false positive. |
| GET | `/vulnerabilities` | viewer | The vulnerability catalogue ranked by priority, exploit likelihood, recency, severity or mentions. |
| GET | `/vulnerabilities/{cve}` | viewer | One CVE: scores, why it ranks where it does, findings that mention it, related entities, and owned hosts reported with it. |

### findings

| Method | Path | Role | What it does |
|---|---|---|---|
| GET | `/findings/{doc_id}` | viewer | A finding in full: text, classification, explained risk, indicators, entities, versions, alerts, cases, duplicates, related findings, techniques, exposure records, verification. |
| PATCH | `/findings/{doc_id}` | analyst | Set triage status, tags, or mark as confirmed by an analyst. |
| GET | `/findings/{doc_id}/diff` | viewer | Line diff between two captures of the same finding. |
| POST | `/findings/{doc_id}/entities` | analyst | Attach a finding to an entity by hand, e.g. to a campaign an analyst is tracking. |
| DELETE | `/findings/{doc_id}/entities/{entity_id}` | analyst | Remove a wrongly attached entity from a finding. |
| GET | `/findings/{doc_id}/evidence` | viewer | Evidence record for a finding, with the hash chain re-verified on every request. |
| GET | `/findings/{doc_id}/versions/{version}` | viewer | The stored text of one capture. |
| GET | `/notes` | viewer | Notes on a finding, case, entity, indicator or source. |
| POST | `/notes` | analyst | Add a note. |
| DELETE | `/notes/{note_id}` | analyst | Delete your own note (admins: any). |

### integrations

| Method | Path | Role | What it does |
|---|---|---|---|
| GET | `-keys` | viewer | List api keys |
| POST | `-keys` | viewer | Create a key that acts as you, with your role. The key is shown once and only its hash is kept. |
| DELETE | `-keys/{key_id}` | viewer | Revoke api key |
| GET | `/integrations` | analyst | Alert destinations and the kinds available. |
| POST | `/integrations` | admin | Add an alert destination. Its token or webhook address is stored encrypted. |
| DELETE | `/integrations/{integration_id}` | admin | Remove a destination. |
| PATCH | `/integrations/{integration_id}` | admin | Change, pause or resume a destination. |
| GET | `/integrations/{integration_id}/deliveries` | analyst | The last 50 delivery attempts and their results. |
| POST | `/integrations/{integration_id}/test` | admin | Send a test alert. The outcome appears in the destination's deliveries. |
| PATCH | `/iocs/{ioc_id}` | analyst | Mark an indicator benign (a common service, not a threat) so it stops driving correlation. |
| POST | `/iocs/{ioc_id}/enrich` | analyst | Ask the configured providers about an indicator. The indicator itself is never contacted. |
| GET | `/iocs/{ioc_id}/enrichment` | viewer | What providers said about an indicator, the feeds that list it, and whether it is marked benign. |
| GET | `/providers` | viewer | Every enrichment provider and the AI analyst: whether it is switched on, where its key comes from, and how its last test went. |
| PUT | `/providers/anthropic/config` | admin | Choose the model the AI analyst uses, then test it. |
| GET | `/providers/tests/{job_id}` | analyst | Progress and result of a provider connection test. |
| DELETE | `/providers/{name}/key` | admin | Forget the key entered in the console. A key in .env, if there is one, comes back into force. |
| PUT | `/providers/{name}/key` | admin | Store a provider's API key (encrypted) and immediately test it against the provider. |
| POST | `/providers/{name}/test` | analyst | Make one real request to the provider and report whether it works. Poll the returned job for the answer. |

### intel

| Method | Path | Role | What it does |
|---|---|---|---|
| GET | `/entities` | viewer | Actors, organisations, malware, campaigns, incidents and techniques; filter by type and text. |
| POST | `/entities` | analyst | Create an actor, organisation, malware family or campaign. |
| GET | `/entities/{entity_id}` | viewer | An entity: profile, activity over time, findings, related entities, indicators, countries and sectors. |
| PATCH | `/entities/{entity_id}` | analyst | Edit name, aliases or description. |
| GET | `/entities/{entity_id}/patterns` | viewer | How an actor operates: tempo, weekdays, where it posts, how its targeting changes, and who reports on it. |
| GET | `/graph` | viewer | Relationship neighbourhood of an entity, indicator or finding. |
| GET | `/graph/path` | viewer | The shortest chains linking two entities or indicators, each hop with the finding or statement behind it. |
| GET | `/iocs` | viewer | Indicators; filter by type and text. |
| GET | `/iocs/{ioc_id}` | viewer | An indicator: where it appears with surrounding text, associated entities, and indicators seen with it. |
| GET | `/timeline` | viewer | Incidents over time by actor, and the victims, CVEs and indicators that connect them. |

### reports

| Method | Path | Role | What it does |
|---|---|---|---|
| GET | `/reports/executive` | viewer | A plain-language summary of a period for leadership: `format=html` (printable) or `json`. |

### research

| Method | Path | Role | What it does |
|---|---|---|---|
| GET | `/collection/status` | viewer | Tor connection, collectors answering, sources by state, queue depth, pages indexed, last collection, failed fetches, blocklist state and the policy in force. |
| GET | `/crawls` | viewer | Research crawls, newest first, with progress. |
| POST | `/crawls` | analyst | Start a research crawl from one URL. It stays on that site, reads text only, and follows links to the chosen depth. |
| GET | `/crawls/{job_id}` | viewer | A crawl and every page it has reached so far, with what led to each one. |
| POST | `/crawls/{job_id}/stop` | analyst | Stop queuing further pages for a crawl. Pages already being fetched finish. |
| GET | `/findings/{finding_id}/observations` | viewer | When this page was seen, when it changed, and whether it is still there. |
| POST | `/findings/{finding_id}/preserve` | analyst | Pin the current capture of a page into an investigation as evidence: the exact version, its hashes, who preserved it and when. |
| GET | `/research/home` | viewer | What a researcher needs on opening the workstation: what is new, what matched, what is being worked on, and whether collection is healthy. |
| GET | `/settings/collection` | viewer | The collection policy and research-crawl limits. |
| PUT | `/settings/collection` | admin | Change the collection policy or limits. Waiting sites are re-checked against the new policy. |
| GET | `/sources/suggest` | viewer | Known sites that are not being collected yet and whose name, title or discovery context matches: places a search has not reached. |
| GET | `/sources/{source_id}/profile` | viewer | Everything known about one source: what it is, when it has been up, what was found there and what it connects to. |

### rules

| Method | Path | Role | What it does |
|---|---|---|---|
| GET | `/rules` | viewer | Detection rules with how often each has fired. |
| POST | `/rules` | analyst | Create a detection rule from a search. |
| POST | `/rules/preview` | viewer | How a rule would have behaved: matches in the window, and the windows before it. |
| DELETE | `/rules/{rule_id}` | analyst | Delete a rule and its alerts. |
| PATCH | `/rules/{rule_id}` | analyst | Change, pause or resume a rule. |
| POST | `/rules/{rule_id}/run` | analyst | Evaluate a rule now instead of waiting for the five-minute cycle. |

### search

| Method | Path | Role | What it does |
|---|---|---|---|
| GET | `/meta` | viewer | Vocabularies the console needs to render filters and forms. |
| GET | `/saved-searches` | viewer | Your saved searches. |
| POST | `/saved-searches` | viewer | Save the current query and filters under a name. |
| DELETE | `/saved-searches/{search_id}` | viewer | Delete a saved search. |
| GET | `/search` | viewer | Search everything collected. Returns ranked results with highlights, why each matched, facets, a timeline, the sources carrying the results and how the query was understood. |
| GET | `/search/export` | viewer | Export up to 5,000 matching findings as CSV or JSON. |
| GET | `/search/suggest` | viewer | Type-ahead: operators, entities, indicators, countries and matching titles. |

### sources

| Method | Path | Role | What it does |
|---|---|---|---|
| GET | `/sources` | viewer | Sources, optionally through one of the explorer's views: new, offline, changed, referenced, relevant, valuable. |
| POST | `/sources` | analyst | Add a source by address. Added as a candidate unless `approve` is set. |
| POST | `/sources/discover` | analyst | Look up where ransomware groups publish and file their sites as candidates for review. |
| DELETE | `/sources/{source_id}` | admin | Delete a source that has no findings. One with findings can only be paused or blocked, so evidence is kept. |
| PATCH | `/sources/{source_id}` | analyst | Approve, pause or block a source, or change how it is crawled. |
| POST | `/sources/{source_id}/crawl` | analyst | Crawl an active source now. |
| GET | `/sources/{source_id}/log` | viewer | Recent fetches for a source: address, result, size, timing, what was new. |
| POST | `/sources/{source_id}/verify` | analyst | Check that the link is alive. Fetches the first bytes only and stores nothing. |

### taxii

| Method | Path | Role | What it does |
|---|---|---|---|
| POST | `/stix/import` | analyst | Absorb a STIX 2.1 bundle: actors, malware, campaigns, techniques, indicators and relationships. |
| GET | `/taxii2/` | viewer | TAXII 2.1 discovery document. |
| GET | `/taxii2/root/` | viewer | TAXII API root. |
| GET | `/taxii2/root/collections/` | viewer | The three collections: indicators, high-risk indicators, and actors/malware/techniques. |
| GET | `/taxii2/root/collections/{collection_id}/` | viewer | One collection. |
| GET | `/taxii2/root/collections/{collection_id}/manifest/` | viewer | Identifiers and dates of the objects in a collection. |
| GET | `/taxii2/root/collections/{collection_id}/objects/` | viewer | STIX 2.1 objects in a collection, paged; `added_after`, `limit` and `next` as in the TAXII specification. |

### tools

| Method | Path | Role | What it does |
|---|---|---|---|
| POST | `/tools/decode` | analyst | Undo obfuscation layer by layer and report what the decoded text does. Nothing is run. |
| POST | `/tools/headers` | analyst | Where an email came from and whether it is who it claims to be. Offline. |
| GET | `/tools/verdict` | viewer | Everything known about one indicator: collected intelligence, watchlists and provider answers. |
| POST | `/tools/verdict` | analyst | Ask the providers about an indicator now. Poll GET /tools/verdict for the answers as they arrive. |

### watch

| Method | Path | Role | What it does |
|---|---|---|---|
| GET | `/alerts` | viewer | The alert queue with counts by status, severity and category. Ordered by priority unless `sort=newest`. |
| POST | `/alerts/bulk` | analyst | Change the status of many alerts at once. |
| PATCH | `/alerts/{alert_id}` | analyst | Change an alert's status or assign it. |
| GET | `/watchlists` | viewer | Everything being watched, with open alert and match counts. |
| POST | `/watchlists` | analyst | Watch a value. Existing intelligence is checked at once; an owned domain or IP range also starts passive attack-surface discovery. |
| DELETE | `/watchlists/{watch_id}` | analyst | Stop watching. Its alerts are removed. |
| PATCH | `/watchlists/{watch_id}` | analyst | Change label, email settings, ownership, criticality, or pause it. |
| POST | `/watchlists/{watch_id}/hunt` | analyst | Re-check everything already collected against this entry. |

Every TAXII path also answers without its trailing slash, because reverse proxies often strip it.

### not in the OpenAPI schema

| Method | Path | Role | What it does |
|---|---|---|---|
| GET | `/docs` | public | Api docs |
| GET | `/healthz` | public | Liveness probe for the container. |
| GET | `/openapi.json` | viewer | Openapi schema |
| GET | `/metrics` | analyst | Prometheus exposition. Scrape with an API key: Authorization: Bearer <key>. |
| GET | `/shell/authorize` | public | Asked by Caddy (forward_auth) before every request to /shell. 204 lets it through. |

150 operations. The machine-readable schema is served at `/api/openapi.json` and an interactive view at `/api/docs`, to signed-in users and API keys.

## Data model

PostgreSQL is the system of record. Every table, with its columns. `PK` primary key, `FK` foreign key (with what happens on delete), `idx` indexed, `uniq` unique, `null` nullable.

### `alerts`

| Column | Type | Notes |
|---|---|---|
| `id` | bigint | PK |
| `watchlist_id` | integer | FK watchlists.id (cascade), idx, null |
| `document_id` | UUID | FK documents.id (cascade), idx, null |
| `rule_id` | integer | FK rules.id (cascade), idx, null |
| `title` | text |  |
| `priority` | integer | idx |
| `factors` | JSONB |  |
| `dedupe_key` | varchar(80) | null |
| `detail` | JSONB |  |
| `category` | varchar(16) |  |
| `reason` | varchar(16) |  |
| `matched` | text |  |
| `snippet` | text |  |
| `severity` | varchar(16) | idx |
| `risk_score` | integer |  |
| `status` | varchar(16) | idx |
| `assigned_to` | integer | null |
| `created_at` | DATETIME | idx |
| `notified_at` | DATETIME | null |
| `resolved_at` | DATETIME | null |

unique (watchlist_id, document_id).

### `api_keys`

| Column | Type | Notes |
|---|---|---|
| `id` | integer | PK |
| `user_id` | integer | FK users.id (cascade), idx |
| `name` | varchar(120) |  |
| `prefix` | varchar(16) | idx |
| `key_hash` | varchar(64) | uniq |
| `scopes` | ARRAY |  |
| `created_at` | DATETIME |  |
| `last_used_at` | DATETIME | null |
| `expires_at` | DATETIME | null |
| `revoked` | boolean |  |

### `app_settings`

A setting an administrator changes in the console (collection policy and limits).

| Column | Type | Notes |
|---|---|---|
| `key` | varchar(64) | PK |
| `value` | JSONB |  |
| `updated_by` | integer | null |
| `updated_at` | DATETIME |  |

### `assets`

An internet-facing host discovered passively for an owned domain or range.

| Column | Type | Notes |
|---|---|---|
| `id` | integer | PK |
| `watchlist_id` | integer | FK watchlists.id (cascade), idx |
| `host` | varchar(255) |  |
| `ips` | ARRAY |  |
| `ports` | ARRAY |  |
| `cpes` | ARRAY |  |
| `tags` | ARRAY |  |
| `vulns` | ARRAY |  |
| `asn` | varchar(160) |  |
| `discovered_via` | varchar(40) |  |
| `risk` | integer | idx |
| `risk_factors` | JSONB |  |
| `first_seen_at` | DATETIME |  |
| `last_seen_at` | DATETIME |  |
| `last_scanned_at` | DATETIME | null |
| `meta` | JSONB |  |

unique (watchlist_id, host).

### `audit_log`

| Column | Type | Notes |
|---|---|---|
| `id` | bigint | PK |
| `ts` | DATETIME | idx |
| `user_id` | integer | null |
| `user_email` | varchar(254) |  |
| `action` | varchar(64) | idx |
| `object_type` | varchar(32) |  |
| `object_id` | varchar(64) |  |
| `ip` | varchar(64) |  |
| `detail` | JSONB |  |

### `case_items`

| Column | Type | Notes |
|---|---|---|
| `id` | integer | PK |
| `case_id` | integer | FK cases.id (cascade), idx |
| `object_type` | varchar(16) |  |
| `object_id` | varchar(64) |  |
| `note` | text |  |
| `added_by` | integer | null |
| `added_at` | DATETIME |  |

unique (case_id, object_type, object_id).

### `cases`

| Column | Type | Notes |
|---|---|---|
| `id` | integer | PK |
| `title` | varchar(300) |  |
| `description` | text |  |
| `status` | varchar(16) |  |
| `priority` | varchar(16) |  |
| `tlp` | varchar(16) |  |
| `owner_id` | integer | null |
| `created_by` | integer | null |
| `created_at` | DATETIME |  |
| `updated_at` | DATETIME |  |
| `closed_at` | DATETIME | null |

### `chain_addresses`

A cryptocurrency address the platform has looked up on-chain. Global, like an indicator.

| Column | Type | Notes |
|---|---|---|
| `address` | varchar(128) | PK |
| `chain` | varchar(8) | idx |
| `token` | varchar(32) |  |
| `label` | varchar(160) |  |
| `category` | varchar(24) | idx |
| `balance` | FLOAT |  |
| `total_in` | FLOAT |  |
| `total_out` | FLOAT |  |
| `tx_count` | integer |  |
| `counterparty_count` | integer |  |
| `first_tx_at` | DATETIME | null |
| `last_tx_at` | DATETIME | null |
| `truncated` | boolean |  |
| `in_intel` | boolean |  |
| `co_spent` | ARRAY |  |
| `enriched_at` | DATETIME | null |
| `error` | text |  |
| `created_at` | DATETIME |  |

### `chain_edges`

A flow of value between two addresses, aggregated over the transactions examined.

| Column | Type | Notes |
|---|---|---|
| `id` | bigint | PK |
| `chain` | varchar(8) | idx |
| `src` | varchar(128) | idx |
| `dst` | varchar(128) | idx |
| `value` | FLOAT |  |
| `tx_count` | integer |  |
| `sample_txid` | varchar(80) |  |
| `first_seen_at` | DATETIME | null |
| `last_seen_at` | DATETIME | null |

unique (chain, src, dst).

### `crawl_jobs`

A research crawl a researcher started from one URL: its limits, who asked, and how it ended.

| Column | Type | Notes |
|---|---|---|
| `id` | integer | PK |
| `source_id` | integer | FK sources.id (cascade), idx |
| `url` | varchar(2048) |  |
| `run_id` | varchar(36) | uniq |
| `depth` | integer |  |
| `max_pages` | integer |  |
| `status` | varchar(16) | idx |
| `note` | text |  |
| `case_id` | integer | null |
| `created_by` | integer | null |
| `created_at` | DATETIME | idx |
| `finished_at` | DATETIME | null |

### `crawl_log`

| Column | Type | Notes |
|---|---|---|
| `id` | bigint | PK |
| `run_id` | varchar(36) | idx |
| `source_id` | integer | FK sources.id (cascade), idx |
| `url` | varchar(2048) |  |
| `depth` | integer |  |
| `probe` | boolean |  |
| `fetched_at` | DATETIME | idx |
| `ok` | boolean |  |
| `http_status` | integer | null |
| `bytes` | integer |  |
| `elapsed_ms` | integer |  |
| `error` | text |  |
| `new_docs` | integer |  |
| `changed_docs` | integer |  |
| `unchanged_docs` | integer |  |
| `dropped_docs` | integer |  |
| `parent_url` | varchar(2048) |  |

### `deliveries`

| Column | Type | Notes |
|---|---|---|
| `id` | bigint | PK |
| `integration_id` | integer | FK integrations.id (cascade), idx |
| `alert_id` | bigint | FK alerts.id (cascade), null |
| `ts` | DATETIME | idx |
| `ok` | boolean |  |
| `status_code` | integer | null |
| `error` | text |  |

unique (integration_id, alert_id).

### `document_entities`

| Column | Type | Notes |
|---|---|---|
| `document_id` | UUID | PK, FK documents.id (cascade) |
| `entity_id` | integer | PK, FK entities.id (cascade), idx |
| `role` | varchar(16) |  |
| `confidence` | integer |  |

### `document_iocs`

| Column | Type | Notes |
|---|---|---|
| `document_id` | UUID | PK, FK documents.id (cascade) |
| `ioc_id` | bigint | PK, FK iocs.id (cascade), idx |
| `count` | integer |  |
| `context` | text |  |

### `document_tags`

| Column | Type | Notes |
|---|---|---|
| `document_id` | UUID | PK, FK documents.id (cascade) |
| `tag_id` | integer | PK, FK tags.id (cascade), idx |

### `document_versions`

Immutable capture of a finding. Rows form a per-document hash chain.

| Column | Type | Notes |
|---|---|---|
| `id` | bigint | PK |
| `document_id` | UUID | FK documents.id (cascade), idx |
| `version` | integer |  |
| `captured_at` | DATETIME |  |
| `url` | varchar(2048) |  |
| `title` | text |  |
| `content` | text |  |
| `content_sha256` | varchar(64) |  |
| `raw_sha256` | varchar(64) |  |
| `http_status` | integer | null |
| `headers` | JSONB |  |
| `bytes` | integer |  |
| `prev_chain_hash` | varchar(64) |  |
| `chain_hash` | varchar(64) |  |
| `signature` | varchar(64) |  |
| `change` | JSONB |  |

unique (document_id, version).

### `documents`

A finding: one page, post or feed item, tracked across every capture.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | PK |
| `doc_key` | varchar(64) | uniq |
| `source_id` | integer | FK sources.id (cascade), idx |
| `url` | varchar(2048) |  |
| `host` | varchar(255) |  |
| `network` | varchar(16) |  |
| `title` | text |  |
| `summary` | text |  |
| `content` | text |  |
| `content_sha256` | varchar(64) | idx |
| `raw_sha256` | varchar(64) |  |
| `simhash` | bigint |  |
| `sh0` | integer |  |
| `sh1` | integer |  |
| `sh2` | integer |  |
| `sh3` | integer |  |
| `lang` | varchar(8) |  |
| `threat_type` | varchar(32) | idx |
| `threat_types` | ARRAY |  |
| `severity` | varchar(16) | idx |
| `risk_score` | integer | idx |
| `risk_factors` | JSONB |  |
| `confidence` | integer |  |
| `countries` | ARRAY |  |
| `sectors` | ARRAY |  |
| `has_credentials` | boolean |  |
| `exposure` | JSONB |  |
| `status` | varchar(16) | idx |
| `duplicate_of` | UUID | idx, null |
| `first_seen_at` | DATETIME | idx |
| `last_seen_at` | DATETIME |  |
| `last_changed_at` | DATETIME |  |
| `published_at` | DATETIME | null |
| `version_count` | integer |  |
| `meta` | JSONB |  |
| `verification` | varchar(16) |  |
| `corroboration` | integer |  |
| `techniques` | ARRAY |  |
| `ai_summary` | text |  |

### `email_log`

| Column | Type | Notes |
|---|---|---|
| `id` | bigint | PK |
| `ts` | DATETIME | idx |
| `kind` | varchar(16) |  |
| `recipients` | ARRAY |  |
| `subject` | text |  |
| `alert_count` | integer |  |
| `ok` | boolean |  |
| `error` | text |  |

### `enrichments`

What a third-party provider said about an indicator. The indicator itself is never contacted.

| Column | Type | Notes |
|---|---|---|
| `id` | bigint | PK |
| `subject_type` | varchar(16) |  |
| `subject` | varchar(1024) |  |
| `provider` | varchar(32) |  |
| `fetched_at` | DATETIME |  |
| `ok` | boolean |  |
| `verdict` | varchar(16) |  |
| `score` | integer | null |
| `summary` | JSONB |  |
| `error` | text |  |

unique (subject_type, subject, provider).

### `entities`

| Column | Type | Notes |
|---|---|---|
| `id` | integer | PK |
| `type` | varchar(16) | idx |
| `name` | varchar(300) |  |
| `slug` | varchar(300) |  |
| `aliases` | ARRAY |  |
| `description` | text |  |
| `curated` | boolean |  |
| `first_seen_at` | DATETIME | null |
| `last_seen_at` | DATETIME | null |
| `doc_count` | integer |  |
| `meta` | JSONB |  |

unique (type, slug).

### `exposures`

One exposed identity or secret seen in a finding. The secret itself is never stored.

| Column | Type | Notes |
|---|---|---|
| `id` | bigint | PK |
| `document_id` | UUID | FK documents.id (cascade), idx |
| `kind` | varchar(16) | idx |
| `identity` | varchar(320) |  |
| `domain` | varchar(255) | idx |
| `service` | varchar(255) |  |
| `secret_type` | varchar(40) |  |
| `fingerprint` | varchar(24) |  |
| `password_exposed` | boolean |  |
| `status` | varchar(16) | idx |
| `first_seen_at` | DATETIME |  |
| `last_seen_at` | DATETIME |  |

unique (document_id, kind, identity, service, fingerprint).

### `integrations`

An outbound destination for alerts: webhook, chat, SIEM or ticketing.

| Column | Type | Notes |
|---|---|---|
| `id` | integer | PK |
| `name` | varchar(120) |  |
| `kind` | varchar(24) |  |
| `url` | varchar(1024) |  |
| `config` | JSONB |  |
| `secret` | text |  |
| `min_severity` | varchar(16) |  |
| `categories` | ARRAY |  |
| `is_active` | boolean |  |
| `last_delivery_at` | DATETIME | null |
| `last_error` | text |  |
| `failures` | integer |  |
| `created_by` | integer | null |
| `created_at` | DATETIME |  |

### `iocs`

| Column | Type | Notes |
|---|---|---|
| `id` | bigint | PK |
| `type` | varchar(16) | idx |
| `value` | varchar(1024) |  |
| `first_seen_at` | DATETIME |  |
| `last_seen_at` | DATETIME |  |
| `doc_count` | integer |  |
| `tags` | ARRAY |  |
| `feeds` | ARRAY |  |
| `benign` | boolean |  |

unique (type, value).

### `notes`

| Column | Type | Notes |
|---|---|---|
| `id` | integer | PK |
| `object_type` | varchar(16) |  |
| `object_id` | varchar(64) |  |
| `user_id` | integer | null |
| `user_name` | varchar(120) |  |
| `body` | text |  |
| `created_at` | DATETIME |  |

### `provider_keys`

An enrichment or AI provider configured from the console: its API key (encrypted), settings and last connection test.

| Column | Type | Notes |
|---|---|---|
| `name` | varchar(32) | PK |
| `secret` | text |  |
| `hint` | varchar(8) |  |
| `config` | JSONB |  |
| `updated_by` | integer | null |
| `updated_at` | DATETIME | null |
| `last_test_at` | DATETIME | null |
| `last_test_ok` | boolean | null |
| `last_test_message` | text |  |
| `last_test_detail` | JSONB |  |

### `relationships`

A typed, sourced edge between two entities (actor uses technique, ...).

| Column | Type | Notes |
|---|---|---|
| `id` | integer | PK |
| `src_id` | integer | FK entities.id (cascade), idx |
| `dst_id` | integer | FK entities.id (cascade), idx |
| `kind` | varchar(24) |  |
| `confidence` | integer |  |
| `source` | varchar(120) |  |
| `first_seen_at` | DATETIME |  |
| `last_seen_at` | DATETIME |  |
| `meta` | JSONB |  |

unique (src_id, dst_id, kind).

### `rules`

A detection rule over the intelligence stream: any search can become an alert.

| Column | Type | Notes |
|---|---|---|
| `id` | integer | PK |
| `name` | varchar(200) |  |
| `kind` | varchar(16) |  |
| `query` | text |  |
| `threshold` | integer |  |
| `window_hours` | integer |  |
| `severity` | varchar(16) |  |
| `notify_mode` | varchar(16) |  |
| `recipients` | ARRAY |  |
| `is_active` | boolean |  |
| `match_count` | integer |  |
| `last_run_at` | DATETIME | null |
| `last_triggered_at` | DATETIME | null |
| `created_by` | integer | null |
| `created_at` | DATETIME |  |

### `saved_searches`

| Column | Type | Notes |
|---|---|---|
| `id` | integer | PK |
| `user_id` | integer | FK users.id (cascade), idx |
| `name` | varchar(200) |  |
| `query` | text |  |
| `params` | JSONB |  |
| `created_at` | DATETIME |  |

### `source_links`

Source A links to host B: the map of which dark-web sites reference which.

| Column | Type | Notes |
|---|---|---|
| `id` | bigint | PK |
| `src_source_id` | integer | FK sources.id (cascade), idx |
| `dst_host` | varchar(255) | idx |
| `first_seen_at` | DATETIME |  |
| `last_seen_at` | DATETIME |  |
| `count` | integer |  |

unique (src_source_id, dst_host).

### `sources`

| Column | Type | Notes |
|---|---|---|
| `id` | integer | PK |
| `name` | varchar(200) |  |
| `url` | varchar(1024) | uniq |
| `host` | varchar(255) | idx |
| `network` | varchar(16) |  |
| `connector` | varchar(32) |  |
| `route` | varchar(16) |  |
| `category` | varchar(32) |  |
| `status` | varchar(16) | idx |
| `trust` | integer |  |
| `reliability` | varchar(1) |  |
| `crawl_interval_minutes` | integer |  |
| `max_depth` | integer |  |
| `max_pages` | integer |  |
| `config` | JSONB |  |
| `is_live` | boolean | null |
| `last_checked_at` | DATETIME | null |
| `last_live_at` | DATETIME | null |
| `last_crawled_at` | DATETIME | null |
| `last_http_status` | integer | null |
| `last_error` | text |  |
| `consecutive_failures` | integer |  |
| `doc_count` | integer |  |
| `discovered_from_id` | integer | FK sources.id (set null), null |
| `discovery_context` | text |  |
| `notes` | text |  |
| `title` | text |  |
| `language` | varchar(8) |  |
| `relevance` | integer |  |
| `last_changed_at` | DATETIME | null |
| `created_by` | integer | null |
| `created_at` | DATETIME |  |
| `updated_at` | DATETIME |  |

### `tags`

| Column | Type | Notes |
|---|---|---|
| `id` | integer | PK |
| `name` | varchar(64) | uniq |

### `users`

| Column | Type | Notes |
|---|---|---|
| `id` | integer | PK |
| `email` | varchar(254) | uniq |
| `name` | varchar(120) |  |
| `password_hash` | varchar(255) |  |
| `role` | varchar(16) |  |
| `is_active` | boolean |  |
| `failed_logins` | integer |  |
| `locked_until` | DATETIME | null |
| `last_login_at` | DATETIME | null |
| `created_at` | DATETIME |  |
| `mfa_enabled` | boolean |  |
| `mfa_secret` | text |  |
| `recovery_codes` | ARRAY |  |

### `vulnerabilities`

| Column | Type | Notes |
|---|---|---|
| `cve` | varchar(24) | PK |
| `title` | text |  |
| `vendor` | varchar(200) |  |
| `product` | varchar(200) |  |
| `description` | text |  |
| `cvss` | FLOAT | null |
| `cvss_vector` | varchar(120) |  |
| `epss` | FLOAT | null |
| `epss_percentile` | FLOAT | null |
| `kev` | boolean | idx |
| `kev_added` | DATE | null |
| `kev_due` | DATE | null |
| `ransomware_use` | boolean |  |
| `mention_count` | integer |  |
| `last_mentioned_at` | DATETIME | null |
| `exposed_assets` | integer |  |
| `priority` | integer | idx |
| `priority_factors` | JSONB |  |
| `enriched_at` | DATETIME | null |
| `updated_at` | DATETIME |  |

### `watchlists`

| Column | Type | Notes |
|---|---|---|
| `id` | integer | PK |
| `name` | varchar(200) |  |
| `kind` | varchar(16) |  |
| `value` | varchar(500) |  |
| `description` | text |  |
| `is_active` | boolean |  |
| `min_severity` | varchar(16) |  |
| `notify_mode` | varchar(16) |  |
| `recipients` | ARRAY |  |
| `match_count` | integer |  |
| `last_matched_at` | DATETIME | null |
| `created_by` | integer | null |
| `created_at` | DATETIME |  |
| `is_asset` | boolean |  |
| `criticality` | integer |  |
| `org` | varchar(120) |  |
| `last_scanned_at` | DATETIME | null |

## Configuration

Environment settings, read from `.env` by `./ctl.sh` and passed to the containers that need them. Each container receives only its own. Secrets are generated on first start. Settings marked *console* can also be changed in the console, which then takes precedence.

| Variable | Default | What it controls |
|---|---|---|
| `APP_NAME` | `Kivuli` | Name shown in the console and in alert email. |
| `ROLE` | `api` | Which role a backend container plays (api, crawler, pipeline, enricher, notify, beat, egress). Set by docker-compose, not by you. |
| `PUBLIC_URL` | `http://localhost:28941` | Address researchers use to reach the console. Links in alert email and the TAXII discovery document point here. |
| `DATABASE_URL` | *empty* | PostgreSQL connection. Built by docker-compose from POSTGRES_PASSWORD. |
| `OPENSEARCH_URL` | `http://search:9200` | Search node address. |
| `OPENSEARCH_USER` | *empty* | Search node user, if it has authentication. |
| `OPENSEARCH_PASSWORD` | *empty* | Search node password, if it has authentication. |
| `OPENSEARCH_INDEX` | `kivuli-findings` | Name of the findings index. |
| `REDIS_URL` | `redis://redis:6379/0` | Queue and cache connection. Built by docker-compose from REDIS_PASSWORD. |
| `JWT_SECRET` | *generated* | Signs session cookies. Generated. |
| `SESSION_TTL_MINUTES` | `480` | How long a console session lasts. |
| `COOKIE_SECURE` | `False` | Set to true when the console is served over HTTPS. |
| `SHELL_ENABLED` | `False` |  |
| `SHELL_SSH_HOST` | `host.docker.internal` |  |
| `SHELL_SSH_PORT` | `22` |  |
| `RATE_LIMIT_PER_MINUTE` | `300` | API requests allowed per client address per minute. |
| `LOGIN_RATE_LIMIT_PER_MINUTE` | `10` | Sign-in attempts allowed per client address per minute. |
| `BOOTSTRAP_ADMIN_EMAIL` | *empty* | First administrator, created once when there are no users. |
| `BOOTSTRAP_ADMIN_PASSWORD` | *generated* | That administrator's initial password. Generated. |
| `EVIDENCE_HMAC_KEY` | *generated* | Signs the evidence chain. Generated. Back it up: without it stored evidence cannot be verified. |
| `EVIDENCE_STORE_RAW` | `False` | Also keep the unredacted capture on the evidence volume. Off: turning it on makes the system a store of stolen credentials. |
| `EVIDENCE_DIR` | `/evidence` | Where raw captures are written inside the container. |
| `REDACT_SECRETS` | `True` | Mask passwords, keys and card numbers before anything is stored, indexed or emailed. |
| `TOR_SOCKS_URL` | `socks5h://tor:9050` | The Tor gateway's SOCKS address. |
| `EGRESS_PROXY_URL` | `http://egress:8888` | The allow-listing egress proxy. |
| `RENDER_URL` | `http://render:9300` | The JavaScript renderer (crawler only). |
| `RENDER_TIMEOUT_SECONDS` | `90` | Seconds allowed to render one page in the headless browser. |
| `TOR_USER_AGENT` | `Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0` | User-Agent sent through Tor (that of Tor Browser, so the crawler does not stand out). |
| `DIRECT_USER_AGENT` | `Kivuli-TI/1.0 (defensive threat-intelligence collection)` | User-Agent sent to clearnet feeds and providers (identifies the platform honestly). |
| `CRAWL_MAX_BYTES` | `2000000` | Largest page body read. Larger responses are cut off. |
| `CRAWL_TIMEOUT_SECONDS` | `75` | Longest wait for one page. |
| `CRAWL_HOST_DELAY_SECONDS` | `3.0` | Pause between two requests to the same host, across all crawler processes. |
| `CRAWL_MAX_REDIRECTS` | `3` | Redirect hops followed. Each must stay on the same site and is re-validated. |
| `EGRESS_ALLOW_HOSTS` | *empty* | Clearnet hosts that may be reached directly over HTTPS. Everything else, and every onion site, goes through Tor. A leading dot allows subdomains. Deliberately not editable in the console. |
| `FOCUS_COUNTRIES` | `KE` | ISO country codes you care most about. Findings about them score higher. |
| `DISCOVER_ONION_LINKS` | `True` | Record onion sites linked from crawled pages as discovered sources. |
| `MAX_CANDIDATES_PER_CRAWL` | `25` | Most discovered sources filed from one page. |
| `LIVENESS_INTERVAL_HOURS` | `12` | How often discovered and paused sources are re-checked. |
| `EMAIL_ENABLED` | `True` | Send alert email at all. |
| `SMTP_HOST` | `mailpit` | Mail relay. The bundled test inbox by default. |
| `MAILPIT_PORT` | `28942` |  |
| `SMTP_PORT` | `1025` | Mail relay port. |
| `SMTP_USERNAME` | *empty* | Mail relay user. |
| `SMTP_PASSWORD` | *empty* | Mail relay password. |
| `SMTP_TLS` | `none` | none, starttls or ssl. |
| `SMTP_FROM` | `Kivuli Alerts <alerts@kivuli.local>` | Sender shown on alert email. |
| `ALERT_EMAIL_TO` | *empty* | Default recipients for watchlists and rules that name none. |
| `DIGEST_HOUR_UTC` | `6` | Hour at which daily digests are sent. |
| `EMAIL_MAX_ALERTS_PER_MESSAGE` | `25` | Alerts batched into one message. |
| `SECRETS_KEY` | *generated* | Encrypts alert-destination credentials and two-step sign-in seeds in the database. Generated. Back it up. |
| `PROVIDER_KEYS_KEY` | *generated* | Encrypts provider API keys entered in the console. Held only by the api and enricher containers. Generated. Back it up. |
| `REQUIRE_MFA` | `False` | Prompt administrators who have not enrolled two-step sign-in. |
| `FOCUS_SECTORS` | *empty* | Industries you care most about, as trackers name them. |
| `INTEGRATIONS_ALLOW_PRIVATE` | `False` | Allow alert destinations on private addresses (an internal SIEM). Off so the console cannot be pointed at internal services by mistake. |
| `VIRUSTOTAL_API_KEY` | *empty* | VirusTotal key. *Also settable in the console.* |
| `SHODAN_API_KEY` | *empty* | Shodan key. *Also settable in the console.* |
| `ABUSEIPDB_API_KEY` | *empty* | AbuseIPDB key. *Also settable in the console.* |
| `GREYNOISE_API_KEY` | *empty* | GreyNoise key. *Also settable in the console.* |
| `NVD_API_KEY` | *empty* | Optional NVD key; raises the rate limit. *Also settable in the console.* |
| `DWI_API_KEY` | *empty* |  |
| `DWI_BASE_URL` | `https://api.darkwebinformer.com` |  |
| `INTELOWL_URL` | *empty* |  |
| `INTELOWL_API_KEY` | *empty* |  |
| `INTELOWL_DIRECT` | `False` |  |
| `INTELOWL_PLAYBOOK` | `FREE_TO_USE_ANALYZERS` |  |
| `INTELOWL_ANALYZERS` | *empty* |  |
| `INTELOWL_TLP` | `AMBER` |  |
| `ANTHROPIC_API_KEY` | *empty* | Anthropic key; switches the AI analyst on. *Also settable in the console.* |
| `AI_MODEL` | `claude-opus-5-5` | Model the AI analyst uses. *Also settable in the console.* |
| `ASM_MAX_HOSTS` | `300` | Most hosts tracked per owned domain. |
| `ASM_INTERVAL_DAYS` | `7` | How often owned assets are re-checked. |

Read only by docker-compose and `ctl.sh`, not by the application:

| Variable | Default | What it controls |
|---|---|---|
| `POSTGRES_PASSWORD` | *generated* | Database password. |
| `REDIS_PASSWORD` | *generated* | Queue password. |
| `WEB_PORT` | `28941` | Port the console is published on, on 127.0.0.1 only. |
| `MAILPIT_PORT` | `28942` | Port of the bundled test inbox, on 127.0.0.1 only. |
| `SEARCH_HEAP` | `768m` | Memory given to the search node. |
| `CRAWLER_CONCURRENCY` | `6` | Simultaneous fetches. |
| `PIPELINE_CONCURRENCY` | `4` | Simultaneous pages being processed. |

### Settings changed in the console

Stored in the `app_settings` table (collection policy) and `provider_keys` table (provider keys and the AI model).

| Setting | Default | Allowed |
|---|---|---|
| `collection.auto_approve` | `leak_sites` | manual / leak_sites / relevant |
| `collection.relevance_threshold` | `4` | 1 to 10 |
| `collection.max_onion_sources` | `400` | 0 to 5000 |
| `collection.discovery_groups_per_run` | `10` | 1 to 40 |
| `collection.research_max_depth` | `4` | 1 to 6 |
| `collection.research_max_pages` | `300` | 5 to 2000 |

## Scheduled work and tasks

The `beat` container fires these; the named worker role runs them.

| Schedule | Task | Runs in |
|---|---|---|
| every 300 s | `crawl.tor_check` | crawler |
| every 600 s | `enrich.status` | enricher |
| every 60 s | `notify.dispatch_alerts` | notify |
| every 60 s | `notify.dispatch_integrations` | notify |
| cron: minute 0, hour * UTC | `notify.send_digest` | notify |
| every 3600 s | `pipeline.asm_sweep` | pipeline |
| cron: minute 20, hour 3 UTC | `pipeline.discover_sources` | pipeline |
| every 300 s | `pipeline.evaluate_rules` | pipeline |
| every 1800 s | `pipeline.liveness_sweep` | pipeline |
| every 3600 s | `pipeline.refresh_vulnerabilities` | pipeline |
| every 60 s | `pipeline.schedule_due` | pipeline |
| every 300 s | `pipeline.sync_provider_keys` | pipeline |

Task routing: `crawl.*` → queue `crawl`, `pipeline.*` → queue `pipeline`, `notify.*` → queue `notify`, `enrich.*` → queue `enrich`, `ai.*` → queue `enrich`, `chain.*` → queue `enrich`.

## Enumerations

### Threat types

| Value | Meaning |
|---|---|
| `ransomware` | Ransomware / extortion |
| `data_breach` | Data breach / leak |
| `credential_leak` | Credential exposure |
| `access_sale` | Initial access sale |
| `defacement` | Compromised / defaced site |
| `malware` | Malware |
| `phishing` | Phishing |
| `ddos` | DDoS |
| `vulnerability` | Vulnerability / exploit |
| `fraud` | Fraud / carding |
| `hacktivism` | Hacktivism |
| `other` | Other |

### Other fixed values

- **Severities:** `info`, `low`, `medium`, `high`, `critical`
- **Finding statuses:** `new`, `triaged`, `escalated`, `dismissed`
- **Alert statuses:** `open`, `acknowledged`, `resolved`, `false_positive`
- **Source statuses:** `candidate`, `approved`, `paused`, `blocked`
- **Indicator types:** `domain`, `onion`, `url`, `ip`, `email`, `hash`, `cve`, `crypto`, `username`, `tox`, `session`, `matrix`, `discord`, `jabber`, `edb`
- **Entity types:** `actor`, `organization`, `malware`, `campaign`, `incident`, `technique`
- **Watchlist kinds:** `keyword`, `domain`, `email`, `ip`, `organization`, `actor`, `cve`, `hash`, `crypto`, `username`, `brand`, `technology`, `vendor`, `executive`
- **Verification states:** `unverified`, `reported`, `corroborated`, `confirmed`
- **Relationship kinds:** `uses`, `targets`, `attributed_to`, `exploits`, `delivers`, `related_to`
- **Exposure kinds:** `credential`, `stealer_log`, `api_key`, `token`, `private_key`, `cloud_secret`, `card`
- **Exposure statuses:** `open`, `remediated`, `ignored`, `false_positive`
- **Rule kinds:** `query`, `threshold`, `spike`
- **Crawl job statuses:** `running`, `done`, `stopped`, `failed`
- **User roles:** `viewer`, `analyst`, `admin`

### Source connectors

| Value | Meaning |
|---|---|
| `html` | Web page (crawled) |
| `rss` | RSS / Atom feed |
| `ransomware_live` | Ransomware.live API |
| `ransomlook_recent` | RansomLook recent posts API |
| `ransomlook_group` | RansomLook group profile (source discovery) |
| `cisa_kev` | CISA Known Exploited Vulnerabilities |
| `telegram_public` | Public Telegram channel |
| `ioc_feed` | Indicator feed (plain text list) |
| `onion_blocklist` | Safety blocklist (hashes of banned onion services) |
| `deepdark_catalog` | deepdarkCTI source catalogue (discovers sources) |

### Alert destinations

| Value | Meaning |
|---|---|
| `webhook` | Generic webhook (signed JSON) |
| `slack` | Slack incoming webhook |
| `teams` | Microsoft Teams workflow webhook |
| `splunk_hec` | Splunk HTTP Event Collector |
| `jira` | Jira issue |
| `servicenow` | ServiceNow incident |

### Source reliability (Admiralty letter)

| Grade | Meaning |
|---|---|
| `A` | Completely reliable |
| `B` | Usually reliable |
| `C` | Fairly reliable |
| `D` | Not usually reliable |
| `E` | Unreliable |
| `F` | Reliability cannot be judged |

### Information credibility (Admiralty digit)

| Grade | Meaning |
|---|---|
| `1` | Confirmed by other sources |
| `2` | Probably true |
| `3` | Possibly true |
| `4` | Doubtful |
| `5` | Improbable |
| `6` | Truth cannot be judged |

### Verification states

| State | Meaning |
|---|---|
| `unverified` | Unverified: single source of unknown or low reliability |
| `reported` | Reported: stated by an established source, not yet corroborated |
| `corroborated` | Corroborated: independently seen by more than one source |
| `confirmed` | Confirmed: validated by an analyst |

### Enrichment providers

| Provider | Tier | Asks about | Hosts contacted | Key setting |
|---|---|---|---|---|
| Shodan InternetDB | free | ip | internetdb.shodan.io | - |
| RIPEstat | free | ip | stat.ripe.net | - |
| Public DNS | free | domain | dns.google | - |
| Certificate transparency | free | domain | api.certspotter.com, crt.sh | - |
| Wayback Machine | free | domain, url | web.archive.org | - |
| FIRST EPSS | free | cve | api.first.org | - |
| NVD | free (key optional) | cve | services.nvd.nist.gov | `NVD_API_KEY` |
| VirusTotal | commercial | ip, domain, url, hash | www.virustotal.com | `VIRUSTOTAL_API_KEY` |
| Shodan | commercial | ip | api.shodan.io | `SHODAN_API_KEY` |
| AbuseIPDB | commercial | ip | api.abuseipdb.com | `ABUSEIPDB_API_KEY` |
| GreyNoise | commercial | ip | api.greynoise.io | `GREYNOISE_API_KEY` |
| Dark Web Informer | commercial |  | api.darkwebinformer.com | `DWI_API_KEY` |
| IntelOwl | commercial | ip, domain, url, hash | - | `INTELOWL_API_KEY` |
| Have I Been Pwned | planned | email, domain | - | - |
| urlscan.io | planned | url, domain | - | - |
| SecurityTrails | planned | domain, ip | - | - |
| Censys | planned | ip, domain | - | - |

### Search operators and their aliases

| Operator | Accepted spellings |
|---|---|
| `actor:` | `actor:`, `gang:`, `group:`, `threat_actor:` |
| `after:` | `after:`, `since:` |
| `before:` | `before:`, `until:` |
| `campaign:` | `campaign:` |
| `category:` | `category:`, `kind:` |
| `confidence:` | `conf:`, `confidence:` |
| `country:` | `country:`, `geo:` |
| `crypto:` | `btc:`, `crypto:`, `eth:`, `wallet:` |
| `cve:` | `cve:` |
| `discord:` | `discord:` |
| `domain:` | `domain:` |
| `edb:` | `edb:`, `exploitdb:` |
| `email:` | `email:` |
| `has:` | `has:` |
| `hash:` | `hash:`, `md5:`, `sha1:`, `sha256:` |
| `host:` | `host:`, `site:` |
| `inurl:` | `inurl:` |
| `ioc:` | `ioc:` |
| `ip:` | `ip:` |
| `jabber:` | `jabber:`, `xmpp:` |
| `lang:` | `lang:`, `language:` |
| `malware:` | `family:`, `malware:` |
| `matrix:` | `matrix:` |
| `network:` | `net:`, `network:` |
| `onion:` | `onion:` |
| `organization:` | `company:`, `org:`, `organisation:`, `organization:`, `victim:` |
| `regex:` | `re:`, `regex:` |
| `risk:` | `risk:` |
| `sector:` | `industry:`, `sector:` |
| `seen:` | `seen:` |
| `session:` | `session:` |
| `severity:` | `sev:`, `severity:` |
| `similar:` | `like:`, `similar:` |
| `source:` | `source:` |
| `source_id:` | `source_id:` |
| `status:` | `status:` |
| `tactic:` | `tactic:` |
| `tag:` | `tag:` |
| `technique:` | `attack:`, `technique:`, `ttp:` |
| `title:` | `intitle:`, `title:` |
| `tox:` | `tox:` |
| `type:` | `threat:`, `type:` |
| `url:` | `url:` |
| `username:` | `handle:`, `user:`, `username:` |
| `verified:` | `verification:`, `verified:` |

### `has:` flags

| Flag |  |
|---|---|
| `actor` |  |
| `changes` |  |
| `credentials` |  |
| `creds` |  |
| `cve` |  |
| `history` |  |
| `ioc` |  |
| `iocs` |  |
| `org` |  |
| `passwords` |  |
| `victim` |  |

### Languages recognised

| Code | Language |
|---|---|
| `en` | English |
| `ru` | Russian |
| `zh` | Chinese |
| `ar` | Arabic |
| `ja` | Japanese |
| `ko` | Korean |
| `he` | Hebrew |
| `th` | Thai |
| `fa` | Persian |
| `es` | Spanish |
| `fr` | French |
| `de` | German |
| `pt` | Portuguese |
| `it` | Italian |
| `nl` | Dutch |
| `tr` | Turkish |
| `sw` | Swahili |
| `id` | Indonesian |
| `pl` | Polish |

