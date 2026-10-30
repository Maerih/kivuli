# Coverage

What the platform covers, what it does not, and how far each part has been
proven. Read this before relying on it for something that matters.

## Contents

1. [In one paragraph](#1-in-one-paragraph)
2. [What is collected](#2-what-is-collected)
3. [What is stored for each page](#3-what-is-stored-for-each-page)
4. [Capabilities, area by area](#4-capabilities-area-by-area)
5. [What it will never do](#5-what-it-will-never-do)
6. [What it does not do yet](#6-what-it-does-not-do-yet)
7. [How far each part has been proven](#7-how-far-each-part-has-been-proven)
8. [Accuracy: where to be careful](#8-accuracy-where-to-be-careful)
9. [This installation today](#9-this-installation-today)
10. [Roadmap](#10-roadmap)

---

## 1. In one paragraph

The platform collects publicly readable text from Tor hidden services and from
clearnet intelligence feeds, keeps every page with its history, extracts
indicators and names, and makes all of it searchable in one console, with
watchlists, alerts, investigations, source profiles and evidence preservation
on top. It reads only: it never logs in, solves a CAPTCHA, downloads a file,
runs a page's scripts or probes a system. **It searches what it has collected,
not the live dark web**, so its coverage is exactly as wide as the sources it
collects and the crawls you run.

## 2. What is collected

### Kinds of source

| Kind | Covered | Notes |
|---|---|---|
| Ransomware and extortion leak sites on Tor | **Yes** | Found automatically from victim trackers; collected under the default policy as soon as they answer |
| Other onion sites that are publicly readable (blogs, paste sites, open boards, open market listings) | **Yes, when added or approved** | Found through links and research crawls; collected when a researcher approves them, starts a crawl, or the policy allows |
| Any onion or web address a researcher supplies | **Yes** | Research crawl, to a chosen depth |
| Clearnet victim trackers (ransomware.live, RansomLook) | **Yes** | Structured: actor, victim, country, sector, date |
| Security news and advisories (RSS) | **Yes** | Eight feeds built in; add more |
| CISA Known Exploited Vulnerabilities | **Yes** | Also feeds the vulnerability catalogue |
| Indicator feeds (plain text lists) | **Yes** | Feodo Tracker and OpenPhish built in; indicators are flagged, not turned into findings |
| Public Telegram channels | **Yes, public web preview only** | `t.me/s/<channel>`. Tested on a sample page, not yet on a live channel |
| Forums and markets that need an account, an invitation or a CAPTCHA | **No** | Reported as "login required" or "CAPTCHA wall" and skipped. This excludes most established criminal forums and markets |
| Private Telegram groups, Discord, chat services | **No** | Need an account |
| Onion search engines and directories | **No** | Not scraped |
| I2P, Freenet, other networks | **No** | Tor only |
| Sites that need JavaScript to show their content | **Partial** | Only for sources marked "Render JavaScript": loaded in a disposable, network-isolated headless browser |

### How new sites are found

1. Victim trackers list where a ransomware group publishes.
2. A crawled page links to another onion service.
3. A research crawl comes across one.

There is no bulk import of onion directories and no search-engine scraping.
Discovery therefore grows outward from what is already collected.

### Built-in sources

Collected from a fresh install without any action:

| Source | Kind | Every |
|---|---|---|
| Ransomware.live: recent victims | Victim tracker | 1 h |
| Ransomware.live: victims in your focus country | Victim tracker | 3 h |
| RansomLook: recent posts | Victim tracker | 90 min |
| The Hacker News, BleepingComputer | News | 60-90 min |
| DataBreaches.net, HackRead, Security Affairs, The Record | News | 2 h |
| Krebs on Security | Blog | 6 h |
| Vendor threat research: Unit 42, Check Point Research, Kaspersky Securelist, ESET, SentinelLabs, Proofpoint, Recorded Future, The DFIR Report, Volexity, Huntress, Zscaler ThreatLabz, Fortinet FortiGuard, Trend Micro, CrowdStrike, Rapid7 | Research blogs | 6 h |
| CISA Known Exploited Vulnerabilities | Vulnerability catalogue | 12 h |
| CISA cybersecurity advisories | Advisories | 6 h |
| Feodo Tracker, OpenPhish | Indicator feeds | 3-6 h |
| deepdarkCTI catalogue (ransomware sites, forums, markets) | Source discovery | daily |
| Ahmia: banned onion services | Safety blocklist (hashes) | 24 h |

Onion sources are not built in. They are discovered, starting about ten minutes
after the first start, and collected according to the collection policy.

## 3. What is stored for each page

| Stored | Detail |
|---|---|
| Address | The URL, the host, and whether it came through Tor or the web |
| Source | Which source it belongs to |
| Title and text | The readable text, with secrets replaced by `[REDACTED]` |
| Every version | A new immutable copy each time the content changes, with what changed |
| Timestamps | When the source says it was published, first seen, last seen, last changed, and when each version was captured |
| Hashes | SHA-256 of the original response, SHA-256 of the stored text, a chained hash and an HMAC signature per version |
| HTTP details | Status code and response headers of each capture; size |
| Language | ISO code, when it could be determined |
| Indicators | Domains, onion addresses, URLs, IPs, emails, hashes, CVEs, crypto wallets, usernames, contact handles (Tox, Session, Matrix, Discord, Jabber/XMPP), Exploit-DB IDs, each with surrounding text |
| Entities | Threat actors, organisations, malware, campaigns, incidents, ATT&CK techniques |
| Classification | Threat type, secondary types, confidence, countries, sectors |
| Scores | Risk with every factor; verification state; corroboration count |
| Exposure records | Which accounts and secrets the page exposed (never the secret) |
| Fetch log | Every time the address was fetched: when, result, size, what led to it |
| Links between sites | Which onion service links to which |

**Not stored:** images, screenshots, archives, attachments, media, style sheets,
scripts; passwords, keys, tokens or card numbers; the unredacted page (unless
an operator turns on `EVIDENCE_STORE_RAW`, which is off and should stay off).

## 4. Capabilities, area by area

Status: **Built** works as described. **Partial** works with the stated
limits. **Not built** is absent.

### Search

| Capability | Status | Notes |
|---|---|---|
| Full-text search over everything collected | Built | Stemming, synonyms, typo tolerance |
| Exact phrases | Built | `"…"` |
| Boolean AND / OR / NOT | Built | Also `-term` |
| Wildcards | Built | `*`, `?` |
| Regular expressions | Partial | Matched against one word at a time; cannot span spaces |
| Field-specific search | Built | About forty operators; see the user guide |
| Date ranges, relative dates | Built | |
| Filter by source, site, onion service | Built | |
| Filter by source type | Built | Leak site, forum, marketplace, paste, tracker, news, … |
| Filter by language | Partial | Heuristic detection, 19 languages |
| Filter by entity, indicator, actor, organisation, country | Built | |
| Filter by confidence, risk, verification | Built | |
| Pasted indicators recognised, defanged accepted | Built | |
| Relevance ranking beyond keyword match | Built | Risk, recency, source reliability, corroboration, same-content count, change frequency |
| "Why matched" on every result | Built | |
| Saved searches | Built | |
| Similar-content search | Built | |
| Sources behind a result set; uncollected sites that match | Built | |
| Export | Built | CSV and JSON, up to 5,000 results |
| Type-ahead suggestions, spelling suggestions | Built | |
| Semantic (meaning-based) search | Not built | Needs embeddings and a vector index |
| Searching the live dark web | Not built | By design: search covers what was collected |

### Collection and crawling

| Capability | Status | Notes |
|---|---|---|
| Collection through Tor, isolated from the console | Built | |
| Scheduled crawling with back-off | Built | |
| Research crawl from a starting URL with depth and page limit | Built | Depth up to an administrator's limit (default 4) |
| Same-site boundary | Built | |
| Link extraction, recursive crawling | Built | |
| Duplicate address and duplicate content detection | Built | |
| Retry handling, dead-source detection | Built | |
| Live view of pages as they are found | Built | By depth, with the page that led to each |
| Queue and crawl management | Built | Start, watch, stop; at most twelve at once |
| Automatic onion discovery | Partial | From trackers, links, crawls and the deepdarkCTI catalogue; not yet from onion search engines |
| Collection policy set in the console | Built | Never / leak sites / leak sites and relevant sites |
| Page snapshots | Partial | Text and hashes; no rendered image |
| Images and attachments | Not built | Deliberately |
| JavaScript rendering | Built | Per source, opt-in; disposable Chromium behind Tor or the egress proxy; no images, no screenshots |
| Logins, CAPTCHAs | Not built | Deliberately |

### Sources

| Capability | Status | Notes |
|---|---|---|
| Source explorer: active, discovered, new, changed, most referenced, offline, paused, blocked | Built | |
| Source profile: address, first and last observed, availability, pages, related sources, actors, crawl history, notes | Built | |
| Source health: online, degraded, offline, unknown | Built | |
| Source relevance from its own title | Partial | Keyword-based |
| High-value source ranking | Partial | Relevance, references and volume are shown; there is no single "value" score |

### History and evidence

| Capability | Status | Notes |
|---|---|---|
| Every version kept; compare versions | Built | |
| First seen, last seen, days observed, page status | Built | For crawled pages. Feed entries have first and last seen only |
| Searchable after the page or site disappears | Built | |
| Tamper-evident evidence chain | Built | Hash chain and HMAC, re-verified on request |
| Preserve evidence into an investigation | Built | |
| Screenshot as evidence | Not built | |

### Extraction and analysis

| Capability | Status | Notes |
|---|---|---|
| Domains, subdomains, URLs, onion addresses, IPs, emails, hashes, CVEs, crypto wallets | Built | With validation |
| Usernames, Telegram handles, forum handles | Partial | One "username" type; context-dependent |
| Malware names, threat actors | Built | Matched against known names and ATT&CK, with context rules |
| Organisations | Partial | Exact from trackers; pattern-based and conservative in free text |
| People | Not built | Only through an "executive" watchlist entry |
| File names, technologies as entity types | Not built | Technology only as a watchlist kind |
| Countries and sectors | Built | |
| Threat-type classification with confidence | Built | Rule-based |
| ATT&CK technique tagging | Partial | Explicit identifiers and about 35 behaviour patterns |
| Credential and secret redaction with exposure records | Built | |
| Verification states and Admiralty grading | Built | |
| Corroboration across independent sources | Built | |

### Pivoting and graph

| Capability | Status | Notes |
|---|---|---|
| Event timeline by actor, linking same victim, same CVE and shared indicators; alias suggestions | Built | Indicator links only across actors and sources; common platforms excluded |
| World map of countries named in findings, click-through to findings | Built | Natural Earth 1:110m (public domain); ISO numeric codes from pycountry |
| Search everywhere from any indicator or entity | Built | |
| Find connections from any indicator, entity or finding | Built | |
| Relationship graph with stated relationships and co-occurrence | Built | |
| Analyst-added relationships; entity merge | Built | |
| Source-to-source links | Partial | In the source profile, not yet in the graph |
| Multi-hop path finding between two entities | Not built | |
| Actor and campaign clustering | Not built | |
| Crypto wallet tracing (BTC, ETH, TRON/USDT): balance, flow graph, hop expansion | Built | Public blockchain explorers, keyless; read-only |
| Quick verdict on any indicator: collected intelligence, feeds, watchlists, providers | Built | The indicator is never contacted |
| Email header analysis: delivery path, origin IP, SPF/DKIM/DMARC, spoofing signs | Built | Offline; pasted text is not stored |
| Payload decoding: PowerShell -enc, base64, hex, URL, gzip/deflate, char codes, escapes, ROT13 | Built | Offline; nothing is executed; output capped per layer |
| Wallet labelling: sanctioned/OFAC, mixers, exchanges, in-intelligence, shape heuristics | Built | Small verified built-in list plus heuristics and our own findings |
| Bitcoin common-input clustering | Built | |
| Monero, Solana, Litecoin, Zcash lookup | Partial | Recognised and traceable in collected intelligence; no on-chain lookup |

### Monitoring and alerts

| Capability | Status | Notes |
|---|---|---|
| Watchlists: keyword, domain, email, IP, organisation, actor, CVE, hash, wallet, username, brand, technology, vendor, executive | Built | |
| Retro-hunt over what is already collected | Built | |
| Detection rules: every match, threshold, spike | Built | Spike rules not yet seen to fire |
| Look-alike domain detection | Built | |
| Alert priority with explanation | Built | |
| Duplicate suppression | Built | A copy of something that already alerted does not alert again |
| One "event" grouping many alerts | Not built | Results show "seen at N sources"; alerts are not regrouped |
| Email: immediate or daily digest | Built | |
| Destinations: webhook, Slack, Teams, Splunk, Jira, ServiceNow | Built | See section 7 for what was delivered for real |

### Investigations

| Capability | Status | Notes |
|---|---|---|
| Findings, indicators, entities, notes | Built | |
| Saved hunts, graph bookmarks, linked research crawls | Built | |
| Timeline | Built | |
| Preserved evidence | Built | |
| Report (HTML), indicators (CSV), STIX 2.1, JSON | Built | |
| Screenshots, file attachments | Not built | |
| Per-investigation access control | Not built | Roles apply platform-wide |

### Exposure

| Capability | Status | Notes |
|---|---|---|
| Identity exposure with remediation workflow | Built | |
| Passive attack-surface discovery for owned assets | Built | Public datasets only; findings unverified |
| Vulnerability prioritisation (KEV, EPSS, mentions, presence) | Built | |
| Active scanning | Not built | Deliberately |

### Integration and platform

| Capability | Status | Notes |
|---|---|---|
| REST API with keys | Built | 130 operations |
| TAXII 2.1 server, STIX import and export | Built | |
| Enrichment providers, keys set and tested in the console | Built | |
| AI analyst with citations | Built, unproven | No key has been available; see section 7 |
| Roles, two-step sign-in, audit log | Built | |
| Collection health screen, Prometheus metrics | Built | |
| Backup and restore | Built, restore unproven | |
| Single sign-on, multi-tenancy | Not built | Internal, single-team tool |
| High availability | Not built | One database, one search node, one queue |

## 5. What it will never do

These are boundaries of the design, not gaps.

| It will not | Why |
|---|---|
| Fetch an onion service on the abuse blocklist | About 60,000 services banned by Ahmia for child sexual abuse material. Enforced where sites are filed, where crawls are started, and in the fetcher itself |
| Store or display abuse material | A content guardrail drops such pages and blocks the source |
| Log in, register, or solve a CAPTCHA | Access control on someone else's system is not ours to bypass |
| Download archives, documents, images or media | That is where stolen data, illegal material and malware are |
| Run a page's scripts | Hostile code |
| Keep passwords, keys or card numbers | It must not become a store of stolen credentials |
| Use or test a credential it sees | Credentials are exposure intelligence, nothing else |
| Buy, post, message or otherwise interact | Read only |
| Scan, probe or resolve anything it discovers | Indicators are recorded, never contacted. Attack-surface data comes from public datasets, and only for assets you declare |
| Contact a clearnet host that is not on the operator's allow-list | The application cannot widen its own network access |
| Let the AI act | It has no tools, sees only retrieved findings, and must cite them |

## 6. What it does not do yet

Reasonable to want; not built.

- **Sources as nodes in the relationship graph.**
- **Alert "events"** that group many alerts about the same thing.
- **People, file names and technologies** as entity types of their own.
- **Clustering** of actors and campaigns; path finding between two entities.
- **Semantic search.**
- **Screenshots**, which would need a disposable, network-isolated browser.
- **A single "source value" score.**
- **Per-investigation permissions; single sign-on; several tenants.**
- **Replication** of the database, the index or the queue.
- **Have I Been Pwned, urlscan.io, SecurityTrails, Censys**: listed in the
  console as planned.
- **WHOIS and passive DNS.**

## 7. How far each part has been proven

Three levels. **Live**: run against real services and data on this
installation. **Unit**: covered by automated tests of the logic, with the
service's documented responses. **Unproven**: built, and never seen to work
against the real thing.

| Part | Level | Evidence |
|---|---|---|
| Tor gateway exits through Tor | Live | Checked every five minutes against the Tor Project's service |
| Collection from onion leak sites | Live | Nine leak sites collected; pages searchable |
| Network isolation of the crawler | Live | Measured from inside the containers (release 1.0) |
| Refusal of archives | Live | `refused: content type application/zip is not collected` on a leak site's links |
| Refusal of internal, IP-literal and non-HTTP addresses | Live | Research crawl start refused each |
| Login and CAPTCHA walls reported, not bypassed | Unit | Parser tests |
| Abuse blocklist loaded and enforced | Live (load), Unit (matching) | 59,973 hashes loaded. No listed site was ever requested, so enforcement was not triggered for real, by design |
| Content guardrail | Unit | |
| Automatic discovery from trackers | Live | Fifteen leak sites filed from two runs |
| Discovery from links on crawled pages | Live | Source links recorded; few so far |
| deepdarkCTI catalogue import | Live | ~800 sources filed as candidates (450 leak sites, 225 forums, 116 markets), not auto-collected |
| Collection policy auto-approval | Live | Eight sites approved on first application |
| Research crawl: depth, limit, parent tracking, completion, stop | Live | Six pages of a benign onion site in thirty seconds |
| Redaction; no secret in storage, API or export | Live | Synthetic leak: checked the stored text, every API response and the CSV |
| Exposure records | Live | Synthetic leak, and real leak pages since |
| Search operators, ranking, "why matched" | Live | On the collected Tor data |
| Versions, observations, page status | Live | |
| Evidence chain; tamper detection | Live | Release 1.0 |
| Evidence preservation | Live | |
| Watchlists, look-alikes, technology and executive watches | Live | Synthetic data |
| Query and threshold rules | Live | Synthetic data |
| Spike rules | Unproven | Same evaluation path as threshold rules; never made to fire |
| Alert email | Live | To the bundled test inbox, not to a real relay |
| Webhook and Splunk destinations | Live | To a listener inside the container, HMAC verified on receipt |
| Slack, Teams, Jira, ServiceNow destinations | Unit | Payloads tested; no real workspace or instance |
| Destination guard | Live | A link-local address was refused |
| Free enrichment providers | Live | All answered through the egress proxy, including the Wayback Machine |
| VirusTotal, Shodan, AbuseIPDB, GreyNoise, NVD with a key | Live (rejection), Unit (acceptance) | Each real service rejected a deliberately invalid key. No valid key has been available |
| AI analyst | Live (rejection), Unproven (answers) | Anthropic rejected an invalid key. No model answer has ever been seen |
| KEV sync, EPSS, NVD severity | Live | |
| Passive attack-surface discovery | Live | On `example.com` |
| Tools: quick verdict, email headers, payload decoder | Live | Feed-listed C2 IP judged malicious; headers flagged Reply-To, display-name spoof, SPF/DMARC fail; PowerShell -enc decoded with indicators cross-referenced |
| Crypto tracer: BTC, ETH, TRON lookup; flow graph; OFAC/mixer labels; hop expand; pin to investigation | Live | Real addresses through the egress proxy (BTC 348 txs; Tornado Cash labelled sanctioned; USDT TRC20) |
| Crypto tracer console page | Unproven (visual) | Type-checked and built; API fully proven; the page was not rendered signed-in |
| API keys, scopes, revocation | Live | |
| TAXII discovery, collections, paging, manifests | Live | With curl-style clients, not with a named SIEM product |
| STIX import and export | Live | Round trip with a synthetic bundle |
| Two-step sign-in | Live | Enrolment, codes, recovery codes, admin reset |
| Migrations on existing data | Live | Four revisions applied in place |
| Backup | Live | Dump confirmed readable |
| Restore | Unproven | Not run against the live database |
| Telegram connector | Unit | Sample page |
| Scale beyond a few dozen sources and a few hundred pages | Unproven | |
| Every console screen | Live | Opened in a browser. The sign-in code step and most add/edit dialogs were exercised through the API rather than clicked |

## 8. Accuracy: where to be careful

- **A leak-site post is a claim.** A group listing a victim does not prove a
  breach. Such findings start as *unverified* or *reported*; treat them so
  until corroborated or confirmed.
- **Classification is rule-based.** It will sometimes mislabel. The confidence
  and the factors are shown so you can judge.
- **Organisation names in free text** are recognised conservatively; some are
  missed, a few are wrong. Names from trackers are exact.
- **Technique tags** come from explicit identifiers and a limited set of
  behaviour patterns. Absence of a tag is not absence of the technique.
- **Language** is a heuristic. It confuses close languages (Belarusian with
  Russian, Catalan with Spanish) and gives no answer for short text.
- **Attack-surface vulnerabilities** come from banner matching in public scan
  data. Confirm the version before acting.
- **"No longer on the site"** means the crawler did not find the page again,
  not that it was verifiably deleted. "Removed" is used only when the site
  answered "not found".
- **Source relevance** is scored from a site's title alone.
- **Tracker data is second-hand.** Trackers can be late or wrong.
- **Duplicates** are detected by exact hash and near-identical wording.
  Rewritten copies of the same story are separate findings, linked by
  corroboration when they name the same incident.

## 9. This installation today

A snapshot taken on 2026-10-08. It will be out of date; the live figures are on
the command centre and *Collection & crawls*.

| | |
|---|---|
| Findings | 595 (82 from Tor, 513 from the web) |
| Stored versions | 620 |
| Sources being collected | 24 (9 onion leak sites, 15 clearnet feeds) |
| Onion sites discovered and waiting | 7 (most not answering) |
| Indicators | 3,007 (hashes 1,655, URLs 650, domains 248, emails 221, CVEs 171, onion addresses 41, IPs 15, usernames 6) |
| Entities | 2,245 (malware 791, techniques 697, organisations 306, actors 251, incidents 200) |
| Stated relationships | 5,545 (mostly from the ATT&CK catalogue) |
| Vulnerabilities tracked | 1,828 |
| Abuse blocklist | 59,973 hashes |
| Collection policy | Leak sites collected automatically |
| Provider keys | None set. The six free providers are on |
| AI analyst | Off |
| Alert email | Going to the bundled test inbox |

Most malware and technique entities come from the ATT&CK catalogue and have not
yet appeared in a finding.

## 10. Roadmap

In the order the brief gave them.

**Next, to widen what search can reach**

- More source kinds a researcher can add in one click (paste sites, open
  boards), with per-kind parsing.
- Source nodes and source-to-source links in the relationship graph.
- Alert events.
- A source value score from relevance, references, volume and freshness.

**Then, research power**

- People, file names and technologies as entities.
- Path finding between two entities; clustering of actors and campaigns.
- Screenshots from a disposable, network-isolated renderer.
- Semantic search, once the corpus is large and multilingual enough to benefit.

**Operational**

- Prove restore; prove a valid key for each provider and for the AI analyst;
  prove Slack, Teams, Jira and ServiceNow against real instances.
- Redis ACLs per worker role.
- A second crawler and a load test.
- Single sign-on.

The history of what was built in each phase, and why, is in
[GAP-ANALYSIS.md](GAP-ANALYSIS.md).
