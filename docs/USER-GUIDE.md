# User guide

For the researchers and analysts who use the console. It covers every screen
and the tasks you will do most. For how the system works underneath, see
[TECHNICAL.md](TECHNICAL.md); for what it does and does not cover, see
[COVERAGE.md](COVERAGE.md).

## Contents

1. [What this is](#1-what-this-is)
2. [Signing in and roles](#2-signing-in-and-roles)
3. [The workflow in one page](#3-the-workflow-in-one-page)
4. [Command centre](#4-command-centre)
5. [Dark-web search](#5-dark-web-search)
6. [Source explorer and source profiles](#6-source-explorer-and-source-profiles)
7. [Collection and research crawls](#7-collection-and-research-crawls)
8. [Findings](#8-findings)
9. [Investigations](#9-investigations)
10. [Alerts, watchlists and detection rules](#10-alerts-watchlists-and-detection-rules)
11. [Intelligence: entities, indicators, relationships, ATT&CK](#11-intelligence)
12. [Exposure: identities, attack surface, vulnerabilities](#12-exposure)
13. [Trends, integrations and system](#13-trends-integrations-and-system)
14. [How to… (common tasks)](#14-how-to)
15. [What you will not find here](#15-what-you-will-not-find-here)
16. [Glossary](#16-glossary)

---

## 1. What this is

One console for dark-web security research. It collects publicly readable pages
from Tor hidden services and from a set of clearnet intelligence feeds, keeps
every page and every later version of it, extracts the indicators and names in
them, and lets you search all of it. You do not need to know an onion address
to find something: you search, and the platform shows you where it was seen.

It is a defensive, internal tool. It reads; it does not log in, buy, post,
download files or probe anything.

Things shown in the console follow three rules you will notice everywhere:

- **Indicators are defanged and never clickable.** `example[.]com`,
  `hxxp[://]…`. The copy button copies the real value; the small search icon
  searches for it.
- **Secrets are never shown or stored.** Where a page contained a password or a
  key you see `[REDACTED]`. The platform tells you an account is exposed without
  keeping the password.
- **Every score opens into its reasons.** Risk, priority and relevance always
  list what produced them.

## 2. Signing in and roles

Open the console (by default http://localhost:28941) and sign in with your email
and password. If two-step sign-in is on for your account you are then asked for
the six-digit code from your authenticator app, or a recovery code.

| Role | Can |
|---|---|
| **Viewer** | Search, read everything, export, save searches, create read-only API keys |
| **Analyst** | Everything a viewer can, plus: triage findings and alerts, manage watchlists, rules, sources and investigations, start research crawls, preserve evidence, run connection tests |
| **Admin** | Everything an analyst can, plus: manage users, read the audit log, add alert destinations, set provider and AI keys, change the collection policy |

Five wrong passwords lock an account for fifteen minutes. Everything you do
that changes or exports something is written to the audit log.

**Turn on two-step sign-in:** System > My account > Two-step sign-in > Set up.
Scan the QR code with an authenticator app, enter the code it shows, and save
the ten recovery codes. Each recovery code works once.

## 3. The workflow in one page

```
SEARCH      type a keyword, domain, email, name, indicator or actor
  ↓
DISCOVER    see which sources carry it, and known sites not collected yet
  ↓
COLLECT     start a research crawl, or let the collection policy do it
  ↓
FILTER      narrow by network, source type, language, date, risk, entity…
  ↓
OPEN        read the page as captured, with its indicators marked
  ↓
PIVOT       search any indicator or entity everywhere; open its connections
  ↓
PRESERVE    pin the exact capture, with its hashes, to an investigation
  ↓
INVESTIGATE notes, timeline, saved hunts, report, STIX export
```

## 4. Command centre

The home screen. From the top:

- **The search box.** Type and press Enter. Tick *Tor sources only* to search
  only what came through Tor. The chips underneath are example searches and your
  saved searches.
- **Collection status.** Eight tiles: Tor connection, collectors answering,
  active sources (and how many on Tor), offline sources, crawl queue, pages
  indexed (and how many from Tor), last collection, failed fetches. Click any to
  open the collection screen. A tile turns red when it needs attention.
- **Recent intelligence.** The newest findings collected through Tor.
- **Critical findings.** Highest risk in the last seven days.
- **New matches.** Open alerts on what you watch.
- **Watched keywords.** Your watchlist; click a value to search for it.
- **New sources.** Sites discovered or added this week, with whether they
  answer.
- **Active research.** Running research crawls and open investigations.

If nothing is being collected from Tor, a notice says so and tells you how many
discovered sites are waiting.

## 5. Dark-web search

### 5.1 Just type

| You type | What happens |
|---|---|
| `cyber attack kenya` | Findings about Kenya (by name, demonym, city or `.ke` domain). "cyber" and "attack" only influence ranking, because nearly every finding is one |
| `company.com` | Recognised as a domain: matches it, every subdomain and every mailbox under it |
| `username@example.com` | Recognised as an email address and matched exactly |
| `41.90.64.0/20`, `CVE-2024-3400`, a hash, a wallet | Recognised as indicators. Pasting a defanged value (`example[.]com`) works |
| `leaked credentials` | Both words must appear; "leaked" also matches findings classified as a data breach |
| `"initial access" bank` | Exact phrase plus a word |

Under the box, **Understood as** shows how the query was read. If a word was
ignored or misread, you see it there.

### 5.2 Operators

Combine any of these with free text.

**Logic**

| Write | Meaning |
|---|---|
| `ransomware kenya` or `ransomware AND kenya` | Both |
| `lockbit OR akira` | Either |
| `-advertisement` or `NOT advertisement` | Exclude |
| `"exact phrase"` | The words in that order |
| `ransom*`, `exampl?` | Wildcards: any ending, any one character |
| `/cve-2026-[0-9]+/` or `re:cve-2026-[0-9]+` | Regular expression. It is matched against one whole word at a time, so it cannot span spaces |

**Where it was seen**

| Operator | Example | Meaning |
|---|---|---|
| `network:` | `network:tor`, `network:web` | Collected through Tor, or from the surface web |
| `kind:` | `kind:leak`, `kind:forum`, `kind:market`, `kind:paste`, `kind:news`, `kind:tracker` | Type of source |
| `site:` | `site:example.onion` | One site or onion service |
| `inurl:` | `inurl:thread` | Text in the page address |
| `source:` | `source:"RansomEXX v2"` | One named source |
| `lang:` | `lang:russian`, `lang:ru` | Language of the page |

**What it is about**

| Operator | Example |
|---|---|
| `actor:` | `actor:lockbit` |
| `org:` | `org:"Kenya Airways"` (victim or organisation) |
| `malware:`, `campaign:` | `malware:lumma` |
| `country:` | `country:KE`, `country:kenya` |
| `sector:` | `sector:"Financial services"` |
| `type:` | `type:ransomware` (also `breach`, `credentials`, `access`, `phishing`, `malware`, `ddos`, `vulnerability`, `fraud`, `hacktivism`, `defacement`) |
| `technique:`, `tactic:` | `technique:T1566`, `tactic:initial-access` |
| `title:` | `title:database` (words in the title) |
| `tag:` | `tag:priority` |

**Indicators**

| Operator | Example |
|---|---|
| `domain:` | `domain:example.co.ke` (with subdomains and mailboxes) |
| `email:`, `ip:`, `url:`, `onion:` | `ip:41.90.0.0/16` |
| `hash:`, `cve:`, `crypto:`, `user:` | `user:threat_handle` |
| `tox:`, `session:`, `matrix:`, `discord:`, `jabber:`, `edb:` | `jabber:seller@exploit.im` (contact handles actors post; `edb:51234` is an Exploit-DB ID; found in pages collected from this release on) |
| `ioc:` | `ioc:exampl*` (any indicator type, wildcards allowed) |

**Quality, time and state**

| Operator | Example | Meaning |
|---|---|---|
| `risk:` | `risk:>70`, `risk:40..80` | Risk score |
| `confidence:` | `confidence:>=80` | Classification confidence |
| `severity:` | `severity:critical` | |
| `verified:` | `verified:corroborated` | `unverified`, `reported`, `corroborated`, `confirmed` |
| `has:` | `has:creds`, `has:iocs`, `has:changes`, `has:actor`, `has:victim`, `has:cve` | Findings that have that thing |
| `after:`, `before:` | `after:30d`, `after:2026-01-01` | Reported since / until. `h`, `d`, `w`, `m`, `y` |
| `seen:` | `seen:7d` | Same as `after:` |
| `status:` | `status:escalated` | Triage status |
| `similar:` | `similar:<finding id>` | Findings worded like that one (the *Similar* button writes this for you) |

*Search syntax* under the box lists the operators with examples you can click.

### 5.3 Filters

The panel on the left narrows the results without changing the query: date
range, minimum risk, *Credentials exposed*, *Include duplicates*, *Require every
term*, then threat type, severity, country, network, source type, language,
site, actor, organisation, sector, malware, source, technique, verification,
tag and triage status. Active filters appear as chips above the results; click
one to remove it.

Sort by *Most relevant*, *Newest*, *Highest risk*, *Recently changed* or
*Oldest*.

### 5.4 Reading a result

Each result shows:

- **Title**, with your terms highlighted, and up to two passages from the page.
- **Risk** (0-100) and **Relevance** (0-100, relative to the best result of this
  search).
- Badges: severity, threat type, Tor or Web, verification grade, *Credentials*
  when passwords were present, *N versions* when the page has changed, *Seen at
  N sources* when the same content was collected from several places (it is
  shown once).
- Actors, organisations, malware and techniques named in it. Click one to
  filter by it.
- **Why matched**: the parts of your query this result matched, then what
  lifted it in the ranking (corroborated, seen at several sources, high risk,
  reliable source).
- Source (links to its profile), countries, first seen, last seen, confidence,
  number of indicators.

And the actions:

| Button | Does |
|---|---|
| **Open** | The finding: full text as captured, indicators, history, evidence |
| **Crawl** | Start a research crawl from that page (Tor results only) |
| **Source** | The profile of the site it came from |
| **Similar** | Other findings with similar wording |
| **History** | When it was seen and how it changed |
| **Connections** | The relationship graph around it |
| **Add to investigation** | Attach it to an investigation |

### 5.5 Sources behind the results

Above the results, **Sources carrying these results** lists the sites the
matches came from, with counts. Click a name to show only that source; click
*profile* to open it.

**Known sites that may cover this but are not being collected** lists
discovered sites whose name or title matches your query. *Crawl it* starts a
research crawl there.

### 5.6 Other things on the search page

- **Save** stores the query with all its filters; saved searches appear under
  the box and on the command centre.
- **Watch** turns the query into a watchlist entry.
- **Alert** turns it into a detection rule.
- **Save hunt to case** stores the query in an investigation.
- **CSV** / **JSON** export up to 5,000 results.
- **Ask a question** answers in prose from the best-matching findings, citing
  each one. It needs the AI analyst to be switched on (Integrations). Without
  it, your question runs as an interpreted search.
- **Did you mean** appears when a word finds almost nothing and a near spelling
  does.

### 5.7 Command line

*Research → Command line* is a terminal for the console. Type `help` for the
list. Tab completes a command, ↑ and ↓ walk your history, Ctrl+L clears.

| Command | What it does |
|---|---|
| `search <query>` | Search everything collected; every operator works (`search actor:qilin country:KE last:7d`) |
| `verdict <indicator>` | Quick verdict on an IP, domain, URL, hash, email, wallet, CVE or handle |
| `trace <wallet>` | Read a wallet on-chain and open its flow graph |
| `decode "<payload>"` | Peel encodings off a payload; nothing is run |
| `actor <name>` | An actor's claims, tempo, sites and month-by-month targeting |
| `sources [text]` / `source <id> check\|crawl\|monitor\|pause\|js-on\|js-off` | List and act on sources |
| `crawl <url> [depth] [pages]` | Start a research crawl |
| `watch <kind> <value> [name]` | Add a watchlist |
| `alerts`, `timeline [days]`, `stats [days]`, `providers` | What is open, who is active, headline numbers, provider status |
| `open <page>` | Go to a page (`open trends`) |

Each command calls the same API as the rest of the console with your
session: it can do what your role can, and it is in the audit log like any
other action.

**Server shell** (administrators). A second tab gives a real terminal on the
server, when an administrator has turned it on with `./ctl.sh shell on`
(HTTPS is required). You need two-step sign-in on your account. Press *Open
server shell*, then log in with the server's SSH username and password; every
session asks again. Opening it is recorded in the audit log and lasts 12 hours
unless you press *Close the shell*.

## 6. Source explorer and source profiles

**Source explorer** lists every site the platform knows.

| Tab | Shows |
|---|---|
| **Active** | Being collected on a schedule |
| **Discovered** | Found but not collected. Each was checked when found: does it answer, what does it call itself |
| **New this week** | Added or discovered in the last seven days |
| **Recently changed** | Sources where the last crawl found new or changed pages |
| **Most referenced** | Sources that other sources link to, most first |
| **Offline** | Not answering |
| **Paused** | Not monitored (includes sites you crawled once) |
| **Blocked** | Never contacted again |

Filter by Tor or web, and by name, title or address. A **Relevant** badge means
the site's own title scores well for security research. *N links in* is how many
other sources point at it.

Per source: **Profile**, the crawl log, *check now*, **Crawl** (active sources),
**Pause**, **Approve** (start collecting), **Block**.

*Approve all that respond* on the Discovered tab approves every discovered site
that answered its check, after showing you the list.

**Discover leak sites** looks up where ransomware groups publish, using the
public RansomLook tracker. Name a group, or leave it empty for the groups most
recently active in your findings.

The platform also imports the **deepdarkCTI** catalogue (a public, curated list
of dark-web ransomware sites, forums and markets): hundreds of entries appear in
*Discovered*, each tagged with the list it came from. Nothing is collected from
them until you approve it; forum and market entries are marked as likely needing
a login or invitation, which the platform does not do.

**Add source** adds a site, feed or public Telegram channel by address.
Tick *Render JavaScript* for a site whose pages are empty without scripts; it
can also be switched on or off later under *How it is collected* on the source's
page. Rendered pages load in a disposable browser through the same route (Tor or
the allow-list), take longer, and never load images.

### Source profile

Everything about one source:

- **Header**: state (online, degraded, offline, unknown), network, type, whether
  it is being collected, relevance.
- **Facts**: onion address, first observed and how it was found, last observed
  and when its content last changed, pages discovered, language.
- **Availability, last 30 days**: one square per day (✓ answered every check,
  ~ some, × none) and the percentage.
- **Pages and observations**: what was found there, with first and last seen.
  *No longer on the site* marks pages the site has stopped linking to; the
  stored copy remains.
- **Related sources**: what it links to and what links to it.
- **Collection history**: each crawl, with pages fetched, new and changed.
- **Research notes**: your team's notes on the source.
- **Related actors and malware**, **organisations**: named in what was
  collected there.

Actions: *Search this source*, *Research crawl*, *Crawl now*, *Check*, and
**Monitor** / **Stop monitoring**.

## 7. Collection and research crawls

### 7.1 Collection status

*Collection & crawls* shows whether collection is healthy:

- **Tor connection**: ONLINE means the gateway was confirmed to exit through
  Tor within the last few minutes.
- **Collectors**: how many of the four worker roles answer.
- **Active / offline sources**, **crawl queue**, **pages indexed**, **last
  collection**, **failed fetches in 24 hours**. Some failures are normal on Tor.
- **Source health**: sources being collected, by state, for Tor and web.
- **Safety controls**: the size and age of the abuse blocklist.

### 7.2 Research crawl

*Start research crawl* (also on search results, source profiles and
investigations):

1. **Starting URL**: an onion address or a web address.
2. **Depth**: 0 reads that page only; 1 also reads the pages it links to; and so
   on up to the limit an administrator set.
3. **Page limit**: the crawl stops after that many pages.
4. **Keep monitoring this site afterwards**: tick to have it re-crawled on a
   schedule.

You are taken to the crawl's live view:

- Counters: pages reached, in progress, stored as findings, new, changed,
  failed.
- **Pages discovered**, grouped by depth. Each shows whether it was read, its
  title (a link to the finding), its address, and the page that led to it.
- **Other sites it found**: recorded as sources, not followed.
- **Stop** ends it; pages already being fetched finish.

A crawl stays on the site it started on. It reads text only, through Tor,
without logging in. Pages behind a login or CAPTCHA are reported and skipped.
Links to files are never followed.

### 7.3 Collection policy (administrators)

What happens when a new onion site is discovered:

| Setting | Meaning |
|---|---|
| **Never** | Nothing is collected until someone approves the site |
| **Leak sites** | Leak sites listed by victim trackers are collected as soon as they respond. Everything else waits |
| **Leak sites and relevant sites** | Also any discovered site whose own title scores at or above the relevance you set |

Also here: the most onion sources that may be collected automatically, how many
groups each discovery run looks up, and the largest depth and page limit a
researcher may choose for a research crawl.

## 8. Findings

A finding is one page, post or feed entry, followed across every capture.

**Header**: severity, threat type, network, verification grade, credentials,
versions, first seen. Actions: triage status, **Confirm**, **Similar**,
**Connections**, **Crawl**, **Preserve evidence**, **Add to investigation**.

**Tabs**

| Tab | Shows |
|---|---|
| **Content** | The text as captured, indicators highlighted, secrets replaced with `[REDACTED]`. A banner says what was redacted |
| **Indicators** | Every indicator extracted, with the text around it and how many findings it appears in. Filter by type. The search icon searches for that value everywhere |
| **Exposed accounts** | Who and what this capture exposes: account, kind, where it works, status. Appears only when there are any |
| **History** | Page status (online, no longer on the site, removed, source offline), first seen, last seen, last changed, the days it was observed, then each version. *Compare* shows what changed between two versions |
| **Evidence** | Each capture's hashes and signature, re-verified when you open the tab. *Download evidence record* saves it as JSON |
| **Notes** | Your team's notes |

**Side panel**

- **Analyst summary** (when the AI analyst is on): what it says, key points,
  what to check.
- **Risk**: every factor and its points, and the total.
- **Details**: source (links to its profile), reliability and verification,
  location, countries, sector, dates, tags.
- **ATT&CK techniques** described in the text.
- **Actors and organisations**, each with *search* and *connections*.
- **Linked work**: alerts and investigations that reference it.
- **Also seen at**: other sources carrying the same content.

**Verification grade.** `B2` and the like is the Admiralty code: the letter is
how reliable the source is (A to F), the digit how credible the information is
(1 confirmed … 6 cannot be judged).

| State | Meaning |
|---|---|
| Unverified | One source of unknown or low reliability. Treat as a claim |
| Reported | One source considered reliable |
| Corroborated | Independent sources report the same thing |
| Confirmed | An analyst confirmed it |

## 9. Investigations

An investigation (case) holds everything you gather on one question.

- **Summary**: appears at the top of the exported report. With the AI analyst
  on, *Draft with AI* writes one from the attached findings, with citations, for
  you to review.
- **Findings**, **Indicators** (collected from the attached findings, or pinned
  by hand), **Actors and organisations**.
- **Evidence**: captures you preserved, each with its address, when it was
  collected, version, hashes, who preserved it and why.
- **Hunts, crawls and bookmarks**: saved searches (they run against current
  data when clicked), research crawls started for this investigation, and
  graph bookmarks.
- **Timeline**: in order, what the sources reported, what was collected, what
  changed, what alerted, and what your team did.
- **Notes**.
- **Details**: status, priority, sharing level (TLP), owner.

Exports: **Report** (printable), **CSV** (indicators), **STIX** (STIX 2.1
bundle), **JSON**.

## 10. Alerts, watchlists and detection rules

### Watchlists

Tell the platform what matters. Each new finding is checked against every entry.

| Kind | Matches |
|---|---|
| Keyword or phrase | Whole words in titles and content |
| Domain | The domain, every subdomain, any mailbox under it |
| Email address | That exact address; says whether a password was exposed with it |
| IP or CIDR range | An address or a block |
| Organisation, Vendor | Named as a victim or mentioned |
| Threat actor | A group or alias |
| CVE, File hash, Crypto wallet, Username | Exact |
| Brand | Mentions, plus look-alike domains |
| Technology in use | Vulnerability and exploitation reports that name it |
| Executive or VIP | A person's full name |

Options: email (*immediately*, *daily digest*, *none*), minimum severity,
recipients, and whether to also email matches already collected.

**This is an asset we own** (domains, emails, IP ranges, organisations, brands,
executives) with a criticality from 1 to 5: turns on look-alike detection for a
domain or brand, starts passive attack-surface discovery for a domain or IP
range, and raises the priority of alerts about it.

### Detection rules

For what a single value cannot express. Write any search; the dialog shows how
it is understood and how often it would have fired. Choose:

- **Every new match**: one alert per new finding.
- **Volume threshold**: one alert when matches in a window reach a number.
- **Unusual spike**: one alert when matches in a window are well above the
  average of the seven windows before.

### Alerts

The queue, ordered by priority. Each alert shows what matched, the finding, the
watchlist or rule it came from, and whether it was emailed. Click *Priority* to
see what it is made of. *Take* assigns it to you; *Resolve*, *False positive*
and *Reopen* change its state; tick several to change them together.

| Category | Meaning |
|---|---|
| Possible compromise | Something you watch appears in a leak, extortion post or credential dump |
| Look-alike domain | A domain imitating one you own |
| Vulnerability | An exploited flaw in technology you said you use |
| Attack surface | Something exposed on a host you own |
| Detection rule | A rule fired |
| Mention | Any other match |

A copy of something that already alerted does not alert again.

## 11. Intelligence

**Actors & entities.** Threat actors, organisations, incidents, malware,
campaigns and ATT&CK techniques. An entity page shows its profile, activity over
time, findings, who it appears with, countries, sectors and indicators.
*Stated relationships* lists what it uses, targets or is attributed to, each
with a confidence and where the statement came from; analysts can add or remove
them. When two records look like the same thing, *Merge into it* combines them.

**Indicators.** Every indicator, by type. An indicator page shows where it
appears with surrounding text, associated entities and indicators seen with it.
*External context* asks the configured providers about it (the indicator itself
is never contacted). For a domain or URL this includes the Wayback Machine: how
many archived snapshots exist, the first and last, and how many distinct versions. *Mark benign* stops a harmless shared value from linking
unrelated findings.

**Activity patterns** (on a threat actor's page). Counted from the actor's own
claims (tracker posts naming it as the actor, and pages of its leak site), not
from news that mentions it. Claims in total and in the last 30 days (compared
with the 30 before only once Kivuli has collected for 60 days), the typical
gap between claim days, the longest quiet stretch, claims by day of the week,
where its claims appear and who writes about it, and month by month its main
sectors and countries and the ones that are new that month. Days on which
Kivuli did not collect the actor's sources are left out of the gap and quiet
figures, so downtime is not mistaken for the actor going quiet. Hours of the
day are not shown: trackers date a post when they discover it, which says
more about the tracker than the actor.

**Event timeline.** Incidents over 7, 30 or 90 days on a time axis, one row
per threat actor (the twelve busiest, then *Other actors* and *No named
actor*). Each dot is a finding, coloured by type; larger dots are high or
critical. Lines join events that are connected: *Same victim, different
actors*; *Reported again* (the same actor naming the same victim, often a
second tracker reporting one claim, drawn faint); *Same CVE*; and *Shared
indicator* (only across different actors and different sources, and never a
common platform domain, an indicator marked benign or one seen in more than
25 findings, so boilerplate and leak-site addresses do not tie everything
together). Hover a dot for its details; click it to highlight what it connects
to and list those events; click an actor's name to show only that actor.
*Possibly the same actor* lists actor names that keep claiming the same
victims, usually one group that two trackers spell differently; open both
profiles and use *Merge into it* if they match. Nothing is merged automatically.

**Relationships.** A graph around any actor, organisation, malware, indicator
or finding. Labelled lines are stated relationships; plain lines mean the two
appear in the same findings. Click a legend entry to hide that type; double
click a node to re-centre; *Bookmark to case* saves the node.

*Find a connection*, below the graph, answers "how is this connected to
that?": pick another actor, organisation or malware family and Kivuli shows
the shortest chains (up to four steps) between them, each step with the
finding both appear in or the relationship that joins them. Techniques every
group uses, common platforms and very common entities are not used as steps,
so a connection means something specific. The address of the page with
`&to=` is a link you can share.

**ATT&CK.** The MITRE ATT&CK Enterprise matrix, shaded by how often each
technique appears in what you collected. Click a technique for its description,
the findings tagged with it and the groups known to use it.

**Crypto tracer.** Trace a Bitcoin, Ethereum or TRON (USDT) wallet. Paste an
address, or press *Trace wallet* on any crypto indicator. You get the balance,
total received and sent, first and last activity, and a graph of the flow of
funds: each node is an address, each arrow a flow with its amount. *Expand* a
counterparty to look it up and follow the money one hop further; a dashed node
is one not looked up yet. Addresses stand out when they are sanctioned (OFAC),
a mixer, a high-throughput service, or already seen in your collected
intelligence. Bitcoin addresses spent together are flagged as one wallet
(common-input clustering). *Add to investigation* pins a wallet to a case. It
reads only public blockchain data; nothing is signed or sent. Monero and some
other chains are recognised but cannot be looked up on-chain; they can still be
traced where they appear in collected intelligence.

**Tools.** Three tools under *Intelligence → Tools*:

- *Quick verdict.* Paste any indicator (defanged is fine) to see everything
  known about it in one place: findings that mention it, threat feeds that list
  it, watchlists that cover it, and what the enrichment providers say. The
  verdict is *Malicious* (on a feed, or a provider says so), *Suspicious* (a
  provider is unsure), *Seen in intelligence* (mentioned in findings, which on
  its own proves nothing: victims and vendors are mentioned too), *No sign of
  harm*, *Benign* (an analyst marked it so) or *Unknown*. Every verdict lists
  its reasons. The indicator itself is never contacted. For a Bitcoin,
  Ethereum or TRON wallet, *Check* also reads it from the public blockchain
  explorer: balance, received and sent, transactions and counterparties, beside
  where it appears in collected open- and dark-web intelligence. *Trace the
  flow* opens it in the crypto tracer. The activity dates cover the latest
  transactions read (50), not the wallet's whole life.
- *Email headers.* Paste an email's headers ("Show original" in Gmail, "View
  message source" in Outlook). You get the delivery path oldest hop first, the
  first public IP it came from, the SPF, DKIM and DMARC results the receiving
  server recorded, and warnings for the usual signs of phishing and spoofing:
  replies going to another domain, a display name showing a different address,
  bounces going elsewhere, a signature from an unrelated domain. Offline: nothing
  in the message is looked up.
- *Payload decoder.* Paste a script, a command line or an encoded blob. It
  removes layers of encoding one after another (PowerShell `-enc`, base64, hex,
  URL encoding, gzip and deflate, `fromCharCode` and `[char]` arrays, escapes,
  reversed text, ROT13, base64 hidden inside a script) and shows each layer, the
  final text, what the text does (downloads, runs code, persists, evades
  defences, injects, touches credentials) and the indicators in it. Nothing is
  run.

Indicators found by any tool are marked when your collected intelligence
already knows them, with a link to the indicator. Pasted text is not stored;
the audit log records only that a tool was used.

## 12. Exposure

**Identity exposure.** Accounts, sessions and secrets found in leaks and
infostealer logs. Each row: the account or secret type, kind, where it works,
the finding it came from. Filter to your own domains, mark rows *Remediated*,
*Ignored* or *False positive*, export CSV. A fingerprint (`fp …`) lets the same
secret be recognised elsewhere without storing it.

**Attack surface.** For assets you declared as owned: hosts named in public
certificate logs and DNS, with the open ports and known vulnerabilities that
public scan data reports. Nothing is scanned. Expand a host for why it scores
as it does.

**Vulnerabilities.** Ranked by what attackers are doing and what you run:
confirmed exploitation (CISA KEV), likelihood of exploitation (EPSS), mentions
in collected intelligence, presence on your hosts, severity.

## 13. Trends, integrations and system

**Trends.** Charts over 7, 30 or 90 days: volume, threat types, countries,
actors, sectors, what is rising. *Where it is happening* is a world map shaded
by how many findings name each country (darker in the light theme, brighter in
the dark one); hover a country for its count, click it to open its findings.
The *Countries* list beside it gives the same numbers as text. *Executive
brief* opens a printable summary.

**Integrations**

- *Alert destinations* (admins): send alerts to a signed webhook, Slack, Teams,
  Splunk, Jira or ServiceNow. Adding one, or pressing **Test**, sends a test
  alert and shows whether it was accepted.
- *Enrichment and AI*: every provider with whether it is on, where its key comes
  from, and its last test. **Set key** saves a key and immediately makes a real
  request to the provider to confirm it. **Test** repeats that at any time.
  *Dark Web Informer* is a paid feed rather than a lookup: set its key here
  (or `DWI_API_KEY` in `.env`), press **Test**, then open its three sources
  (threat feed, ransomware victims, IOC feed) and press **Monitor**. Every six
  hours Kivuli imports what changed: each alert or victim claim becomes a
  finding with its actor, victim, country and indicators, and the IOC feed's
  indicators are marked as listed by a threat feed. It stays within Dark Web
  Informer's limits (two exports a minute, 150 requests a day).
  *IntelOwl* connects your own IntelOwl instance: set `INTELOWL_URL` in
  `.env` and its API token (here or as `INTELOWL_API_KEY`). Indicator lookups
  then also run IntelOwl's playbook (`FREE_TO_USE_ANALYZERS` by default, at
  TLP AMBER) and show which of its analyzers judged the indicator malicious,
  suspicious or clean, with a link to the full job in IntelOwl. Analyzers that
  scan or probe the target (Nmap, Nuclei and the like) are never requested.
  If IntelOwl runs on the same machine, see `docker-compose.intelowl.yml`.
  When a provider rejects its key, Kivuli stops using that key and says so on
  the provider (*Not in use*) and once on lookups, instead of failing on every
  lookup; the free providers keep answering. Saving a different key, or a
  passing test, puts it back in use.
- *API, TAXII and STIX*: your API keys, the TAXII 2.1 feed address, and STIX
  import.

**System**: service health, intelligence quality, email settings and log, users
and audit log (admins), your password and two-step sign-in.

## 14. How to…

**…find out whether my organisation is mentioned on the dark web.**
Search your domain (`company.com`) with *Tor sources only* ticked. Then
Watchlists > Add entry, kind Domain, tick *This is an asset we own*: you are
alerted the next time it appears.

**…look at one leak site in depth.**
Source explorer > find it > Profile > Research crawl, depth 2. Watch the crawl,
then *Search what it found*.

**…follow an email address from a leak to everything else.**
Open the finding > Indicators > click the search icon beside the address. Open
*Connections* on any result to see what it shares with other findings.

**…be told when a ransomware group names a company in my country.**
Detection rules > New rule > `type:ransomware country:KE`, *Every new match*.

**…keep proof of what a page said.**
Open the finding > Preserve evidence > choose the investigation. The capture,
its hashes, your name and the time are pinned there.

**…see what changed on a page.**
Open the finding > History > *Compare with v…* on the version you care about.

**…search only one site.**
`site:` plus its address, or open its profile and press *Search this source*.

**…give another tool the indicators.**
Integrations > API, TAXII and STIX > New key, then point the tool at the TAXII
discovery address. Or export an investigation as STIX.

**…check that an API key works.**
Integrations > Enrichment and AI > Test beside the provider.

## 15. What you will not find here

- Pages behind a login, an invitation or a CAPTCHA.
- Images, screenshots, archives or attachments. Only text is collected.
- A search of the whole dark web. Search covers what the platform has
  collected.
- Passwords or secrets. They are redacted before storage.

The full list is in [COVERAGE.md](COVERAGE.md).

## 16. Glossary

| Term | Meaning |
|---|---|
| **Finding** | One page, post or feed entry, tracked across every capture |
| **Version** | One capture of a finding. A new one is stored whenever the content changes |
| **Source** | A site or feed the platform knows about |
| **Discovered source** | A site found automatically and not yet collected |
| **Research crawl** | A crawl you start from one address, with a depth and a page limit |
| **Indicator (IOC)** | A domain, onion address, URL, IP, email, hash, CVE, wallet or username |
| **Entity** | A threat actor, organisation, malware family, campaign, incident or ATT&CK technique |
| **Defanged** | Written so it cannot be clicked or resolved by accident: `example[.]com` |
| **Risk** | 0-100, how serious a finding is, with every point attributed |
| **Priority** | 0-100, how urgently an alert or vulnerability deserves attention |
| **Relevance** | How strongly a result matches this search, relative to the best one |
| **Verification** | How far a finding has been checked: unverified, reported, corroborated, confirmed |
| **Admiralty grade** | Source reliability (A-F) and information credibility (1-6), e.g. `B2` |
| **Corroboration** | The number of other independent sources reporting the same thing |
| **TLP** | Traffic Light Protocol: how widely an investigation may be shared |
| **KEV** | CISA's catalogue of vulnerabilities known to be exploited |
| **EPSS** | Probability that a vulnerability is exploited in the next 30 days |
| **STIX / TAXII** | Standard format and transport for sharing threat intelligence |
| **Common-input clustering** | Bitcoin addresses spent together in one transaction, so likely the same wallet |
