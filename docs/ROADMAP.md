# Roadmap

What comes next, in order, and what each step needs. What is built today, and
how far each part has been proven, is in [COVERAGE.md](COVERAGE.md); the
history of each phase is in [GAP-ANALYSIS.md](GAP-ANALYSIS.md).

## 1. Going live (now)

These finish what is built. None needs new code; each needs something only
the operator has.

| Step | Needs | How |
|---|---|---|
| Deploy to the VPS | the server, a DNS A record for the subdomain | `sudo ./install.sh --check …` then `sudo ./install.sh …` ([OPERATIONS.md](OPERATIONS.md#2-install-on-a-server-installsh)) |
| Prove HTTPS on the real domain | the deployment above | `./ctl.sh doctor` shows the address answering |
| Turn on Dark Web Informer | the paid API key | Integrations → Test, then Monitor its three sources; check the first import's alerts, victims and indicators |
| Real alert email | an SMTP account | `SMTP_*` settings, System → Email alerts → Send a test message |
| Two-step sign-in for everyone | — | each user enrols, then `REQUIRE_MFA=true` |
| Prove restore | one backup | restore it on a scratch install and compare finding counts |
| Off-site backups | somewhere to keep them | copy `backups/` off the server, encrypted, on a schedule |
| Server shell (optional) | SSH password login for one account | `./ctl.sh shell on`, then a real login through the browser |
| IntelOwl (optional) | an IntelOwl instance and its token | `INTELOWL_URL`, token in Integrations; prove one job end to end |

Not yet proven against the real service, because no key or instance was
available while building: a valid key for each commercial provider and for
the AI analyst; a Dark Web Informer import; an IntelOwl job; Slack, Teams,
Jira and ServiceNow deliveries; HTTPS and the server shell on a public domain.

## 2. Wider collection

| Item | Needs | Notes |
|---|---|---|
| Telegram channels through an account | a Telegram API id and hash, and a logged-in session | Today only public channel previews (t.me/s/…) are read. Media would go through the same guardrails as pages |
| Pastebin's scraping API | a Pastebin PRO account with the server's IP whitelisted | Their sanctioned route for collecting new public pastes; most other paste sites forbid automated collection |
| More research feeds | — | Cisco Talos and Microsoft block automated readers and Google publishes no feed; revisit if they change. Add others as sources in one click |
| A value score per source | — | From relevance, how often others reference it, volume and freshness, to rank what to approve |
| Source nodes in the relationship graph | — | Which sites link to which, drawn with the entities |

## 3. Analysis

Built since this list was written: path finding between two entities
(Relationships → Find a connection).

| Item | Needs | Notes |
|---|---|---|
| Translation of non-English findings | an Anthropic key | Worth it once the collection includes more Russian- and Chinese-language forums; today almost everything is English |
| Actor and campaign clustering | — | From shared indicators, victims and infrastructure; the timeline's alias suggestions are a first step |
| People, file names and technologies as entities | — | Extends extraction and the graph |
| Semantic search | a larger, multilingual corpus | Embeddings and a vector index; only worth it at scale |

## 4. Operations

| Item | Notes |
|---|---|
| Redis access control per worker role | Each container could then only touch its own queues |
| Single sign-on (OIDC) | For a team with an identity provider |
| A second crawler and a load test | To know the ceiling before collection grows |
| Server shell behind Apache | Today it needs Caddy or nginx in front |
| Alerting on `./ctl.sh doctor` | Run it from cron or a monitoring agent and alert when it fails |

## Will not be built

Kept out on purpose, to keep the tool defensive and lawful to operate:

- Active scanning of systems Kivuli's operators do not own (IVRE, port
  scanners, scanning analyzers in IntelOwl). Lookups use data that is already
  published; the indicator itself is never contacted.
- Logging in to forums or markets, bypassing CAPTCHAs or invitations, or
  sock-puppet accounts.
- Downloading images, archives, attachments or dumps; storing leaked
  passwords or secrets (only a fingerprint is kept).
- Scraping onion search engines that gate automated queries.
- Three tools whose development was stopped by a safety review: a
  lookalike-domain generator, an RDAP domain-intelligence tool with a link
  expander, and a MISP/Sigma/YARA export renderer. They are not to be added
  from third-party code either.
