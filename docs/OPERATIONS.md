# Installing and running Kivuli

Everything an operator needs: putting Kivuli on a server (including one that
already runs other websites), configuring it, running it day to day, backing
it up, updating it, fixing it, and taking it off again.

How each part works inside is in [TECHNICAL.md](TECHNICAL.md); how to use the
console is in [USER-GUIDE.md](USER-GUIDE.md).

## Contents

1. [What you need](#1-what-you-need)
2. [Install on a server: install.sh](#2-install-on-a-server-installsh)
3. [Install by hand](#3-install-by-hand)
4. [Beside other websites on the same server](#4-beside-other-websites-on-the-same-server)
5. [First sign-in and setup](#5-first-sign-in-and-setup)
6. [Configuration (.env)](#6-configuration-env)
7. [Keys and integrations](#7-keys-and-integrations)
8. [Day-to-day management: ctl.sh](#8-day-to-day-management-ctlsh)
9. [Backups and restore](#9-backups-and-restore)
10. [Updating](#10-updating)
11. [The server shell](#11-the-server-shell)
12. [Monitoring and logs](#12-monitoring-and-logs)
13. [Troubleshooting](#13-troubleshooting)
14. [Security checklist](#14-security-checklist)
15. [Moving to another server](#15-moving-to-another-server)
16. [Uninstalling](#16-uninstalling)

---

## 1. What you need

| | Minimum | Comfortable |
|---|---|---|
| CPU | 4 cores | 8 cores |
| RAM | 8 GB | 16 GB |
| Disk | 40 GB | 80 GB or more (collection grows) |
| OS | 64-bit Linux with systemd: Ubuntu 22.04/24.04, Debian 12 | |
| Network out | HTTPS (443) and Tor (9001, 443) to the internet | |
| Network in | 80 and 443 for HTTPS, 22 for SSH | |
| A domain | e.g. `kivuli.example.org`, with a DNS **A record** pointing at the server | |

Search (OpenSearch) and the disposable browser that renders JavaScript are the
memory-hungry parts. Nothing else on the server needs to change: Kivuli runs
entirely in Docker.

## 2. Install on a server: install.sh

The recommended way is one line. It downloads Kivuli into `/opt/kivuli` (or
updates it if it is already there) and runs the installer:

```bash
curl -fsSL https://raw.githubusercontent.com/Maerih/kivuli/main/install.sh | sudo bash -s -- --domain kivuli.example.org --email you@example.org
```

Or from a checkout. As root:

```bash
git clone https://github.com/Maerih/kivuli.git /opt/kivuli && cd /opt/kivuli
```

Look first. This changes nothing, and tells you what it would do:

```bash
sudo ./install.sh --check --domain kivuli.example.org
```

Then install:

```bash
sudo ./install.sh --domain kivuli.example.org --email you@example.org
```

What it does, in order:

1. **Inspects the server:** OS, CPU, RAM, free disk, whether Docker is there,
   the firewall (ufw), `vm.max_map_count` (search needs 262144), which program
   owns ports 80 and 443 and which sites it already serves, and whether the
   domain's DNS points at this server.
2. **Stops** (and changes nothing) if the domain does not resolve here, or if
   the existing web server already has a site for that domain that it did not
   write.
3. **Installs what is missing:** git, curl, Docker (from get.docker.com), and
   raises `vm.max_map_count` (in `/etc/sysctl.d/99-kivuli.conf`).
4. **Configures `.env`:** generates every secret on first install, picks
   Kivuli's ports (28941 console, 28942 test inbox, 28943 shell, or the next
   free ones), sets the domain and HTTPS cookies, and makes the first admin
   your email address.
5. **Builds and starts Kivuli.** The first build takes several minutes.
6. **Serves it over HTTPS,** depending on what owns ports 80/443 (see
   [section 4](#4-beside-other-websites-on-the-same-server)).
7. **Turns on start-at-boot and daily backups** (skip with `--no-autostart`).
8. **Runs `./ctl.sh doctor`** and prints the address and where the admin
   password is.

On a server with less than 12 GB of RAM it sizes Kivuli down (search 512 MB,
3 crawler and 2 pipeline workers, one browser at a time) so that other
applications keep their memory; raise them later with `./ctl.sh set`.

Options: `--dir /opt/kivuli` (where to install), `--yes` (do not ask; needed
when there is no terminal to ask on),
`--no-autostart`, `--repo URL`. Running it again is safe: it keeps the ports
and secrets it chose before and rewrites only its own site file.

## 3. Install by hand

The same steps without the script, on a server where ports 80/443 are free.
As root (`export KIVULI_DOCKER=system` saves typing it each time):

```bash
curl -fsSL https://get.docker.com | sh
```
```bash
git clone https://github.com/Maerih/kivuli.git /opt/kivuli && cd /opt/kivuli
```
```bash
export KIVULI_DOCKER=system && ./ctl.sh start
```
```bash
./ctl.sh https kivuli.example.org you@example.org
```
```bash
./ctl.sh doctor && ./ctl.sh autostart on
```

`./ctl.sh start` creates `.env` with generated secrets the first time. To
choose the first admin's email, run `./ctl.sh init` first, then
`./ctl.sh set BOOTSTRAP_ADMIN_EMAIL=you@example.org`, then `./ctl.sh start`.

**Without root,** `ctl.sh` can run Kivuli on a private copy of Docker kept in
the folder (`.runtime/`): `sudo apt install -y curl uidmap`, then
`./ctl.sh start` as a normal user. It cannot listen on ports 80/443 that way,
so put the server's own web server in front ([section 4](#4-beside-other-websites-on-the-same-server)).

## 4. Beside other websites on the same server

Two sites on one server do not collide: they share ports 80 and 443 through
the web server, which sends each request to the right application by its
domain name. Kivuli never listens on 80/443 itself unless they are free.

```
internet ──443──> nginx ──┬─ bloody.example.org ──> your existing app
                          └─ kivuli.example.org ──> 127.0.0.1:28941 (Kivuli, in Docker)
```

| What owns 80/443 | What install.sh does |
|---|---|
| Nothing | Starts Kivuli's own HTTPS (Caddy) with a Let's Encrypt certificate |
| Caddy as a system service | Adds **one** site file, `/etc/caddy/kivuli/<domain>.caddy`, and one `import` line to `/etc/caddy/Caddyfile` (backed up first as `Caddyfile.before-kivuli-<date>`), validates the whole config, reloads, and waits for HTTPS to answer; Caddy gets the certificate itself. If validation fails, the Caddyfile is put back exactly as it was. A site you already added by hand for the domain, pointing at Kivuli, is kept. The server shell's gate is included |
| nginx | Adds **one** site file, `/etc/nginx/sites-available/kivuli-<domain>.conf` (or `conf.d/`), tests it with `nginx -t`, reloads, and gets the certificate with `certbot --nginx`. The server shell's gate is included |
| Apache | Adds **one** site, `kivuli-<domain>.conf`, tests it with `apachectl configtest`, reloads, and gets the certificate with `certbot --apache` |
| Traefik, Caddy, a Docker container, anything else | Changes nothing; starts Kivuli on `127.0.0.1:28941` and prints what to add to that proxy |

If a test of the new site fails, the file is removed and nothing else is
touched. Each file it writes starts with a comment saying how to remove it.

**Kivuli's ports,** all on `127.0.0.1` (not reachable from outside):

| Port | What | Change with |
|---|---|---|
| 28941 | Console (web) | `./ctl.sh set WEB_PORT=…` |
| 28942 | Test mail inbox | `./ctl.sh set MAILPIT_PORT=…` |
| 28943 | Server shell, only behind your own nginx | `./ctl.sh set SHELL_PORT=…` |

They are uncommon on purpose (3000, 8000 and 8080 usually belong to
something else) and below Linux's ephemeral range, so outgoing connections
never take them. Everything else Kivuli runs is on private Docker networks.

**Your own proxy by hand.** Send the domain to `http://127.0.0.1:28941`,
passing `Host` and `X-Forwarded-Proto`, allow uploads of 12 MB and responses
of 300 s. Then `./ctl.sh set PUBLIC_URL=https://kivuli.example.org COOKIE_SECURE=true KIVULI_DOMAIN=kivuli.example.org`
and `./ctl.sh restart`. From inside a Docker container (e.g. a Traefik
container), `127.0.0.1` is the container itself: use the host's address.

## 5. First sign-in and setup

1. Open `https://<your domain>`. The first admin is the email you gave
   install.sh (or `BOOTSTRAP_ADMIN_EMAIL`); the password is in `.env`:
   `grep BOOTSTRAP_ADMIN_PASSWORD /opt/kivuli/.env`
2. **System → My account:** change the password.
3. **System → My account → Two-step sign-in:** turn it on. Then, for everyone,
   `./ctl.sh set REQUIRE_MFA=true` and `./ctl.sh restart`.
4. **System → Users:** add analysts (role *analyst*) and read-only users
   (*viewer*).
5. **Integrations → Enrichment and AI:** add keys ([section 7](#7-keys-and-integrations)).
6. **Watchlists:** add your organisation's domains, brands, executives,
   wallets and keywords, so alerts mean something.
7. **Collection & crawls:** review the collection policy and approve the
   discovered dark-web sources you want collected.

## 6. Configuration (.env)

All settings live in `/opt/kivuli/.env`, created from `.env.example` with
generated secrets. Change them with `./ctl.sh set KEY=VALUE` (or an editor),
then `./ctl.sh restart`. Every setting, with its default, is listed in
[REFERENCE.md](REFERENCE.md); the ones operators change most:

| Group | Settings |
|---|---|
| Console | `PUBLIC_URL`, `WEB_PORT`, `WEB_BIND` (keep 127.0.0.1), `COOKIE_SECURE`, `APP_NAME` |
| HTTPS and proxy | `KIVULI_DOMAIN`, `ACME_EMAIL`, `COMPOSE_PROFILES` (`https`, `shell`), `KIVULI_PROXY` |
| Server shell | `SHELL_ENABLED`, `SHELL_SSH_PORT`, `SHELL_PORT` |
| Collection | `FOCUS_COUNTRIES` (default KE), `FOCUS_SECTORS`, `DISCOVER_ONION_LINKS`, `CRAWL_HOST_DELAY_SECONDS`, `RENDER_TIMEOUT_SECONDS`, `RENDER_CONCURRENCY` |
| Egress | `EGRESS_ALLOW_HOSTS`: every clearnet host Kivuli may reach. Kept in `.env` on purpose, so the application cannot widen its own egress |
| Email | `EMAIL_ENABLED`, `ALERT_EMAIL_TO`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_TLS`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, `DIGEST_HOUR_UTC` |
| Access | `REQUIRE_MFA` |
| Resources | `SEARCH_HEAP` (search memory), `CRAWLER_CONCURRENCY`, `PIPELINE_CONCURRENCY` |
| Secrets | `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `JWT_SECRET`, `EVIDENCE_HMAC_KEY`, `SECRETS_KEY`, `PROVIDER_KEYS_KEY`: generated; never change them on a running install, and keep them with your backups |

**Real email.** Out of the box, alerts go to the bundled test inbox
(`127.0.0.1:28942`). For real delivery, for example:

```bash
./ctl.sh set SMTP_HOST=smtp.example.org SMTP_PORT=587 SMTP_TLS=starttls SMTP_USERNAME=alerts@example.org SMTP_PASSWORD='…' SMTP_FROM='Kivuli <alerts@example.org>' ALERT_EMAIL_TO=soc@example.org
```

then `./ctl.sh restart` and **System → Email alerts → Send a test message**.

**Bigger servers.** With 16 GB of RAM or more: `SEARCH_HEAP=2g`,
`CRAWLER_CONCURRENCY=10`, `PIPELINE_CONCURRENCY=6`.

## 7. Keys and integrations

Keys are best entered in the console (**Integrations → Enrichment and AI**): they are stored
encrypted, tested against the provider's own server, and take effect without a
restart. A key in `.env` works too; the console's wins.

| Integration | Needs | Notes |
|---|---|---|
| Shodan InternetDB, RIPEstat, public DNS, certificate transparency, Wayback Machine, EPSS, NVD | nothing | On by default |
| VirusTotal, AbuseIPDB, GreyNoise, Shodan | an API key | A key the provider rejects is skipped until replaced |
| **Dark Web Informer** | `DWI_API_KEY` (paid) | Press **Test**, then **Monitor** on its three sources (threat feed, ransomware victims, IOC feed). Imports every 6 hours within its limits |
| **IntelOwl** (your own instance) | `INTELOWL_URL` + its API token | Runs its playbook (`FREE_TO_USE_ANALYZERS` at TLP AMBER by default). On the same server: `docker-compose.intelowl.yml`, see the comments in `.env.example`. Scanning analyzers are refused |
| AI analyst | `ANTHROPIC_API_KEY` | Summaries and briefs |
| Slack, Teams, webhooks, Jira, ServiceNow, Splunk | the destination's URL or token | **Integrations → Alert destinations** |
| TAXII / API | an API key from **Integrations → API, TAXII and STIX** | For a SIEM or another platform to read from Kivuli |

A provider whose host is not in `EGRESS_ALLOW_HOSTS` shows as *host not
allowed*: add it there (comma-separated) and `./ctl.sh restart`.

## 8. Day-to-day management: ctl.sh

Run from the install folder (`cd /opt/kivuli`). On a server, root with
`KIVULI_DOCKER=system`.

| Command | What it does |
|---|---|
| `./ctl.sh start` / `stop` / `restart` | Start, stop, restart the whole stack |
| `./ctl.sh status` | What is running |
| `./ctl.sh doctor` | Health check: containers, API, Tor, disk, the HTTPS address |
| `./ctl.sh logs [service]` | Follow logs: `api`, `web`, `crawler`, `pipeline`, `enricher`, `notify`, `tor`, `egress`, `render`, `search`, `https`, `shell` |
| `./ctl.sh update` | Pull the latest code, rebuild, restart ([section 10](#10-updating)) |
| `./ctl.sh set KEY=VALUE …` | Change settings in `.env` (then restart) |
| `./ctl.sh https <domain> <email>` / `https off` | Kivuli's own HTTPS on or off |
| `./ctl.sh shell on` / `off` | The server shell ([section 11](#11-the-server-shell)) |
| `./ctl.sh autostart on` / `off` | Start at boot and back up daily |
| `./ctl.sh backup [dir] [--keep N]` / `restore <folder>` | [Section 9](#9-backups-and-restore) |
| `./ctl.sh crawl` | Crawl every approved source now |
| `./ctl.sh reindex` | Rebuild the search index from the database |
| `./ctl.sh manage create-user <email> <role>` | Add a user from the command line (roles: admin, analyst, viewer) |
| `./ctl.sh manage test-email` | Send a test alert email |
| `./ctl.sh upgrade-intel` | Re-derive intelligence for findings collected by an older release |
| `./ctl.sh build [backend\|web\|tor\|render\|search]` | Rebuild images after changing code |
| `./ctl.sh test` | Run the backend test suite |
| `./ctl.sh docker <args>` | The Docker CLI for this stack, e.g. `./ctl.sh docker compose ps` |
| `./ctl.sh destroy` | Delete everything, including collected data ([section 16](#16-uninstalling)) |

In the console, **Research → Command line** gives the same everyday actions
(search, verdict, trace, crawl, watch, alerts, timeline…) as typed commands.

## 9. Backups and restore

```bash
./ctl.sh backup
```

writes `backups/kivuli-<date>-<time>/` with the database, the evidence
volume and a copy of `.env`, readable only by the account that ran it. `--keep 14` then deletes
all but the newest 14. With `./ctl.sh autostart on` this runs every night at
about 03:30 with `--keep 14`.

**Copy backups off the server** (encrypted: they contain the database and the
keys that read it). For example, from your own machine:

```bash
rsync -a root@your-server:/opt/kivuli/backups/ ~/kivuli-backups/
```

**Restore** (asks for confirmation, replaces the database, then reindexes):

```bash
./ctl.sh restore backups/kivuli-20261031-033000
```

A backup from another install needs that install's `EVIDENCE_HMAC_KEY`,
`SECRETS_KEY` and `PROVIDER_KEYS_KEY` copied into `.env` (they are in the
backup's `env.backup`).

## 10. Updating

```bash
cd /opt/kivuli && ./ctl.sh backup && ./ctl.sh update
```

`update` pulls the latest code from GitHub (fast-forward only, and refuses if
you have changed tracked files), adds any new settings to `.env` without
changing yours, rebuilds and restarts. Database migrations run on start. After
updating across a release that adds new intelligence, run
`./ctl.sh upgrade-intel` once.

## 11. The server shell

A terminal on the server itself, in the browser, for administrators:
**Research → Command line → Server shell**.

Turn it on (HTTPS must already be on, through Kivuli's Caddy or the nginx
site install.sh wrote):

```bash
./ctl.sh shell on
```

It is WeTTY, a browser SSH client in its own container. Access is gated:

1. only an administrator with two-step sign-in can open it;
2. they press **Open server shell**, which is recorded in the audit log and
   lasts 12 hours for that browser session only;
3. every request to `/shell` is checked with Kivuli first by the web server;
4. then the server's own SSH login (username and password) is asked, every
   session.

On the server, SSH password login must be allowed for that user
(`PasswordAuthentication yes` in `/etc/ssh/sshd_config`, `systemctl restart ssh`),
and `SHELL_SSH_PORT` must match your SSH port. Behind Apache it is not
available. `./ctl.sh shell off` removes it.

## 12. Monitoring and logs

- `./ctl.sh doctor` for a quick health check; it exits non-zero when
  something fails, so it can run from cron or a monitoring agent.
- **Health alerts.** With `./ctl.sh autostart on`, `./ctl.sh doctor --alert`
  runs every 15 minutes and tells you only when the verdict changes: once
  when something breaks, once when it recovers. It emails `ALERT_EMAIL_TO`
  through Kivuli's mail settings, and posts to `OPS_ALERT_WEBHOOK` if set
  (a Slack incoming webhook, or anything that accepts `{"text": …}`). The
  webhook is sent from the server itself, so it still arrives when Kivuli is
  down: set it if you want to hear about a full outage.
- **System → Health** in the console: Tor status, queue depths, provider
  status, collection health.
- **Collection & crawls:** which sources are failing and why.
- `./ctl.sh logs crawler` (and other services) for detail. Logs rotate: at
  most 5 files of 20 MB per container.
- **System → Audit log:** every sign-in, change, export and shell opening.

## 13. Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| Browser: `SSL_ERROR_INTERNAL_ERROR_ALERT` (or "secure connection failed") | The web server on 80/443 has no site for Kivuli's domain yet. Run the installer again (it now configures a system Caddy too), or add the site yourself ([section 4](#4-beside-other-websites-on-the-same-server)) |
| Browser cannot reach `:28941` | Expected: the console listens on 127.0.0.1 only. Use `https://<domain>`, or an SSH tunnel: `ssh -L 28941:127.0.0.1:28941 root@server` then http://localhost:28941 |
| install.sh stops: domain does not resolve | Add the DNS A record for the domain pointing at the server; wait a few minutes; run again |
| No certificate / HTTPS fails | DNS not pointing here yet, or ports 80/443 closed at the provider's firewall or in ufw (`ufw allow 80,443/tcp`). `./ctl.sh logs https` (Caddy) or `/var/log/letsencrypt/letsencrypt.log` (certbot) |
| `search` keeps restarting | `sysctl -w vm.max_map_count=262144` and add it to `/etc/sysctl.conf`; or not enough RAM: lower `SEARCH_HEAP` |
| "Docker is installed but this user cannot use it" | Run as root, or `usermod -aG docker <user>` and log in again |
| Console says it cannot reach the API | `./ctl.sh logs api`; database migrations print there on start |
| Tor not confirmed in doctor | Normal for a few minutes after start; otherwise outbound Tor is blocked: allow outbound 9001 and 443 |
| A provider shows "host not allowed" | Add its host to `EGRESS_ALLOW_HOSTS` and restart |
| A provider shows "key rejected" | Replace the key under Integrations; it is used again at once |
| Alerts not arriving by email | Still on the test inbox: set `SMTP_*` ([section 6](#6-configuration-env)); **System → Email alerts → Send a test message** |
| Disk filling up | `./ctl.sh backup --keep 7`; old backups are the usual culprit. Search data grows with collection |
| Server shell: 403 | Shell off, not an administrator, two-step sign-in off, or not opened from this browser session |
| Server shell: SSH login refused | Password login disabled for that user, wrong `SHELL_SSH_PORT`, or a firewall blocking Docker from reaching the host's SSH |

## 14. Security checklist

- Console behind HTTPS only, with `COOKIE_SECURE=true` (install.sh and
  `./ctl.sh https` do this).
- `WEB_BIND=127.0.0.1` (the default): only the web server reaches the console.
- Two-step sign-in for every account, then `REQUIRE_MFA=true`.
- Change the first admin's password; remove accounts that are not used.
- Keep `EGRESS_ALLOW_HOSTS` to the providers you use.
- Remove the test mail inbox once real SMTP works (delete the `mailpit`
  service from `docker-compose.yml`).
- Keep `.env` at mode 600 and back it up separately and encrypted.
- Turn the server shell on only if you need it; prefer SSH keys for your own
  SSH and allow password login only for the account the shell uses.
- Update regularly (`./ctl.sh update`) and keep the server's OS patched.

## 15. Moving to another server

1. On the old server: `./ctl.sh backup`.
2. Install on the new server ([section 2](#2-install-on-a-server-installsh)).
3. Copy the backup folder across, put the old `EVIDENCE_HMAC_KEY`,
   `SECRETS_KEY` and `PROVIDER_KEYS_KEY` (from its `env.backup`) into the new
   `.env`, then `./ctl.sh restore <folder>`.
4. Point the domain's DNS at the new server.

## 16. Uninstalling

```bash
cd /opt/kivuli && ./ctl.sh backup
```
```bash
./ctl.sh autostart off && ./ctl.sh shell off
```
```bash
./ctl.sh destroy
```

`destroy` deletes the containers and all of Kivuli's Docker data, including
the database and collected findings. Then remove what install.sh added
outside the folder, if any: the nginx or Apache site file it names in its
first lines (and `certbot delete --cert-name <domain>`), and
`/etc/sysctl.d/99-kivuli.conf`. Finally remove the folder itself
(`rm -r /opt/kivuli`) once you no longer need the backups inside it.
