#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  Kivuli server installer
#
#  Installs Kivuli on a server that may already run other websites, without
#  disturbing them. It looks first, then decides:
#
#    * Nothing on ports 80/443   -> Kivuli's own HTTPS (Caddy, Let's Encrypt)
#    * nginx on 80/443           -> one new nginx site for Kivuli's domain + certbot
#    * Apache on 80/443          -> one new Apache site for Kivuli's domain + certbot
#    * anything else on 80/443   -> leaves it alone and prints what to add to it
#
#  Kivuli itself runs in Docker on private networks and opens nothing to the
#  outside: the console listens on 127.0.0.1 on an uncommon port (28941, or the
#  next free one), and only the web server above talks to it.
#
#  Usage (as root, from a checkout or on its own):
#    ./install.sh --check --domain kivuli.example.org          look only, change nothing
#    ./install.sh --domain kivuli.example.org --email you@example.org
#  Options:
#    --dir /opt/kivuli      where to install (default: this checkout, or /opt/kivuli)
#    --yes                  do not ask before making changes
#    --no-autostart         do not install the start-at-boot and daily-backup timers
#    --repo URL             git repository (default https://github.com/Maerih/kivuli.git)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

DOMAIN="" EMAIL="" DIR="" CHECK=0 YES=0 AUTOSTART=1 REPO="https://github.com/Maerih/kivuli.git"
while [ $# -gt 0 ]; do
	case "$1" in
		--domain) DOMAIN="${2:-}"; shift 2 ;;
		--email) EMAIL="${2:-}"; shift 2 ;;
		--dir) DIR="${2:-}"; shift 2 ;;
		--check) CHECK=1; shift ;;
		--yes | -y) YES=1; shift ;;
		--no-autostart) AUTOSTART=0; shift ;;
		--repo) REPO="${2:-}"; shift 2 ;;
		-h | --help) sed -n '2,27p' "$0"; exit 0 ;;
		*) echo "Unknown option: $1 (see --help)" >&2; exit 1 ;;
	esac
done

if [ -t 1 ]; then B=$'\e[1m' G=$'\e[32m' Y=$'\e[33m' R=$'\e[31m' N=$'\e[0m'; else B="" G="" Y="" R="" N=""; fi
say() { echo "${B}==>${N} $*"; }
ok() { echo "  ${G}ok${N}    $*"; }
warn() { echo "  ${Y}note${N}  $*"; }
bad() { echo "  ${R}stop${N}  $*"; }
die() { echo "${R}Error:${N} $*" >&2; exit 1; }
ask() {
	[ "$YES" = 1 ] && return 0
	local answer
	# From the terminal, so this also works when the script itself arrives on stdin (curl ... | sudo bash).
	[ -r /dev/tty ] || die "No terminal to ask on: add --yes to go ahead without asking."
	read -r -p "$1 [y/N] " answer </dev/tty
	[ "$answer" = "y" ] || [ "$answer" = "Y" ] || [ "$answer" = "yes" ]
}

[ -n "$DOMAIN" ] || die "Give the domain Kivuli will use: --domain kivuli.example.org"
echo "$DOMAIN" | grep -Eq '^([A-Za-z0-9-]+\.)+[A-Za-z]{2,}$' || die "Not a domain name: $DOMAIN"
[ "$CHECK" = 1 ] && [ "$(id -u)" != 0 ] && echo "(Not root: programs on ports show as 'something'. sudo ./install.sh --check ... names them.)"
if [ "$CHECK" = 0 ]; then
	[ "$(id -u)" = 0 ] || die "Run as root (sudo ./install.sh ...), or add --check to only look."
	[ -n "$EMAIL" ] && echo "$EMAIL" | grep -q '@' || die "Give an email for the certificate and the first admin: --email you@example.org"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-.}")" 2>/dev/null && pwd || echo /nonexistent)"
if [ -z "$DIR" ]; then
	if [ -x "$SCRIPT_DIR/ctl.sh" ]; then DIR="$SCRIPT_DIR"; else DIR="/opt/kivuli"; fi
fi

# ── Look ─────────────────────────────────────────────────────────────────────

port_owner() {
	# The program listening on a TCP port, or "" when it is free. Names need root; without it, "something".
	local line
	line="$(ss -Htlnp "sport = :$1" 2>/dev/null | head -1)" || true
	[ -n "$line" ] || { echo ""; return; }
	local name
	name="$(echo "$line" | grep -o 'users:(("[^"]*"' | head -1 | sed 's/users:(("//; s/"$//' || true)"
	echo "${name:-something}"
}

free_port() {
	# The first free port from $1 upwards, skipping $2 (already chosen).
	local p="$1"
	while [ "$p" -lt "$(($1 + 60))" ]; do
		[ "$p" != "${2:-}" ] && [ -z "$(port_owner "$p")" ] && { echo "$p"; return; }
		p=$((p + 1))
	done
	die "No free port between $1 and $(($1 + 60))"
}

say "Looking at this server"
. /etc/os-release 2>/dev/null || true
ok "System: ${PRETTY_NAME:-unknown} on $(uname -m), $(nproc) CPU, $(free -g | awk '/^Mem:/ { print $2 }') GB RAM"
mem_gb="$(free -g | awk '/^Mem:/ { print $2 }')"
[ "$mem_gb" -ge 7 ] || warn "Kivuli runs best with 8 GB of RAM or more (search and the headless browser are the heavy parts). It will run, but slower."
SHARED_SIZING=0
if [ "$mem_gb" -lt 12 ]; then
	SHARED_SIZING=1
	ok "Under 12 GB of RAM: Kivuli will be sized down (search 512 MB, fewer workers) to leave room for other applications"
fi
parent="$(dirname "$DIR")"; [ -d "$parent" ] || parent=/
disk_gb="$(df -BG --output=avail "$parent" | tail -1 | tr -dc 0-9)"
[ "$disk_gb" -ge 40 ] && ok "Disk: ${disk_gb} GB free" || warn "Only ${disk_gb} GB free on $parent; collection grows over time, 80 GB is comfortable."

FRONT="" FRONT_NAME=""
o80="$(port_owner 80)" o443="$(port_owner 443)"
case "$o80$o443" in
	"") FRONT=caddy FRONT_NAME="nothing (free)" ;;
	*nginx*) FRONT=nginx FRONT_NAME="nginx" ;;
	*apache2* | *httpd*) FRONT=apache FRONT_NAME="Apache" ;;
	*docker-proxy*) FRONT=external FRONT_NAME="a Docker container" ;;
	*caddy*)
		if systemctl is-active -q caddy 2>/dev/null && [ -f /etc/caddy/Caddyfile ]; then FRONT=caddyhost FRONT_NAME="Caddy (system service)"
		else FRONT=external FRONT_NAME="Caddy"; fi ;;
	*traefik*) FRONT=external FRONT_NAME="Traefik" ;;
	*) FRONT=external FRONT_NAME="${o80:-$o443}" ;;
esac
if [ "$FRONT" = caddy ]; then
	ok "Ports 80 and 443 are free: Kivuli will bring its own HTTPS"
else
	ok "Ports 80/443 are used by $FRONT_NAME: Kivuli will sit behind it and leave its sites alone"
fi

if [ "$FRONT" = external ] && command -v docker >/dev/null 2>&1; then
	holder="$(docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null | grep -E ':(80|443)->' | awk '{ print $1 }' | head -3 | tr '\n' ' ' || true)"
	[ -n "$holder" ] && warn "Container(s) publishing 80/443: $holder"
fi

# Sites the existing web server already serves, and whether Kivuli's domain is among them.
taken=0
if [ "$FRONT" = nginx ] && command -v nginx >/dev/null 2>&1; then
	sites="$(nginx -T 2>/dev/null | awk '/^[[:space:]]*server_name/ { for (i = 2; i <= NF; i++) { gsub(";", "", $i); print $i } }' | sort -u | grep -v '^_$' | tr '\n' ' ' || true)"
	[ -n "$sites" ] && ok "nginx already serves: $sites"
	domain_re="$(echo "$DOMAIN" | sed 's/\./\\./g')"
	if nginx -T 2>/dev/null | grep -Eq "server_name[^;]*[[:space:]]${domain_re}[[:space:];]"; then
		if nginx -T 2>/dev/null | grep -q "Kivuli ($DOMAIN) - written by install.sh"; then ok "$DOMAIN is Kivuli's own site from an earlier install: it will be rewritten"
		else bad "nginx already has a site for $DOMAIN that install.sh did not write. Remove it or pick another domain."; taken=1; fi
	fi
elif [ "$FRONT" = apache ] && command -v apachectl >/dev/null 2>&1; then
	sites="$(apachectl -S 2>/dev/null | grep -Eo 'namevhost [^ ]+' | awk '{ print $2 }' | sort -u | tr '\n' ' ' || true)"
	[ -n "$sites" ] && ok "Apache already serves: $sites"
	if apachectl -S 2>/dev/null | grep -Fq "namevhost $DOMAIN " && ! grep -rqs "Kivuli ($DOMAIN) - written by install.sh" /etc/apache2 /etc/httpd 2>/dev/null; then
		bad "Apache already has a site for $DOMAIN that install.sh did not write. Remove it or pick another domain."; taken=1
	fi
fi

# Kivuli's own ports, all on 127.0.0.1: keep the ones an earlier install chose, else the first free ones.
existing_env="$DIR/.env"
env_val() { [ -f "$existing_env" ] && grep -E "^$1=" "$existing_env" | head -1 | cut -d= -f2- || true; }
WEB_PORT="$(env_val WEB_PORT)" MAILPIT_PORT="$(env_val MAILPIT_PORT)" SHELL_PORT="$(env_val SHELL_PORT)"
kivuli_running=0
command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${COMPOSE_PROJECT_NAME:-kivuli}-web-1$" && kivuli_running=1
pick() { # keep $1 if this install already uses it (Kivuli is running) or it is free; else the next free from $2
	if [ -n "$1" ] && { [ "$kivuli_running" = 1 ] || [ -z "$(port_owner "$1")" ]; }; then echo "$1"; else free_port "$2" "${3:-}"; fi
}
WEB_PORT="$(pick "$WEB_PORT" 28941)"
MAILPIT_PORT="$(pick "$MAILPIT_PORT" 28942 "$WEB_PORT")"
SHELL_PORT="$(pick "$SHELL_PORT" 28943 "$MAILPIT_PORT")"
ok "Kivuli's ports on 127.0.0.1: console $WEB_PORT, test mail inbox $MAILPIT_PORT, server shell $SHELL_PORT"

# The system Caddy: which sites it serves, and whether one already answers for Kivuli's domain.
CADDY_SITE="/etc/caddy/kivuli/$DOMAIN.caddy" caddy_ready=0
caddy_hosts() { # "host upstream" lines from the running Caddyfile
	caddy adapt --config /etc/caddy/Caddyfile --adapter caddyfile 2>/dev/null | python3 -c '
import json, sys
def walk(routes, hosts=()):
    for r in routes or []:
        hs = [h for m in r.get("match", []) for h in m.get("host", [])] or list(hosts)
        for h in r.get("handle", []):
            if h.get("handler") == "reverse_proxy":
                for u in h.get("upstreams", []): [print(x, u.get("dial", "")) for x in hs]
            elif h.get("handler") == "subroute": walk(h.get("routes"), hs)
            else: [print(x, "-") for x in hs]  # served some other way (files, a fixed answer, a redirect)
cfg = json.load(sys.stdin)
for srv in cfg.get("apps", {}).get("http", {}).get("servers", {}).values(): walk(srv.get("routes"))
' 2>/dev/null || true
}
if [ "$FRONT" = caddyhost ]; then
	served="$(caddy_hosts | awk '{ print $1 }' | sort -u | tr '\n' ' ')"
	[ -n "$served" ] && ok "Caddy already serves: $served"
	ours="$(caddy_hosts | awk -v d="$DOMAIN" '$1 == d && $2 != "-" { print $2 }' | sort -u | tr '\n' ' ')"
	[ -z "$ours" ] && caddy_hosts | awk -v d="$DOMAIN" '$1 == d' | grep -q . && ours="(not a proxy)"
	if [ -n "$ours" ]; then
		if [ -f "$CADDY_SITE" ]; then ok "$DOMAIN is Kivuli's own Caddy site from an earlier install: it will be rewritten"
		elif echo " $ours " | grep -q " 127.0.0.1:$WEB_PORT \| localhost:$WEB_PORT "; then ok "Caddy already sends $DOMAIN to Kivuli ($ours): kept as it is"; caddy_ready=1
		else bad "Caddy already sends $DOMAIN somewhere else ($ours). Remove that site or pick another domain."; taken=1; fi
	fi
fi

# A domain's A records as public DNS sees them (Google, then Cloudflare, over HTTPS). That is what
# Let's Encrypt checks, and it is not fooled by a stale answer cached on this machine.
public_a() {
	local url
	for url in "https://dns.google/resolve?name=$1&type=A" "https://cloudflare-dns.com/dns-query?name=$1&type=A"; do
		curl -fsS --max-time 8 -H 'accept: application/dns-json' "$url" 2>/dev/null | python3 -c '
import json, sys
print(" ".join(sorted(a["data"] for a in json.load(sys.stdin).get("Answer", []) if a.get("type") == 1)))' 2>/dev/null | grep . && return 0
	done
	return 1
}

# DNS: the domain must point here before a certificate can be issued. Asked of public DNS, not this
# machine's resolver, which may still hold an old answer after a change.
dns_ok=1
local_resolved="$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '{ print $1 }' | sort -u | tr '\n' ' ' || true)"
resolved="$(public_a "$DOMAIN" || true)" dns_from="public DNS"
[ -n "$resolved" ] || { resolved="$local_resolved"; dns_from="this server's resolver; public DNS did not answer"; }
DOMAIN_IP="${resolved%% *}"
public_ip="$(curl -4 -s --max-time 8 https://api.ipify.org 2>/dev/null || true)"
local_ips="$(hostname -I 2>/dev/null || true) $public_ip"
if [ -z "$resolved" ]; then
	bad "$DOMAIN does not resolve yet. Add a DNS A record pointing to ${public_ip:-the public IP of this server}."; dns_ok=0
elif ! echo " $local_ips " | grep -Eq " ($(echo "$resolved" | sed 's/ $//; s/ /|/g')) "; then
	bad "$DOMAIN points to $resolved, but this server is ${public_ip:-$(hostname -I)}. Fix the DNS A record first."; dns_ok=0
else
	ok "DNS: $DOMAIN points to this server ($(echo "$resolved" | xargs), $dns_from)"
fi
if [ -n "$local_resolved" ] && [ "$(echo "$local_resolved" | xargs)" != "$(echo "$resolved" | xargs)" ]; then
	warn "This server's own resolver still says $DOMAIN is $(echo "$local_resolved" | xargs) (an old cached answer, or an entry in /etc/hosts)."
	warn "Certificates use public DNS, so the install is not affected. To refresh it here: resolvectl flush-caches; and check /etc/hosts"
fi

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
	ok "Docker: $(docker --version | sed 's/^Docker version //; s/,.*//') with Compose"
else
	warn "Docker is not installed: it will be installed from docker.com (get.docker.com)"
fi
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
	ufw status 2>/dev/null | grep -Eq '(^| )(80|443)(/tcp)?[[:space:]]+ALLOW' && ok "Firewall (ufw): ports 80/443 allowed" || warn "Firewall (ufw) is on; 80 and 443 must be allowed: ufw allow 80,443/tcp"
fi
[ "$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)" -ge 262144 ] || warn "vm.max_map_count is low for the search engine; it will be raised to 262144"

echo
case "$FRONT" in
	caddy) say "Plan: Kivuli's own HTTPS for https://$DOMAIN (Caddy on 80/443, certificate from Let's Encrypt)" ;;
	nginx) say "Plan: add one nginx site for $DOMAIN -> 127.0.0.1:$WEB_PORT, certificate with certbot; other nginx sites untouched" ;;
	apache) say "Plan: add one Apache site for $DOMAIN -> 127.0.0.1:$WEB_PORT, certificate with certbot; other sites untouched" ;;
	caddyhost) [ "$caddy_ready" = 1 ] && say "Plan: start Kivuli on 127.0.0.1:$WEB_PORT behind the Caddy site already there for $DOMAIN" \
		|| say "Plan: add one Caddy site for $DOMAIN -> 127.0.0.1:$WEB_PORT in $CADDY_SITE (Caddy gets its certificate); other sites untouched" ;;
	external) say "Plan: start Kivuli on 127.0.0.1:$WEB_PORT and print what to add to $FRONT_NAME (it is not changed)" ;;
esac
say "Install into: $DIR"

if [ "$CHECK" = 1 ]; then
	echo
	[ "$taken" = 0 ] && [ "$dns_ok" = 1 ] && echo "Looks ready. Run again without --check (as root, with --email) to install." \
		|| echo "Fix the items marked 'stop' above, then run again."
	exit 0
fi
[ "$taken" = 0 ] || die "The domain is already used by another site on this server."
if [ "$dns_ok" = 0 ] && [ "$FRONT" != external ]; then
	die "A certificate cannot be issued until $DOMAIN points to this server. Fix DNS and run again."
fi
ask "Go ahead?" || die "Nothing was changed."

# ── Install ──────────────────────────────────────────────────────────────────

export KIVULI_DOCKER=system DEBIAN_FRONTEND=noninteractive
have_apt() { command -v apt-get >/dev/null 2>&1; }

say "Installing what is missing"
for tool in git curl; do
	command -v "$tool" >/dev/null 2>&1 || { have_apt && apt-get update -qq && apt-get install -y -qq "$tool" ca-certificates; } || die "Install $tool first"
done
if ! { command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; }; then
	curl -fsSL https://get.docker.com | sh
	systemctl enable --now docker
fi
ok "Docker ready"
if [ "$(sysctl -n vm.max_map_count)" -lt 262144 ]; then
	echo "vm.max_map_count=262144" >/etc/sysctl.d/99-kivuli.conf && sysctl -q -w vm.max_map_count=262144
	ok "vm.max_map_count raised to 262144 (/etc/sysctl.d/99-kivuli.conf)"
fi

say "Getting Kivuli"
if [ -x "$DIR/ctl.sh" ]; then
	if [ -d "$DIR/.git" ] && [ -z "$(git -C "$DIR" status --porcelain --untracked-files=no)" ]; then
		git -C "$DIR" pull -q --ff-only && ok "Updated the code in $DIR" || warn "Could not update $DIR from git; using it as it is"
	else
		ok "Using the code in $DIR"
	fi
else
	git clone "$REPO" "$DIR"
	ok "Cloned into $DIR"
fi
cd "$DIR"

say "Configuring"
had_env=0; [ -f .env ] && had_env=1
./ctl.sh init >/dev/null
first_install=0
grep -q '^BOOTSTRAP_ADMIN_EMAIL=admin@kivuli.local$' .env && first_install=1
./ctl.sh set WEB_PORT="$WEB_PORT" MAILPIT_PORT="$MAILPIT_PORT" SHELL_PORT="$SHELL_PORT" WEB_BIND=127.0.0.1 \
	KIVULI_DOMAIN="$DOMAIN" ACME_EMAIL="$EMAIL" PUBLIC_URL="https://$DOMAIN" COOKIE_SECURE=true KIVULI_PROXY="$FRONT" KIVULI_PREFETCH=0
[ "$first_install" = 1 ] && ./ctl.sh set BOOTSTRAP_ADMIN_EMAIL="$EMAIL"
if [ "$SHARED_SIZING" = 1 ]; then
	./ctl.sh set SEARCH_HEAP=512m CRAWLER_CONCURRENCY=3 PIPELINE_CONCURRENCY=2 RENDER_CONCURRENCY=1
	ok "Sized for a shared server (change later with ./ctl.sh set SEARCH_HEAP=... CRAWLER_CONCURRENCY=...)"
fi
[ "$had_env" = 1 ] && ok "Settings updated in $DIR/.env (existing secrets, ports and data kept)" || ok "Settings written to $DIR/.env (secrets generated)"

say "Building and starting Kivuli (the first build takes several minutes)"
./ctl.sh start

	# The nginx site for Kivuli's domain. $1 = 1 to include the server shell's gate.
write_nginx() {
	cat >"$conf" <<NGINX
# Kivuli ($DOMAIN) - written by install.sh. Only this site; other sites are untouched.
# Remove: rm $conf ${link:+$link }&& nginx -s reload
map \$http_upgrade \$kivuli_connection_upgrade { default upgrade; '' close; }

server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    client_max_body_size 12m;

    location / {
        proxy_pass http://127.0.0.1:$WEB_PORT;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 300s;
    }
NGINX
	if [ "$1" = 1 ]; then cat >>"$conf" <<NGINX

    # The server shell (./ctl.sh shell on): every request first asks Kivuli, which lets
    # through only an administrator with two-step sign-in who opened it in the console.
    location /shell {
        auth_request /_kivuli_shell_auth;
        proxy_pass http://127.0.0.1:$SHELL_PORT;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$kivuli_connection_upgrade;
        proxy_read_timeout 1h;
    }
    location = /_kivuli_shell_auth {
        internal;
        proxy_pass http://127.0.0.1:$WEB_PORT/api/shell/authorize;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header Host \$host;
        proxy_set_header Upgrade "";
        proxy_set_header Connection "";
    }
NGINX
	fi
	echo "}" >>"$conf"
	[ -n "$link" ] && ln -sf "$conf" "$link"
	true
}

case "$FRONT" in
	caddy)
		say "Turning on HTTPS"
		./ctl.sh https "$DOMAIN" "$EMAIL"
		;;
	nginx)
		say "Adding the nginx site for $DOMAIN"
		if [ -d /etc/nginx/sites-available ]; then conf=/etc/nginx/sites-available/kivuli-$DOMAIN.conf link=/etc/nginx/sites-enabled/kivuli-$DOMAIN.conf
		else conf=/etc/nginx/conf.d/kivuli-$DOMAIN.conf link=""; fi
		write_nginx 1
		if ! nginx -t 2>/tmp/kivuli-nginx-test; then
			if grep -q "auth_request" /tmp/kivuli-nginx-test; then
				warn "This nginx has no auth_request module: the server shell will not be available behind it"
				write_nginx 0
			fi
			nginx -t || { rm -f "$conf" ${link:+"$link"}; die "nginx rejected the new site; it was removed and nothing else changed."; }
		fi
		systemctl reload nginx
		ok "Site added: $conf"
		say "Getting a certificate for $DOMAIN (Let's Encrypt, via certbot; by continuing you accept its terms)"
		command -v certbot >/dev/null 2>&1 && certbot plugins 2>/dev/null | grep -q nginx || { have_apt && apt-get install -y -qq certbot python3-certbot-nginx; }
		certbot --nginx -d "$DOMAIN" -m "$EMAIL" --agree-tos --non-interactive --redirect --keep-until-expiring
		ok "HTTPS on https://$DOMAIN (certbot renews it automatically)"
		;;
	apache)
		say "Adding the Apache site for $DOMAIN"
		a2enmod -q proxy proxy_http proxy_wstunnel headers >/dev/null
		conf=/etc/apache2/sites-available/kivuli-$DOMAIN.conf
		cat >"$conf" <<APACHE
# Kivuli ($DOMAIN) - written by install.sh. Only this site; other sites are untouched.
# Remove: a2dissite kivuli-$DOMAIN && rm $conf && systemctl reload apache2
<VirtualHost *:80>
    ServerName $DOMAIN
    ProxyPreserveHost On
    ProxyTimeout 300
    RequestHeader set X-Forwarded-Proto "https" env=HTTPS
    ProxyPass / http://127.0.0.1:$WEB_PORT/
    ProxyPassReverse / http://127.0.0.1:$WEB_PORT/
</VirtualHost>
APACHE
		a2ensite -q "kivuli-$DOMAIN" >/dev/null
		apachectl configtest || { a2dissite -q "kivuli-$DOMAIN"; rm -f "$conf"; die "Apache rejected the new site; it was removed and nothing else changed."; }
		systemctl reload apache2
		ok "Site added: $conf (the server shell is only available behind Caddy or nginx)"
		say "Getting a certificate for $DOMAIN (Let's Encrypt, via certbot; by continuing you accept its terms)"
		command -v certbot >/dev/null 2>&1 && certbot plugins 2>/dev/null | grep -q apache || { have_apt && apt-get install -y -qq certbot python3-certbot-apache; }
		certbot --apache -d "$DOMAIN" -m "$EMAIL" --agree-tos --non-interactive --redirect --keep-until-expiring
		ok "HTTPS on https://$DOMAIN (certbot renews it automatically)"
		;;
	caddyhost)
		if [ "$caddy_ready" = 1 ]; then
			ok "Caddy already serves $DOMAIN for Kivuli; it was not changed"
		else
			say "Adding the Caddy site for $DOMAIN"
			# Kivuli's site lives in its own file; the Caddyfile only gains one import line. Everything is
			# validated before Caddy reloads, and put back exactly as it was if validation fails.
			stamp="$(date +%Y%m%d-%H%M%S)"
			cp -p /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.before-kivuli-$stamp"
			mkdir -p /etc/caddy/kivuli
			cat >"$CADDY_SITE" <<CADDY
# Kivuli ($DOMAIN) - written by install.sh. Only this site; other sites are untouched.
# Remove: rm $CADDY_SITE && systemctl reload caddy   (and the import line in /etc/caddy/Caddyfile)
$DOMAIN {
	encode zstd gzip
	header Strict-Transport-Security "max-age=31536000; includeSubDomains"
	# The server shell (./ctl.sh shell on): every request first asks Kivuli, which lets through only
	# an administrator with two-step sign-in who opened it in the console.
	handle /shell* {
		forward_auth 127.0.0.1:$WEB_PORT {
			uri /api/shell/authorize
			header_up -Connection
			header_up -Upgrade
		}
		reverse_proxy 127.0.0.1:$SHELL_PORT
	}
	handle {
		reverse_proxy 127.0.0.1:$WEB_PORT
	}
}
CADDY
			added_import=0
			if ! grep -q '^import /etc/caddy/kivuli/\*.caddy' /etc/caddy/Caddyfile; then
				printf '\n# Kivuli sites (install.sh)\nimport /etc/caddy/kivuli/*.caddy\n' >>/etc/caddy/Caddyfile
				added_import=1
			fi
			if ! caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/tmp/kivuli-caddy-validate 2>&1; then
				cp -p "/etc/caddy/Caddyfile.before-kivuli-$stamp" /etc/caddy/Caddyfile
				rm -f "$CADDY_SITE"
				tail -5 /tmp/kivuli-caddy-validate >&2
				die "Caddy rejected the new site. Your Caddyfile was put back exactly as it was; nothing else changed."
			fi
			systemctl reload caddy
			ok "Site added: $CADDY_SITE"
			[ "$added_import" = 1 ] && ok "One import line added to /etc/caddy/Caddyfile (backup: /etc/caddy/Caddyfile.before-kivuli-$stamp)"
		fi
		say "Waiting for https://$DOMAIN (Caddy gets the certificate on its own; usually under a minute)"
		for _ in $(seq 1 24); do
			code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 ${DOMAIN_IP:+--resolve "$DOMAIN:443:$DOMAIN_IP"} "https://$DOMAIN/login" || true)"
			[ "$code" = 200 ] && break
			sleep 5
		done
		[ "$code" = 200 ] && ok "https://$DOMAIN answers" || warn "https://$DOMAIN is not answering yet ($code). Check: journalctl -u caddy --since '10 min ago' | tail -30"
		;;
	external)
		say "Kivuli is running on 127.0.0.1:$WEB_PORT. Point $FRONT_NAME at it for $DOMAIN, for example:"
		cat <<EOF
    Caddy:    $DOMAIN { reverse_proxy 127.0.0.1:$WEB_PORT }
    Traefik:  a router for Host(\`$DOMAIN\`) to the service url http://127.0.0.1:$WEB_PORT
    Other:    proxy https://$DOMAIN to http://127.0.0.1:$WEB_PORT, passing Host and X-Forwarded-Proto
  (From inside a Docker container, 127.0.0.1 is the container itself: use the host's address, e.g. host.docker.internal.)
EOF
		;;
esac

if [ "$AUTOSTART" = 1 ]; then
	say "Start at boot, daily backups"
	./ctl.sh autostart on
fi

say "Checking"
sleep 5
./ctl.sh doctor || warn "Some checks failed; see above. The first Tor check and certificate can take a few minutes: run ./ctl.sh doctor again shortly."

echo
say "Done"
echo "  Console:      https://$DOMAIN"
echo "  First admin:  $(grep -E '^BOOTSTRAP_ADMIN_EMAIL=' .env | cut -d= -f2-)   password: grep BOOTSTRAP_ADMIN_PASSWORD $DIR/.env"
echo "  Next:         sign in, change the password, turn on two-step sign-in (System > My account),"
echo "                then add your keys under Integrations."
echo "  Manage:       cd $DIR && ./ctl.sh status | logs | doctor | update | backup"
echo "  Kivuli uses:  127.0.0.1:$WEB_PORT (console), :$MAILPIT_PORT (test inbox), :$SHELL_PORT (shell)"
case "$FRONT" in
	caddy) echo "                and ports 80/443 for its own HTTPS." ;;
	nginx | apache) echo "                and one new $FRONT_NAME site file for $DOMAIN; no other site was changed." ;;
	caddyhost) echo "                and one Caddy site file for $DOMAIN; no other site was changed." ;;
	external) echo "                $FRONT_NAME was not changed." ;;
esac
