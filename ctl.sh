#!/usr/bin/env bash
# Control script for the self-contained Kivuli threat-intelligence stack.
#
# Everything lives under this folder: the Docker binaries (.runtime/bin), the
# Docker data (.runtime/data: images, database, search index, evidence) and the
# config. Docker runs rootless as your own user - no sudo, nothing installed
# system-wide. The daemon gets its own runtime dir and socket, so it can run
# next to any other rootless Docker on this machine.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RT="$ROOT/.runtime"
UNIT="kivuli-dockerd"
HOST_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
DAEMON_RUNTIME_DIR="$HOST_RUNTIME_DIR/kivuli"

# Which Docker to use. "system": the Docker already installed on this machine (the
# usual choice on a server). "rootless": a private copy kept in .runtime/, needing
# no installation. Chosen automatically; force one with KIVULI_DOCKER=system|rootless.
MODE="${KIVULI_DOCKER:-}"
if [ -z "$MODE" ]; then
	if [ -x "$RT/bin/dockerd-rootless.sh" ]; then
		MODE=rootless # this folder already runs its own Docker: keep it, even if a system Docker appears later
	elif command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
		MODE=system
	else
		MODE=rootless
	fi
fi
if [ "$MODE" = rootless ]; then
	export PATH="$RT/bin:$PATH"
	export DOCKER_CONFIG="$RT/config"
	export DOCKER_HOST="unix://$DAEMON_RUNTIME_DIR/docker.sock"
	LEGACY_BUILD="DOCKER_BUILDKIT=0"  # the private copy ships without buildx
else
	LEGACY_BUILD="KIVULI_BUILD=1"
fi

cd "$ROOT"

daemon_up() { docker info >/dev/null 2>&1; }

DOCKER_VERSION="${DOCKER_VERSION:-29.8.2}"
COMPOSE_VERSION="${COMPOSE_VERSION:-v5.6.0}"

# Fetch Docker's static binaries into this folder on first use. Nothing is installed system-wide.
runtime_install() {
	[ -x "$RT/bin/dockerd-rootless.sh" ] && [ -x "$RT/config/cli-plugins/docker-compose" ] && return 0
	local arch tmp
	arch="$(uname -m)"
	case "$arch" in x86_64 | aarch64) ;; *) echo "Unsupported CPU architecture: $arch" >&2; exit 1 ;; esac
	for tool in curl tar newuidmap newgidmap; do
		command -v "$tool" >/dev/null 2>&1 || { echo "Missing '$tool'. On Debian/Ubuntu: sudo apt install -y curl uidmap" >&2; exit 1; }
	done
	grep -q "^$(id -un):" /etc/subuid 2>/dev/null || { echo "No subordinate user ids for $(id -un) in /etc/subuid. Run: sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $(id -un)" >&2; exit 1; }
	echo "Downloading Docker $DOCKER_VERSION into .runtime/ (first run only)..."
	mkdir -p "$RT/bin" "$RT/config/cli-plugins"
	tmp="$(mktemp -d)"
	for pkg in docker docker-rootless-extras; do
		curl -fL --retry 5 -C - -o "$tmp/$pkg.tgz" "https://download.docker.com/linux/static/stable/$arch/$pkg-$DOCKER_VERSION.tgz"
		tar -xzf "$tmp/$pkg.tgz" -C "$tmp"
		cp -f "$tmp/$pkg"/* "$RT/bin/"
	done
	curl -fL --retry 5 -o "$RT/config/cli-plugins/docker-compose" \
		"https://github.com/docker/compose/releases/download/$COMPOSE_VERSION/docker-compose-linux-$arch"
	chmod +x "$RT/bin"/* "$RT/config/cli-plugins/docker-compose"
	rm -rf "$tmp"
}

daemon_start() {
	daemon_up && return 0
	if [ "$MODE" = system ]; then
		echo "Docker is installed but this user cannot use it (or the service is stopped)." >&2
		echo "  Start it:            sudo systemctl enable --now docker" >&2
		echo "  Allow your user:     sudo usermod -aG docker $(id -un)   then log out and back in" >&2
		exit 1
	fi
	runtime_install
	echo "Starting rootless Docker daemon..."
	mkdir -p "$DAEMON_RUNTIME_DIR" "$RT/data"
	if systemctl --user show-environment >/dev/null 2>&1; then
		# Transient user unit: leaves no unit file behind, logs go to the journal.
		systemctl --user reset-failed "$UNIT" 2>/dev/null || true
		systemd-run --user --quiet --collect --unit="$UNIT" -p Delegate=yes \
			-E PATH="$PATH" -E HOME="$HOME" -E XDG_RUNTIME_DIR="$DAEMON_RUNTIME_DIR" \
			"$RT/bin/dockerd-rootless.sh" --data-root "$RT/data"
	else
		XDG_RUNTIME_DIR="$DAEMON_RUNTIME_DIR" setsid nohup \
			"$RT/bin/dockerd-rootless.sh" --data-root "$RT/data" \
			>"$RT/dockerd.log" 2>&1 &
	fi
	for _ in $(seq 1 60); do
		daemon_up && return 0
		sleep 1
	done
	echo "Docker daemon did not come up." >&2
	echo "Logs: journalctl --user -u $UNIT   (or $RT/dockerd.log)" >&2
	exit 1
}

daemon_stop() {
	[ "$MODE" = system ] && return 0  # the system service is not ours to stop
	if systemctl --user is-active --quiet "$UNIT" 2>/dev/null; then
		systemctl --user stop "$UNIT"
	elif [ -f "$DAEMON_RUNTIME_DIR/docker.pid" ]; then
		kill "$(cat "$DAEMON_RUNTIME_DIR/docker.pid")" 2>/dev/null || true
	fi
}

# The bundled Docker ships without the buildx plugin that `docker compose build`
# relies on, so images are built with plain `docker build`. Layers are cached:
# when nothing changed this takes a second or two.
build_images() {
	local targets=("$@")
	[ ${#targets[@]} -eq 0 ] && targets=(backend tor render search web)
	local name dir img
	for name in "${targets[@]}"; do
		case "$name" in
			backend | api | crawler | pipeline | notify | beat | egress) dir=backend img=kivuli-backend ;;
			tor) dir=tor img=kivuli-tor ;;
			render) dir=render img=kivuli-render ;;
			search) dir=search img=kivuli-search ;;
			web | frontend) dir=frontend img=kivuli-web ;;
			*) echo "Unknown image: $name" >&2; exit 1 ;;
		esac
		# Parallel, checksum-verified download of the pinned dependencies; a no-op
		# when they are already there. Without python3 (or if it fails) the image
		# build simply downloads them itself.
		# Off on servers (install.sh sets KIVULI_PREFETCH=0): their networks download normally.
		if command -v python3 >/dev/null 2>&1 && [ "${KIVULI_PREFETCH:-$(env_get KIVULI_PREFETCH || true)}" != 0 ]; then
			case "$img" in
				kivuli-backend) python3 tools/fetch_deps.py wheels || echo "Prefetch failed; the image build will download dependencies itself." ;;
				kivuli-web) python3 tools/fetch_deps.py npm || echo "Prefetch failed; the image build will download dependencies itself." ;;
			esac
		fi
		if docker image inspect "$img" >/dev/null 2>&1; then
			echo "Building $img..."
			env "$LEGACY_BUILD" docker build -q -t "$img" "./$dir" 2>&1 | grep -v -e DEPRECATED -e 'BuildKit' -e 'buildx' -e 'environment-variable' -e '^$' || true
		else
			# First build downloads packages and can take several minutes: show progress.
			echo "Building $img for the first time..."
			env "$LEGACY_BUILD" docker build -t "$img" "./$dir" 2>&1 | grep -v -e DEPRECATED -e 'BuildKit' -e 'buildx' -e 'environment-variable' -e '^$' || true
		fi
		docker image inspect "$img" >/dev/null 2>&1 || { echo "Build of $img failed. Re-run: ./ctl.sh docker build -t $img ./$dir" >&2; exit 1; }
	done
}

rand() { head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c "${1:-40}"; }

# Create .env on first run, with generated secrets. Never overwrites an existing one.
env_init() {
	[ -f .env ] && return 0
	echo "Creating .env with generated secrets..."
	local admin_pw
	admin_pw="$(rand 20)"
	sed \
		-e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(rand 32)|" \
		-e "s|^REDIS_PASSWORD=.*|REDIS_PASSWORD=$(rand 32)|" \
		-e "s|^JWT_SECRET=.*|JWT_SECRET=$(rand 64)|" \
		-e "s|^EVIDENCE_HMAC_KEY=.*|EVIDENCE_HMAC_KEY=$(rand 64)|" \
		-e "s|^SECRETS_KEY=.*|SECRETS_KEY=$(rand 64)|" \
		-e "s|^PROVIDER_KEYS_KEY=.*|PROVIDER_KEYS_KEY=$(rand 64)|" \
		-e "s|^BOOTSTRAP_ADMIN_PASSWORD=.*|BOOTSTRAP_ADMIN_PASSWORD=$admin_pw|" \
		.env.example >.env
	chmod 600 .env
}

env_get() { grep -E "^$1=" .env 2>/dev/null | head -1 | cut -d= -f2-; }

# Bring an .env written by an earlier release up to date. Never changes a value
# you set: it only adds settings that are missing, generating any new secret.
env_upgrade() {
	[ -f .env ] || return 0
	local key line added=""
	for key in SECRETS_KEY PROVIDER_KEYS_KEY; do
		if [ -z "$(env_get "$key")" ]; then
			sed -i "/^$key=/d" .env
			echo "$key=$(rand 64)" >>.env
			added="$added $key"
		fi
	done
	while IFS= read -r line; do
		key="${line%%=*}"
		case "$key" in '' | \#* | *' '*) continue ;; esac
		if ! grep -q "^$key=" .env; then
			echo "$line" >>.env
			added="$added $key"
		fi
	done < <(grep -E '^[A-Z_]+=' .env.example)
	[ -n "$added" ] && echo "Added new settings to .env:$added"
	# New built-in feeds and providers need their hosts on the egress allowlist.
	local current missing="" host
	current="$(env_get EGRESS_ALLOW_HOSTS)"
	for host in $(grep -E '^EGRESS_ALLOW_HOSTS=' .env.example | cut -d= -f2- | tr ',' ' '); do
		case ",$current," in *",$host,"*) ;; *) missing="$missing,$host" ;; esac
	done
	if [ -n "$missing" ]; then
		sed -i "s|^EGRESS_ALLOW_HOSTS=.*|EGRESS_ALLOW_HOSTS=${current}${missing}|" .env
		echo "Added to EGRESS_ALLOW_HOSTS for new built-in feeds and providers:${missing//,/ }"
		echo "(remove any you do not want; the features that need them will say so)"
	fi
	return 0
}

app_url() {
	local domain
	domain="$(env_get KIVULI_DOMAIN || true)"
	case ",$(env_get COMPOSE_PROFILES || true),$(env_get KIVULI_PROXY || true)," in
		*,https,* | *,nginx,* | *,apache,* | *,caddyhost,*) [ -n "$domain" ] && { echo "https://$domain"; return; } ;;
	esac
	echo "http://localhost:$(env_get WEB_PORT || true)"
}

# Set KEY=VALUE in .env, replacing an existing line or adding one.
env_set() {
	if grep -q "^$1=" .env; then
		local tmp
		tmp="$(mktemp)"
		awk -v k="$1" -v v="$2" 'BEGIN { FS = OFS = "=" } $1 == k { print k "=" v; next } { print }' .env >"$tmp" && cat "$tmp" >.env && rm -f "$tmp"
	else
		echo "$1=$2" >>.env
	fi
}

usage() {
	cat <<EOF
Usage: ./ctl.sh <command>

  start              Start Docker and the whole stack
  init               Create .env with generated secrets, without starting
  set KEY=VALUE ...  Change settings in .env (take effect at the next start)
  update             Pull the latest code from git, rebuild and restart
  https <domain> <email>
                     Serve the console over HTTPS with a Let's Encrypt certificate
  https off          Back to the console on 127.0.0.1 only
  shell on|off       Browser SSH terminal to this server for admins (needs HTTPS)
  doctor             Check the stack: containers, API, Tor, disk, HTTPS
  stop               Stop the stack and the Docker daemon
  restart            Stop, then start
  status             Show what is running
  build [service]    Rebuild images after a code change
  logs [service]     Follow container logs
  crawl              Queue a crawl of every approved source now
  reindex            Rebuild the search index from PostgreSQL
  test               Run the backend test suite
  lock               Re-pin backend dependencies after editing requirements.txt
  backup [dir] [--keep N]
                     Dump the database and evidence to a dated folder; --keep N deletes all but the newest N
  autostart on|off   Start at boot and back up daily (systemd)
  restore <folder>   Restore a backup made by 'backup'
  upgrade-intel      Backfill new intelligence onto findings collected by an older release
  manage <args>      Run a backend management command (see: manage --help)
  docker <args>      Run the bundled docker CLI against this daemon
  destroy            Delete the stack, its databases and all Docker data

Console: printed by 'start'. The first admin login is in .env
(BOOTSTRAP_ADMIN_EMAIL / BOOTSTRAP_ADMIN_PASSWORD).
EOF
}

cmd="${1:-}"
[ $# -gt 0 ] && shift

case "$cmd" in
	start)
		env_init
		env_upgrade
		daemon_start
		build_images
		docker compose up -d --no-build
		echo
		echo "Console:      $(app_url)"
		echo "Admin login:  $(env_get BOOTSTRAP_ADMIN_EMAIL)  (password is BOOTSTRAP_ADMIN_PASSWORD in .env)"
		echo "Mail catcher: http://localhost:$(env_get MAILPIT_PORT)  (dev inbox for alert email)"
		;;
	init)
		# Create .env with generated secrets (or add settings a newer release needs), without starting anything.
		env_init
		env_upgrade
		;;
	set)
		# ./ctl.sh set KEY=VALUE [KEY=VALUE ...]: change settings in .env. Takes effect at the next start.
		env_init
		[ $# -gt 0 ] || { echo "Usage: ./ctl.sh set KEY=VALUE [KEY=VALUE ...]" >&2; exit 1; }
		for pair in "$@"; do
			key="${pair%%=*}"
			echo "$key" | grep -Eq '^[A-Z][A-Z0-9_]*$' && [ "$key" != "$pair" ] || { echo "Not KEY=VALUE: $pair" >&2; exit 1; }
			env_set "$key" "${pair#*=}"
		done
		;;
	update)
		# The working tree must be clean: an update never discards your changes.
		if [ -n "$(git status --porcelain --untracked-files=no 2>/dev/null)" ]; then
			echo "Local changes to tracked files; commit or stash them first:" >&2
			git status --short --untracked-files=no >&2
			exit 1
		fi
		git pull --ff-only
		"$0" start
		;;
	https)
		env_init
		if [ "${1:-}" = "off" ]; then
			env_set COMPOSE_PROFILES ""
			env_set COOKIE_SECURE false
			env_set PUBLIC_URL "http://localhost:$(env_get WEB_PORT)"
			daemon_start
			docker compose rm -sf https >/dev/null 2>&1 || true
			docker compose up -d --no-build
			echo "HTTPS is off. The console is on http://127.0.0.1:$(env_get WEB_PORT) (reach it through an SSH tunnel)."
			exit 0
		fi
		domain="${1:-}" email="${2:-}"
		if [ -z "$domain" ] || [ -z "$email" ] || ! echo "$domain" | grep -Eq '^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$' || ! echo "$email" | grep -q '@'; then
			echo "Usage: ./ctl.sh https <domain> <email>   e.g. ./ctl.sh https intel.example.org you@example.org" >&2
			echo "The domain's DNS must point at this server, and ports 80 and 443 must be open." >&2
			exit 1
		fi
		if [ "$MODE" = "rootless" ]; then
			echo "Note: rootless Docker cannot listen on ports 80 and 443 unless the kernel allows it:" >&2
			echo "  sudo sysctl net.ipv4.ip_unprivileged_port_start=80   (or run with KIVULI_DOCKER=system)" >&2
		fi
		env_set KIVULI_DOMAIN "$domain"
		env_set ACME_EMAIL "$email"
		env_set COMPOSE_PROFILES https
		env_set PUBLIC_URL "https://$domain"
		env_set COOKIE_SECURE true
		env_set WEB_BIND 127.0.0.1
		daemon_start
		build_images
		docker compose up -d --no-build
		echo
		echo "Console: https://$domain  (the certificate is issued on the first request; give it a minute)"
		echo "Check it with: ./ctl.sh doctor"
		;;
	autostart)
		# Start Kivuli when the server boots, and back it up daily (keeping 14), with systemd.
		case "${1:-}" in
			on | off) ;;
			*) echo "Usage: ./ctl.sh autostart on|off" >&2; exit 1 ;;
		esac
		if [ "$MODE" = "system" ]; then
			[ "$(id -u)" = 0 ] || { echo "With system Docker this needs root: sudo KIVULI_DOCKER=system ./ctl.sh autostart ${1}" >&2; exit 1; }
			unit_dir=/etc/systemd/system ctl=(systemctl) target=multi-user.target after="docker.service network-online.target"
		else
			unit_dir="$HOME/.config/systemd/user" ctl=(systemctl --user) target=default.target after="network-online.target"
		fi
		if [ "$1" = "off" ]; then
			"${ctl[@]}" disable --now kivuli-backup.timer kivuli.service 2>/dev/null || true
			rm -f "$unit_dir/kivuli.service" "$unit_dir/kivuli-backup.service" "$unit_dir/kivuli-backup.timer"
			"${ctl[@]}" daemon-reload
			echo "Autostart and daily backups are off."
			exit 0
		fi
		mkdir -p "$unit_dir"
		cat >"$unit_dir/kivuli.service" <<UNIT
[Unit]
Description=Kivuli dark-web research workstation
After=$after
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
Environment=KIVULI_DOCKER=$MODE
WorkingDirectory=$ROOT
ExecStart=$ROOT/ctl.sh start
ExecStop=$ROOT/ctl.sh stop
TimeoutStartSec=1800

[Install]
WantedBy=$target
UNIT
		cat >"$unit_dir/kivuli-backup.service" <<UNIT
[Unit]
Description=Kivuli daily backup (keeps the newest 14)

[Service]
Type=oneshot
Environment=KIVULI_DOCKER=$MODE
WorkingDirectory=$ROOT
ExecStart=$ROOT/ctl.sh backup --keep 14
UNIT
		cat >"$unit_dir/kivuli-backup.timer" <<UNIT
[Unit]
Description=Kivuli daily backup

[Timer]
OnCalendar=*-*-* 03:30:00
RandomizedDelaySec=15m
Persistent=true

[Install]
WantedBy=timers.target
UNIT
		"${ctl[@]}" daemon-reload
		"${ctl[@]}" enable kivuli.service
		"${ctl[@]}" enable --now kivuli-backup.timer
		echo "Kivuli now starts at boot and is backed up daily at about 03:30 to $ROOT/backups (newest 14 kept)."
		if [ "$MODE" != "system" ] && [ "$(loginctl show-user "$USER" -p Linger --value 2>/dev/null)" != "yes" ]; then
			echo "For a user service to start at boot without you logging in, enable lingering once: sudo loginctl enable-linger $USER"
		fi
		;;
	shell)
		env_init
		profiles="$(env_get COMPOSE_PROFILES || true)"
		case "${1:-}" in
			on)
				proxy="$(env_get KIVULI_PROXY || true)"
				if [ "$proxy" = "nginx" ] || [ "$proxy" = "caddyhost" ]; then
					# Behind the server's own nginx or Caddy (install.sh wrote its /shell gate): publish the shell on 127.0.0.1 for it.
					case ":$(env_get COMPOSE_FILE || true):" in *:docker-compose.shell-local.yml:*) ;; *)
						env_set COMPOSE_FILE "$(env_get COMPOSE_FILE | sed 's/^$/docker-compose.yml/'):docker-compose.shell-local.yml" ;; esac
				else
					case ",$profiles," in *,https,*) ;; *) echo "Turn HTTPS on first: ./ctl.sh https <domain> <email> (or install behind nginx with install.sh). The shell is never served over plain HTTP." >&2; exit 1 ;; esac
				fi
				case ",$profiles," in *,shell,*) ;; *) env_set COMPOSE_PROFILES "$(echo "$profiles,shell" | sed 's/^,//')" ;; esac
				env_set SHELL_ENABLED true
				daemon_start
				docker compose up -d --no-build
				echo "Server shell is on: Research > Command line > Server shell (administrators with two-step sign-in)."
				echo "It asks for this server's SSH username and password each session."
				;;
			off)
				env_set COMPOSE_PROFILES "$(echo ",$profiles," | sed 's/,shell,/,/; s/^,//; s/,$//')"
				env_set COMPOSE_FILE "$(env_get COMPOSE_FILE | sed 's/:docker-compose.shell-local.yml//')"
				env_set SHELL_ENABLED false
				daemon_start
				docker compose rm -sf shell >/dev/null 2>&1 || true
				docker compose up -d --no-build
				echo "Server shell is off."
				;;
			*) echo "Usage: ./ctl.sh shell on|off" >&2; exit 1 ;;
		esac
		;;
	doctor)
		daemon_start
		ok=0
		echo "Containers:"
		docker compose ps --format '  {{.Service}}: {{.Status}}' | sort
		for svc in api pipeline crawler enricher web egress tor search postgres redis; do
			state="$(docker compose ps --format '{{.Service}} {{.State}}' | awk -v s="$svc" '$1 == s { print $2 }')"
			[ "$state" = "running" ] || { echo "  ! $svc is not running ($state)"; ok=1; }
		done
		echo "API:"
		if docker compose exec -T api python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/api/healthz',timeout=10)" 2>/dev/null; then
			echo "  answering"
		else
			echo "  ! not answering"; ok=1
		fi
		echo "Tor:"
		docker compose exec -T api python -c "
import json, redis
from app.config import get_settings
s = json.loads(redis.Redis.from_url(get_settings().redis_url).get('kivuli:status:tor') or '{}')
print('  exits through Tor' if s.get('is_tor') else '  ! not confirmed yet: ' + str(s.get('error') or 'no check has run'))" 2>/dev/null || echo "  ! could not read the Tor check"
		echo "Disk:"
		df -h "$ROOT" | awk 'NR == 2 { print "  " $4 " free of " $2 " (" $5 " used)" }'
		used="$(df -P "$ROOT" | awk 'NR == 2 { gsub("%", "", $5); print $5 }')"
		[ "${used:-0}" -lt 90 ] || { echo "  ! the disk is over 90% full"; ok=1; }
		url="$(env_get PUBLIC_URL || true)"
		if [ "${url#https://}" != "$url" ]; then
			# Whatever fronts it (Kivuli's Caddy, or the server's own nginx or Apache), the public address must answer.
			echo "HTTPS:"
			code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$url/login" || true)"
			if [ "$code" = "200" ]; then echo "  $url answers"; else echo "  ! $url answered '$code' (DNS, ports 80/443, the web server's site for it, or the certificate is still being issued)"; ok=1; fi
		fi
		[ "$ok" = 0 ] && echo "All checks passed." || { echo "Some checks failed; see above. Logs: ./ctl.sh logs <service>"; exit 1; }
		;;
	stop)
		if daemon_up; then docker compose stop; fi
		daemon_stop
		;;
	restart)
		"$0" stop
		"$0" start
		;;
	status)
		if daemon_up; then
			docker compose ps
		else
			echo "Docker daemon is not running. Start with: ./ctl.sh start"
		fi
		;;
	build)
		env_init
		env_upgrade
		daemon_start
		build_images "$@"
		docker compose up -d --no-build
		;;
	logs)
		daemon_start
		docker compose logs -f --tail=100 "$@"
		;;
	crawl)
		daemon_start
		docker compose exec -T api python -m app.manage crawl-all
		;;
	reindex)
		daemon_start
		docker compose exec -T api python -m app.manage reindex
		;;
	backup)
		# Database dump plus the evidence volume. Keep .env with it: the keys inside are needed to read both.
		# --keep N then deletes all but the newest N backups in that folder (only folders this command made).
		dir="$ROOT/backups" keep=""
		while [ $# -gt 0 ]; do
			case "$1" in
				--keep) keep="${2:-}"; shift 2 ;;
				*) dir="$1"; shift ;;
			esac
		done
		if [ -n "$keep" ] && ! [ "$keep" -ge 1 ] 2>/dev/null; then echo "--keep needs a number of backups, at least 1" >&2; exit 1; fi
		daemon_start
		dest="$dir/kivuli-$(date +%Y%m%d-%H%M%S)"
		umask 077 # the dump holds collected intelligence and password hashes
		mkdir -p "$dest"
		docker compose exec -T postgres pg_dump -U kivuli -Fc kivuli >"$dest/database.dump"
		docker compose exec -T pipeline tar -C /evidence -czf - . >"$dest/evidence.tar.gz" 2>/dev/null || true
		cp .env "$dest/env.backup" && chmod 600 "$dest/env.backup"
		echo "Backup written to $dest ($(du -sh "$dest" | cut -f1))"
		echo "It contains secrets (env.backup). Store it encrypted."
		if [ -n "$keep" ]; then
			# Newest first by name (the timestamp); only complete backups made by this command are candidates.
			find "$dir" -maxdepth 1 -type d -name 'kivuli-[0-9]*-[0-9]*' -exec test -f '{}/database.dump' ';' -print | sort -r | tail -n +"$((keep + 1))" | while read -r old; do
				rm -rf -- "$old" && echo "Removed old backup $(basename "$old")"
			done
		fi
		;;
	restore)
		[ -f "${1:-}/database.dump" ] || { echo "Usage: ./ctl.sh restore <backup-folder>" >&2; exit 1; }
		read -r -p "Replace the current database with the backup in $1? Type 'yes': " answer
		[ "$answer" = "yes" ] || { echo "Aborted."; exit 1; }
		daemon_start
		docker compose stop api pipeline notify beat crawler enricher web
		docker compose exec -T postgres pg_restore -U kivuli -d kivuli --clean --if-exists --no-owner <"$1/database.dump"
		docker compose up -d --no-build
		[ -s "$1/evidence.tar.gz" ] && docker compose exec -T pipeline tar -C /evidence -xzf - <"$1/evidence.tar.gz"
		docker compose exec -T api python -m app.manage reindex
		echo "Restored. If this backup came from another install, copy its EVIDENCE_HMAC_KEY and SECRETS_KEY into .env."
		;;
	upgrade-intel)
		daemon_start
		docker compose exec -T api python -m app.manage upgrade-intel
		;;
	lock)
		# Re-resolve requirements.txt into exact pins. Run after editing requirements.txt.
		daemon_start
		docker run --rm -v "$ROOT/backend/requirements.txt:/requirements.txt:ro" python:3.12-slim \
			pip install --quiet --disable-pip-version-check --dry-run --ignore-installed --report - -r /requirements.txt \
			| python3 -c 'import json, re, sys
pins = sorted((re.sub(r"[-_.]+", "-", i["metadata"]["name"]).lower(), i["metadata"]["version"]) for i in json.load(sys.stdin)["install"])
print("# Exact versions of every package in the backend image. Generated from")
print("# requirements.txt by `./ctl.sh lock` - do not edit by hand.\n")
print("\n".join(f"{n}=={v}" for n, v in pins))' >backend/requirements.lock.new
		mv backend/requirements.lock.new backend/requirements.lock
		echo "Wrote backend/requirements.lock ($(grep -c '==' backend/requirements.lock) packages). Rebuild with: ./ctl.sh build backend"
		;;
	test)
		daemon_start
		docker run --rm --network none -e ROLE=test -v "$ROOT/backend:/srv:ro" kivuli-backend python -m pytest -q -p no:cacheprovider "$@"
		;;
	manage)
		daemon_start
		docker compose exec -T api python -m app.manage "$@"
		;;
	docker)
		daemon_start
		docker "$@"
		;;
	destroy)
		read -r -p "Delete the stack, its databases, evidence and all Docker data? Type 'yes': " answer
		[ "$answer" = "yes" ] || { echo "Aborted."; exit 1; }
		if daemon_up; then
			docker compose down -v --remove-orphans || true
		fi
		daemon_stop
		sleep 2
		# Docker's data is owned by sub-uids, so remove it from inside a user namespace.
		if [ "$MODE" = rootless ] && [ -d "$RT/data" ]; then "$RT/bin/rootlesskit" rm -rf "$RT/data"; fi
		echo "Removed. Delete this folder to get rid of the Docker binaries too."
		;;
	*)
		usage
		;;
esac
