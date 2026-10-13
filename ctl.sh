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

export PATH="$RT/bin:$PATH"
export DOCKER_CONFIG="$RT/config"
export DOCKER_HOST="unix://$DAEMON_RUNTIME_DIR/docker.sock"

cd "$ROOT"

daemon_up() { docker info >/dev/null 2>&1; }

daemon_start() {
	daemon_up && return 0
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
	[ ${#targets[@]} -eq 0 ] && targets=(backend tor search web)
	local name dir img
	for name in "${targets[@]}"; do
		case "$name" in
			backend | api | crawler | pipeline | notify | beat | egress) dir=backend img=kivuli-backend ;;
			tor) dir=tor img=kivuli-tor ;;
			search) dir=search img=kivuli-search ;;
			web | frontend) dir=frontend img=kivuli-web ;;
			*) echo "Unknown image: $name" >&2; exit 1 ;;
		esac
		# Parallel, checksum-verified download of the pinned dependencies; a no-op
		# when they are already there. Without python3 (or if it fails) the image
		# build simply downloads them itself.
		if command -v python3 >/dev/null 2>&1; then
			case "$img" in
				kivuli-backend) python3 tools/fetch_deps.py wheels || echo "Prefetch failed; the image build will download dependencies itself." ;;
				kivuli-web) python3 tools/fetch_deps.py npm || echo "Prefetch failed; the image build will download dependencies itself." ;;
			esac
		fi
		if docker image inspect "$img" >/dev/null 2>&1; then
			echo "Building $img..."
			DOCKER_BUILDKIT=0 docker build -q -t "$img" "./$dir" 2>&1 | grep -v -e DEPRECATED -e 'BuildKit' -e 'buildx' -e 'environment-variable' -e '^$' || true
		else
			# First build downloads packages and can take several minutes: show progress.
			echo "Building $img for the first time..."
			DOCKER_BUILDKIT=0 docker build -t "$img" "./$dir" 2>&1 | grep -v -e DEPRECATED -e 'BuildKit' -e 'buildx' -e 'environment-variable' -e '^$' || true
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

app_url() { echo "http://localhost:$(env_get WEB_PORT || true)"; }

usage() {
	cat <<EOF
Usage: ./ctl.sh <command>

  start              Start Docker and the whole stack
  stop               Stop the stack and the Docker daemon
  restart            Stop, then start
  status             Show what is running
  build [service]    Rebuild images after a code change
  logs [service]     Follow container logs
  crawl              Queue a crawl of every approved source now
  reindex            Rebuild the search index from PostgreSQL
  test               Run the backend test suite
  lock               Re-pin backend dependencies after editing requirements.txt
  backup [dir]       Dump the database and evidence to a dated folder
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
		daemon_start
		dest="${1:-$ROOT/backups}/kivuli-$(date +%Y%m%d-%H%M%S)"
		umask 077 # the dump holds collected intelligence and password hashes
		mkdir -p "$dest"
		docker compose exec -T postgres pg_dump -U kivuli -Fc kivuli >"$dest/database.dump"
		docker compose exec -T pipeline tar -C /evidence -czf - . >"$dest/evidence.tar.gz" 2>/dev/null || true
		cp .env "$dest/env.backup" && chmod 600 "$dest/env.backup"
		echo "Backup written to $dest ($(du -sh "$dest" | cut -f1))"
		echo "It contains secrets (env.backup). Store it encrypted."
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
		[ -d "$RT/data" ] && "$RT/bin/rootlesskit" rm -rf "$RT/data"
		echo "Removed. Delete this folder to get rid of the Docker binaries too."
		;;
	*)
		usage
		;;
esac
