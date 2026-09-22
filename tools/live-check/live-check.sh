#!/usr/bin/env bash
# tools/live-check — a real IdP login against the standalone template at this
# checkout, with the template's default configuration. README.md says when and
# how; this file is the how.
#
#   live-check.sh start [profile]   profiles/<profile>.env (default: google)
#   live-check.sh stop
#   live-check.sh status | report | logs
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
TEMPLATE="$ROOT/templates/standalone"
STATE="$HERE/.state"
PORT="${LIVE_CHECK_PORT:-3210}"
PROVIDER_PORT="${LIVE_CHECK_PROVIDER_PORT:-3000}"
# The template resolves `{CONFIG_ENV}.conf` beside application.conf and
# git-ignores `config/*.local.conf`, so the overlay lives there for the run.
OVERLAY_ENV="live-check.local"
OVERLAY="$TEMPLATE/config/$OVERLAY_ENV.conf"
REDIS_CONTAINER="auth-live-check-redis"
REDIS_URL=""

usage() {
	cat <<EOF
usage: live-check.sh start [profile]   boot the provider and the front for profiles/<profile>.env (default: google)
       live-check.sh stop              stop both, remove the overlay and the Redis container start began
       live-check.sh status            the record so far, as JSON
       live-check.sh report            the record so far, as the markdown to paste into an issue
       live-check.sh logs              the tail of both logs
EOF
}

say() { printf 'live-check: %s\n' "$*"; }
die() {
	printf 'live-check: %s\n' "$*" >&2
	exit 1
}
listening() { lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; }

# Descendants first, then the process. Killing only the pnpm wrapper leaves
# its tsx and node children alive and the port held — the provider then
# answers, but it is the old one.
kill_tree() {
	local pid="$1" child
	for child in $(pgrep -P "$pid" 2>/dev/null || true); do kill_tree "$child"; done
	kill "$pid" 2>/dev/null || true
}
kill_pidfile() {
	local f="$STATE/$1.pid"
	[ -f "$f" ] || return 0
	kill_tree "$(cat "$f")"
	rm -f "$f"
}

# The workspace has to be installed and built: the provider imports the
# packages' dist. A package whose src is newer than its dist is rebuilt.
deps() {
	if [ ! -d "$TEMPLATE/node_modules/@o3co/auth-provider-core" ]; then
		say "installing the workspace (templates/standalone has no node_modules)"
		(cd "$ROOT" && pnpm install --frozen-lockfile) >"$STATE/install.log" 2>&1 ||
			die "pnpm install failed — see $STATE/install.log"
	fi
	local p stale=""
	for p in "$ROOT"/packages/*/; do
		grep -q '"build"' "$p/package.json" || continue
		if [ ! -f "$p/dist/index.mjs" ] ||
			[ -n "$(find "$p/src" -name '*.mts' -not -path '*/__tests__/*' -newer "$p/dist/index.mjs" | head -n 1)" ]; then
			stale="$stale $(basename "$p")"
		fi
	done
	if [ -n "$stale" ]; then
		say "building the workspace (missing or stale dist:$stale)"
		(cd "$ROOT" && pnpm run build) >"$STATE/build.log" 2>&1 || die "build failed — see $STATE/build.log"
	fi
}

keys() {
	[ -f "$STATE/keys/jwt-private.pem" ] && return 0
	node -e '
const { generateKeyPairSync, randomBytes } = require("node:crypto");
const fs = require("node:fs");
const dir = process.argv[1];
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
fs.writeFileSync(`${dir}/keys/jwt-private.pem`, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
fs.writeFileSync(`${dir}/keys/jwt-public.pem`, publicKey.export({ type: "spki", format: "pem" }));
fs.writeFileSync(`${dir}/session-secret`, randomBytes(32).toString("hex"), { mode: 0o600 });
' "$STATE"
	say "generated a throwaway Ed25519 key pair and session secret in .state/"
}

redis() {
	if [ -n "${LIVE_CHECK_REDIS_URL:-}" ]; then
		REDIS_URL="$LIVE_CHECK_REDIS_URL"
		say "using Redis at $REDIS_URL"
		return 0
	fi
	REDIS_URL="redis://localhost:6379"
	if listening 6379; then
		say "using the Redis already listening on :6379"
		return 0
	fi
	command -v docker >/dev/null || die "no Redis on :6379 and no docker — start one, or set LIVE_CHECK_REDIS_URL"
	say "starting Redis in docker ($REDIS_CONTAINER on 127.0.0.1:6379)"
	docker run -d --name "$REDIS_CONTAINER" -p 127.0.0.1:6379:6379 redis:7.2-alpine >/dev/null
	touch "$STATE/redis.started"
	local i
	for i in $(seq 1 20); do
		docker exec "$REDIS_CONTAINER" redis-cli ping 2>/dev/null | grep -q PONG && return 0
		sleep 0.5
	done
	die "Redis did not answer"
}

overlay() {
	cat >"$OVERLAY" <<EOF
# Written by tools/live-check at start and removed at stop (git-ignored as
# config/*.local.conf). The one key a live check needs that has no environment
# form: where the browser lands after the callback — the live-check page.
federations { $1 { clientUrl = "http://localhost:$PORT/" } }
EOF
}

start() {
	local profile="${1:-google}"
	local profile_file="$HERE/profiles/$profile.env"
	[ -f "$profile_file" ] ||
		die "no profiles/$profile.env — copy profiles/$profile.env.example (or oidc.env.example) to it and fill it in"
	[ -f "$STATE/provider.pid" ] && die "already started — run 'live-check.sh stop' first"
	listening "$PORT" && die "port $PORT is taken — LIVE_CHECK_PORT picks another (the redirect URI changes with it)"
	listening "$PROVIDER_PORT" && die "port $PROVIDER_PORT is taken — LIVE_CHECK_PROVIDER_PORT picks another"
	mkdir -p "$STATE/keys"

	set -a
	# shellcheck disable=SC1090
	. "$profile_file"
	set +a
	[ -n "${LIVE_CHECK_FEDERATION:-}" ] || die "$profile_file sets no LIVE_CHECK_FEDERATION"
	local fed="$LIVE_CHECK_FEDERATION" FED
	FED="$(printf '%s' "$fed" | tr '[:lower:]' '[:upper:]' | tr -c 'A-Z0-9\n' '_')"
	export "FEDERATIONS_${FED}_ENABLED=true"
	export "FEDERATIONS_${FED}_CALLBACK_URL=http://localhost:$PORT/session/oauth/federation/$fed/callback"

	deps
	keys
	redis
	overlay "$fed"

	LIVE_CHECK_PORT="$PORT" LIVE_CHECK_PROVIDER_PORT="$PROVIDER_PORT" SESSION_NAME=auth.session \
		node "$HERE/proxy.mjs" >"$STATE/proxy.log" 2>&1 &
	echo $! >"$STATE/proxy.pid"

	# The template's default configuration plus what a plain-http local run
	# needs: the session cookie without Secure and without the __Host- prefix,
	# the key pair, the issuer, the Redis URLs, and the Store above.
	(
		cd "$TEMPLATE"
		export CONFIG_ENV="$OVERLAY_ENV" HTTP_PORT="$PROVIDER_PORT"
		export OAUTH_JWT_ISSUER="http://localhost:$PROVIDER_PORT"
		export OAUTH_JWT_PRIVATE_KEY_PATH="$STATE/keys/jwt-private.pem"
		export OAUTH_JWT_PUBLIC_KEY_PATH="$STATE/keys/jwt-public.pem"
		SESSION_SECRET="$(cat "$STATE/session-secret")"
		export SESSION_SECRET
		export SESSION_SECURE=false SESSION_NAME=auth.session
		export CLIENT_USER_AUTHENTICATE_URL="http://localhost:$PORT/__store/authenticate"
		export CLIENT_USER_AUTHENTICATE_BY_TOKEN_URL="http://localhost:$PORT/__store/authenticate-by-token"
		export CLIENT_CODE_ENDPOINT_URI="$REDIS_URL"
		export SESSION_STORAGE_REDIS_URL="$REDIS_URL"
		export REFRESH_TOKEN_FAMILY_STORE_REDIS_URL="$REDIS_URL"
		export NODE_OPTIONS='--conditions=development'
		exec pnpm exec tsx src/app.mts
	) >"$STATE/provider.log" 2>&1 &
	echo $! >"$STATE/provider.pid"

	local i
	for i in $(seq 1 90); do
		grep -q "Server is running" "$STATE/provider.log" 2>/dev/null && break
		if ! kill -0 "$(cat "$STATE/provider.pid")" 2>/dev/null; then
			tail -n 30 "$STATE/provider.log" >&2
			stop
			die "the provider refused to boot — its log is above"
		fi
		sleep 1
	done
	if ! grep -q "Server is running" "$STATE/provider.log"; then
		stop
		die "the provider did not come up in 90 s — see $STATE/provider.log"
	fi

	local code
	code="$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$PORT/session/oauth/federation/$fed")"
	if [ "$code" != "302" ]; then
		stop
		die "GET /session/oauth/federation/$fed answered $code, not a redirect to the IdP — see $STATE/provider.log"
	fi
	say "up. Open   http://localhost:$PORT/"
	say "the IdP client must have exactly this redirect URI:   http://localhost:$PORT/session/oauth/federation/$fed/callback"
}

stop() {
	kill_pidfile provider
	kill_pidfile proxy
	rm -f "$OVERLAY"
	if [ -f "$STATE/redis.started" ]; then
		docker rm -f "$REDIS_CONTAINER" >/dev/null 2>&1 || true
		rm -f "$STATE/redis.started"
	fi
	say "stopped"
}

status() {
	curl -sf "http://localhost:$PORT/__live-check/state" || die "nothing answers on :$PORT — not started?"
	echo
}

report() {
	curl -sf "http://localhost:$PORT/__live-check/report" || die "nothing answers on :$PORT — not started?"
}

logs() {
	tail -n 40 "$STATE/proxy.log" "$STATE/provider.log"
}

case "${1:-}" in
start) start "${2:-google}" ;;
stop) stop ;;
status) status ;;
report) report ;;
logs) logs ;;
*)
	usage
	exit 2
	;;
esac
