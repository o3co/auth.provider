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
# A Redis this tool did not start is shared: the run keeps to one database of
# it, flushed at stop, so the session record (whose user id carries the `sub`)
# does not outlive the check.
REDIS_DB="${LIVE_CHECK_REDIS_DB:-15}"
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
	local f="$STATE/$1.pid" pid
	[ -f "$f" ] || return 0
	pid="$(cat "$f")"
	rm -f "$f"
	# A pid file that survived a reboot may now name anything.
	if ! ps -p "$pid" -o command= 2>/dev/null | grep -q -e proxy.mjs -e tsx -e pnpm -e node; then
		say "pid $pid in $1.pid is not ours any more — left alone"
		return 0
	fi
	kill_tree "$pid"
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

# Sets REDIS_URL and records in .state/redis.mode which of the three it is:
# `given` (LIVE_CHECK_REDIS_URL, left alone at stop), `found` (one already on
# :6379, database $REDIS_DB flushed at stop), `started` (the container, removed).
redis() {
	if [ -n "${LIVE_CHECK_REDIS_URL:-}" ]; then
		REDIS_URL="$LIVE_CHECK_REDIS_URL"
		echo given >"$STATE/redis.mode"
		# Not the URL itself: it may carry a password, and this line lands in shell captures.
		say "using the Redis LIVE_CHECK_REDIS_URL names — its records are yours to clear after the check"
		return 0
	fi
	REDIS_URL="redis://localhost:6379/$REDIS_DB"
	if listening 6379; then
		echo found >"$STATE/redis.mode"
		say "using the Redis already listening on :6379, database $REDIS_DB (flushed at stop)"
		return 0
	fi
	command -v docker >/dev/null || die "no Redis on :6379 and no docker — start one, or set LIVE_CHECK_REDIS_URL"
	say "starting Redis in docker ($REDIS_CONTAINER on 127.0.0.1:6379)"
	# The name may be held by a container a failed run left behind.
	docker rm -f "$REDIS_CONTAINER" >/dev/null 2>&1 || true
	echo started >"$STATE/redis.mode"
	docker run -d --name "$REDIS_CONTAINER" -p 127.0.0.1:6379:6379 redis:7.2-alpine >/dev/null ||
		die "docker run failed — is the daemon up?"
	local i
	for i in $(seq 1 20); do
		docker exec "$REDIS_CONTAINER" redis-cli ping 2>/dev/null | grep -q PONG && return 0
		sleep 0.5
	done
	die "Redis did not answer"
}

# The template ships ioredis, so no redis-cli is needed to clear the database.
flush_found_redis() {
	if (cd "$TEMPLATE" && node -e '
const Redis = require("ioredis");
const r = new Redis(process.argv[1], { lazyConnect: true, maxRetriesPerRequest: 1 });
r.connect().then(() => r.flushdb()).then(() => r.quit()).catch(() => process.exit(1));
' "redis://localhost:6379/$REDIS_DB") >/dev/null 2>&1; then
		say "flushed database $REDIS_DB of the Redis on :6379"
	else
		say "could not flush database $REDIS_DB of the Redis on :6379 — its session record expires with session.maxAge (1 h by default)"
	fi
}

overlay() {
	cat >"$OVERLAY" <<EOF
# Written by tools/live-check at start and removed at stop (git-ignored as
# config/*.local.conf). The one key a live check needs that has no environment
# form: where the browser lands after the callback — the live-check page.
federations { $1 { clientUrl = "http://localhost:$PORT/" } }
EOF
}

# One value out of the profile, read in a subshell so the client id and
# secret it also holds never enter this process's environment.
profile_value() {
	# shellcheck disable=SC1090
	(. "$1" >/dev/null 2>&1 && printf '%s' "${!2:-}")
}

start() {
	local profile="${1:-google}"
	local profile_file="$HERE/profiles/$profile.env"
	[ -f "$profile_file" ] ||
		die "no profiles/$profile.env — copy profiles/$profile.env.example (or oidc.env.example) to it and fill it in"
	[ -f "$STATE/provider.pid" ] && die "already started — run 'live-check.sh stop' first"
	command -v lsof >/dev/null || die "lsof is required (the port checks)"
	command -v curl >/dev/null || die "curl is required"
	listening "$PORT" && die "port $PORT is taken — LIVE_CHECK_PORT picks another (the redirect URI changes with it)"
	listening "$PROVIDER_PORT" && die "port $PROVIDER_PORT is taken — LIVE_CHECK_PROVIDER_PORT picks another"
	mkdir -p "$STATE/keys"

	local fed expected FED
	fed="$(profile_value "$profile_file" LIVE_CHECK_FEDERATION)"
	expected="$(profile_value "$profile_file" LIVE_CHECK_EXPECTED_ISS)"
	[ -n "$fed" ] || die "$profile_file sets no LIVE_CHECK_FEDERATION"
	FED="$(printf '%s' "$fed" | tr '[:lower:]' '[:upper:]' | tr -c 'A-Z0-9\n' '_')"

	deps
	keys
	redis
	overlay "$fed"

	# From here on a failure or an interrupt takes the processes down with it.
	trap 'stop; exit 130' INT TERM

	LIVE_CHECK_PORT="$PORT" LIVE_CHECK_PROVIDER_PORT="$PROVIDER_PORT" SESSION_NAME=auth.session \
		LIVE_CHECK_FEDERATION="$fed" LIVE_CHECK_EXPECTED_ISS="$expected" \
		node "$HERE/proxy.mjs" >"$STATE/proxy.log" 2>&1 &
	echo $! >"$STATE/proxy.pid"

	# The template's default configuration plus what a plain-http local run
	# needs: the session cookie without Secure and without the __Host- prefix,
	# the key pair, the issuer, the Redis URLs, and the Store above. The
	# profile — the client id and secret — is read here and nowhere else.
	(
		cd "$TEMPLATE"
		set -a
		# shellcheck disable=SC1090
		. "$profile_file"
		set +a
		export "FEDERATIONS_${FED}_ENABLED=true"
		export "FEDERATIONS_${FED}_CALLBACK_URL=http://localhost:$PORT/session/oauth/federation/$fed/callback"
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
	# `report` shows what the provider logs from here on — the check, not the boot.
	date +%s >"$STATE/started-at"

	# The start route has to send the browser to the IdP: a 302 alone could be
	# a redirect back to a local page, and the check would begin nowhere.
	local probe code idp
	probe="$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' "http://localhost:$PORT/session/oauth/federation/$fed")" ||
		{
			stop
			die "the front on :$PORT did not answer — see $STATE/proxy.log"
		}
	code="${probe%% *}"
	idp="${probe#* }"
	if [ "$code" != "302" ]; then
		stop
		die "GET /session/oauth/federation/$fed answered $code, not a redirect to the IdP — see $STATE/provider.log"
	fi
	case "$idp" in
	http://localhost* | http://127.* | https://localhost* | https://127.* | "")
		stop
		die "GET /session/oauth/federation/$fed redirected to '${idp:-nowhere}', not to an IdP — see $STATE/provider.log"
		;;
	esac
	trap - INT TERM
	say "up. The start route redirects to ${idp%%\?*}"
	say "Open   http://localhost:$PORT/"
	say "the IdP client must have exactly this redirect URI:   http://localhost:$PORT/session/oauth/federation/$fed/callback"
}

stop() {
	kill_pidfile provider
	kill_pidfile proxy
	local i
	for i in $(seq 1 20); do
		listening "$PROVIDER_PORT" || listening "$PORT" || break
		sleep 0.5
	done
	rm -f "$OVERLAY"
	case "$(cat "$STATE/redis.mode" 2>/dev/null || true)" in
	started) docker rm -f "$REDIS_CONTAINER" >/dev/null 2>&1 || true ;;
	found) flush_found_redis ;;
	esac
	rm -f "$STATE/redis.mode" "$STATE/started-at"
	say "stopped"
}

status() {
	curl -sf "http://localhost:$PORT/__live-check/state" || die "nothing answers on :$PORT — not started?"
	echo
}

# The record, then what the provider logged at warn or above since start —
# an adapter-side refusal (a callback without the `iss` Google's default
# requires, say) reaches the browser as a generic 502 and its reason only
# lands here. Message fields only: no request, no body, no value.
report() {
	curl -sf "http://localhost:$PORT/__live-check/report" || die "nothing answers on :$PORT — not started?"
	[ -f "$STATE/provider.log" ] || return 0
	node -e '
const fs = require("node:fs");
const since = Number(process.argv[2]) * 1000;
const lines = fs.readFileSync(process.argv[1], "utf8").split("\n");
const out = [];
for (const line of lines) {
	let e;
	try { e = JSON.parse(line); } catch { continue; }
	if (typeof e.level !== "number" || e.level < 40 || (typeof e.time === "number" && e.time < since)) continue;
	const err = e.err && typeof e.err.message === "string" ? `: ${e.err.message}` : "";
	out.push(`  - [${e.level >= 50 ? "error" : "warn"}] ${e.msg ?? "(no message)"}${err}`);
}
console.log(`- provider log since start (warn and above):${out.length === 0 ? " nothing" : ""}`);
for (const l of out) console.log(l);
' "$STATE/provider.log" "$(cat "$STATE/started-at" 2>/dev/null || echo 0)"
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
