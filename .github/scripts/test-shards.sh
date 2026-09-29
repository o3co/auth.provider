#!/usr/bin/env bash
# The shards CI's `test` job splits the workspaces' suites into, one parallel
# job each. The workflow reads its matrix from here (`list`), each job its pnpm
# selection (`filters <shard>`) and the packages a named shard must find
# (`packages <shard>`), so the shards are written down once, in SHARDS below.
#
# The named shards hold the heaviest suites; `rest` is every workspace they do
# not name, the workspace root excepted (its own `test` script runs every
# workspace). A workspace added tomorrow therefore lands in `rest` and is
# tested without editing this file, and moving a package out of a named shard
# moves it into `rest`, never out of CI.
#
# Balanced on the suites' durations with coverage at develop 01659dd0b:
# core ~100 s; redis + oauth ~80 s; the browser-facing packages ~65 s; the
# rest ~80 s. Re-balance here when one shard becomes the long pole.
set -euo pipefail

P=@o3co/auth-provider

# name:packages — the one list.
SHARDS=(
	"core:$P-core"
	"redis-oauth:$P-redis $P-oauth"
	"browser:$P-federation-grants $P-session $P-webauthn $P-mtls $P-federation-oidc"
)

packages_of() {
	local entry
	for entry in "${SHARDS[@]}"; do
		if [[ "${entry%%:*}" == "$1" ]]; then
			echo "${entry#*:}"
			return 0
		fi
	done
	echo "test-shards.sh: unknown shard '$1'" >&2
	return 2
}

case "${1:-}" in
list)
	# JSON, for the workflow's matrix.
	printf '['
	for entry in "${SHARDS[@]}"; do printf '"%s",' "${entry%%:*}"; done
	printf '"rest"]\n'
	;;
packages)
	# The packages a named shard names; nothing for `rest`.
	shard="${2:?usage: test-shards.sh packages <shard>}"
	if [[ "$shard" != rest ]]; then
		pkgs="$(packages_of "$shard")"
		echo "$pkgs"
	fi
	;;
filters)
	shard="${2:?usage: test-shards.sh filters <shard>}"
	if [[ "$shard" == rest ]]; then
		for entry in "${SHARDS[@]}"; do
			for p in ${entry#*:}; do printf -- '--filter !%s ' "$p"; done
		done
		printf -- '--filter !.\n'
	else
		pkgs="$(packages_of "$shard")"
		for p in $pkgs; do printf -- '--filter %s ' "$p"; done
		printf '\n'
	fi
	;;
*)
	echo "usage: test-shards.sh list | packages <shard> | filters <shard>" >&2
	exit 2
	;;
esac
