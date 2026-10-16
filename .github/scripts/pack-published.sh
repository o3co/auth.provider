#!/usr/bin/env bash
# Packs every package the release publishes into <destination>, with
# `pnpm pack` — what CI's release-check job checks and what release.yml
# checks and then publishes, so the two cannot pack different sets.
#
# The list is `published-packages.sh`'s: the bundles and the entrance that
# `pnpm bundles` built. Each already holds the root LICENSE, which
# `pnpm bundles` copies in, so any packer ships it.
#
# Each `pnpm pack` runs with stdin closed. The list is read line by line from
# stdin, and a pack's lifecycle scripts (`prepack`, `prepare`, `postpack`)
# would otherwise inherit it: one that reads stdin would swallow the rest of
# the list, and those packages would silently go unpacked.
#
# Fails closed: a list pnpm cannot produce, or a pack that fails, stops it.
#
# Usage (from the workspace root, after pnpm bundles): pack-published.sh <destination>
set -euo pipefail

destination="${1:?usage: pack-published.sh <destination>}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "$destination"
destination="$(cd "$destination" && pwd)"
packages="$("$here/published-packages.sh")"

while IFS=$'\t' read -r name directory; do
	[ -n "$name" ] || continue
	echo "packing ${name}"
	(cd "$directory" && pnpm pack --pack-destination "$destination" >/dev/null </dev/null)
done <<<"$packages"
