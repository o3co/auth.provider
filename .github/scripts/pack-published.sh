#!/usr/bin/env bash
# Packs every package the release publishes into <destination>, by
# `pnpm release:pack`: every bundle but the index's, then the index sealed with
# their integrity and zod's, then the index's bundle and the entrance. What
# CI's release-check job checks and what release.yml checks and then
# publishes, so the two cannot pack different sets or in another order.
#
# Each package is one `pnpm bundles` built, and already holds the root
# LICENSE, which `pnpm bundles` copies in, so any packer ships it. Each pack
# runs with stdin closed, so no lifecycle script reads it.
#
# Fails closed: a pack that fails, or an index that cannot be sealed, stops it.
#
# Usage (from the workspace root, after pnpm bundles): pack-published.sh <destination>
set -euo pipefail

destination="${1:?usage: pack-published.sh <destination>}"
if [ ! -d dist/bundles ]; then
	echo "::error::dist/bundles is missing — run pnpm bundles first"
	exit 2
fi
mkdir -p "$destination"
destination="$(cd "$destination" && pwd)"
pnpm release:pack "$destination" </dev/null
