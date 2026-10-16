#!/usr/bin/env bash
# Every package the release publishes, one per line: `<name><TAB><directory>`.
#
# The workspace's packages are all private: what is published is what
# `pnpm bundles` builds into dist/bundles, one bundle per concern directory
# and the entrance `@o3co/create-auth-provider`. This reads that build rather
# than restating it, so a bundle added tomorrow is on the list the day it is
# built.
#
# Run from the workspace root after `pnpm bundles`. Fails closed: no build, or
# a build with nothing in it, is an error — never "nothing to publish".
#
# Usage: published-packages.sh
set -euo pipefail

if [ ! -d dist/bundles ]; then
	echo "::error::dist/bundles is missing — run pnpm bundles first"
	exit 2
fi
found=0
for manifest in dist/bundles/*/package.json; do
	[ -e "$manifest" ] || continue
	name="$(node -p 'require(process.argv[1]).name' "$PWD/$manifest")"
	printf '%s\t%s\n' "$name" "$PWD/$(dirname "$manifest")"
	found=$((found + 1))
done
if [ "$found" -eq 0 ]; then
	echo "::error::dist/bundles holds no package to publish"
	exit 2
fi
