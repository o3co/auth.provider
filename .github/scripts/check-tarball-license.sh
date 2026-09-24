#!/usr/bin/env bash
# Every tarball the release publishes carries the repository's LICENSE, word
# for word.
#
# The root LICENSE is the only copy. Releases pack and publish with pnpm, and
# pnpm puts the workspace root's LICENSE into the tarball of any package that
# has none beside its package.json — so no package keeps one of its own, and
# there is nothing to drift. (npm does not do this: `npm pack` run in a
# package directory ships no LICENSE, which is why a package whose `files`
# names `LICENSE` can look as if it publishes none. Publish with pnpm.)
#
# A package's own LICENSE takes precedence over the root one, and that is how
# this went wrong: the four packages that committed a copy committed the
# licence's unfilled template — `Copyright [yyyy] [name of copyright owner]`
# — instead of the root file, and published it.
#
# So this reads the packed tarballs, which is what a consumer downloads, and
# not the checkout: every tarball must hold `package/LICENSE`, byte for byte
# the root file. It fails on a package that commits a LICENSE that differs, and
# on a pnpm that stops supplying the root one.
#
# Fails closed: a directory with no tarballs in it is a failure, never an
# empty scan reported as clean.
#
# Usage: check-tarball-license.sh <tarball-dir> <license-file>
set -euo pipefail

dir="${1:?usage: check-tarball-license.sh <tarball-dir> <license-file>}"
license="${2:?usage: check-tarball-license.sh <tarball-dir> <license-file>}"

if [ ! -f "$license" ]; then
	echo "::error::${license} is not a file"
	exit 2
fi

failures=0
count=0
for tgz in "$dir"/*.tgz; do
	[ -e "$tgz" ] || continue
	count=$((count + 1))
	name="$(basename "$tgz")"
	if ! tar -tzf "$tgz" | grep -qx 'package/LICENSE'; then
		echo "::error::${name} ships no LICENSE — pack it with pnpm from inside the workspace, which adds the root LICENSE"
		failures=$((failures + 1))
	elif ! tar -xzOf "$tgz" package/LICENSE | cmp -s - "$license"; then
		echo "::error::${name} ships a LICENSE that differs from ${license} — delete the package's own LICENSE so the root one is packed"
		failures=$((failures + 1))
	fi
done

if [ "$count" -eq 0 ]; then
	echo "::error::no tarballs found in ${dir}"
	exit 2
fi
if [ "$failures" -gt 0 ]; then
	echo "tarball LICENSE: ${failures} of ${count} tarball(s) would not publish the root LICENSE"
	exit 1
fi
echo "OK: all ${count} tarballs ship the root LICENSE"
