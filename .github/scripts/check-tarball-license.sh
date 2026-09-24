#!/usr/bin/env bash
# Every package the release publishes goes out with the repository's LICENSE,
# word for word, and none goes out unchecked.
#
# The root LICENSE is the only copy. The release packs and publishes with
# pnpm, and pnpm adds the workspace root's LICENSE to a tarball only when
# nothing it already packs for that package looks like a licence file to it.
# Its test is loose: `/LICEN[CS]E(\..+)?/i` against every packed path,
# unanchored — so a package's own LICENSE counts, but so would a
# `templates/standalone/LICENSE` shipped inside create-app, or a
# `dist/licenseKey.mjs`, and either leaves the root file out. So no package
# keeps a LICENSE of its own, and no packed path may be named like one. (npm
# adds no root LICENSE at all: `npm pack` in a package directory ships none.)
#
# This reads the packed tarballs, which is what a consumer downloads:
#   - each must hold `package/LICENSE`, byte for byte the root file; when one
#     holds none, the packed paths that made pnpm leave the root file out are
#     named;
#   - every package `published-packages.sh` lists must be among them, so a new
#     public package cannot be published without passing through here, and no
#     tarball may be of a package the release does not publish.
#
# Fails closed: no tarballs, or a package list pnpm cannot produce, stops the
# check; a tarball that cannot be read, or whose package.json cannot be, is
# reported as a failure naming it, and the other tarballs are still checked.
# Never a clean scan.
#
# Usage (from inside the workspace):
#   check-tarball-license.sh <tarball-dir> <license-file>
set -euo pipefail

dir="${1:?usage: check-tarball-license.sh <tarball-dir> <license-file>}"
license="${2:?usage: check-tarball-license.sh <tarball-dir> <license-file>}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -f "$license" ]; then
	echo "::error::${license} is not a file"
	exit 2
fi

# `<name><TAB><directory>` of every package the release publishes.
expected="$("$here/published-packages.sh")"

scratch="$(mktemp)"
trap 'rm -f "$scratch"' EXIT

failures=0
count=0
packed=""
fail() {
	echo "::error::$1"
	failures=$((failures + 1))
}

for tgz in "$dir"/*.tgz; do
	[ -e "$tgz" ] || continue
	count=$((count + 1))
	file="$(basename "$tgz")"

	# Into a variable, never piped into `grep -q`: grep stops reading at its
	# first match, tar is then killed by SIGPIPE mid-listing, and `pipefail`
	# reports the match as a failure — a LICENSE packed first read as missing.
	# A tarball that cannot be read is reported and passed over, like any
	# other failure here, so the rest are still checked.
	if ! listing="$(tar -tzf "$tgz")"; then
		fail "${file} cannot be read as a gzipped tarball (tar's own message is above)"
		continue
	fi

	if ! manifest="$(tar -xzOf "$tgz" package/package.json)"; then
		fail "${file} has no readable package/package.json"
		continue
	fi
	if ! name="$(printf '%s' "$manifest" | node -e '
		let pkg;
		try {
			pkg = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
		} catch {
			process.exit(3);
		}
		process.stdout.write(String(pkg?.name ?? ""));
	')"; then
		fail "${file}: package/package.json is not JSON"
		continue
	fi
	if [ -z "$name" ]; then
		fail "${file}: its package.json names no package"
		continue
	fi
	if grep -qxF "$name" <<<"$packed"; then
		fail "${file}: ${name} is packed more than once"
	fi
	packed="${packed}${name}"$'\n'
	if ! cut -f1 <<<"$expected" | grep -xF "$name" >/dev/null; then
		fail "${file}: ${name} is not a package the release publishes (private, or not in this workspace)"
	fi

	if ! grep -qx 'package/LICENSE' <<<"$listing"; then
		lookalikes="$(grep -iE 'LICEN[CS]E' <<<"$listing" || true)"
		if [ -n "$lookalikes" ]; then
			fail "${file} ships no LICENSE: pnpm left the root one out because it packs these paths, which its licence-file test matches — rename them or stop packing them:"
			printf '%s\n' "$lookalikes" | sed 's/^/    /'
		else
			fail "${file} ships no LICENSE and packs nothing pnpm takes for one — pack it with pnpm from inside the workspace (npm pack adds no root LICENSE)"
		fi
		continue
	fi
	if ! tar -xzOf "$tgz" package/LICENSE >"$scratch"; then
		fail "${file}: package/LICENSE could not be read"
	elif ! cmp -s "$scratch" "$license"; then
		fail "${file} ships a LICENSE that differs from the root file (${license}) — a LICENSE of the package's own was packed in place of it; delete that one"
	fi
done

if [ "$count" -eq 0 ]; then
	echo "::error::no tarballs found in ${dir}"
	exit 2
fi

while IFS=$'\t' read -r name directory; do
	[ -n "$name" ] || continue
	if ! grep -qxF "$name" <<<"$packed"; then
		fail "${name} (${directory#"$PWD"/}) is published by the release, but no tarball of it is in ${dir}"
	fi
done <<<"$expected"

published="$(grep -c . <<<"$expected")"
if [ "$failures" -gt 0 ]; then
	echo "tarball LICENSE: ${failures} problem(s) across ${count} tarball(s) for ${published} published package(s)"
	exit 1
fi
echo "OK: all ${published} packages the release publishes were packed, and each tarball ships the root LICENSE"
