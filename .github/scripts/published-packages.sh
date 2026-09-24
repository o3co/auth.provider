#!/usr/bin/env bash
# Every workspace package the release publishes, one per line:
# `<name><TAB><directory>`.
#
# `pnpm -r publish` publishes each workspace package that is not private. This
# asks pnpm for the same list rather than restating it, so a package added
# tomorrow is on it the day it is added, wherever in the workspace it lives.
#
# Run from inside the workspace. Fails closed: a list pnpm cannot produce, or
# one with nothing on it, is an error — never "nothing to publish".
#
# Usage: published-packages.sh
set -euo pipefail

listing="$(pnpm -r ls --json --depth -1)"
printf '%s' "$listing" | node -e '
	let all;
	try {
		all = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
	} catch {
		console.error("::error::pnpm printed no workspace package list — run this from inside the workspace");
		process.exit(2);
	}
	const published = all.filter((p) => p.private !== true);
	if (published.length === 0) {
		console.error("::error::pnpm lists no workspace package that the release would publish");
		process.exit(2);
	}
	for (const p of published) console.log(`${p.name}\t${p.path}`);
'
