#!/usr/bin/env bash
# Every package the release publishes names a sibling — another
# `@o3co/auth-provider-*` package — in one shape only: a peer dependency
# `workspace:^`, with a `workspace:*` devDependency beside it. Never a
# `dependencies` or `optionalDependencies` entry.
#
# A peer, because a sibling is shared state, not a private helper. Packages
# extend core's types with `declare module "@o3co/auth-provider-core"`
# (ComponentMap slots, contribution kinds), and the modules of one
# composition meet through core's `createApp` and its error classes. A
# sibling that is a dependency is the dependent's own copy: whenever its range
# and the deployment's differ, the package manager installs it twice, the
# augmentations reach one copy and the deployment runs the other, and an
# `instanceof` across the two is false. A peer is the deployment's one copy.
#
# `workspace:^`, because release.yml sets versions with `pnpm version`, which
# rewrites only the `version` field: a literal range such as `^0.0.0` is
# published verbatim, and `^0.0.0` means `<0.0.1`, which no released sibling
# satisfies (pnpm warns, npm 7+ fails ERESOLVE). `pnpm pack` / `pnpm publish`
# rewrite `workspace:^` to `^<sibling version>` at pack time, so the range
# tracks the release with no second rewrite step. The packed-manifest check in
# CI's publish-readiness job asserts that rewrite on the tarballs; it cannot see
# a literal range on its own, because at 0.0.0 a literal `^0.0.0` and a
# rewritten `workspace:^` produce the same manifest — so this reads the source.
#
# The `workspace:*` devDependency is what satisfies the peer inside the
# workspace: the package's own build and tests run against the sibling's
# checkout (docs/release-runbook.md).
#
# The list is `published-packages.sh`'s, so a package added tomorrow is held to
# this the day it is added, wherever in the workspace it lives. Private
# workspaces (the standalone template, the tools) are applications, not
# libraries: they install siblings as dependencies, as a deployment does.
#
# Fails closed: a list pnpm cannot produce, or a manifest that cannot be read,
# stops the check. Never a clean scan.
#
# Usage (from inside the workspace): check-sibling-deps.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
packages="$("$here/published-packages.sh")"

printf '%s' "$packages" | node -e '
	const fs = require("node:fs");
	const path = require("node:path");
	const SIBLING = "@o3co/auth-provider-";
	const lines = fs.readFileSync(0, "utf8").split("\n").filter(Boolean);
	if (lines.length === 0) {
		console.error("::error::no published package to check");
		process.exit(2);
	}
	const failures = [];
	for (const line of lines) {
		const [name, directory] = line.split("\t");
		const file = path.join(directory, "package.json");
		const where = path.relative(process.cwd(), file);
		let pkg;
		try {
			pkg = JSON.parse(fs.readFileSync(file, "utf8"));
		} catch (err) {
			console.error(`::error::${where} (${name}) cannot be read: ${err.message}`);
			process.exit(2);
		}
		for (const section of ["dependencies", "optionalDependencies"]) {
			for (const sibling of Object.keys(pkg[section] ?? {})) {
				if (!sibling.startsWith(SIBLING)) continue;
				failures.push(`${where}: ${section}["${sibling}"] — declare it in peerDependencies as "workspace:^", with a "workspace:*" devDependency`);
			}
		}
		for (const [sibling, range] of Object.entries(pkg.peerDependencies ?? {})) {
			if (!sibling.startsWith(SIBLING)) continue;
			if (range !== "workspace:^") failures.push(`${where}: peerDependencies["${sibling}"] is "${range}", not "workspace:^"`);
			const dev = pkg.devDependencies?.[sibling];
			if (dev !== "workspace:*") failures.push(`${where}: peer ${sibling} has ${dev === undefined ? "no devDependency" : `devDependencies["${sibling}"] = "${dev}"`}; the workspace needs "workspace:*" to satisfy the peer`);
		}
	}
	if (failures.length > 0) {
		console.error("::error::a published package names a sibling other than as a workspace:^ peer:");
		for (const f of failures) console.error(`  ${f}`);
		process.exit(1);
	}
	console.log(`OK: all ${lines.length} published packages name their @o3co/auth-provider-* siblings as workspace:^ peers, none as a dependency`);
'
