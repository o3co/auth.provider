/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

import { readdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
// create-app/scripts/ -> create-app/ -> repo root
const root = resolve(__dirname, "../..");
const pkgsDir = resolve(root, "packages");

// Enumerate published packages from packages/*/package.json directly.
// pnpm-workspace.yaml always contains "packages/*" — directory listing is sufficient.
const publishedPackages = new Set();
for (const entry of readdirSync(pkgsDir, { withFileTypes: true })) {
	if (!entry.isDirectory()) continue;
	const pkgJsonPath = resolve(pkgsDir, entry.name, "package.json");
	try {
		const pkg = JSON.parse(readFileSync(pkgJsonPath, "utf-8"));
		if (pkg.private) continue;
		publishedPackages.add(pkg.name);
	} catch {
		// directory without package.json (e.g. orphaned dirs) — skip
	}
}

// Extract tracked package names from copy-templates.mjs source.
// Pattern: keys of the `versions` object literal — "@o3co/auth-provider-*" strings.
const copyTemplatesSrc = readFileSync(resolve(__dirname, "copy-templates.mjs"), "utf-8");
const trackedPackages = new Set(
	[...copyTemplatesSrc.matchAll(/"(@o3co\/auth-provider-[^"]+)":/g)].map((m) => m[1]),
);

const missing = [...publishedPackages].filter((name) => !trackedPackages.has(name));
const extra = [...trackedPackages].filter((name) => !publishedPackages.has(name));

let failed = false;

if (missing.length > 0) {
	console.error("check-versions-json: packages in workspace but missing from copy-templates.mjs:");
	for (const name of missing) console.error(`  - ${name}`);
	console.error(
		"Fix: add the package to the `versions` object in create-app/scripts/copy-templates.mjs",
	);
	failed = true;
}

if (extra.length > 0) {
	console.error("check-versions-json: packages in copy-templates.mjs but not in workspace:");
	for (const name of extra) console.error(`  - ${name}`);
	console.error("Fix: remove the stale entry from create-app/scripts/copy-templates.mjs");
	failed = true;
}

if (failed) process.exit(1);
console.log(`check-versions-json: OK — ${trackedPackages.size} packages in sync`);
