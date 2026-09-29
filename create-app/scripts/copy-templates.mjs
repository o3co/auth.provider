/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

// Bundles the templates into this package (`prebuild` / `prepack`): copies
// every template under `templates/` — each directory there with a
// `package.json` — to `create-app/templates/<name>`, stages each one's
// `.gitignore` under a name npm will publish, and writes
// `create-app/templates/versions.json` — the version of every published
// sibling package, which `scaffold()` substitutes for `workspace:*`. The
// published tarball carries no monorepo, so this copy is what a scaffold is
// made from. `check-versions-json.mjs` keeps the version list below in step
// with `packages/`.

import {
	cpSync,
	existsSync,
	mkdirSync,
	readdirSync,
	readFileSync,
	renameSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { dirname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const srcRoot = resolve(__dirname, "../../templates");
const destRoot = resolve(__dirname, "../templates");

const EXCLUDED_DIRS = new Set(["node_modules", "dist"]);

// NOTE: `reference.conf` is intentionally NOT copied here. It lives in
// `packages/core/config/reference.conf` and is shipped to consumers via the
// `@o3co/auth-provider-core` package's `exports` field (`./reference.conf`
// subpath export, files: ["config", ...]). Consumers and the standalone
// composition root resolve it at boot via
// `import.meta.resolve("@o3co/auth-provider-core/reference.conf")`.
// The template's `config/` directory contains only consumer-facing files
// (`application.conf`, `development.conf`, `production.conf`) — the
// per-deployment delta layer, not the library baseline.

// Mirrors `shouldCopyTemplateEntry` in src/internal/template-filter.mts: only
// segments INSIDE the template's root are checked against EXCLUDED_DIRS, not
// the absolute install-prefix path above it. Without this, running the
// prebuild script with the workspace itself living under a `node_modules`
// directory would copy zero files. (This script runs at build time before tsc,
// so it cannot import the compiled module — the logic is duplicated by
// necessity.)
const shouldCopyFrom = (root) => (source) => {
	if (source === root) return true;
	const prefix = root.endsWith(sep) ? root : `${root}${sep}`;
	if (!source.startsWith(prefix)) return true;
	const rel = source.slice(prefix.length);
	return !rel.split(sep).some((segment) => EXCLUDED_DIRS.has(segment));
};

// A template is a directory under `templates/` with a `package.json` — the
// same test `availableTemplates()` applies to the copy, so what is copied here
// is what the scaffolder offers.
const templates = readdirSync(srcRoot, { withFileTypes: true })
	.filter(
		(entry) => entry.isDirectory() && existsSync(resolve(srcRoot, entry.name, "package.json")),
	)
	.map((entry) => entry.name)
	.sort();
if (templates.length === 0) {
	throw new Error(`copy-templates: no template found under ${srcRoot}`);
}

// The whole destination is rebuilt, so a template removed from the repository
// does not linger in the next tarball.
rmSync(destRoot, { recursive: true, force: true });
mkdirSync(destRoot, { recursive: true });

for (const name of templates) {
	const src = resolve(srcRoot, name);
	const dest = resolve(destRoot, name);
	cpSync(src, dest, {
		recursive: true,
		filter: shouldCopyFrom(src),
	});

	// #407: npm drops a file literally named `.gitignore` from a published
	// package, so each template's copy is staged here under a dot-less name and
	// `scaffold()` renames it back when it writes the project. The source of
	// truth stays `templates/<name>/.gitignore`, where it also does its own job
	// for anyone working on the template in-tree.
	//
	// Verified rather than assumed: `published-package.test.mts` packs this
	// package, scaffolds every template from the tarball, and asserts each
	// scaffolded project has a `.gitignore` — which is how the omission was
	// found in the first place.
	const stagedGitignore = resolve(dest, ".gitignore");
	if (existsSync(stagedGitignore)) {
		renameSync(stagedGitignore, resolve(dest, "gitignore"));
	}
}

// Embed package versions so they're available at runtime without
// traversing the monorepo source tree (which won't exist in published tarballs).
const readVersion = (pkgPath) => {
	const pkg = JSON.parse(readFileSync(resolve(__dirname, pkgPath), "utf-8"));
	return pkg.version ?? "0.0.0";
};

const versions = {
	"@o3co/auth-provider-core": readVersion("../../packages/core/package.json"),
	"@o3co/auth-provider-device-grant": readVersion("../../packages/device-grant/package.json"),
	"@o3co/auth-provider-dpop": readVersion("../../packages/dpop/package.json"),
	"@o3co/auth-provider-mtls": readVersion("../../packages/mtls/package.json"),
	"@o3co/auth-provider-federation-apple": readVersion(
		"../../packages/federation-apple/package.json",
	),
	"@o3co/auth-provider-federation-google": readVersion(
		"../../packages/federation-google/package.json",
	),
	"@o3co/auth-provider-federation-github": readVersion(
		"../../packages/federation-github/package.json",
	),
	"@o3co/auth-provider-federation-grants": readVersion(
		"../../packages/federation-grants/package.json",
	),
	"@o3co/auth-provider-federation-oidc": readVersion("../../packages/federation-oidc/package.json"),
	"@o3co/auth-provider-oauth": readVersion("../../packages/oauth/package.json"),
	"@o3co/auth-provider-oauth-token-exchange": readVersion(
		"../../packages/oauth-token-exchange/package.json",
	),
	"@o3co/auth-provider-session": readVersion("../../packages/session/package.json"),
	"@o3co/auth-provider-foundation": readVersion("../../packages/foundation/package.json"),
	"@o3co/auth-provider-redis": readVersion("../../packages/redis/package.json"),
	"@o3co/auth-provider-webauthn": readVersion("../../packages/webauthn/package.json"),
};

writeFileSync(resolve(destRoot, "versions.json"), `${JSON.stringify(versions, null, "\t")}\n`);
