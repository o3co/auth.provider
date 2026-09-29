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
// every template under `templates/` to `create-app/templates/<name>`
// (`copyTemplates` in `templates.mjs`, which also says what a template is and
// stages each one's `.gitignore` under a name npm will publish), and writes
// `create-app/templates/versions.json` — the version of every published
// sibling package, which `scaffold()` substitutes for `workspace:*`. The
// published tarball carries no monorepo, so this copy is what a scaffold is
// made from. `check-versions-json.mjs` keeps the version list below in step
// with `packages/`.
//
// Verified rather than assumed: `published-package.test.mts` packs this
// package, scaffolds every template from the tarball, and asserts each
// scaffolded project has a `.gitignore` — which is how its omission (#407) was
// found in the first place.

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { copyTemplates } from "./templates.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const destRoot = resolve(__dirname, "../templates");

// NOTE: `reference.conf` is intentionally NOT copied here. It lives in
// `packages/core/config/reference.conf` and is shipped to consumers via the
// `@o3co/auth-provider-core` package's `exports` field (`./reference.conf`
// subpath export, files: ["config", ...]). Each package that ships defaults
// does the same, and its modules declare the file (#728): the standalone
// composition root layers core's reference and the ones its loaded modules
// declare with `coreReference()` / `moduleReferences(modules)`.
// The template's `config/` directory contains only consumer-facing files
// (`application.conf`, `development.conf`, `production.conf`) — the
// per-deployment delta layer, not the library baseline.

copyTemplates(resolve(__dirname, "../../templates"), destRoot);

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
