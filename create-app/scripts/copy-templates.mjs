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
// every template under `templates/` to `create-app/templates/<name>` (see
// `copyTemplates` in `templates.mjs`), and writes
// `create-app/templates/versions.json`, the version of every published sibling
// package, which `scaffold()` substitutes for `workspace:*`. The published
// tarball carries no monorepo, so this copy is what a scaffold is made from.
// `check-versions-json.mjs` keeps the version list below in step with
// `packages/`; `published-package.test.mts` scaffolds every template from the
// packed tarball.

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { copyTemplates } from "./templates.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const destRoot = resolve(__dirname, "../templates");

// No package's `reference.conf` is copied: each package that ships defaults
// exports its own (`./reference.conf`), and a composition root layers them
// with `coreReference()` / `moduleReferences(modules)`. A template's `config/`
// holds the deployment's layers and, in its own `reference.conf`, the defaults
// of the template's own modules. See ADR 2026-05-13-reference-conf-shipping.

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
	"@o3co/auth-provider-standard": readVersion("../../packages/standard/package.json"),
	"@o3co/auth-provider-test-kit": readVersion("../../packages/test-kit/package.json"),
	"@o3co/auth-provider-webauthn": readVersion("../../packages/webauthn/package.json"),
};

writeFileSync(resolve(destRoot, "versions.json"), `${JSON.stringify(versions, null, "\t")}\n`);
