/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License").
 */

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// Resolve the monorepo root from this test file's location:
//   packages/core/src/__tests__/engines.test.mts → ../../../..
const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..", "..", "..");

/**
 * Every package published to npm (the `@o3co/auth-provider-*` libraries and
 * the `@o3co/create-auth-provider` scaffolder) declares the same
 * `engines.node` floor, so consumers on an end-of-life Node get a warning, and
 * an install failure with `engines-strict=true`. The floor is Node 22 LTS;
 * Node 18 and 20 are past end-of-life. Keep `PUBLISHED_PACKAGES` complete: a
 * package missing there can drift to another floor unnoticed.
 */
const REQUIRED_NODE_ENGINE = ">=22.0.0";

const PUBLISHED_PACKAGES = [
	"packages/core",
	"packages/oauth",
	"packages/redis",
	"packages/session",
	"packages/foundation",
	"packages/federation-github",
	"packages/federation-google",
	"packages/federation-oidc",
	"packages/oauth-token-exchange",
	"packages/webauthn",
	"packages/dpop",
	"packages/mtls",
	"create-app",
];

describe("engines.node on every published package", () => {
	for (const pkg of PUBLISHED_PACKAGES) {
		it(`${pkg} declares engines.node ${REQUIRED_NODE_ENGINE}`, () => {
			const pkgPath = resolve(REPO_ROOT, pkg, "package.json");
			const content = readFileSync(pkgPath, "utf8");
			const parsed = JSON.parse(content) as { engines?: { node?: string } };
			expect(parsed.engines?.node).toBe(REQUIRED_NODE_ENGINE);
		});
	}
});
