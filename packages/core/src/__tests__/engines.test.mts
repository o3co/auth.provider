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
 * Every non-private package that ships to npm — the eleven `@o3co/auth-provider-*`
 * libraries AND the `@o3co/create-auth-provider` scaffolder (`create-app`). Each
 * published `package.json` must declare the same `engines.node` floor so consumers
 * on an end-of-life Node see at least a warning — and a hard install failure with
 * `engines-strict=true`. The floor is Node 22 LTS: Node 18 (EOL 2025-04) and
 * Node 20 (EOL 2026-04) are past end-of-life, so 22 and 24 are the supported
 * LTS lines. Keep this list COMPLETE: a published package missing here can
 * silently drift to a different floor (as `webauthn` once did at `>=20.0.0`)
 * without this guard catching it.
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
