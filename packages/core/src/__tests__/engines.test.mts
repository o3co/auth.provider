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
 * The eight published packages that ship to npm. The Redis 7.2 LTS commitment
 * (D-10) requires every published `package.json` to declare
 * `engines.node >=18.19.0` so consumers on Node <18.19 see at least a warning,
 * and a hard install failure with `engines-strict=true`.
 */
const PUBLISHED_PACKAGES = [
	"packages/core",
	"packages/oauth",
	"packages/redis",
	"packages/session",
	"packages/foundation",
	"packages/federation-github",
	"packages/federation-google",
	"packages/oauth-token-exchange",
];

describe("D-10: engines.node on every published package", () => {
	for (const pkg of PUBLISHED_PACKAGES) {
		it(`${pkg} declares engines.node >=18.19.0`, () => {
			const pkgPath = resolve(REPO_ROOT, pkg, "package.json");
			const content = readFileSync(pkgPath, "utf8");
			const parsed = JSON.parse(content) as { engines?: { node?: string } };
			expect(parsed.engines?.node).toBe(">=18.19.0");
		});
	}
});
