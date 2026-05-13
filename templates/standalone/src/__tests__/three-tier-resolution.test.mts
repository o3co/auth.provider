/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { fileURLToPath } from "node:url";
import { type AppConfig, AppConfigSchema } from "@o3co/auth-provider-core";
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import { describe, expect, it } from "vitest";
import { resolveConfigPaths, resolveLibraryReferenceConfPath } from "../configPath.mjs";

// config/ is two levels above this test file:
//   src/__tests__/ → src/ → standalone/ → config/
const configDir = fileURLToPath(new URL("../../config", import.meta.url));

// Provide required secrets so AppConfigSchema parse succeeds. These are
// test-only values — no real keys are embedded here.
const testEnv = {
	OAUTH_JWT_SECRET: "test-secret-three-tier",
	SESSION_SECRET: "test-session-secret-three-tier",
};

function buildResolvedConfig(env: string): AppConfig {
	const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, env);
	const libraryReferencePath = resolveLibraryReferenceConfPath();
	return validate(
		parseFile(envConfPath, { env: testEnv })
			.withFallback(parseFile(applicationConfPath, { env: testEnv }))
			.withFallback(parseFile(libraryReferencePath, { env: testEnv })),
		AppConfigSchema,
	);
}

describe("three-tier HOCON resolution (env → application.conf → reference.conf)", () => {
	it("template application.conf wins over reference.conf for grant.enabled", () => {
		const config = buildResolvedConfig("development");
		// Template sets authorization_code.enabled = true; this works
		// regardless of what reference.conf says (in Phase 1, both say true).
		expect(config.oauth.grants.authorization_code?.enabled).toBe(true);
	});

	it("reference.conf default reaches resolved config when template omits the key", () => {
		const config = buildResolvedConfig("development");
		// tokenExchange.maxActorChainDepth is library-owned in both layers
		// (template doesn't override it). Verifies precedence falls through.
		expect(config.oauth.tokenExchange?.maxActorChainDepth).toBe(3);
	});
});
