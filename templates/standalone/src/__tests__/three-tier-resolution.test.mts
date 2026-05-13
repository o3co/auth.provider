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

function buildResolvedConfig(env: string, extraEnv: Record<string, string> = {}): AppConfig {
	const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, env);
	const libraryReferencePath = resolveLibraryReferenceConfPath();
	const resolvedEnv = { ...testEnv, ...extraEnv };
	return validate(
		parseFile(envConfPath, { env: resolvedEnv })
			.withFallback(parseFile(applicationConfPath, { env: resolvedEnv }))
			.withFallback(parseFile(libraryReferencePath, { env: resolvedEnv })),
		AppConfigSchema,
	);
}

describe("three-tier HOCON resolution (env → application.conf → reference.conf)", () => {
	it("template application.conf wins over reference.conf for grant.enabled", () => {
		const config = buildResolvedConfig("development");
		// Template's application.conf sets authorization_code.enabled = true.
		// This test asserts the resolved value — it remains true whether
		// reference.conf says false (current secure-default) or true (legacy).
		expect(config.oauth.grants.authorization_code?.enabled).toBe(true);
	});

	it("reference.conf default reaches resolved config when template omits the key", () => {
		const config = buildResolvedConfig("development");
		// tokenExchange.maxActorChainDepth is library-owned in both layers
		// (template doesn't override it). Verifies precedence falls through.
		expect(config.oauth.tokenExchange?.maxActorChainDepth).toBe(3);
	});

	it("env var at template layer can disable a template-enabled grant (precedence: env-override line must be repeated)", () => {
		// Template enables authorization_code via application.conf. The env-override
		// line is repeated at the template layer alongside `enabled = true`,
		// so OAUTH_GRANTS_AUTHORIZATION_CODE_ENABLED=false reaches the resolved value.
		// Without the repeated env line, the substitution at reference.conf is
		// shadowed by the template's literal `true`.
		// Note: ts.hocon substitutes env vars as strings; the schema (passthrough)
		// preserves the string. The assertion checks the string form so that
		// the precedence invariant is testable now; a future schema-coercion PR
		// (separate from this one) will make this resolve to boolean false.
		const config = buildResolvedConfig("development", {
			OAUTH_GRANTS_AUTHORIZATION_CODE_ENABLED: "false",
		});
		expect(config.oauth.grants.authorization_code?.enabled).toBe("false");
	});

	it("reference.conf default for rateLimit.failMode is 'closed'", () => {
		const config = buildResolvedConfig("development");
		expect(config.rateLimit?.failMode).toBe("closed");
	});

	it("reference.conf default for client_credentials.enabled is false", () => {
		// Template doesn't enable client_credentials. Reference default propagates.
		const config = buildResolvedConfig("development");
		expect(config.oauth.grants.client_credentials?.enabled).toBe(false);
	});
});
