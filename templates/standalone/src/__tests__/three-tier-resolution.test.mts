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
import { buildModules } from "../buildModules.mjs";
import { resolveConfigPaths, resolveLibraryReferenceConfPath } from "../configPath.mjs";

// config/ is two levels above this test file:
//   src/__tests__/ → src/ → standalone/ → config/
const configDir = fileURLToPath(new URL("../../config", import.meta.url));

// Provide required secrets so AppConfigSchema parse succeeds. These are
// test-only values — no real keys are embedded here. #282: SESSION_SECRET
// carries a 256-bit entropy floor, so these clear it (the '.' characters keep
// them outside the base64 alphabet, so the UTF-8 length is what counts).
const testEnv = {
	OAUTH_JWT_SECRET: "test-secret-three-tier.at-least-32-bytes.ok",
	OAUTH_JWT_ISSUER: "https://auth.test",
	SESSION_SECRET: "test-session-secret-three-tier.at-least-32-bytes.ok",
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

// `oauth.grants` is declared as `z.object({}).passthrough()` in the schema,
// so the inferred TS type is `{}` per entry and accessing `.enabled` doesn't
// compile under `tsc --strict`. Tests assert against the resolved runtime
// shape (string from env substitution, boolean from literal), so the cast
// is intentional and well-bounded.
type GrantEntry = { enabled?: unknown };
const grants = (config: AppConfig) =>
	(config.oauth.grants as unknown as Record<string, GrantEntry | undefined>) ?? {};

describe("three-tier HOCON resolution (env → application.conf → reference.conf)", () => {
	it("template application.conf wins over reference.conf for grant.enabled", () => {
		const config = buildResolvedConfig("development");
		// Template's application.conf sets authorization_code.enabled = true.
		// This test asserts the resolved value — it remains true whether
		// reference.conf says false (current secure-default) or true (legacy).
		expect(grants(config).authorization_code?.enabled).toBe(true);
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
		// Note: ts.hocon substitutes env vars as strings, and `oauth.grants` is
		// `z.object({}).passthrough()` — an open tree each grant module's own
		// `configSchema` validates — so no shape-walking coercion reaches this
		// leaf and the string survives to the resolved config. #288 unified the
		// coercion for every DECLARED boolean in the schema and deliberately
		// left this one alone: every consumer of a grant's `enabled`
		// (`GrantRegistry.isEnabled`, `oauthAuthorization`, `oauthSession`)
		// already reads `true` and `"true"` as enabled and everything else,
		// `"false"` included, as not-enabled.
		const config = buildResolvedConfig("development", {
			OAUTH_GRANTS_AUTHORIZATION_CODE_ENABLED: "false",
		});
		expect(grants(config).authorization_code?.enabled).toBe("false");
	});

	it("reference.conf default for rateLimit.failMode is 'closed'", () => {
		const config = buildResolvedConfig("development");
		expect(config.rateLimit?.failMode).toBe("closed");
	});

	it("reference.conf default for client_credentials.enabled is false", () => {
		// Template doesn't enable client_credentials. Reference default propagates.
		const config = buildResolvedConfig("development");
		expect(grants(config).client_credentials?.enabled).toBe(false);
	});

	it("reference.conf default for oauth.resourceIndicator.enabled is false", () => {
		// reference.conf must ship the literal `false` anchor so that the
		// schema coercion (coerceBooleanFromEnv) can produce a boolean value.
		// Without the HOCON block the field resolves to undefined.
		const config = buildResolvedConfig("development");
		expect(config.oauth.resourceIndicator?.enabled).toBe(false);
	});

	it("env var OAUTH_RESOURCE_INDICATOR_ENABLED=true reaches resolved config and coerces to boolean true", () => {
		// HOCON env-substitution returns a string. The reference.conf anchor
		// (`enabled = ${?OAUTH_RESOURCE_INDICATOR_ENABLED}`) lets the env var
		// reach the resolved layer; the schema's coerceBooleanFromEnv turns
		// "true" → true so `=== true` guards in grant handlers work correctly.
		const config = buildResolvedConfig("development", {
			OAUTH_RESOURCE_INDICATOR_ENABLED: "true",
		});
		expect(config.oauth.resourceIndicator?.enabled).toBe(true);
	});

	// #277 — this is the shape the umbrella E2E (o3co/auth) boots: the shipped
	// application.conf, `DEPLOYMENT_MODE=multi`, and one shared ioredis socket.
	// The assertions below are what keep that stack booting: a memory denylist
	// under `multi` is refused by the replica-safety guard, and NO denylist is
	// refused by the #277 guard, so the template has to land on "redis" without
	// the deployment naming it.
	describe("#277: access-token revocation as the shipped artifact resolves it", () => {
		it("resolves accessTokenDenylist.adapter to redis with nothing set", () => {
			const config = buildResolvedConfig("production");
			expect(config.accessTokenDenylist?.adapter).toBe("redis");
		});

		it("resolves oauth.revocation.accessToken to denylist with nothing set", () => {
			const config = buildResolvedConfig("production");
			expect(config.oauth.revocation?.accessToken).toBe("denylist");
		});

		it("picks the replica-safe denylist module for that resolved config", () => {
			const names = buildModules(buildResolvedConfig("production")).map((m) => m.name);
			expect(names).toContain("redis-access-token-denylist");
			expect(names).not.toContain("core-access-token-denylist-memory");
		});

		it("leaves nothing replica-unsafe under the umbrella E2E's environment", async () => {
			// The environment `o3co/auth`'s tests/docker-compose.yml sets. Under
			// `DEPLOYMENT_MODE=multi` the replica-safety guard fails boot naming
			// every in-memory shared store, so the denylist this change adds has to
			// come out of that environment as the Redis one — from the template's
			// own config, since the compose file names no denylist variable.
			// Asserted against the guard's own list rather than a module name, so a
			// rename cannot quietly invalidate it.
			const { REPLICA_UNSAFE_MODULES } = await import("@o3co/auth-provider-core");
			const config = buildResolvedConfig("production", {
				USER_SESSION_STORES_ADAPTER: "redis",
				RATE_LIMITER_ADAPTER: "redis",
				OAUTH_CODE_ADAPTER: "redis",
			});
			const names = buildModules(config).map((m) => m.name);
			expect(names).toContain("redis-access-token-denylist");
			for (const name of names) {
				expect(REPLICA_UNSAFE_MODULES).not.toContain(name);
			}
		});

		it("lets a single-instance deployment opt down to memory by env var", () => {
			const config = buildResolvedConfig("production", {
				ACCESS_TOKEN_DENYLIST_ADAPTER: "memory",
			});
			expect(config.accessTokenDenylist?.adapter).toBe("memory");
			const names = buildModules(config).map((m) => m.name);
			expect(names).toContain("core-access-token-denylist-memory");
		});

		it("lets a deployment declare access-token revocation unsupported by env var", () => {
			const config = buildResolvedConfig("production", {
				OAUTH_REVOCATION_ACCESS_TOKEN: "unsupported",
			});
			expect(config.oauth.revocation?.accessToken).toBe("unsupported");
		});
	});
});
