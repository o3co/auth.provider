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
import type { AppConfig } from "@o3co/auth-provider-core";
import { type OAuthSection, oauthEndpointsModule } from "@o3co/auth-provider-oauth";
import { parseFile } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";
import { readAdapters } from "../adapters.mjs";
import { buildModules } from "../buildModules.mjs";
import {
	readOwnLayers,
	readSwitches,
	resolveConfigPaths,
	resolveForBoot,
	type Switches,
} from "../configPath.mjs";
import { templateReference } from "../modules.mjs";
import { configuredMfaMode } from "./configured-mfa-mode.fixture.mjs";
import { type BothPhases, withSwitches } from "./library-references.fixture.mjs";

// config/ is two levels above this test file:
//   src/__tests__/ → src/ → standalone/ → config/
const configDir = fileURLToPath(new URL("../../config", import.meta.url));

// Provide the secrets the template's files require. These are
// test-only values — no real keys are embedded here. SESSION_STORE_SECRET
// carries a 256-bit entropy floor, so these clear it (the '.' characters keep
// them outside the base64 alphabet, so the UTF-8 length is what counts).
const testEnv = {
	KEY_STORE_LOCAL_SECRET: "test-secret-three-tier.at-least-32-bytes.ok",
	OAUTH_JWT_ISSUER: "https://auth.test",
	SESSION_STORE_SECRET: "test-session-secret-three-tier.at-least-32-bytes.ok",
};

/**
 * The three tiers under `env`, as `app.mts` reads them: what phase one reads
 * of the template's own layers, laid over what phase two hands boot — the
 * own layers over the reference of every package the chosen modules come
 * from, resolved and unparsed.
 */
function buildResolvedConfig(env: string, extraEnv: Record<string, string> = {}): BothPhases {
	const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, env);
	const own = readOwnLayers([envConfPath, applicationConfPath], {
		env: { ...testEnv, ...extraEnv },
	});
	const switches = readSwitches(own);
	return withSwitches(
		resolveForBoot(own, buildModules(switches), switches) as unknown as Record<string, unknown>,
		switches,
	);
}

/** `oauth.resourceIndicator` as the section's owner, the oauth module, parses it at boot. */
function parsedResourceIndicator(config: AppConfig): { readonly enabled?: unknown } | undefined {
	const schema = oauthEndpointsModule.section?.schema;
	if (schema === undefined) throw new Error("the oauth module declares no section");
	return (schema.parse(config.oauth) as { resourceIndicator?: { enabled?: unknown } })
		.resourceIndicator;
}

// The oauth-authorization module's section as resolved, unparsed: the
// runtime shape is a string from env substitution, a boolean from a literal.
type GrantEntry = { enabled?: unknown };
const grants = (config: AppConfig) =>
	((config["oauth-authorization"] as { grants?: unknown } | undefined)?.grants as
		| Record<string, GrantEntry | undefined>
		| undefined) ?? {};

/** `oauth {}` as the resolution leaves it, read as the shape the oauth module parses. */
const oauthOf = (config: AppConfig): OAuthSection => config.oauth as OAuthSection;

describe("three-tier HOCON resolution (env → application.conf → reference.conf)", () => {
	it("template application.conf wins over reference.conf for grant.enabled", () => {
		const config = buildResolvedConfig("development");
		// Template's application.conf sets authorizationCode.enabled = true,
		// so the resolved value is true whatever reference.conf says.
		expect(grants(config).authorizationCode?.enabled).toBe(true);
	});

	it("reference.conf default reaches resolved config when template omits the key", () => {
		const config = buildResolvedConfig("development");
		// nonce.maxLength is library-owned in both layers (template doesn't
		// override it). Verifies precedence falls through.
		expect(oauthOf(config).nonce?.maxLength).toBe(256);
	});

	it("env var at template layer can disable a template-enabled grant (precedence: env-override line must be repeated)", () => {
		// The env-override line is repeated at the template layer alongside
		// `enabled = true`; without it, the package reference's substitution is
		// shadowed by the template's literal `true`. The value stays a string
		// until boot: the module reads the switch with its own schema, `"false"`
		// as off.
		const config = buildResolvedConfig("development", {
			OAUTH_AUTHORIZATION_GRANTS_AUTHORIZATION_CODE_ENABLED: "false",
		});
		expect(grants(config).authorizationCode?.enabled).toBe("false");
	});

	it("reads the MFA switch, mfaMode, as the files write it where MFA_MODE is unset, and installs no MFA module under MFA_MODE=off", () => {
		// The template's reference.conf ships the switch required and binds
		// MFA_MODE; a project's application.conf may write it over that.
		const mfaNames = (config: Switches) =>
			buildModules(config)
				.map((m) => m.name)
				.filter((name) => /mfa/i.test(name));
		const shipped = buildResolvedConfig("development");
		const configured = configuredMfaMode("development");
		expect(shipped.mfaMode).toBe(configured);
		if (configured === "off") expect(mfaNames(shipped)).toEqual([]);
		else expect(mfaNames(shipped)).toContain("mfa");
		const off = buildResolvedConfig("development", { MFA_MODE: "off" });
		expect(off.mfaMode).toBe("off");
		expect(mfaNames(off)).toEqual([]);
		const optional = buildResolvedConfig("development", { MFA_MODE: "optional" });
		expect(optional.mfaMode).toBe("optional");
		expect(mfaNames(optional)).toContain("mfa");
	});

	it("core's reference.conf ships no rateLimit.failMode: it is the Redis limiter's own key", () => {
		const config = buildResolvedConfig("development");
		expect(config).not.toHaveProperty("rateLimit.failMode");
	});

	it("template application.conf ships clientCredentials.enabled off", () => {
		// The template writes every grant switch it reads before boot, so the
		// value phase one reads is the one boot parses.
		const config = buildResolvedConfig("development");
		expect(grants(config).clientCredentials?.enabled).toBe(false);
	});

	it("reference.conf default for oauth.resourceIndicator.enabled is false", () => {
		// reference.conf must ship the literal `false` anchor so that the
		// schema coercion (coerceBooleanFromEnv) can produce a boolean value.
		// Without the HOCON block the field resolves to undefined.
		const config = buildResolvedConfig("development");
		expect(oauthOf(config).resourceIndicator?.enabled).toBe(false);
		expect(parsedResourceIndicator(config)?.enabled).toBe(false);
	});

	it("env var OAUTH_RESOURCE_INDICATOR_ENABLED=true reaches resolved config and coerces to boolean true", () => {
		// HOCON env-substitution returns a string. The reference.conf anchor
		// (`enabled = ${?OAUTH_RESOURCE_INDICATOR_ENABLED}`) lets the env var
		// reach the resolved layer; the schema's coerceBooleanFromEnv turns
		// "true" → true so `=== true` guards in grant handlers work correctly.
		const config = buildResolvedConfig("development", {
			OAUTH_RESOURCE_INDICATOR_ENABLED: "true",
		});
		expect(oauthOf(config).resourceIndicator?.enabled).toBe("true");
		expect(parsedResourceIndicator(config)?.enabled).toBe(true);
	});

	// The selection is the composition root's own, `adapters.auditSink`,
	// which phase one reads over the template's own layers. These assertions
	// run the real merge, so they fail if a layer stops carrying the key.
	describe("the audit sink as the shipped artifact resolves it", () => {
		it("resolves adapters.auditSink to the template's logger sink with nothing set", () => {
			const config = buildResolvedConfig("production");
			expect(config.adapters.auditSink).toBe("logger");
		});

		it("wires exactly one auditSink provider for that resolved config", () => {
			const modules = buildModules(buildResolvedConfig("production"));
			const providers = modules.filter((m) => Object.keys(m.provides ?? {}).includes("auditSink"));
			expect(providers).toHaveLength(1);
		});

		it("lets an operator select core's built-in console sink by env var", () => {
			const config = buildResolvedConfig("production", { ADAPTERS_AUDIT_SINK: "console" });
			expect(config.adapters.auditSink).toBe("console");
		});

		it("the template's reference.conf alone selects a sink, not a drop", () => {
			// A composition resolved against the template's reference alone
			// still lands on a sink: an application.conf that forgets the
			// selection must not thereby lose its audit trail.
			const referenceOnly = parseFile(fileURLToPath(templateReference()), { env: {} });
			expect(readAdapters(referenceOnly.toObject() as Record<string, unknown>, {}).auditSink).toBe(
				"logger",
			);
		});
	});

	// The shape the umbrella E2E (o3co/auth) boots: the shipped
	// application.conf, `CORE_DEPLOYMENT_MODE=multi`, and one shared ioredis socket.
	// A memory denylist under `multi` is refused by the replica-safety guard,
	// and NO denylist by core's denylist boot guard, so the template has to
	// land on "redis" without the deployment naming it.
	describe("access-token revocation as the shipped artifact resolves it", () => {
		it("resolves adapters.accessTokenDenylist to redis with nothing set", () => {
			const config = buildResolvedConfig("production");
			expect(config.adapters.accessTokenDenylist).toBe("redis");
		});

		it("resolves oauth.revocation.accessToken to denylist with nothing set", () => {
			const config = buildResolvedConfig("production");
			expect(oauthOf(config).revocation?.accessToken).toBe("denylist");
		});

		it("picks the replica-safe denylist module for that resolved config", () => {
			const names = buildModules(buildResolvedConfig("production")).map((m) => m.name);
			expect(names).toContain("redis-access-token-denylist");
			expect(names).not.toContain("core-access-token-denylist-memory");
		});

		it("leaves nothing replica-unsafe under the umbrella E2E's environment", async () => {
			// The environment `o3co/auth`'s tests/docker-compose.yml sets. Under
			// `CORE_DEPLOYMENT_MODE=multi` the replica-safety guard fails boot naming
			// every in-memory shared store, so the denylist has to come out as
			// the Redis one from the template's own config: the compose file
			// names no denylist variable. Asked of each manifest, as the guard
			// does, so a rename cannot quietly invalidate it and the template's
			// own memory modules count too.
			const { replicaUnsafeReason } = await import("@o3co/auth-provider-core");
			const config = buildResolvedConfig("production", {
				ADAPTERS_USER_SESSION_STORES: "redis",
				ADAPTERS_RATE_LIMITER: "redis",
				ADAPTERS_CODE_REPOSITORY: "redis",
				// The federation token store defaults to memory, and the memory
				// module declares itself replica-unsafe.
				ADAPTERS_FEDERATION_TOKEN_STORE: "redis",
				REDIS_FEDERATION_TOKEN_STORE_ENCRYPTION_KEY: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
				// The umbrella sets MFA off.
				MFA_MODE: "off",
			});
			const modules = buildModules(config);
			expect(modules.map((m) => m.name)).toContain("redis-access-token-denylist");
			// Each module's section at its name: a declaration made from the
			// section is answered for it.
			const sections = config as unknown as Record<string, unknown>;
			for (const module of modules) {
				expect(replicaUnsafeReason(module, sections[module.name]), module.name).toBeUndefined();
			}
		});

		it("lets a single-instance deployment opt down to memory by env var", () => {
			const config = buildResolvedConfig("production", {
				ADAPTERS_ACCESS_TOKEN_DENYLIST: "memory",
			});
			expect(config.adapters.accessTokenDenylist).toBe("memory");
			const names = buildModules(config).map((m) => m.name);
			expect(names).toContain("core-access-token-denylist-memory");
		});

		it("lets a deployment declare access-token revocation unsupported by env var", () => {
			const config = buildResolvedConfig("production", {
				OAUTH_REVOCATION_ACCESS_TOKEN: "unsupported",
			});
			expect(oauthOf(config).revocation?.accessToken).toBe("unsupported");
		});
	});
});
