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

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { type AppConfig, AppConfigSchema } from "@o3co/auth-provider-core";
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import { describe, expect, it } from "vitest";
import { buildModules } from "../buildModules.mjs";
import { resolveConfigPaths, resolveLibraryReferenceConfPath } from "../configPath.mjs";

/**
 * #288 — boot the shipped config with EVERY documented override supplied the
 * way an operator actually supplies one: as a string.
 *
 * HOCON substitutes `${?VAR}` as a string, always. Whether that string is
 * usable depends entirely on the schema leaf it lands on, and the schema had
 * two answers to that question — an explicit `coerceBooleanFromEnv` on two
 * fields, and a bare `z.boolean()` everywhere else that only worked because
 * `@o3co/ts.hocon`'s zod bridge coerces a bare boolean leaf it can *reach*.
 * The bridge stops at anything that is not a `ZodObject` shape (or an
 * optional/nullable/default/catch/readonly wrapper around one), so wrapping a
 * section in `z.preprocess(...)` silently took the override away — which is
 * precisely what had happened to `OAUTH_JWT_LEGACY_TYP_ACCEPT`.
 *
 * This suite is the thing that stops the two paths diverging again. It is not
 * a sample of interesting variables: `covers every documented override` below
 * fails when a `${?VAR}` is added to either config layer, or documented in the
 * README, without being exercised here.
 */

// config/ is two levels above this test file: src/__tests__/ → src/ → standalone/
const standaloneDir = fileURLToPath(new URL("../..", import.meta.url));
const configDir = fileURLToPath(new URL("../../config", import.meta.url));
const readmePath = fileURLToPath(new URL("../../README.md", import.meta.url));

/**
 * Every environment variable the shipped artifact documents, with a value in
 * the shape an operator would supply. Strings throughout — that is the whole
 * point of the exercise.
 *
 * `OAUTH_JWT_ALGORITHM` is `EdDSA` here so the asymmetric key variables can be
 * in the same map: the HS256 branch of `signingKey.local` is a `.strict()`
 * discriminated-union member and refuses `privateKeyPath` and friends by
 * design. The HS256 shape gets its own test below.
 */
const DOCUMENTED_ENV: Readonly<Record<string, string>> = {
	// --- http ---------------------------------------------------------
	HTTP_PORT: "3000",
	HTTP_TRUST_PROXY: "10.0.0.0/8,loopback",
	HTTP_READINESS_TIMEOUT_MS: "1500",

	// --- logging ------------------------------------------------------
	LOG_LEVEL: "debug",

	// --- oauth.jwt ----------------------------------------------------
	OAUTH_JWT_ISSUER: "https://auth.test",
	OAUTH_JWT_SIGNING_KEY_PROVIDER: "local",
	OAUTH_JWT_ALGORITHM: "EdDSA",
	OAUTH_JWT_KID: "v1",
	OAUTH_JWT_SECRET: "documented-env-secret.at-least-32-bytes.ok",
	OAUTH_JWT_PRIVATE_KEY: "-----BEGIN PRIVATE KEY-----\nMC4=\n-----END PRIVATE KEY-----",
	OAUTH_JWT_PRIVATE_KEY_PATH: "./config/jwt-private.pem",
	OAUTH_JWT_PUBLIC_KEY: "-----BEGIN PUBLIC KEY-----\nMCo=\n-----END PUBLIC KEY-----",
	OAUTH_JWT_PUBLIC_KEY_PATH: "./config/jwt-public.pem",
	// The override this issue was filed over: a bare `z.boolean()` behind a
	// `z.preprocess` wrapper the hocon bridge cannot see through.
	OAUTH_JWT_LEGACY_TYP_ACCEPT: "true",

	// --- oauth tokens / policy ----------------------------------------
	OAUTH_ACCESS_TOKEN_EXPIRES_IN: "3600",
	OAUTH_REFRESH_TOKEN_EXPIRES_IN: "86400",
	OAUTH_REFRESH_TOKEN_UNKNOWN_FAMILY_POLICY: "reject",
	OAUTH_OIDC_MODE: "dual",
	OAUTH_CODE_ADAPTER: "redis",
	OAUTH_REVOCATION_ACCESS_TOKEN: "denylist",
	OAUTH_REQUIRE_EMAIL_VERIFIED: "true",
	OAUTH_REQUIRE_GRANT_TYPE_ALLOWLIST: "true",
	OAUTH_NONCE_MAX_LENGTH: "256",
	OAUTH_TOKEN_EXCHANGE_MAX_ACTOR_CHAIN_DEPTH: "3",
	OAUTH_RESOURCE_INDICATOR_ENABLED: "true",
	OAUTH_TOKEN_BINDING_DISPATCH_POLICY: "intent-explicit",
	OAUTH_TOKEN_BINDING_BIND_CONFIDENTIAL_CLIENT_REFRESH_TOKENS: "true",

	// --- oauth.grants -------------------------------------------------
	OAUTH_GRANTS_SESSION_ENABLED: "false",
	OAUTH_GRANTS_AUTHORIZATION_CODE_ENABLED: "true",
	OAUTH_GRANTS_REFRESH_TOKEN_ENABLED: "true",
	OAUTH_GRANTS_CLIENT_CREDENTIALS_ENABLED: "true",
	// #273 tombstone: inert, but a still-exported value must reach the boot
	// warning rather than failing parse.
	OAUTH_GRANTS_AUTHORIZATION_CODE_PKCE_REQUIRE_S256: "true",

	// --- session ------------------------------------------------------
	SESSION_SECRET: "documented-env-session-secret.at-least-32-bytes.ok",
	SESSION_NAME: "auth.session",
	SESSION_MAX_AGE: "3600000",
	SESSION_SECURE: "false",
	SESSION_SAME_SITE: "lax",
	SESSION_DOMAIN: "auth.example.com",
	SESSION_CSRF_TTL_SECONDS: "7200",
	SESSION_STORAGE_TYPE: "redis",
	SESSION_STORAGE_REDIS_URL: "redis://redis:6379",
	SESSION_STORAGE_REDIS_PASSWORD: "session-store-password",

	// --- rate limiting ------------------------------------------------
	RATE_LIMIT_FAIL_MODE: "open",
	RATE_LIMITER_ADAPTER: "redis",
	MEMORY_RATE_LIMITER_MAX_BUCKETS: "10000",

	// --- audit --------------------------------------------------------
	// #287: selects the sink builder; "console" is the registered builtin.
	// There is deliberately no "none" — an unknown type fails boot in
	// buildModules (pinned by audit-sink.test.mts), not at config parse,
	// because the schema keeps `audit.sink.type` an open string so
	// out-of-tree sinks need no schema change here.
	AUDIT_SINK_TYPE: "console",

	// --- shared stores ------------------------------------------------
	DEPLOYMENT_MODE: "multi",
	USER_SESSION_STORES_ADAPTER: "redis",
	ACCESS_TOKEN_DENYLIST_ADAPTER: "redis",
	REDIS_ACCESS_TOKEN_DENYLIST_KEY_PREFIX: "atdeny:",
	REDIS_SESSION_STORES_KEY_PREFIX: "ss:",
	REFRESH_TOKEN_FAMILY_STORE_KEY_PREFIX: "rtfam:",
	REFRESH_TOKEN_FAMILY_STORE_CAS_RETRY_LIMIT: "3",
	REFRESH_TOKEN_FAMILY_STORE_REDIS_URL: "redis://redis:6379",
	REFRESH_TOKEN_FAMILY_STORE_REDIS_PASSWORD: "rt-family-password",

	// --- federation ---------------------------------------------------
	FEDERATIONS_GOOGLE_ENABLED: "true",
	FEDERATIONS_GOOGLE_CLIENT_ID: "google-client-id",
	FEDERATIONS_GOOGLE_CLIENT_SECRET: "google-client-secret",
	FEDERATIONS_GOOGLE_CALLBACK_URL: "https://auth.test/session/oauth/federation/google/callback",

	// --- repositories -------------------------------------------------
	CLIENT_TYPE: "yaml",
	CLIENT_PATH: "./config/clients.yaml",
	CLIENT_USER_TYPE: "yaml",
	CLIENT_USER_PATH: "./config/users.yaml",
	CLIENT_USER_AUTHENTICATE_URL: "https://users.example.com/authenticate",
	CLIENT_USER_AUTHENTICATE_BY_TOKEN_URL: "https://users.example.com/authenticate-by-token",
	CLIENT_USER_TIMEOUT: "5000",
	CLIENT_USER_MAX_RESPONSE_BYTES: "1048576",
	CLIENT_CODE_TYPE: "redis",
	CLIENT_CODE_DEFAULT_EXPIRES_IN: "600",
	CLIENT_CODE_ENDPOINT_URI: "redis://redis:6379",
	CLIENT_CODE_PASSWORD: "code-store-password",
	CLIENT_CODE_KEY_PREFIX: "oauth:code:",

	// --- endpoints ----------------------------------------------------
	ENDPOINTS_LOGIN_URL: "/login",
};

/**
 * Substitutions that must NOT appear in `DOCUMENTED_ENV`, and why. Each one is
 * a variable whose documented behaviour is to *fail* boot, so setting it in
 * the all-overrides case would assert the opposite of the contract.
 */
const DELIBERATELY_UNSET: Readonly<Record<string, string>> = {
	OAUTH_AUTHORIZE_ALLOW_UNMARKED_CLIENTS:
		"#330 tombstone — any value must fail boot with migration instructions",
};

/**
 * The provider environment `o3co/auth`'s `tests/docker-compose.yml` sets,
 * transcribed. The umbrella E2E boots the shipped template with exactly this,
 * so a parse failure here is a red umbrella build that this repository can see
 * first. `SESSION_SECURE=false` is the one it cannot run without: the suite
 * speaks plain HTTP.
 */
const UMBRELLA_E2E_ENV: Readonly<Record<string, string>> = {
	OAUTH_JWT_ALGORITHM: "HS256",
	OAUTH_JWT_SECRET: "e2e-shared-hs256-secret.at-least-32-bytes.ok",
	OAUTH_JWT_ISSUER: "https://auth.e2e.test",
	SESSION_SECRET: "lO0QH09fuKSGuViZ9myJbH3jsgai99A2GpC3RYRuy6Y=",
	SESSION_SECURE: "false",
	SESSION_NAME: "auth.session",
	DEPLOYMENT_MODE: "multi",
	REFRESH_TOKEN_FAMILY_STORE_REDIS_URL: "redis://redis:6379",
	SESSION_STORAGE_REDIS_URL: "redis://redis:6379",
	USER_SESSION_STORES_ADAPTER: "redis",
	RATE_LIMITER_ADAPTER: "redis",
	OAUTH_CODE_ADAPTER: "redis",
	CLIENT_USER_TYPE: "yaml",
	OAUTH_RESOURCE_INDICATOR_ENABLED: "true",
	OAUTH_REQUIRE_EMAIL_VERIFIED: "true",
	OAUTH_GRANTS_AUTHORIZATION_CODE_PKCE_REQUIRE_S256: "true",
};

function buildResolvedConfig(env: Record<string, string>, configEnv = "production"): AppConfig {
	const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, configEnv);
	const libraryReferencePath = resolveLibraryReferenceConfPath();
	return validate(
		parseFile(envConfPath, { env })
			.withFallback(parseFile(applicationConfPath, { env }))
			.withFallback(parseFile(libraryReferencePath, { env })),
		AppConfigSchema,
	);
}

/** Every `${?VAR}` in a HOCON layer, ignoring commented-out lines. */
function substitutionsIn(path: string): Set<string> {
	const found = new Set<string>();
	for (const line of readFileSync(path, "utf8").split("\n")) {
		const code = line.replace(/(^|\s)(#|\/\/).*$/, "");
		for (const match of code.matchAll(/\$\{\?([A-Z][A-Z0-9_]*)\}/g)) {
			found.add(match[1] as string);
		}
	}
	return found;
}

/**
 * Every variable named in a leading `| \`VAR\` |` cell of a README table.
 *
 * The underscore is what separates an environment variable from the HTTP
 * methods in the endpoint table, which share the shouting-case shape.
 */
function documentedInReadme(): Set<string> {
	const found = new Set<string>();
	for (const match of readFileSync(readmePath, "utf8").matchAll(
		/^\|\s*`([A-Z][A-Z0-9_]*)`\s*\|/gm,
	)) {
		const name = match[1] as string;
		if (name.includes("_")) found.add(name);
	}
	return found;
}

function liveSubstitutions(): Set<string> {
	const { applicationConfPath } = resolveConfigPaths(configDir, "production");
	return new Set([
		...substitutionsIn(resolveLibraryReferenceConfPath()),
		...substitutionsIn(applicationConfPath),
	]);
}

describe("#288: the shipped config boots with every documented override supplied as a string", () => {
	it("parses with every documented environment variable set", () => {
		expect(() => buildResolvedConfig(DOCUMENTED_ENV)).not.toThrow();
	});

	it("turns every boolean override into an actual boolean", () => {
		const config = buildResolvedConfig(DOCUMENTED_ENV);
		// Each of these arrives from HOCON as a string. A leftover string is
		// not a cosmetic defect: `=== true` is how the runtime reads them.
		expect(config.session.secure).toBe(false);
		expect(config.oauth.jwt.legacyTypAccept).toBe(true);
		expect(config.oauth.requireEmailVerified).toBe(true);
		expect(config.oauth.resourceIndicator?.enabled).toBe(true);
		expect(config.federations.google?.enabled).toBe(true);
	});

	it("turns every non-boolean override into its declared type", () => {
		const config = buildResolvedConfig(DOCUMENTED_ENV);
		expect(config.http.port).toBe(3000);
		expect(config.http.readinessTimeoutMs).toBe(1500);
		expect(config.http.trustProxy).toEqual(["10.0.0.0/8", "loopback"]);
		expect(config.oauth.accessToken.expiresIn).toBe(3600);
		expect(config.oauth.refreshToken.expiresIn).toBe(86400);
		expect(config.session.maxAge).toBe(3600000);
		expect(config.session.csrf?.ttlSeconds).toBe(7200);
		expect(config.oauth.nonce?.maxLength).toBe(256);
	});

	it("parses the HS256 shape, whose strict union refuses asymmetric key fields", () => {
		// `OAUTH_JWT_ALGORITHM=HS256` is not a variation on the map above: the
		// HS256 member of the signingKey union is `.strict()`, so a deployment
		// that switches algorithm must also stop exporting the key-file
		// variables. Worth pinning — it is the umbrella E2E's shape.
		const { OAUTH_JWT_PRIVATE_KEY, OAUTH_JWT_PRIVATE_KEY_PATH, ...rest } = DOCUMENTED_ENV;
		void OAUTH_JWT_PRIVATE_KEY;
		void OAUTH_JWT_PRIVATE_KEY_PATH;
		const { OAUTH_JWT_PUBLIC_KEY, OAUTH_JWT_PUBLIC_KEY_PATH, ...hs256 } = rest;
		void OAUTH_JWT_PUBLIC_KEY;
		void OAUTH_JWT_PUBLIC_KEY_PATH;
		const config = buildResolvedConfig({ ...hs256, OAUTH_JWT_ALGORITHM: "HS256" });
		expect(config.oauth.jwt.signingKey.local?.algorithm).toBe("HS256");
	});

	it("parses the environment the umbrella E2E boots, with SESSION_SECURE=false as a string", () => {
		const config = buildResolvedConfig(UMBRELLA_E2E_ENV);
		expect(config.session.secure).toBe(false);
		expect(config.oauth.requireEmailVerified).toBe(true);
		expect(config.oauth.resourceIndicator?.enabled).toBe(true);
		expect(config.deployment?.mode).toBe("multi");
	});

	it("wires nothing replica-unsafe for the umbrella E2E environment", async () => {
		// `DEPLOYMENT_MODE=multi` makes the provider audit its own store wiring
		// at boot, so a config that parses but wires a memory store still fails
		// there. Assert against the guard's own list rather than module names.
		const { REPLICA_UNSAFE_MODULES } = await import("@o3co/auth-provider-core");
		for (const name of buildModules(buildResolvedConfig(UMBRELLA_E2E_ENV)).map((m) => m.name)) {
			expect(REPLICA_UNSAFE_MODULES).not.toContain(name);
		}
	});

	describe("boolean overrides accept the spellings an operator writes", () => {
		const cases: ReadonlyArray<[string, boolean]> = [
			["true", true],
			["TRUE", true],
			["1", true],
			["false", false],
			["0", false],
			// An exported-but-empty variable — the `.env` / compose / ConfigMap
			// shape. Reads as false, matching what #292 decided for trustProxy.
			["", false],
		];

		for (const [supplied, expected] of cases) {
			it(`SESSION_SECURE=${JSON.stringify(supplied)} resolves to ${expected}`, () => {
				const config = buildResolvedConfig({
					...DOCUMENTED_ENV,
					SESSION_SECURE: supplied,
					SESSION_SAME_SITE: "lax",
				});
				expect(config.session.secure).toBe(expected);
			});

			it(`OAUTH_JWT_LEGACY_TYP_ACCEPT=${JSON.stringify(supplied)} resolves to ${expected}`, () => {
				const config = buildResolvedConfig({
					...DOCUMENTED_ENV,
					OAUTH_JWT_LEGACY_TYP_ACCEPT: supplied,
				});
				expect(config.oauth.jwt.legacyTypAccept).toBe(expected);
			});
		}

		it("fails boot on a spelling it does not recognise rather than guessing", () => {
			expect(() => buildResolvedConfig({ ...DOCUMENTED_ENV, SESSION_SECURE: "ture" })).toThrow(
				/true.*false/s,
			);
		});

		it("refuses SESSION_SAME_SITE=none unless SESSION_SECURE is on", () => {
			// The #282 guard reads the coerced value, so it has to keep firing
			// for the string form an environment variable actually delivers.
			expect(() =>
				buildResolvedConfig({
					...DOCUMENTED_ENV,
					SESSION_SAME_SITE: "none",
					SESSION_SECURE: "false",
				}),
			).toThrow(/SESSION_SECURE=true/);
			expect(() =>
				buildResolvedConfig({
					...DOCUMENTED_ENV,
					SESSION_SAME_SITE: "none",
					SESSION_SECURE: "true",
					SESSION_NAME: "auth.session",
				}),
			).not.toThrow();
		});
	});

	describe("the documented surface and this suite cannot drift apart", () => {
		it("covers every substitution the shipped config layers declare", () => {
			const uncovered = [...liveSubstitutions()].filter(
				(name) => !(name in DOCUMENTED_ENV) && !(name in DELIBERATELY_UNSET),
			);
			expect(uncovered).toEqual([]);
		});

		it("covers every environment variable the README documents", () => {
			const uncovered = [...documentedInReadme()].filter(
				(name) => !(name in DOCUMENTED_ENV) && !(name in DELIBERATELY_UNSET),
			);
			expect(uncovered).toEqual([]);
		});

		it("exercises no variable the config layers no longer substitute", () => {
			// Catches the reverse drift: a README row (and a test entry) left
			// behind by a key that was removed from the HOCON.
			const live = liveSubstitutions();
			const dead = Object.keys(DOCUMENTED_ENV).filter((name) => !live.has(name));
			expect(dead).toEqual([]);
		});
	});

	describe("variables whose documented behaviour is to fail boot", () => {
		it("still refuses OAUTH_AUTHORIZE_ALLOW_UNMARKED_CLIENTS (#330 tombstone)", () => {
			expect(() =>
				buildResolvedConfig({
					...DOCUMENTED_ENV,
					OAUTH_AUTHORIZE_ALLOW_UNMARKED_CLIENTS: "true",
				}),
			).toThrow(/allowUnmarkedClients/);
		});

		it("still refuses an empty SESSION_CSRF_TTL_SECONDS (#272)", () => {
			// Pinned alongside the boolean cases because it is the same trap
			// read from the other side: for a *number*, empty means fail loudly.
			expect(() =>
				buildResolvedConfig({ ...DOCUMENTED_ENV, SESSION_CSRF_TTL_SECONDS: "" }),
			).toThrow();
		});
	});

	it("resolves against the shipped standalone template, not a fixture", () => {
		// Guards the guard: if the paths above ever stop pointing at the real
		// artifact these tests would pass while testing nothing.
		expect(standaloneDir).toMatch(/templates[/\\]standalone[/\\]?$/);
		expect(liveSubstitutions().size).toBeGreaterThan(40);
	});
});
