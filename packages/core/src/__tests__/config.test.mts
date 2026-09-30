import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import { describe, expect, it } from "vitest";
import { AppConfigSchema } from "#/config/application.schema.mjs";

describe("provider config", () => {
	it("loads and validates reference.conf with required env vars", () => {
		const raw = parseFile(new URL("../../config/reference.conf", import.meta.url).pathname, {
			env: {
				OAUTH_JWT_ISSUER: "https://auth.test",
			},
		});
		const config = validate(raw, AppConfigSchema);

		// The signing key, the log level, the HTTP settings, the Redis stores'
		// settings and the session's are the sections of the modules that own
		// them, with their defaults in those modules' package: core ships none.
		const sections = config as unknown as Record<string, unknown>;
		expect(config.oauth.jwt.signingKey).toBeUndefined();
		expect(sections["key-store"]).toBeUndefined();
		expect(sections.logging).toBeUndefined();
		expect(sections.http).toBeUndefined();
		expect(config["redis-session-stores"]).toBeUndefined();
		expect(config.oauth.oidcMode).toBe("oidc-required");
		expect(config.session).toBeUndefined();
		expect(config["session-store"]).toBeUndefined();
	});

	it("fails validation when required fields are missing", () => {
		const raw = parseFile(new URL("../../config/reference.conf", import.meta.url).pathname, {
			env: {},
		});
		expect(() => validate(raw, AppConfigSchema)).toThrow();
	});

	it("fails loudly when the removed OAUTH_AUTHORIZE_ALLOW_UNMARKED_CLIENTS is still set", () => {
		// The one-time migration flag for the /authorize first-party
		// invariant is removed. reference.conf deliberately keeps the
		// env-var substitution as a tombstone, so a deployment still exporting
		// the variable fails at boot with migration instructions instead of
		// having the value silently ignored. The value is irrelevant —
		// presence is the failure (even "false", the strict setting, must be
		// deleted).
		const raw = parseFile(new URL("../../config/reference.conf", import.meta.url).pathname, {
			env: {
				OAUTH_JWT_SECRET: "test-jwt-secret.at-least-32-bytes.ok",
				OAUTH_JWT_ISSUER: "https://auth.test",
				OAUTH_AUTHORIZE_ALLOW_UNMARKED_CLIENTS: "false",
			},
		});
		expect(() => validate(raw, AppConfigSchema)).toThrow(/allowUnmarkedClients was removed/);
	});

	it("overrides defaults with env vars", () => {
		const raw = parseFile(new URL("../../config/reference.conf", import.meta.url).pathname, {
			env: {
				OAUTH_JWT_SECRET: "test-jwt-secret.at-least-32-bytes.ok",
				OAUTH_JWT_ISSUER: "https://auth.test",
				CLIENT_USER_BASE_URL: "http://localhost:8080",
				CLIENT_APP_BASE_URL: "http://localhost:8080",
				CLIENT_CODE_ENDPOINT_URI: "redis://localhost:6379",
				OAUTH_OIDC_MODE: "dual",
			},
		});
		const config = validate(raw, AppConfigSchema);

		expect(config.oauth.oidcMode).toBe("dual");
		// federations.google.enabled env-var coercion is covered by the
		// HOCON reference.conf wiring; schema-level boolean coercion for
		// federation entries is tested in federations-schema.test.mts.
	});

	it("repositories.client.type is yaml when reference.conf is loaded with no override", () => {
		const raw = parseFile(new URL("../../config/reference.conf", import.meta.url).pathname, {
			env: {
				OAUTH_JWT_SECRET: "test-jwt-secret.at-least-32-bytes.ok",
				OAUTH_JWT_ISSUER: "https://auth.test",
				CLIENT_USER_BASE_URL: "http://localhost:8080",
				CLIENT_CODE_ENDPOINT_URI: "redis://localhost:6379",
			},
		});
		const config = validate(raw, AppConfigSchema);
		expect(config.repositories.client.type).toBe("yaml");
	});

	it("repositories.user.type is yaml when reference.conf is loaded with no override", () => {
		const raw = parseFile(new URL("../../config/reference.conf", import.meta.url).pathname, {
			env: {
				OAUTH_JWT_SECRET: "test-jwt-secret.at-least-32-bytes.ok",
				OAUTH_JWT_ISSUER: "https://auth.test",
			},
		});
		const config = validate(raw, AppConfigSchema);
		expect(config.repositories.user.type).toBe("yaml");
	});

	it("repositories.code.type is memory when reference.conf is loaded with no override", () => {
		const raw = parseFile(new URL("../../config/reference.conf", import.meta.url).pathname, {
			env: {
				OAUTH_JWT_SECRET: "test-jwt-secret.at-least-32-bytes.ok",
				OAUTH_JWT_ISSUER: "https://auth.test",
			},
		});
		const config = validate(raw, AppConfigSchema);
		expect(config.repositories.code.type).toBe("memory");
	});

	it("loads core-rate-limiter-memory.maxBuckets default and CORE_RATE_LIMITER_MEMORY_MAX_BUCKETS", () => {
		const path = new URL("../../config/reference.conf", import.meta.url).pathname;
		const base = validate(
			parseFile(path, {
				env: {
					OAUTH_JWT_SECRET: "test-jwt-secret.at-least-32-bytes.ok",
					OAUTH_JWT_ISSUER: "https://auth.test",
				},
			}),
			AppConfigSchema,
		);
		// Presence-only in core's schema: the module's own section schema reads it.
		expect(base["core-rate-limiter-memory"]).toMatchObject({ maxBuckets: 10_000 });

		const overridden = validate(
			parseFile(path, {
				env: {
					OAUTH_JWT_SECRET: "test-jwt-secret.at-least-32-bytes.ok",
					OAUTH_JWT_ISSUER: "https://auth.test",
					CORE_RATE_LIMITER_MEMORY_MAX_BUCKETS: "123",
				},
			}),
			AppConfigSchema,
		);
		expect(overridden["core-rate-limiter-memory"]).toMatchObject({ maxBuckets: "123" });
	});
});
