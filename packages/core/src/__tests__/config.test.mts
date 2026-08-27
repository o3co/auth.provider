import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import { describe, expect, it } from "vitest";
import { AppConfigSchema, CoreConfigSchema } from "#/config/application.schema.mjs";
import {
	createKeyStoreFactory,
	DEFAULT_SIGNING_ALGORITHM,
	registerBuiltinKeyStores,
} from "#/keys/factory.mjs";

// jwtSchema now describes the nested signingKey shape (Task 5 migration).
// Schema only enforces shape; field-level validation lives in the local builder.
const jwtSchema = CoreConfigSchema.shape.oauth.shape.jwt;

function makeFactory() {
	const factory = createKeyStoreFactory();
	registerBuiltinKeyStores(factory);
	return factory;
}

describe("provider config", () => {
	it("loads and validates reference.conf with required env vars", () => {
		const raw = parseFile(new URL("../../config/reference.conf", import.meta.url).pathname, {
			env: {
				OAUTH_JWT_SECRET: "test-jwt-secret.at-least-32-bytes.ok",
				OAUTH_JWT_ISSUER: "https://auth.test",
				SESSION_SECRET: "test-session-secret.at-least-32-bytes.ok",
			},
		});
		const config = validate(raw, AppConfigSchema);

		// Nested signingKey shape: provider defaults to "local"
		expect(config.oauth.jwt.signingKey.provider).toBe("local");

		// OAUTH_JWT_SECRET flows into signingKey.local.secret
		const local = config.oauth.jwt.signingKey.local as Record<string, unknown>;
		expect(local).toBeDefined();
		expect(local.secret).toBe("test-jwt-secret.at-least-32-bytes.ok");

		// algorithm and kid come from hocon (`reference.conf`); the schema
		// is strict and supplies no defaults of its own (ADR 2026-04-30).
		// #282: the shipped default is an ASYMMETRIC algorithm. HS256 makes
		// relying parties either unable to verify (no JWKS) or holders of a
		// token-forging key, so it is opt-in rather than what you get by
		// doing nothing.
		expect(local.algorithm).toBe("EdDSA");
		// Drift guard: the shipped HOCON default and the constant the builder's
		// error message quotes are the same value, or an operator gets pointed
		// at an algorithm their config does not use.
		expect(local.algorithm).toBe(DEFAULT_SIGNING_ALGORITHM);
		expect(local.kid).toBe("v0");
		expect(config.oauth.oidcMode).toBe("oidc-required");
		expect(config.session.name).toBe("__Host-auth.session");
		expect(config.redisSessionStores?.keyPrefix).toBe("ss:");
		// #282 wraps `session` in a cross-field refinement (SameSite/Secure) and
		// #272 put `session.csrf` inside the same object. Resolve the real
		// reference.conf and assert the sub-section still arrives COERCED — a
		// wrapper that broke ts.hocon's shape traversal would leave `ttlSeconds`
		// as the string "7200" and fail only once the CSRF arithmetic ran.
		expect(config.session.csrf?.ttlSeconds).toBe(7200);
		expect(config.session.csrf?.trustedOrigins).toEqual([]);
	});

	it("fails to build a keystore when reference.conf is loaded with NO key material (#282)", async () => {
		// The headline requirement: a deployment that sets no signing key at all
		// must not boot. Pre-#282 it silently got HS256 with whatever
		// OAUTH_JWT_SECRET happened to be — including nothing useful.
		const raw = parseFile(new URL("../../config/reference.conf", import.meta.url).pathname, {
			env: {
				OAUTH_JWT_ISSUER: "https://auth.test",
				SESSION_SECRET: "test-session-secret.at-least-32-bytes.ok",
			},
		});
		const config = validate(raw, AppConfigSchema);
		const local = config.oauth.jwt.signingKey.local as Record<string, unknown>;
		let message = "";
		try {
			await makeFactory().create({ type: "local", ...local });
		} catch (err) {
			message = (err as Error).message;
		}
		expect(message).toMatch(/OAUTH_JWT_PRIVATE_KEY_PATH/);
		expect(message).toMatch(/OAUTH_JWT_PUBLIC_KEY_PATH/);
		expect(message).toMatch(/openssl genpkey -algorithm ed25519/i);
	});

	it("fails to build a keystore when only OAUTH_JWT_SECRET is set, and says how to opt into HS256 (#282)", async () => {
		const raw = parseFile(new URL("../../config/reference.conf", import.meta.url).pathname, {
			env: {
				OAUTH_JWT_ISSUER: "https://auth.test",
				OAUTH_JWT_SECRET: "test-jwt-secret.at-least-32-bytes.ok",
				SESSION_SECRET: "test-session-secret.at-least-32-bytes.ok",
			},
		});
		const config = validate(raw, AppConfigSchema);
		const local = config.oauth.jwt.signingKey.local as Record<string, unknown>;
		await expect(makeFactory().create({ type: "local", ...local })).rejects.toThrow(
			/OAUTH_JWT_ALGORITHM=HS256/,
		);
	});

	it("HS256 remains selectable through OAUTH_JWT_ALGORITHM with a strong secret (#282)", async () => {
		const raw = parseFile(new URL("../../config/reference.conf", import.meta.url).pathname, {
			env: {
				OAUTH_JWT_ISSUER: "https://auth.test",
				OAUTH_JWT_ALGORITHM: "HS256",
				OAUTH_JWT_SECRET: "test-jwt-secret.at-least-32-bytes.ok",
				SESSION_SECRET: "test-session-secret.at-least-32-bytes.ok",
			},
		});
		const config = validate(raw, AppConfigSchema);
		const local = config.oauth.jwt.signingKey.local as Record<string, unknown>;
		const keyStore = await makeFactory().create({ type: "local", ...local });
		expect(keyStore.algorithm).toBe("HS256");
	});

	it("HS256 selected with a weak secret fails at boot (#282)", async () => {
		const raw = parseFile(new URL("../../config/reference.conf", import.meta.url).pathname, {
			env: {
				OAUTH_JWT_ISSUER: "https://auth.test",
				OAUTH_JWT_ALGORITHM: "HS256",
				OAUTH_JWT_SECRET: "test-secret-for-e2e",
				SESSION_SECRET: "test-session-secret.at-least-32-bytes.ok",
			},
		});
		const config = validate(raw, AppConfigSchema);
		const local = config.oauth.jwt.signingKey.local as Record<string, unknown>;
		await expect(makeFactory().create({ type: "local", ...local })).rejects.toThrow(
			/at least 32 bytes/i,
		);
	});

	it("rejects a SESSION_SECRET below the 256-bit floor (#282)", () => {
		const raw = parseFile(new URL("../../config/reference.conf", import.meta.url).pathname, {
			env: {
				OAUTH_JWT_ISSUER: "https://auth.test",
				SESSION_SECRET: "too-short",
			},
		});
		expect(() => validate(raw, AppConfigSchema)).toThrow(/at least 32 bytes/i);
	});

	it("fails validation when required fields are missing", () => {
		const raw = parseFile(new URL("../../config/reference.conf", import.meta.url).pathname, {
			env: {},
		});
		expect(() => validate(raw, AppConfigSchema)).toThrow();
	});

	it("fails loudly when the removed OAUTH_AUTHORIZE_ALLOW_UNMARKED_CLIENTS is still set", () => {
		// #330: the one-time migration flag for the /authorize first-party
		// invariant (#316/#317) is gone. reference.conf deliberately keeps the
		// env-var substitution as a tombstone, so a deployment still exporting
		// the variable fails at boot with migration instructions instead of
		// having the value silently ignored. The value is irrelevant —
		// presence is the failure ("false" was the strict endstate answer, and
		// it must be deleted too).
		const raw = parseFile(new URL("../../config/reference.conf", import.meta.url).pathname, {
			env: {
				OAUTH_JWT_SECRET: "test-jwt-secret.at-least-32-bytes.ok",
				OAUTH_JWT_ISSUER: "https://auth.test",
				OAUTH_AUTHORIZE_ALLOW_UNMARKED_CLIENTS: "false",
				SESSION_SECRET: "test-session-secret.at-least-32-bytes.ok",
			},
		});
		expect(() => validate(raw, AppConfigSchema)).toThrow(/allowUnmarkedClients was removed/);
	});

	it("overrides defaults with env vars", () => {
		const raw = parseFile(new URL("../../config/reference.conf", import.meta.url).pathname, {
			env: {
				OAUTH_JWT_SECRET: "test-jwt-secret.at-least-32-bytes.ok",
				OAUTH_JWT_ISSUER: "https://auth.test",
				SESSION_SECRET: "test-session-secret.at-least-32-bytes.ok",
				CLIENT_USER_BASE_URL: "http://localhost:8080",
				CLIENT_APP_BASE_URL: "http://localhost:8080",
				CLIENT_CODE_ENDPOINT_URI: "redis://localhost:6379",
				HTTP_PORT: "9090",
				HTTP_TRUST_PROXY: "true",
				SESSION_SECURE: "false",
				SESSION_NAME: "auth.sid",
				OAUTH_OIDC_MODE: "dual",
				REDIS_SESSION_STORES_KEY_PREFIX: "tenant-a:ss:",
			},
		});
		const config = validate(raw, AppConfigSchema);

		expect(config.http.port).toBe(9090);
		expect(config.http.trustProxy).toBe(true);
		expect(config.session.secure).toBe(false);
		expect(config.session.name).toBe("auth.sid");
		expect(config.oauth.oidcMode).toBe("dual");
		expect(config.redisSessionStores?.keyPrefix).toBe("tenant-a:ss:");
		// federations.google.enabled env-var coercion is covered by the
		// HOCON reference.conf wiring; schema-level boolean coercion for
		// federation entries is tested in federations-schema.test.mts.
	});

	it("repositories.client.type is yaml when reference.conf is loaded with no override", () => {
		const raw = parseFile(new URL("../../config/reference.conf", import.meta.url).pathname, {
			env: {
				OAUTH_JWT_SECRET: "test-jwt-secret.at-least-32-bytes.ok",
				OAUTH_JWT_ISSUER: "https://auth.test",
				SESSION_SECRET: "test-session-secret.at-least-32-bytes.ok",
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
				SESSION_SECRET: "test-session-secret.at-least-32-bytes.ok",
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
				SESSION_SECRET: "test-session-secret.at-least-32-bytes.ok",
			},
		});
		const config = validate(raw, AppConfigSchema);
		expect(config.repositories.code.type).toBe("memory");
	});

	it("loads memoryRateLimiter.maxBuckets default and env override", () => {
		const path = new URL("../../config/reference.conf", import.meta.url).pathname;
		const base = validate(
			parseFile(path, {
				env: {
					OAUTH_JWT_SECRET: "test-jwt-secret.at-least-32-bytes.ok",
					OAUTH_JWT_ISSUER: "https://auth.test",
					SESSION_SECRET: "test-session-secret.at-least-32-bytes.ok",
				},
			}),
			AppConfigSchema,
		);
		expect(base.memoryRateLimiter?.maxBuckets).toBe(10_000);

		const overridden = validate(
			parseFile(path, {
				env: {
					OAUTH_JWT_SECRET: "test-jwt-secret.at-least-32-bytes.ok",
					OAUTH_JWT_ISSUER: "https://auth.test",
					SESSION_SECRET: "test-session-secret.at-least-32-bytes.ok",
					MEMORY_RATE_LIMITER_MAX_BUCKETS: "123",
				},
			}),
			AppConfigSchema,
		);
		expect(overridden.memoryRateLimiter?.maxBuckets).toBe(123);
	});
});

describe("jwt config schema", () => {
	// Schema-level acceptance tests — verify the nested signingKey shape is
	// accepted. Per ADR 2026-04-30 the schema is a pure type contract:
	// algorithm/kid are required at the schema boundary, and hocon
	// (`packages/core/config/reference.conf`) supplies the runtime
	// defaults that production callers rely on. IH-9: the schema is a
	// discriminated union on `algorithm`, so a bare local sub-section
	// fails the discriminator check before per-branch field validation.

	it("rejects bare local sub-section (algorithm/kid are required at the schema boundary)", () => {
		const result = jwtSchema.safeParse({
			issuer: "https://auth.test",
			signingKey: { provider: "local", local: { secret: "x" } },
		});
		expect(result.success).toBe(false);
		if (!result.success) {
			const paths = result.error.issues.map((i) => i.path.join("."));
			// Discriminated union reports the discriminator error first; the
			// branch-level kid check fires only once `algorithm` parses.
			expect(paths).toEqual(expect.arrayContaining(["signingKey.local.algorithm"]));
		}
	});

	it("accepts RS256 with key fields", () => {
		const result = jwtSchema.parse({
			issuer: "https://auth.test",
			signingKey: {
				provider: "local",
				local: {
					algorithm: "RS256",
					kid: "v0",
					previousKeys: [],
					privateKey: "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----",
					publicKey: "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----",
				},
			},
		});
		const local = result.signingKey.local as Record<string, unknown>;
		expect(local.algorithm).toBe("RS256");
		expect(local.privateKey).toBeDefined();
		expect(local.publicKey).toBeDefined();
	});

	it("accepts ES256 and EdDSA algorithms", () => {
		const es256 = jwtSchema.parse({
			issuer: "https://auth.test",
			signingKey: {
				provider: "local",
				local: {
					algorithm: "ES256",
					kid: "v0",
					previousKeys: [],
					privateKey: "pk",
					publicKey: "pub",
				},
			},
		});
		expect((es256.signingKey.local as Record<string, unknown>).algorithm).toBe("ES256");

		const eddsa = jwtSchema.parse({
			issuer: "https://auth.test",
			signingKey: {
				provider: "local",
				local: {
					algorithm: "EdDSA",
					kid: "v0",
					previousKeys: [],
					privateKey: "pk",
					publicKey: "pub",
				},
			},
		});
		expect((eddsa.signingKey.local as Record<string, unknown>).algorithm).toBe("EdDSA");
	});

	it("accepts previousKeys array with valid entries", () => {
		const result = jwtSchema.parse({
			issuer: "https://auth.test",
			signingKey: {
				provider: "local",
				local: {
					algorithm: "ES256",
					kid: "v1",
					privateKey: "pk",
					publicKey: "pub",
					previousKeys: [
						{
							kid: "v0",
							publicKey: "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----",
							expiresAt: "2026-12-31T00:00:00Z",
						},
						{
							kid: "v1",
							publicKeyPath: "/path/to/key.pem",
							expiresAt: "2027-06-01T00:00:00Z",
						},
					],
				},
			},
		});
		const local = result.signingKey.local as { previousKeys: Array<Record<string, unknown>> };
		expect(local.previousKeys).toHaveLength(2);
		expect(local.previousKeys[0].kid).toBe("v0");
		expect(local.previousKeys[1].publicKeyPath).toBe("/path/to/key.pem");
	});

	it("secret is optional for asymmetric algorithms", () => {
		const result = jwtSchema.parse({
			issuer: "https://auth.test",
			signingKey: {
				provider: "local",
				local: {
					algorithm: "ES256",
					kid: "v0",
					previousKeys: [],
					privateKey: "pk",
					publicKey: "pub",
				},
			},
		});
		const local = result.signingKey.local as Record<string, unknown>;
		expect(local.secret).toBeUndefined();
	});

	// Builder-level rejection tests — schema no longer rejects these shapes;
	// the local builder validates field presence at factory.create() time.
	// Error wording is preserved verbatim from the old superRefine messages (Tasks 3/4).

	it("rejects HS256 without secret (builder-level)", async () => {
		// Schema parse succeeds — no secret required at schema level.
		const parsed = jwtSchema.parse({
			issuer: "https://auth.test",
			signingKey: {
				provider: "local",
				local: { algorithm: "HS256", kid: "v0", previousSecrets: [] },
			},
		});
		const local = parsed.signingKey.local as Record<string, unknown>;
		await expect(makeFactory().create({ type: "local", ...local })).rejects.toThrow(
			/secret is required for HS256 algorithm/i,
		);
	});

	it("rejects asymmetric algorithm without privateKey (builder-level)", async () => {
		const parsed = jwtSchema.parse({
			issuer: "https://auth.test",
			signingKey: {
				provider: "local",
				local: { algorithm: "ES256", kid: "v0", previousKeys: [], publicKey: "pub" },
			},
		});
		const local = parsed.signingKey.local as Record<string, unknown>;
		await expect(makeFactory().create({ type: "local", ...local })).rejects.toThrow(
			/privateKey or privateKeyPath is required/i,
		);
	});

	it("rejects asymmetric algorithm without publicKey (builder-level)", async () => {
		const parsed = jwtSchema.parse({
			issuer: "https://auth.test",
			signingKey: {
				provider: "local",
				local: { algorithm: "RS256", kid: "v0", previousKeys: [], privateKey: "pk" },
			},
		});
		const local = parsed.signingKey.local as Record<string, unknown>;
		await expect(makeFactory().create({ type: "local", ...local })).rejects.toThrow(
			/publicKey or publicKeyPath is required/i,
		);
	});

	it("rejects previousKeys entry without publicKey or publicKeyPath (builder-level)", async () => {
		// Schema accepts the shape; builder throws when a previous key has no public key source.
		// We supply real-looking (but fake) inline PEM strings to pass the schema — the builder
		// throws before it attempts to import them, so actual crypto validity is irrelevant here.
		const parsed = jwtSchema.parse({
			issuer: "https://auth.test",
			signingKey: {
				provider: "local",
				local: {
					algorithm: "ES256",
					kid: "v0",
					privateKey: "pk",
					publicKey: "pub",
					previousKeys: [{ kid: "old", expiresAt: "2099-01-01T00:00:00Z" }],
				},
			},
		});
		const local = parsed.signingKey.local as Record<string, unknown>;
		await expect(makeFactory().create({ type: "local", ...local })).rejects.toThrow(
			/publicKey or publicKeyPath is required for previous key old/i,
		);
	});
});
