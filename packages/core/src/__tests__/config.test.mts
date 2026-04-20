import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import { describe, expect, it } from "vitest";
import { AppConfigSchema, CoreConfigSchema } from "#/config/application.schema.mjs";
import { createKeyStoreFactory, registerBuiltinKeyStores } from "#/keys/factory.mjs";

// jwtSchema now describes the nested signingKey shape (Task 5 migration).
// Schema only enforces shape; field-level validation lives in the local builder.
const jwtSchema = CoreConfigSchema.shape.oauth.shape.jwt;

function makeFactory() {
	const factory = createKeyStoreFactory();
	registerBuiltinKeyStores(factory);
	return factory;
}

describe("provider config", () => {
	it("loads and validates application.conf with required env vars", () => {
		const raw = parseFile(new URL("../../config/application.conf", import.meta.url).pathname, {
			env: {
				OAUTH_JWT_SECRET: "test-secret",
				SESSION_SECRET: "test-session-secret",
			},
		});
		const config = validate(raw, AppConfigSchema);

		// Nested signingKey shape: provider defaults to "local"
		expect(config.oauth.jwt.signingKey.provider).toBe("local");

		// OAUTH_JWT_SECRET flows into signingKey.local.secret
		const local = config.oauth.jwt.signingKey.local as Record<string, unknown>;
		expect(local).toBeDefined();
		expect(local.secret).toBe("test-secret");

		// algorithm and kid defaults applied
		expect(local.algorithm).toBe("HS256");
		expect(local.kid).toBe("v0");
	});

	it("fails validation when required fields are missing", () => {
		const raw = parseFile(new URL("../../config/application.conf", import.meta.url).pathname, {
			env: {},
		});
		expect(() => validate(raw, AppConfigSchema)).toThrow();
	});

	it("overrides defaults with env vars", () => {
		const raw = parseFile(new URL("../../config/application.conf", import.meta.url).pathname, {
			env: {
				OAUTH_JWT_SECRET: "test-secret",
				SESSION_SECRET: "test-session-secret",
				CLIENT_USER_BASE_URL: "http://localhost:8080",
				CLIENT_APP_BASE_URL: "http://localhost:8080",
				CLIENT_CODE_ENDPOINT_URI: "redis://localhost:6379",
				HTTP_PORT: "9090",
				HTTP_TRUST_PROXY: "true",
				SESSION_SECURE: "false",
				FEDERATIONS_GOOGLE_ENABLED: "true",
				FEDERATIONS_GOOGLE_CLIENT_ID: "test-client-id",
				FEDERATIONS_GOOGLE_CLIENT_SECRET: "test-client-secret",
				FEDERATIONS_GOOGLE_CALLBACK_URL: "http://localhost:3000/callback",
			},
		});
		const config = validate(raw, AppConfigSchema);

		expect(config.http.port).toBe(9090);
		expect(config.http.trustProxy).toBe(true);
		expect(config.session.secure).toBe(false);
		expect(config.federations.google.enabled).toBe(true);
	});

	it("clients.client.type defaults to yaml", () => {
		const raw = parseFile(new URL("../../config/application.conf", import.meta.url).pathname, {
			env: {
				OAUTH_JWT_SECRET: "test-secret",
				SESSION_SECRET: "test-session-secret",
				CLIENT_USER_BASE_URL: "http://localhost:8080",
				CLIENT_CODE_ENDPOINT_URI: "redis://localhost:6379",
			},
		});
		const config = validate(raw, AppConfigSchema);
		expect(config.clients.client.type).toBe("yaml");
	});

	it("clients.user.type defaults to yaml", () => {
		const raw = parseFile(new URL("../../config/application.conf", import.meta.url).pathname, {
			env: {
				OAUTH_JWT_SECRET: "test-secret",
				SESSION_SECRET: "test-session-secret",
			},
		});
		const config = validate(raw, AppConfigSchema);
		expect(config.clients.user.type).toBe("yaml");
	});

	it("clients.code.type defaults to memory", () => {
		const raw = parseFile(new URL("../../config/application.conf", import.meta.url).pathname, {
			env: {
				OAUTH_JWT_SECRET: "test-secret",
				SESSION_SECRET: "test-session-secret",
			},
		});
		const config = validate(raw, AppConfigSchema);
		expect(config.clients.code.type).toBe("memory");
	});
});

describe("federations.google config validation", () => {
	const googleSchema = AppConfigSchema.shape.federations.shape.google;

	it("fails when google.enabled=true but clientId is missing", () => {
		const result = googleSchema.safeParse({
			enabled: true,
			clientSecret: "secret",
			callbackURL: "http://localhost:3000/callback",
		});
		expect(result.success).toBe(false);
	});

	it("fails when google.enabled=true but clientSecret is missing", () => {
		const result = googleSchema.safeParse({
			enabled: true,
			clientId: "my-client-id",
			callbackURL: "http://localhost:3000/callback",
		});
		expect(result.success).toBe(false);
	});

	it("fails when google.enabled=true but callbackURL is missing", () => {
		const result = googleSchema.safeParse({
			enabled: true,
			clientId: "my-client-id",
			clientSecret: "my-secret",
		});
		expect(result.success).toBe(false);
	});

	it("passes when google.enabled=false and credentials are not set", () => {
		const result = googleSchema.safeParse({ enabled: false });
		expect(result.success).toBe(true);
	});

	it("passes when google.enabled=true and all credentials are set", () => {
		const result = googleSchema.safeParse({
			enabled: true,
			clientId: "my-client-id",
			clientSecret: "my-secret",
			callbackURL: "http://localhost:3000/callback",
		});
		expect(result.success).toBe(true);
	});
});

describe("jwt config schema", () => {
	// Schema-level acceptance tests — verify the nested signingKey shape is accepted
	// and that schema-level defaults are applied inside signingKey.local.

	it("algorithm defaults to HS256", () => {
		// When local sub-section is absent, signingKey.local is undefined (schema: optional).
		// The default lives in signingKeyLocalSchema; test via parse with explicit local: {}.
		const result = jwtSchema.parse({ signingKey: { local: {} } });
		const local = result.signingKey.local as Record<string, unknown>;
		expect(local.algorithm).toBe("HS256");
	});

	it("kid defaults to v0", () => {
		const result = jwtSchema.parse({ signingKey: { local: {} } });
		const local = result.signingKey.local as Record<string, unknown>;
		expect(local.kid).toBe("v0");
	});

	it("previousKeys defaults to empty array", () => {
		const result = jwtSchema.parse({ signingKey: { local: {} } });
		const local = result.signingKey.local as Record<string, unknown>;
		expect(local.previousKeys).toEqual([]);
	});

	it("accepts RS256 with key fields", () => {
		const result = jwtSchema.parse({
			signingKey: {
				provider: "local",
				local: {
					algorithm: "RS256",
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
			signingKey: { local: { algorithm: "ES256", privateKey: "pk", publicKey: "pub" } },
		});
		expect((es256.signingKey.local as Record<string, unknown>).algorithm).toBe("ES256");

		const eddsa = jwtSchema.parse({
			signingKey: { local: { algorithm: "EdDSA", privateKey: "pk", publicKey: "pub" } },
		});
		expect((eddsa.signingKey.local as Record<string, unknown>).algorithm).toBe("EdDSA");
	});

	it("accepts previousKeys array with valid entries", () => {
		const result = jwtSchema.parse({
			signingKey: {
				local: {
					algorithm: "ES256",
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
			signingKey: { local: { algorithm: "ES256", privateKey: "pk", publicKey: "pub" } },
		});
		const local = result.signingKey.local as Record<string, unknown>;
		expect(local.secret).toBeUndefined();
	});

	// Builder-level rejection tests — schema no longer rejects these shapes;
	// the local builder validates field presence at factory.create() time.
	// Error wording is preserved verbatim from the old superRefine messages (Tasks 3/4).

	it("rejects HS256 without secret (builder-level)", async () => {
		// Schema parse succeeds — no secret required at schema level.
		const parsed = jwtSchema.parse({ signingKey: { local: { algorithm: "HS256" } } });
		const local = parsed.signingKey.local as Record<string, unknown>;
		await expect(makeFactory().create({ type: "local", ...local })).rejects.toThrow(
			/secret is required for HS256 algorithm/i,
		);
	});

	it("rejects asymmetric algorithm without privateKey (builder-level)", async () => {
		const parsed = jwtSchema.parse({
			signingKey: { local: { algorithm: "ES256", publicKey: "pub" } },
		});
		const local = parsed.signingKey.local as Record<string, unknown>;
		await expect(makeFactory().create({ type: "local", ...local })).rejects.toThrow(
			/privateKey or privateKeyPath is required/i,
		);
	});

	it("rejects asymmetric algorithm without publicKey (builder-level)", async () => {
		const parsed = jwtSchema.parse({
			signingKey: { local: { algorithm: "RS256", privateKey: "pk" } },
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
			signingKey: {
				local: {
					algorithm: "ES256",
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
