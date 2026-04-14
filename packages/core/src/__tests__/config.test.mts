import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import { describe, expect, it } from "vitest";
import { AppConfigSchema, CoreConfigSchema } from "#/config/application.schema.mjs";

const jwtSchema = CoreConfigSchema.shape.oauth.shape.jwt;

describe("provider config", () => {
	it("loads and validates application.conf with required env vars", () => {
		const raw = parseFile(new URL("../../config/application.conf", import.meta.url).pathname, {
			env: {
				OAUTH_JWT_SECRET: "test-secret",
				SESSION_SECRET: "test-session-secret",
				CLIENT_USER_BASE_URL: "http://localhost:8080",
				CLIENT_APP_BASE_URL: "http://localhost:8080",
				CLIENT_CODE_ENDPOINT_URI: "redis://localhost:6379",
			},
		});
		const config = validate(raw, AppConfigSchema);

		expect(config.oauth.jwt.secret).toBe("test-secret");
		expect(config.session.secret).toBe("test-session-secret");
		expect(config.http.port).toBe(3000);
		expect((config.oauth.grants as Record<string, unknown>).session).toMatchObject({
			enabled: true,
		});
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
	it("algorithm defaults to HS256", () => {
		const result = jwtSchema.parse({ secret: "test-secret" });
		expect(result.algorithm).toBe("HS256");
	});

	it("accepts RS256 with key fields", () => {
		const result = jwtSchema.parse({
			algorithm: "RS256",
			privateKey: "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----",
			publicKey: "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----",
		});
		expect(result.algorithm).toBe("RS256");
		expect(result.privateKey).toBeDefined();
		expect(result.publicKey).toBeDefined();
	});

	it("accepts ES256 and EdDSA algorithms", () => {
		expect(
			jwtSchema.parse({ algorithm: "ES256", privateKey: "pk", publicKey: "pub" }).algorithm,
		).toBe("ES256");
		expect(
			jwtSchema.parse({ algorithm: "EdDSA", privateKey: "pk", publicKey: "pub" }).algorithm,
		).toBe("EdDSA");
	});

	it("previousKeys defaults to empty array", () => {
		const result = jwtSchema.parse({ secret: "test-secret" });
		expect(result.previousKeys).toEqual([]);
	});

	it("accepts previousKeys array with valid entries", () => {
		const result = jwtSchema.parse({
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
		});
		expect(result.previousKeys).toHaveLength(2);
		expect(result.previousKeys[0].kid).toBe("v0");
		expect(result.previousKeys[1].publicKeyPath).toBe("/path/to/key.pem");
	});

	it("secret is optional for asymmetric algorithms", () => {
		const result = jwtSchema.parse({ algorithm: "ES256", privateKey: "pk", publicKey: "pub" });
		expect(result.secret).toBeUndefined();
	});

	it("kid defaults to v0", () => {
		const result = jwtSchema.parse({ secret: "test-secret" });
		expect(result.kid).toBe("v0");
	});

	it("rejects HS256 without secret", () => {
		const result = jwtSchema.safeParse({});
		expect(result.success).toBe(false);
	});

	it("rejects asymmetric algorithm without privateKey", () => {
		const result = jwtSchema.safeParse({ algorithm: "ES256", publicKey: "pub" });
		expect(result.success).toBe(false);
	});

	it("rejects asymmetric algorithm without publicKey", () => {
		const result = jwtSchema.safeParse({ algorithm: "RS256", privateKey: "pk" });
		expect(result.success).toBe(false);
	});

	it("rejects previousKeys entry without publicKey or publicKeyPath", () => {
		const result = jwtSchema.safeParse({
			algorithm: "ES256",
			privateKey: "pk",
			publicKey: "pub",
			previousKeys: [{ kid: "old", expiresAt: "2099-01-01T00:00:00Z" }],
		});
		expect(result.success).toBe(false);
	});
});
