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
import { describe, expect, it } from "vitest";
import { AppConfigSchema, CoreConfigSchema } from "#/config/application.schema.mjs";

/**
 * Access the jwtSchema directly for sub-schema-level tests.
 * Mirrors the pattern in config.test.mts: `CoreConfigSchema.shape.oauth.shape.jwt`.
 */
const jwtSchema = CoreConfigSchema.shape.oauth.shape.jwt;

/**
 * Per ADR 2026-04-30: signingKey.local fields are required at the schema
 * level — defaults live in hocon. Tests assemble valid-shape inputs by
 * supplying every required field; per-test overrides target only the
 * field-under-test.
 */
function validLocal(overrides: Record<string, unknown> = {}) {
	return {
		algorithm: "HS256",
		kid: "v0",
		secret: "s3cret",
		previousSecrets: [],
		...overrides,
	};
}

describe("oauth.jwt.signingKey schema", () => {
	it("accepts nested signingKey.provider = 'local' with local sub-section", () => {
		const parsed = jwtSchema.parse({
			issuer: "https://auth.example.com",
			signingKey: { provider: "local", local: validLocal() },
		});
		expect(parsed.signingKey.provider).toBe("local");
		expect((parsed.signingKey.local as { secret: string }).secret).toBe("s3cret");
	});

	it("rejects signingKey when provider is omitted (schema is strict — defaults live in hocon)", () => {
		const result = jwtSchema.safeParse({
			issuer: "https://auth.test",
			signingKey: { local: validLocal() },
		});
		expect(result.success).toBe(false);
		if (!result.success) {
			const paths = result.error.issues.map((i) => i.path.join("."));
			expect(paths).toContain("signingKey.provider");
		}
	});

	it("preserves unknown provider sub-sections via passthrough", () => {
		const parsed = jwtSchema.parse({
			issuer: "https://auth.test",
			signingKey: { provider: "kms", kms: { keyArn: "arn:aws:..." } },
		});
		expect((parsed.signingKey as Record<string, unknown>).kms).toEqual({
			keyArn: "arn:aws:...",
		});
	});

	it("accepts issuer at oauth.jwt.issuer (not under signingKey)", () => {
		const parsed = jwtSchema.parse({
			issuer: "https://auth.example.com",
			signingKey: { provider: "local", local: validLocal() },
		});
		expect(parsed.issuer).toBe("https://auth.example.com");
	});

	it("accepts an absolute oauth.jwt.jwksPath override", () => {
		const parsed = jwtSchema.parse({
			issuer: "https://auth.test",
			signingKey: { provider: "local", local: validLocal() },
			jwksPath: "/keys/jwks.json",
		});
		expect((parsed as { jwksPath?: string }).jwksPath).toBe("/keys/jwks.json");
	});

	it("rejects a non-absolute oauth.jwt.jwksPath (must begin with '/')", () => {
		const result = jwtSchema.safeParse({
			issuer: "https://auth.test",
			signingKey: { provider: "local", local: validLocal() },
			jwksPath: "keys/jwks.json",
		});
		expect(result.success).toBe(false);
		if (!result.success) {
			const paths = result.error.issues.map((i) => i.path.join("."));
			expect(paths).toContain("jwksPath");
		}
	});

	it("omitting oauth.jwt.jwksPath is valid (resolveJwksPath applies the default)", () => {
		const parsed = jwtSchema.parse({
			issuer: "https://auth.test",
			signingKey: { provider: "local", local: validLocal() },
		});
		expect((parsed as { jwksPath?: string }).jwksPath).toBeUndefined();
	});

	it("accepts a non-negative integer oauth.jwt.jwksCacheMaxAge", () => {
		const parsed = jwtSchema.parse({
			issuer: "https://auth.test",
			signingKey: { provider: "local", local: validLocal() },
			jwksCacheMaxAge: 3600,
		});
		expect((parsed as { jwksCacheMaxAge?: number }).jwksCacheMaxAge).toBe(3600);
	});

	it("rejects a negative or non-integer oauth.jwt.jwksCacheMaxAge", () => {
		for (const bad of [-1, 1.5]) {
			const result = jwtSchema.safeParse({
				issuer: "https://auth.test",
				signingKey: { provider: "local", local: validLocal() },
				jwksCacheMaxAge: bad,
			});
			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.error.issues.map((i) => i.path.join("."))).toContain("jwksCacheMaxAge");
			}
		}
	});

	it("does NOT superRefine-reject missing secret for HS256 (schema does shape only; builder enforces field presence)", () => {
		// Previously the schema would reject HS256 without a secret. After
		// migration the schema only enforces shape (field presence per the
		// type contract); the builder throws at create() time when the
		// algorithm-specific key material is absent.
		expect(() =>
			jwtSchema.parse({
				issuer: "https://auth.test",
				signingKey: {
					provider: "local",
					local: { algorithm: "HS256", kid: "v0", previousSecrets: [] },
				},
			}),
		).not.toThrow();
	});
});

describe("AppConfigSchema exports signingKey shape (integration)", () => {
	it("AppConfigSchema is defined and accessible", () => {
		expect(AppConfigSchema).toBeDefined();
	});
});

describe("signingKey.local schema - HS256 rotation (IH-9)", () => {
	it("rejects HS256 with previousKeys (asymmetric-shaped field) via discriminated union strict", () => {
		const result = jwtSchema.safeParse({
			issuer: "https://auth.test",
			signingKey: {
				provider: "local",
				local: {
					algorithm: "HS256",
					kid: "v0",
					secret: "s3cret",
					previousKeys: [
						{
							kid: "v-old",
							publicKey: "...pem...",
							expiresAt: "2099-12-31T00:00:00Z",
						},
					],
				},
			},
		});
		expect(result.success).toBe(false);
		if (!result.success) {
			// Zod's `.strict()` reports `previousKeys` as the unrecognized key
			// inside the parent path `signingKey.local`. Combine the issue's
			// `keys` array with its message to make the assertion robust.
			const flagged = result.error.issues.some(
				(issue) =>
					(Array.isArray((issue as { keys?: unknown }).keys) &&
						((issue as { keys?: string[] }).keys ?? []).includes("previousKeys")) ||
					issue.message.includes("previousKeys"),
			);
			expect(flagged).toBe(true);
		}
	});

	it("accepts HS256 with previousSecrets containing kid+secret+expiresAt entries", () => {
		const result = jwtSchema.safeParse({
			issuer: "https://auth.test",
			signingKey: {
				provider: "local",
				local: {
					algorithm: "HS256",
					kid: "v1",
					secret: "new-secret",
					previousSecrets: [
						{
							kid: "v0",
							secret: "old-secret",
							expiresAt: "2099-12-31T00:00:00Z",
						},
					],
				},
			},
		});
		expect(result.success).toBe(true);
	});

	it("accepts HS256 without previousSecrets (optional field — backward compatible)", () => {
		const result = jwtSchema.safeParse({
			issuer: "https://auth.test",
			signingKey: {
				provider: "local",
				local: {
					algorithm: "HS256",
					kid: "v0",
					secret: "s3cret",
				},
			},
		});
		expect(result.success).toBe(true);
	});

	it("flags legacy flat oauth.jwt.previousSecrets as a migration error", () => {
		const result = jwtSchema.safeParse({
			previousSecrets: [
				{
					kid: "v0",
					secret: "old-secret",
					expiresAt: "2099-12-31T00:00:00Z",
				},
			],
			issuer: "https://auth.example.com",
		});
		expect(result.success).toBe(false);
		if (!result.success) {
			const msg = result.error.issues.map((i) => i.message).join("\n");
			expect(msg).toMatch(/legacy flat fields/i);
			expect(msg).toMatch(/previousSecrets/);
		}
	});
});

describe("jwtSchema - legacy flat field detection", () => {
	it("rejects legacy flat oauth.jwt.* fields with migration-guiding error", () => {
		const result = jwtSchema.safeParse({
			algorithm: "HS256",
			secret: "legacy",
			issuer: "https://auth.example.com",
		});
		expect(result.success).toBe(false);
		if (!result.success) {
			const msg = result.error.issues.map((i) => i.message).join("\n");
			expect(msg).toMatch(/legacy flat fields/i);
			expect(msg).toMatch(/signingKey\.local/i);
		}
	});

	it("includes the offending field name in the error message", () => {
		const result = jwtSchema.safeParse({
			kid: "v0",
			privateKey: "--- BEGIN ---",
			issuer: "https://auth.example.com",
		});
		expect(result.success).toBe(false);
		if (!result.success) {
			const msg = result.error.issues.map((i) => i.message).join("\n");
			expect(msg).toMatch(/kid|privateKey/i);
		}
	});

	it("accepts valid nested signingKey shape without triggering legacy detection", () => {
		const result = jwtSchema.safeParse({
			issuer: "https://auth.example.com",
			signingKey: { provider: "local", local: validLocal() },
		});
		expect(result.success).toBe(true);
	});
});
