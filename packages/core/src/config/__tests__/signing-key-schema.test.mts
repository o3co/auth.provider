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
		previousKeys: [],
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

	it("does NOT superRefine-reject missing secret for HS256 (schema does shape only; builder enforces field presence)", () => {
		// Previously the schema would reject HS256 without a secret. After
		// migration the schema only enforces shape (field presence per the
		// type contract); the builder throws at create() time when the
		// algorithm-specific key material is absent.
		expect(() =>
			jwtSchema.parse({
				signingKey: {
					provider: "local",
					local: { algorithm: "HS256", kid: "v0", previousKeys: [] },
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
