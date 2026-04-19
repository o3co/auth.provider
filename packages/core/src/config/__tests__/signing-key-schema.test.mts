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

describe("oauth.jwt.signingKey schema", () => {
	it("accepts nested signingKey.provider = 'local' with local sub-section", () => {
		const parsed = jwtSchema.parse({
			issuer: "https://auth.example.com",
			signingKey: {
				provider: "local",
				local: { algorithm: "HS256", kid: "v0", secret: "s3cret", previousKeys: [] },
			},
		});
		expect(parsed.signingKey.provider).toBe("local");
		expect((parsed.signingKey.local as { secret: string }).secret).toBe("s3cret");
	});

	it("defaults signingKey.provider to 'local'", () => {
		const parsed = jwtSchema.parse({
			signingKey: { local: { secret: "x" } },
		});
		expect(parsed.signingKey.provider).toBe("local");
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
			signingKey: { local: { secret: "x" } },
		});
		expect(parsed.issuer).toBe("https://auth.example.com");
	});

	it("does NOT superRefine-reject missing secret for HS256 (schema does shape only; builder enforces field presence)", () => {
		// Previously the schema would reject { algorithm: "HS256" } without secret.
		// After this migration the schema only enforces shape; the builder throws at create() time.
		expect(() =>
			jwtSchema.parse({
				signingKey: { provider: "local", local: { algorithm: "HS256" } },
			}),
		).not.toThrow();
	});
});

describe("AppConfigSchema exports signingKey shape (integration)", () => {
	it("AppConfigSchema is defined and accessible", () => {
		expect(AppConfigSchema).toBeDefined();
	});
});
