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
import { makeValidAppConfig } from "../../testing/fixtures/valid-config.mjs";

/** The schema of `core.federations`, for tests of an entry's shape. */
const federationsSchema = CoreConfigSchema.shape.core.unwrap().shape.federations.unwrap();

/**
 * Per ADR 2026-04-30: schema is a pure type contract; defaults live in
 * hocon. AppConfigSchema.parse rejects bare `{}` inputs, so the fixture
 * supplies a minimal schema-valid baseline (intentionally diverges from
 * reference.conf — see makeValidAppConfig docstring). Per-test
 * overrides target only the field-under-test (e.g. add `core.federations`
 * for federation-specific assertions).
 */
const minimalConfig = makeValidAppConfig();

describe("core.federations schema — open to z.record with passthrough", () => {
	it("accepts shorthand: core.federations.google { enabled: true, clientId, clientSecret, callbackURL }", () => {
		const parsed = federationsSchema.parse({
			google: {
				enabled: true,
				clientId: "test-client-id",
				clientSecret: "test-client-secret",
				callbackURL: "https://example.com/callback",
			},
		});
		expect(parsed.google.enabled).toBe(true);
		const google = parsed.google as Record<string, unknown>;
		expect(google.clientId).toBe("test-client-id");
		expect(google.clientSecret).toBe("test-client-secret");
		expect(google.callbackURL).toBe("https://example.com/callback");
	});

	it("accepts explicit multi-tenant: core.federations['google-work'] { type: 'google', google: { clientId, ... } }", () => {
		const parsed = federationsSchema.parse({
			"google-work": {
				enabled: false,
				type: "google",
				google: {
					clientId: "work-client-id",
					clientSecret: "work-client-secret",
					callbackURL: "https://work.example.com/callback",
				},
			},
		});
		const entry = parsed["google-work"] as Record<string, unknown>;
		expect(entry.type).toBe("google");
		const nested = entry.google as Record<string, unknown>;
		expect(nested.clientId).toBe("work-client-id");
	});

	it("accepts arbitrary custom type: core.federations['corporate-sso'] { type: 'saml', saml: { entityId: '...' } }", () => {
		const parsed = federationsSchema.parse({
			"corporate-sso": {
				enabled: false,
				type: "saml",
				saml: {
					entityId: "https://idp.example.com/saml",
					ssoUrl: "https://idp.example.com/sso",
				},
			},
		});
		const entry = parsed["corporate-sso"] as Record<string, unknown>;
		expect(entry.type).toBe("saml");
		const saml = entry.saml as Record<string, unknown>;
		expect(saml.entityId).toBe("https://idp.example.com/saml");
	});

	it("rejects entries that omit enabled (schema is strict — defaults live in hocon)", () => {
		const result = federationsSchema.safeParse({
			google: {
				clientId: "test-client-id",
				clientSecret: "test-client-secret",
				callbackURL: "https://example.com/callback",
			},
		});
		expect(result.success).toBe(false);
		if (!result.success) {
			const paths = result.error.issues.map((i) => i.path.join("."));
			expect(paths).toContain("google.enabled");
		}
	});

	it("leaves core.federations absent when the configuration has none (no schema-side default)", () => {
		// Core's reference.conf ships the empty map; the schema itself does
		// not inject `{}` when the key is omitted.
		const parsed = AppConfigSchema.parse(minimalConfig);
		expect(parsed.core?.federations).toBeUndefined();
	});

	it("does not enforce clientId/clientSecret/callbackURL when enabled=true", () => {
		// Schema-level: parse succeeds even with enabled=true and no credentials.
		// The builder (factory.create) will throw at runtime instead.
		// This test documents the intentional schema-vs-builder separation.
		expect(() =>
			federationsSchema.parse({
				google: {
					enabled: true,
				},
			}),
		).not.toThrow();
	});

	it("coerces enabled='true' string to boolean true (env var path)", () => {
		// CORE_FEDERATIONS_GOOGLE_ENABLED=true arrives as the string "true" from ts.hocon env-var
		// substitution when the z.record wrapper prevents hocon-level coerce traversal.
		const parsed = federationsSchema.parse({
			google: { enabled: "true" },
		});
		expect(parsed.google.enabled).toBe(true);
	});

	it("coerces enabled='false' string to boolean false (prevents accidental enable via env var)", () => {
		// Critical: z.coerce.boolean() would coerce "false" → true (non-empty string).
		// The preprocess must return false for the string "false".
		const parsed = federationsSchema.parse({
			google: { enabled: "false" },
		});
		expect(parsed.google.enabled).toBe(false);
	});

	it("coerces enabled='1' string to true", () => {
		const parsed = federationsSchema.parse({
			google: { enabled: "1" },
		});
		expect(parsed.google.enabled).toBe(true);
	});

	it("coerces enabled='0' string to false", () => {
		const parsed = federationsSchema.parse({
			google: { enabled: "0" },
		});
		expect(parsed.google.enabled).toBe(false);
	});

	it("preserves enabled=true boolean", () => {
		const parsed = federationsSchema.parse({
			google: { enabled: true },
		});
		expect(parsed.google.enabled).toBe(true);
	});

	it("preserves enabled=false boolean", () => {
		const parsed = federationsSchema.parse({
			google: { enabled: false },
		});
		expect(parsed.google.enabled).toBe(false);
	});

	it("treats empty string as false (env var unset case)", () => {
		const parsed = federationsSchema.parse({
			google: { enabled: "" },
		});
		expect(parsed.google.enabled).toBe(false);
	});

	it("rejects enabled='yes' with type error (unrecognized string values are not silently coerced)", () => {
		expect(() =>
			AppConfigSchema.parse({
				...minimalConfig,
				core: { ...minimalConfig.core, federations: { google: { enabled: "yes" } } },
			}),
		).toThrow();
	});
});
