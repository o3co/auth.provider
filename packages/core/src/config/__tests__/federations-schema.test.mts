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
import { AppConfigSchema, fullSectionsSchema } from "#/config/application.schema.mjs";

/**
 * Access the federations schema directly for sub-schema-level tests.
 * Mirrors the pattern used by schema-open-type.test.mts.
 */
const federationsSchema = fullSectionsSchema.shape.federations;

/**
 * Minimal config for a full AppConfigSchema.parse() call.
 * Derived by observing which fields are required (have no defaults).
 */
const minimalConfig = {
	http: {},
	oauth: {
		jwt: { signingKey: { local: { secret: "s3cret" } } },
		accessToken: {},
		refreshToken: {},
		grants: {},
	},
	session: {
		secret: "session-secret",
		storage: { type: "memory" },
	},
	rateLimit: {
		login: { windowMs: 60000, limit: 10 },
		token: { windowMs: 60000, limit: 10 },
		authorize: { windowMs: 60000, limit: 10 },
	},
	clients: {
		client: {},
		user: {},
		code: {},
	},
	endpoints: {
		login: {},
	},
	cors: {},
};

describe("federations schema — open to z.record with passthrough", () => {
	it("accepts shorthand: federations.google { enabled: true, clientId, clientSecret, callbackURL }", () => {
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

	it("accepts explicit multi-tenant: federations['google-work'] { type: 'google', google: { clientId, ... } }", () => {
		const parsed = federationsSchema.parse({
			"google-work": {
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

	it("accepts arbitrary custom type: federations['corporate-sso'] { type: 'saml', saml: { entityId: '...' } }", () => {
		const parsed = federationsSchema.parse({
			"corporate-sso": {
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

	it("defaults enabled to false when section is present but enabled is omitted", () => {
		const parsed = federationsSchema.parse({
			google: {
				clientId: "test-client-id",
				clientSecret: "test-client-secret",
				callbackURL: "https://example.com/callback",
			},
		});
		expect(parsed.google.enabled).toBe(false);
	});

	it("defaults federations to empty object when entire section is omitted (AppConfigSchema.parse)", () => {
		const parsed = AppConfigSchema.parse(minimalConfig);
		expect(parsed.federations).toEqual({});
	});

	it("no longer enforces clientId/clientSecret/callbackURL when enabled=true (responsibility shift to builder)", () => {
		// Schema-level: parse succeeds even with enabled=true and no credentials.
		// The builder (factory.create) will throw at runtime instead.
		// This test documents the intentional schema-vs-builder separation per spec Section 2 / Q2'-1.
		expect(() =>
			federationsSchema.parse({
				google: {
					enabled: true,
				},
			}),
		).not.toThrow();
	});
});
