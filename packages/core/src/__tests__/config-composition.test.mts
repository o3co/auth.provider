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
import { z } from "zod";
import {
	AppConfigSchema,
	CoreConfigSchema,
	composeConfigSchema,
	fullSectionsSchema,
} from "#/config/application.schema.mjs";
import { createKeyStoreFactory, registerBuiltinKeyStores } from "#/keys/factory.mjs";

const minimalCoreConfig = {
	http: { port: 3000, trustProxy: false, readinessTimeoutMs: 1000 },
	oauth: {
		jwt: {
			signingKey: {
				provider: "local",
				local: { algorithm: "HS256", kid: "v0", secret: "test-secret", previousSecrets: [] },
			},
		},
		accessToken: { expiresIn: 3600 },
		refreshToken: {
			expiresIn: 86400,
			unknownFamilyPolicy: "reject",
			legacyRtPolicy: "reject",
		},
		grants: {},
		oidcMode: "oidc-required",
	},
};

describe("CoreConfigSchema http.readinessTimeoutMs", () => {
	// HOCON substitutes an unset-but-present environment variable as "", and
	// z.coerce.number() turns "" into 0. setTimeout clamps 0 to 1ms, so a
	// deployment that shipped HTTP_READINESS_TIMEOUT_MS= (blank) would answer
	// /readyz with 503 forever against a perfectly healthy Redis. Boot has to
	// reject it rather than silently drain every replica.
	it.each([
		["empty string (blank env var)", ""],
		["zero", 0],
		["negative", -1],
		["fractional", 1.5],
		// setTimeout clamps anything above 2^31-1 to 1ms, so "be very patient"
		// becomes "be maximally impatient".
		["beyond Node's timer range", 2_147_483_648],
	])("rejects %s", (_label, value) => {
		const result = CoreConfigSchema.safeParse({
			...minimalCoreConfig,
			http: { ...minimalCoreConfig.http, readinessTimeoutMs: value },
		});
		expect(result.success).toBe(false);
	});

	it("accepts a positive integer supplied as a string, as HOCON env substitution produces", () => {
		const result = CoreConfigSchema.safeParse({
			...minimalCoreConfig,
			http: { ...minimalCoreConfig.http, readinessTimeoutMs: "250" },
		});
		expect(result.success).toBe(true);
	});
});

describe("CoreConfigSchema", () => {
	it("validates minimal core config (just http + oauth)", () => {
		const result = CoreConfigSchema.safeParse(minimalCoreConfig);
		expect(result.success).toBe(true);
	});

	it("does not require session", () => {
		const result = CoreConfigSchema.safeParse(minimalCoreConfig);
		expect(result.success).toBe(true);
		if (result.success) {
			expect((result.data as Record<string, unknown>).session).toBeUndefined();
		}
	});

	it("does not require federations", () => {
		const result = CoreConfigSchema.safeParse(minimalCoreConfig);
		expect(result.success).toBe(true);
		if (result.success) {
			expect((result.data as Record<string, unknown>).federations).toBeUndefined();
		}
	});

	it("does not require endpoints", () => {
		const result = CoreConfigSchema.safeParse(minimalCoreConfig);
		expect(result.success).toBe(true);
		if (result.success) {
			expect((result.data as Record<string, unknown>).endpoints).toBeUndefined();
		}
	});

	it("does not require cors", () => {
		const result = CoreConfigSchema.safeParse(minimalCoreConfig);
		expect(result.success).toBe(true);
		if (result.success) {
			expect((result.data as Record<string, unknown>).cors).toBeUndefined();
		}
	});

	it("does not require repositories", () => {
		const result = CoreConfigSchema.safeParse(minimalCoreConfig);
		expect(result.success).toBe(true);
		if (result.success) {
			expect((result.data as Record<string, unknown>).repositories).toBeUndefined();
		}
	});

	it("still rejects when jwt secret is missing for HS256 (builder-level)", async () => {
		// Schema no longer rejects this shape — the superRefine moved to the local builder.
		// Verify that CoreConfigSchema parses successfully, then that the builder throws.
		const result = CoreConfigSchema.safeParse({
			...minimalCoreConfig,
			oauth: {
				...minimalCoreConfig.oauth,
				jwt: {
					signingKey: {
						provider: "local",
						local: { algorithm: "HS256", kid: "v0", previousSecrets: [] },
					},
				},
			},
		});
		expect(result.success).toBe(true);

		// Builder-level validation: factory.create() must throw with the legacy wording.
		const factory = createKeyStoreFactory();
		registerBuiltinKeyStores(factory);
		await expect(factory.create({ type: "local", algorithm: "HS256" })).rejects.toThrow(
			/secret is required for HS256 algorithm/i,
		);
	});
});

describe("composeConfigSchema", () => {
	it("merges module schemas with core", () => {
		const moduleSchema = z.object({
			myModule: z.object({ enabled: z.boolean() }),
		});
		const composed = composeConfigSchema([moduleSchema]);
		const result = composed.safeParse({
			...minimalCoreConfig,
			myModule: { enabled: true },
		});
		expect(result.success).toBe(true);
	});

	it("rejects when module-required field is missing", () => {
		const moduleSchema = z.object({
			myModule: z.object({ enabled: z.boolean() }),
		});
		const composed = composeConfigSchema([moduleSchema]);
		// Missing myModule
		const result = composed.safeParse(minimalCoreConfig);
		expect(result.success).toBe(false);
	});

	it("merges multiple module schemas", () => {
		const moduleA = z.object({ moduleA: z.object({ value: z.string() }) });
		const moduleB = z.object({ moduleB: z.object({ count: z.number() }) });
		const composed = composeConfigSchema([moduleA, moduleB]);
		const result = composed.safeParse({
			...minimalCoreConfig,
			moduleA: { value: "hello" },
			moduleB: { count: 42 },
		});
		expect(result.success).toBe(true);
	});

	it("returns CoreConfigSchema when no modules are provided", () => {
		const composed = composeConfigSchema([]);
		const result = composed.safeParse(minimalCoreConfig);
		expect(result.success).toBe(true);
	});
});

describe("fullSectionsSchema endpoints optionality", () => {
	it("accepts endpoints with only login (no client or authCallback)", () => {
		const endpointsOnlyLogin = {
			endpoints: {
				login: { url: "/login" },
			},
		};
		const schema = fullSectionsSchema.pick({ endpoints: true });
		const result = schema.safeParse(endpointsOnlyLogin);
		expect(result.success).toBe(true);
	});

	it("strips dead endpoints fields (client / authCallback removed in IH-10)", () => {
		const endpointsWithDeadFields = {
			endpoints: {
				login: { url: "/login" },
				client: { url: "http://localhost:3001" },
				authCallback: { url: "/auth/callback" },
			},
		};
		const schema = fullSectionsSchema.pick({ endpoints: true });
		const result = schema.safeParse(endpointsWithDeadFields);
		expect(result.success).toBe(true);
		// IH-10: client/authCallback are stripped (not in schema anymore).
		if (result.success) {
			expect((result.data.endpoints as Record<string, unknown>).client).toBeUndefined();
			expect((result.data.endpoints as Record<string, unknown>).authCallback).toBeUndefined();
		}
	});

	it("accepts rateLimit + endpoints without client or authCallback", () => {
		const sessionModuleConfig = {
			rateLimit: {
				login: { windowMs: 60000, limit: 10 },
				failMode: "open" as const,
			},
			endpoints: {
				login: { url: "/login" },
			},
		};
		const sessionConfigSchema = fullSectionsSchema.pick({
			rateLimit: true,
			endpoints: true,
		});
		const result = sessionConfigSchema.safeParse(sessionModuleConfig);
		expect(result.success).toBe(true);
	});
});

describe("AppConfigSchema backward compatibility", () => {
	it("still validates full config with all sections", () => {
		const fullConfig = {
			http: { port: 3000, trustProxy: false, readinessTimeoutMs: 1000 },
			oauth: {
				jwt: {
					signingKey: {
						provider: "local",
						local: { algorithm: "HS256", kid: "v0", secret: "test-secret", previousSecrets: [] },
					},
				},
				accessToken: { expiresIn: 3600 },
				refreshToken: {
					expiresIn: 86400,
					unknownFamilyPolicy: "reject",
					legacyRtPolicy: "reject",
				},
				grants: {
					session: { enabled: true },
					authorization_code: { enabled: true },
					refresh_token: { enabled: true },
				},
				oidcMode: "oidc-required",
			},
			session: {
				secret: "session-secret",
				name: "__Host-auth.session",
				maxAge: 3600000,
				secure: true,
				sameSite: "lax",
				domain: null,
				storage: {
					type: "redis",
					redis: { url: "redis://localhost:6379" },
				},
			},
			rateLimit: {
				login: { windowMs: 60000, limit: 10 },
				failMode: "open",
			},
			federations: {
				google: { enabled: false },
			},
			repositories: {
				client: { type: "yaml", yaml: { path: "./config/clients.yaml" } },
				user: { type: "yaml", yaml: { path: "./config/users.yaml" } },
				code: { type: "memory", memory: { defaultExpiresIn: 600 } },
			},
			endpoints: {
				// IH-17: login.url is now required at the base schema level.
				// IH-10: client / authCallback are removed — stripped if present.
				login: { url: "/login" },
			},
			cors: { allowedOrigins: [] },
		};
		const result = AppConfigSchema.safeParse(fullConfig);
		expect(result.success).toBe(true);
	});

	it("AppConfigSchema is still exported and defined", () => {
		expect(AppConfigSchema).toBeDefined();
	});
});
