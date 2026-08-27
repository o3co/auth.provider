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
import { makeValidFullSections } from "#/testing/fixtures/valid-config.mjs";

/**
 * Per ADR 2026-04-30: schema is a pure type contract; defaults live in
 * hocon. session.{maxAge,secure,sameSite,domain} are required at the
 * schema boundary, so each test supplies them explicitly.
 */
function validSession(overrides: Record<string, unknown> = {}) {
	return {
		// #282: `session.secret` carries a 256-bit entropy floor.
		secret: "test-session-secret.at-least-32-bytes.ok",
		name: "__Host-auth.session",
		maxAge: 3600000,
		secure: true,
		sameSite: "lax" as const,
		domain: null,
		...overrides,
	};
}

describe("schema open type", () => {
	it("accepts non-builtin session storage type (validated at factory level, not schema)", () => {
		const parsed = fullSectionsSchema.shape.session.parse(
			validSession({
				storage: {
					type: "memcached",
					redis: { url: "redis://localhost:6379" },
				},
			}),
		);
		expect(parsed.storage.type).toBe("memcached");
	});

	it("preserves custom session storage sub-section (passthrough carries memcached.servers)", () => {
		const parsed = fullSectionsSchema.shape.session.parse(
			validSession({
				storage: {
					type: "memcached",
					memcached: { servers: ["mc1.example.com:11211", "mc2.example.com:11211"] },
				},
			}),
		);
		expect(parsed.storage.type).toBe("memcached");
		expect(
			(parsed.storage as unknown as { memcached?: { servers?: string[] } }).memcached?.servers,
		).toEqual(["mc1.example.com:11211", "mc2.example.com:11211"]);
	});

	it("allows omitting the redis sub-section when type != 'redis'", () => {
		const parsed = fullSectionsSchema.shape.session.parse(
			validSession({
				storage: { type: "memory" },
			}),
		);
		expect(parsed.storage.type).toBe("memory");
	});

	it("still accepts the builtin session storage types", () => {
		for (const type of ["redis", "memory"]) {
			const parsed = fullSectionsSchema.shape.session.parse(
				validSession({
					storage: {
						type,
						redis: { url: "redis://localhost:6379" },
					},
				}),
			);
			expect(parsed.storage.type).toBe(type);
		}
	});

	it("accepts non-builtin repositories.client.type", () => {
		const parsed = fullSectionsSchema.shape.repositories.parse({
			client: { type: "postgres", postgres: { dsn: "..." } },
			user: { type: "yaml", yaml: { path: "./config/users.yaml" } },
			code: { type: "memory", memory: {} },
		});
		expect(parsed.client.type).toBe("postgres");
	});

	it("accepts non-builtin repositories.user.type and repositories.code.type", () => {
		const parsed = fullSectionsSchema.shape.repositories.parse({
			client: { type: "yaml", yaml: { path: "./clients.yaml" } },
			user: { type: "ldap", ldap: { url: "ldap://..." } },
			code: { type: "dynamodb", dynamodb: { region: "us-east-1" } },
		});
		expect(parsed.user.type).toBe("ldap");
		expect(parsed.code.type).toBe("dynamodb");
	});

	it("rejects legacy top-level `clients` key once renamed to `repositories`", () => {
		const result = AppConfigSchema.safeParse({
			http: { port: 3000, trustProxy: false, readinessTimeoutMs: 1000 },
			logging: { level: "info" },
			oauth: {
				jwt: {
					signingKey: { provider: "local", local: { algorithm: "HS256", kid: "v0", secret: "s" } },
				},
				accessToken: { expiresIn: 3600 },
				refreshToken: { expiresIn: 86400 },
				grants: {
					session: { enabled: true },
					authorization_code: { enabled: true, pkce: { requireS256: false } },
					refresh_token: { enabled: true },
				},
			},
			session: {
				secret: "x",
				maxAge: 3600000,
				secure: true,
				sameSite: "lax",
				domain: null,
				storage: { type: "memory" },
			},
			rateLimit: {
				login: { windowMs: 900000, limit: 20 },
				failMode: "open",
			},
			federations: {},
			// Legacy key — must fail. The renamed key `repositories` is absent.
			clients: {
				client: { type: "yaml", yaml: { path: "./config/clients.yaml" } },
				user: { type: "yaml", yaml: { path: "./config/users.yaml" } },
				code: { type: "memory" },
			},
			endpoints: { login: { url: "/login" } },
			cors: { allowedOrigins: [] },
		});

		expect(result.success).toBe(false);
		if (!result.success) {
			// The parse error must mention the missing `repositories` path,
			// not silently accept the legacy `clients` key.
			const paths = result.error.issues.map((i) => i.path.join("."));
			expect(paths).toContain("repositories");
		}
	});
});

describe("schema nested repositories", () => {
	it("accepts nested repositories.client.yaml sub-section", () => {
		const parsed = fullSectionsSchema.shape.repositories.parse({
			client: {
				type: "yaml",
				yaml: { path: "./config/clients.yaml" },
			},
			user: {
				type: "yaml",
				yaml: { path: "./config/users.yaml" },
			},
			code: {
				type: "memory",
				memory: { defaultExpiresIn: 600 },
			},
		});
		expect(parsed.client.type).toBe("yaml");
		expect(parsed.user.type).toBe("yaml");
		expect(parsed.code.type).toBe("memory");
	});

	it("accepts nested repositories.user.http sub-section with http-specific fields", () => {
		const parsed = fullSectionsSchema.shape.repositories.parse({
			client: {
				type: "yaml",
				yaml: { path: "./config/clients.yaml" },
			},
			user: {
				type: "http",
				http: {
					authenticateUrl: "https://auth.example.com/verify",
					authenticateByTokenUrl: "https://auth.example.com/token",
					timeout: 5000,
				},
			},
			code: {
				type: "memory",
			},
		});
		expect(parsed.user.type).toBe("http");
	});

	it("accepts nested repositories.code.redis sub-section", () => {
		const parsed = fullSectionsSchema.shape.repositories.parse({
			client: {
				type: "yaml",
				yaml: { path: "./config/clients.yaml" },
			},
			user: {
				type: "yaml",
				yaml: { path: "./config/users.yaml" },
			},
			code: {
				type: "redis",
				redis: {
					endpointUri: "redis://localhost:6379",
					password: "secret",
				},
			},
		});
		expect(parsed.code.type).toBe("redis");
	});

	it("allows coexistence of multiple adapter sub-sections (operators can swap type without losing config)", () => {
		const parsed = fullSectionsSchema.shape.repositories.parse({
			client: {
				type: "yaml",
				yaml: { path: "./config/clients.yaml" },
				postgres: { dsn: "postgres://..." },
			},
			user: {
				type: "yaml",
				yaml: { path: "./config/users.yaml" },
				http: {
					authenticateUrl: "https://auth.example.com/verify",
					authenticateByTokenUrl: "https://auth.example.com/token",
				},
			},
			code: {
				type: "memory",
				memory: { defaultExpiresIn: 600 },
				redis: {
					endpointUri: "redis://localhost:6379",
				},
			},
		});
		expect(parsed.user.type).toBe("yaml");
	});

	// IH-10: dead schema fields `endpoints.client` / `endpoints.authCallback`
	// removed. No production consumer reads them; pre-fix configs that wrote
	// the env-var-only HOCON lines silently leaked them through to AppConfig.
	describe("IH-10: endpoints.client / endpoints.authCallback are removed from schema", () => {
		it("parsed result does not expose client or authCallback keys", () => {
			const result = fullSectionsSchema.parse(makeValidFullSections());
			expect(Object.keys(result.endpoints)).not.toContain("client");
			expect(Object.keys(result.endpoints)).not.toContain("authCallback");
		});

		it("strips endpoints.client and endpoints.authCallback when present in input", () => {
			const base = makeValidFullSections();
			const configWithDeadFields = {
				...base,
				endpoints: {
					...base.endpoints,
					client: { url: "https://example.com/client" },
					authCallback: { url: "https://example.com/callback" },
				},
			};
			const result = fullSectionsSchema.parse(configWithDeadFields);
			expect((result.endpoints as Record<string, unknown>).client).toBeUndefined();
			expect((result.endpoints as Record<string, unknown>).authCallback).toBeUndefined();
		});
	});

	// IH-17: `endpoints.login.url` tightened from `z.string().optional()` to
	// `z.string()`. The runtime invariant was already enforced by the oauth
	// module's `configSchema` at boot time; the base schema now matches that
	// contract so AppConfig type no longer types the field as optional.
	describe("IH-17: endpoints.login.url is required at the base schema level", () => {
		it("rejects config missing endpoints.login.url", () => {
			const base = makeValidFullSections();
			const configWithoutLoginUrl = {
				...base,
				endpoints: { login: {} },
			};
			expect(() => fullSectionsSchema.parse(configWithoutLoginUrl)).toThrow();
		});

		it("accepts config with endpoints.login.url", () => {
			const result = fullSectionsSchema.parse(makeValidFullSections());
			expect(result.endpoints.login.url).toBe("/login");
		});
	});

	// IH-18: `rateLimit.login.windowMs` (express-rate-limit) is intentionally
	// distinct from the OAuth-endpoint `RateLimitSpec.windowSeconds`. Keep
	// the field name as a semantic anchor — renaming requires updating every
	// `express-rate-limit` consumer's unit conversion.
	describe("IH-18: rateLimit.login.windowMs is the canonical field name (express-rate-limit)", () => {
		it("rateLimit.login uses windowMs, not windowSeconds", () => {
			const result = fullSectionsSchema.shape.rateLimit.parse({
				login: { windowMs: 900000, limit: 20 },
				failMode: "open",
			});
			expect(result.login.windowMs).toBe(900000);
			expect(result.login.limit).toBe(20);
			// Negative: windowSeconds is not accepted (semantic anchor against rename)
			expect(() =>
				fullSectionsSchema.shape.rateLimit.parse({
					login: { windowSeconds: 900, limit: 20 },
					failMode: "open",
				}),
			).toThrow();
		});
	});
});
