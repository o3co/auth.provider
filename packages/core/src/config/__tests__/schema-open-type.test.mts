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

describe("schema open type", () => {
	it("accepts non-builtin session storage type (validated at factory level, not schema)", () => {
		const parsed = fullSectionsSchema.shape.session.parse({
			secret: "s",
			storage: {
				type: "memcached",
				redis: { url: "redis://localhost:6379" },
			},
		});
		expect(parsed.storage.type).toBe("memcached");
	});

	it("preserves custom session storage sub-section (passthrough carries memcached.servers)", () => {
		const parsed = fullSectionsSchema.shape.session.parse({
			secret: "s",
			storage: {
				type: "memcached",
				memcached: { servers: ["mc1.example.com:11211", "mc2.example.com:11211"] },
			},
		});
		expect(parsed.storage.type).toBe("memcached");
		expect(
			(parsed.storage as unknown as { memcached?: { servers?: string[] } }).memcached?.servers,
		).toEqual(["mc1.example.com:11211", "mc2.example.com:11211"]);
	});

	it("allows omitting the redis sub-section when type != 'redis'", () => {
		const parsed = fullSectionsSchema.shape.session.parse({
			secret: "s",
			storage: { type: "memory" },
		});
		expect(parsed.storage.type).toBe("memory");
	});

	it("still accepts the builtin session storage types", () => {
		for (const type of ["redis", "memory"]) {
			const parsed = fullSectionsSchema.shape.session.parse({
				secret: "s",
				storage: {
					type,
					redis: { url: "redis://localhost:6379" },
				},
			});
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
			http: { port: 3000, trustProxy: false },
			oauth: {
				jwt: { signingKey: { provider: "local", local: { algorithm: "HS256", kid: "v0", secret: "s" } } },
				accessToken: { expiresIn: 3600 },
				refreshToken: { expiresIn: 86400 },
				grants: {
					session: { enabled: true },
					authorization: { enabled: true, pkce: { requireS256: false } },
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
				token: { windowMs: 60000, limit: 60 },
				authorize: { windowMs: 60000, limit: 30 },
			},
			federations: {},
			// Legacy key — must fail. The renamed key `repositories` is absent.
			clients: {
				client: { type: "yaml", yaml: { path: "./config/clients.yaml" } },
				user:   { type: "yaml", yaml: { path: "./config/users.yaml" } },
				code:   { type: "memory" },
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
});
