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

import {
	type AppConfig,
	createSymmetricKeyStore,
	GrantRegistry,
	type ModuleContext,
	type UserRepository,
} from "@o3co/auth-provider-core";
import type { Router } from "express";
import { describe, expect, it, vi } from "vitest";
import { _sessionModuleImpl, sessionModule } from "#/module.mjs";

const mockConfig = {
	oauth: {
		jwt: { secret: "test-secret" },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		grants: {},
	},
	rateLimit: {
		login: { windowMs: 60000, limit: 100 },
	},
	cors: {
		allowedOrigins: [],
	},
	session: {
		domain: null,
	},
	federations: {},
	endpoints: {
		login: { url: "/login" },
		client: { url: "http://localhost:3001" },
		authCallback: { url: "/auth/callback" },
	},
} as unknown as AppConfig;

const makeContext = (overrides?: Partial<ModuleContext>): ModuleContext => ({
	pathResolver: (s: string) => s,
	config: mockConfig,
	keyStore: createSymmetricKeyStore("test-secret"),
	grantRegistry: new GrantRegistry(),
	router: {
		use: vi.fn().mockReturnThis(),
	} as unknown as Router,
	...overrides,
});

describe("sessionModule", () => {
	it("has name 'session'", () => {
		const module = sessionModule({
			userRepository: {} as UserRepository,
		});
		expect(module.name).toBe("session");
	});

	it("mounts /session routes on context.router", async () => {
		const routerMock = {
			use: vi.fn().mockReturnThis(),
		} as unknown as Router;
		const ctx = makeContext({ router: routerMock });
		const module = sessionModule({
			userRepository: {
				authenticate: vi.fn(),
				authenticateByToken: vi.fn(),
			} as unknown as UserRepository,
		});

		await module.init(ctx);

		// Should mount session and federation routes under /session
		const calls = (routerMock.use as ReturnType<typeof vi.fn>).mock.calls;
		const sessionCalls = calls.filter((call: unknown[]) => call[0] === "/session");
		expect(sessionCalls.length).toBeGreaterThanOrEqual(1);
	});

	it("skips federations with enabled=false", async () => {
		// Arrange: one federation entry with enabled=false
		const factory = {
			create: vi.fn(),
		};
		const routerMock = { use: vi.fn().mockReturnThis() } as unknown as Router;
		const config = {
			...mockConfig,
			federations: {
				google: { enabled: false, clientId: "id", clientSecret: "secret", callbackURL: "cb" },
			},
		} as unknown as AppConfig;
		const ctx = makeContext({ router: routerMock, config });
		const module = _sessionModuleImpl({
			userRepository: {
				authenticate: vi.fn(),
				authenticateByToken: vi.fn(),
			} as unknown as UserRepository,
			_federationFactory:
				factory as unknown as import("#/federations/factory.mjs").FederationProviderFactory,
		});

		await module.init(ctx);

		// factory.create should NOT have been called for disabled federation
		expect(factory.create).not.toHaveBeenCalled();
	});

	it("normalizes shorthand config (key name as type)", async () => {
		// key 'google' with no explicit type => type defaults to 'google'
		const factory = {
			create: vi.fn().mockResolvedValue({
				name: "google",
				scope: [],
				validateRedirect: vi.fn(),
				resolveCallbackRedirect: vi.fn(),
				setupPassportStrategy: vi.fn().mockResolvedValue(undefined),
			}),
		};
		const routerMock = { use: vi.fn().mockReturnThis() } as unknown as Router;
		const config = {
			...mockConfig,
			federations: {
				google: {
					enabled: true,
					clientId: "id",
					clientSecret: "secret",
					callbackURL: "https://example.com/cb",
				},
			},
		} as unknown as AppConfig;
		const ctx = makeContext({ router: routerMock, config });
		const module = _sessionModuleImpl({
			userRepository: {
				authenticate: vi.fn(),
				authenticateByToken: vi.fn(),
			} as unknown as UserRepository,
			_federationFactory:
				factory as unknown as import("#/federations/factory.mjs").FederationProviderFactory,
		});

		await module.init(ctx);

		// factory.create called with type='google' (shorthand: key name used as type)
		expect(factory.create).toHaveBeenCalledWith(
			expect.objectContaining({ type: "google", name: "google" }),
		);
	});

	it("normalizes explicit config with nested sub-section", async () => {
		// explicit type + nested sub-section (e.g. { type: 'google', google: { clientId: ... } })
		const factory = {
			create: vi.fn().mockResolvedValue({
				name: "google-work",
				scope: [],
				validateRedirect: vi.fn(),
				resolveCallbackRedirect: vi.fn(),
				setupPassportStrategy: vi.fn().mockResolvedValue(undefined),
			}),
		};
		const routerMock = { use: vi.fn().mockReturnThis() } as unknown as Router;
		const config = {
			...mockConfig,
			federations: {
				"google-work": {
					enabled: true,
					type: "google",
					google: { clientId: "id", clientSecret: "secret", callbackURL: "https://example.com/cb" },
				},
			},
		} as unknown as AppConfig;
		const ctx = makeContext({ router: routerMock, config });
		const module = _sessionModuleImpl({
			userRepository: {
				authenticate: vi.fn(),
				authenticateByToken: vi.fn(),
			} as unknown as UserRepository,
			_federationFactory:
				factory as unknown as import("#/federations/factory.mjs").FederationProviderFactory,
		});

		await module.init(ctx);

		// factory.create called with flattened nested fields, name='google-work', type='google'
		expect(factory.create).toHaveBeenCalledWith(
			expect.objectContaining({ type: "google", name: "google-work", clientId: "id" }),
		);
	});

	it("rejects mixed shape (top-level + nested fields) with fail-fast error", async () => {
		const factory = {
			create: vi.fn(),
		};
		const routerMock = { use: vi.fn().mockReturnThis() } as unknown as Router;
		const config = {
			...mockConfig,
			federations: {
				google: {
					enabled: true,
					type: "google",
					// top-level credential fields (flat shape)
					clientId: "id",
					// AND a nested sub-section — mixed shape
					google: { clientSecret: "secret", callbackURL: "https://example.com/cb" },
				},
			},
		} as unknown as AppConfig;
		const ctx = makeContext({ router: routerMock, config });
		const module = _sessionModuleImpl({
			userRepository: {
				authenticate: vi.fn(),
				authenticateByToken: vi.fn(),
			} as unknown as UserRepository,
			_federationFactory:
				factory as unknown as import("#/federations/factory.mjs").FederationProviderFactory,
		});

		await expect(module.init(ctx)).rejects.toThrow(/mixed shape/i);
		expect(factory.create).not.toHaveBeenCalled();
	});

	it("preserves top-level passthrough fields when config is nested", async () => {
		// Arrange: a custom type with both a nested sub-section AND a top-level passthrough field.
		// Example: federations.corp { type="custom", audience="...", custom { issuer="..." } }
		// The 'audience' field lives at the top level of the federation section and must be
		// forwarded to the builder, not dropped when we extract the nested sub-section.
		let receivedConfig: Record<string, unknown> | undefined;
		const factory = {
			create: vi.fn().mockImplementation(async (cfg: Record<string, unknown>) => {
				receivedConfig = cfg;
				return {
					name: cfg.name as string,
					scope: [],
					validateRedirect: vi.fn(),
					resolveCallbackRedirect: vi.fn(),
					setupPassportStrategy: vi.fn().mockResolvedValue(undefined),
				};
			}),
		};
		const routerMock = { use: vi.fn().mockReturnThis() } as unknown as Router;
		const config = {
			...mockConfig,
			federations: {
				corp: {
					enabled: true,
					type: "custom",
					// top-level passthrough field — must survive normalization
					audience: "api://my-corp",
					// nested adapter-specific sub-section
					custom: { issuer: "https://idp.corp.example" },
				},
			},
		} as unknown as AppConfig;
		const ctx = makeContext({ router: routerMock, config });
		const module = _sessionModuleImpl({
			userRepository: {
				authenticate: vi.fn(),
				authenticateByToken: vi.fn(),
			} as unknown as UserRepository,
			_federationFactory:
				factory as unknown as import("#/federations/factory.mjs").FederationProviderFactory,
		});

		await module.init(ctx);

		expect(factory.create).toHaveBeenCalledTimes(1);
		expect(receivedConfig).toMatchObject({
			type: "custom",
			name: "corp",
			audience: "api://my-corp", // top-level passthrough preserved
			issuer: "https://idp.corp.example", // nested sub-section merged
		});
	});

	it("rejects a custom builder that returns a provider with a different name", async () => {
		// Guard: the config-key ↔ passport-strategy-name invariant requires that
		// the provider returned by factory.create has name === the config key.
		// A buggy builder that ignores config.name would silently break route lookups.
		const factory = {
			create: vi.fn().mockResolvedValue({
				name: "WRONG", // builder returned a different name
				scope: [],
				validateRedirect: vi.fn(),
				resolveCallbackRedirect: vi.fn(),
				setupPassportStrategy: vi.fn().mockResolvedValue(undefined),
			}),
		};
		const routerMock = { use: vi.fn().mockReturnThis() } as unknown as Router;
		const config = {
			...mockConfig,
			federations: {
				corp: { enabled: true, clientId: "id", clientSecret: "secret", callbackURL: "cb" },
			},
		} as unknown as AppConfig;
		const ctx = makeContext({ router: routerMock, config });
		const module = _sessionModuleImpl({
			userRepository: {
				authenticate: vi.fn(),
				authenticateByToken: vi.fn(),
			} as unknown as UserRepository,
			_federationFactory:
				factory as unknown as import("#/federations/factory.mjs").FederationProviderFactory,
		});

		await expect(module.init(ctx)).rejects.toThrow(/provider builder returned name/i);
	});

	it("injects name and context fields into builder config", async () => {
		const factory = {
			create: vi.fn().mockResolvedValue({
				name: "google",
				scope: [],
				validateRedirect: vi.fn(),
				resolveCallbackRedirect: vi.fn(),
				setupPassportStrategy: vi.fn().mockResolvedValue(undefined),
			}),
		};
		const routerMock = { use: vi.fn().mockReturnThis() } as unknown as Router;
		const config = {
			...mockConfig,
			session: { domain: ".example.com" },
			endpoints: {
				login: { url: "/login" },
				authCallback: { url: "/auth/callback" },
				client: { url: "http://app.example.com" },
			},
			federations: {
				google: {
					enabled: true,
					clientId: "id",
					clientSecret: "secret",
					callbackURL: "https://example.com/cb",
				},
			},
		} as unknown as AppConfig;
		const ctx = makeContext({ router: routerMock, config });
		const module = _sessionModuleImpl({
			userRepository: {
				authenticate: vi.fn(),
				authenticateByToken: vi.fn(),
			} as unknown as UserRepository,
			_federationFactory:
				factory as unknown as import("#/federations/factory.mjs").FederationProviderFactory,
		});

		await module.init(ctx);

		expect(factory.create).toHaveBeenCalledWith(
			expect.objectContaining({
				name: "google",
				sessionDomain: ".example.com",
				authCallbackUrl: "/auth/callback",
				clientUrl: "http://app.example.com",
			}),
		);
	});
});
