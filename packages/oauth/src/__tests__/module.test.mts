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

import { createSecretKey } from "node:crypto";
import {
	type AuditEvent,
	type AuditSinkBase,
	type ClientRepository,
	type CodeRepository,
	createSymmetricKeyStore,
	defineModule,
	type FederationProviderHandle,
	type FederationTokenStoreBase,
	type RateLimiterBase,
	type RefreshTokenStoreBase,
	type SessionFamilyIndex,
	type SessionFederationIndex,
	type SessionRPRegistry,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { createTestApp, makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import express from "express";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { oauthModule } from "#/module.mjs";

// ---------------------------------------------------------------------------
// Shared test-only stubs
// ---------------------------------------------------------------------------

const fakeClientRepository: ClientRepository = {
	findById: async () => null,
	authenticate: async () => null,
};

const fakeCodeRepository: CodeRepository = {
	createCode: async () => ({ code: "fake-code" }),
	getByCode: async () => null,
	consumeByCode: async () => null,
	removeByCode: async () => {},
};

/** Inline module that satisfies `requires: ["clientRepository"]`. */
const clientRepositoryModule = defineModule({
	name: "test:client-repository",
	provides: {
		clientRepository: () => fakeClientRepository,
	},
});

/** Inline module that satisfies `requires: ["codeRepository"]`. */
const codeRepositoryModule = defineModule({
	name: "test:code-repository",
	provides: {
		codeRepository: () => fakeCodeRepository,
	},
});

/** Inline module that satisfies `requires: ["keyStore"]`. */
const keyStoreModule = defineModule({
	name: "test:key-store",
	provides: {
		keyStore: () => createSymmetricKeyStore("test-secret-for-oauth-module!!!!!"),
	},
});

// Note: grantHandlerResolver is a SYNTHETIC key — the boot planner injects it
// automatically from collected grants. Do NOT provide it from a module.

// ---------------------------------------------------------------------------
// Module manifest structural tests (§7.1 — static, no createTestApp needed)
// ---------------------------------------------------------------------------

describe("oauthModule — manifest shape", () => {
	it("has name 'oauth'", () => {
		const config = makeValidAppConfig();
		const module = oauthModule({ config });
		expect(module.name).toBe("oauth");
	});

	it("includes oauth-endpoints route contribution when issuer is absent", () => {
		const base = makeValidAppConfig();
		// No issuer set — only oauth-endpoints factory should appear
		const module = oauthModule({ config: base });
		const routes = module.contributes?.routes;
		expect(Array.isArray(routes)).toBe(true);
		// At minimum the oauth-endpoints factory is always present
		expect((routes as unknown[]).length).toBeGreaterThanOrEqual(1);
	});

	it("includes both route contributions when issuer is configured", () => {
		const base = makeValidAppConfig();
		const config = {
			...base,
			oauth: {
				...base.oauth,
				jwt: {
					...base.oauth.jwt,
					issuer: "https://auth.example.com",
				},
			},
		};
		const module = oauthModule({ config });
		const routes = module.contributes?.routes;
		expect(Array.isArray(routes)).toBe(true);
		// oauth-endpoints + oidc-discovery
		expect((routes as unknown[]).length).toBe(2);
	});
});

// ---------------------------------------------------------------------------
// createTestApp integration tests (§7.3 — boot + inspect)
// ---------------------------------------------------------------------------

describe("oauthModule — createTestApp route inspection", () => {
	it("registers only oauth-endpoints route when issuer is absent", async () => {
		const config = makeValidAppConfig();
		// makeValidAppConfig does not set oauth.jwt.issuer
		const handle = await createTestApp({
			modules: [
				oauthModule({ config }),
				clientRepositoryModule,
				codeRepositoryModule,
				keyStoreModule,
			],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		const routeIds = handle.inspect.routes.map((r) => r.contribution.id);
		expect(routeIds).toContain("oauth-endpoints");
		expect(routeIds).not.toContain("oidc-discovery");
		await handle.dispose();
	});

	it("registers both oauth-endpoints and oidc-discovery routes when issuer is set", async () => {
		const base = makeValidAppConfig();
		const config = {
			...base,
			oauth: {
				...base.oauth,
				jwt: {
					...base.oauth.jwt,
					issuer: "https://auth.example.com",
				},
			},
		};
		const handle = await createTestApp({
			modules: [
				oauthModule({ config }),
				clientRepositoryModule,
				codeRepositoryModule,
				keyStoreModule,
			],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		const routeIds = handle.inspect.routes.map((r) => r.contribution.id);
		expect(routeIds).toContain("oauth-endpoints");
		expect(routeIds).toContain("oidc-discovery");
		await handle.dispose();
	});

	it("oauth-endpoints is mounted at /oauth", async () => {
		const config = makeValidAppConfig();
		const handle = await createTestApp({
			modules: [
				oauthModule({ config }),
				clientRepositoryModule,
				codeRepositoryModule,
				keyStoreModule,
			],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		const oauthRoute = handle.inspect.routes.find((r) => r.contribution.id === "oauth-endpoints");
		expect(oauthRoute?.contribution.mountPath).toBe("/oauth");
		await handle.dispose();
	});

	it("oidc-discovery is mounted at /.well-known/openid-configuration", async () => {
		const base = makeValidAppConfig();
		const config = {
			...base,
			oauth: {
				...base.oauth,
				jwt: { ...base.oauth.jwt, issuer: "https://auth.example.com" },
			},
		};
		const handle = await createTestApp({
			modules: [
				oauthModule({ config }),
				clientRepositoryModule,
				codeRepositoryModule,
				keyStoreModule,
			],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		const discoveryRoute = handle.inspect.routes.find(
			(r) => r.contribution.id === "oidc-discovery",
		);
		expect(discoveryRoute?.contribution.mountPath).toBe("/.well-known/openid-configuration");
		await handle.dispose();
	});
});

// ---------------------------------------------------------------------------
// Behavioral: grant dispatch via router
// The HTTP probe builds a full express app to verify createOAuthRouter wires
// correctly through the deps injected by the boot planner.
// ---------------------------------------------------------------------------

describe("oauthModule — behavioral: rateLimiter + auditSink forwarding", () => {
	it("forwards rateLimiter and auditSink into oauth routes (rate limit returns 429)", async () => {
		const SECRET = "test-secret-at-least-32-chars!!";

		const rateLimiter: RateLimiterBase = {
			kind: "spy",
			check: vi.fn().mockResolvedValue({ allowed: false, reason: "limit:token" }),
		};
		const events: AuditEvent[] = [];
		const auditSink: AuditSinkBase = {
			kind: "spy",
			async record(event) {
				events.push(event);
			},
		};

		const rateLimiterModule = defineModule({
			name: "test:rate-limiter",
			provides: { rateLimiter: () => rateLimiter },
		});
		const auditSinkModule = defineModule({
			name: "test:audit-sink",
			provides: { auditSink: () => auditSink },
		});
		const keyStoreWithSecret = defineModule({
			name: "test:key-store-secret",
			provides: { keyStore: () => createSymmetricKeyStore(SECRET) },
		});

		const base = makeValidAppConfig();
		const config = { ...base };

		const handle = await createTestApp({
			modules: [
				oauthModule({ config }),
				clientRepositoryModule,
				codeRepositoryModule,
				keyStoreWithSecret,
				rateLimiterModule,
				auditSinkModule,
			],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});

		// Mount the routes onto an express app for HTTP probing
		const app = express();
		app.set("trust proxy", 1);
		app.use(express.json());
		app.use(express.urlencoded({ extended: false }));
		for (const route of handle.inspect.routes) {
			app.use(route.contribution.mountPath, route.contribution.handler);
		}

		const res = await request(app).post("/oauth/token").send({ grant_type: "password" });

		// rateLimiter was forwarded and invoked by the route
		expect(rateLimiter.check).toHaveBeenCalled();
		expect(res.status).toBe(429);

		await handle.dispose();
	});
});

// ---------------------------------------------------------------------------
// Behavioral: federation logout — deps.federationProviders typed slot
//
// Proves that oauthModule reads federationProviders from typed deps (Theme E
// structural fix — no lazy () => ctx.federationProviders closure). Federation
// providers are supplied at boot time via the DI graph.
// ---------------------------------------------------------------------------

describe("oauthModule — federation logout via typed deps", () => {
	it("federation logout works when federationProviders is supplied via module", async () => {
		const SECRET = "test-secret-at-least-32-chars!!";
		const secretKey = createSecretKey(Buffer.from(SECRET));

		const accessToken = await new SignJWT({ sub: "u-1", sid: "sid-1", family_id: "fam-1" })
			.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "at+jwt" })
			.setExpirationTime("1h")
			.setIssuedAt()
			.sign(secretKey);

		const session: UserSession = {
			sid: "sid-1",
			sub: "u-1",
			authTime: new Date(),
			createdAt: new Date(),
			expiresAt: new Date(Date.now() + 3_600_000),
			claims: {},
		};

		const sessionStore: UserSessionStore = {
			kind: "memory",
			create: vi.fn(),
			get: vi.fn().mockResolvedValue(session),
			delete: vi.fn(),
		};
		const sessionRPRegistry: SessionRPRegistry = {
			kind: "memory",
			registerRP: vi.fn(async () => {}),
			listRPs: vi.fn(async () => []),
			removeBySid: vi.fn(async () => {}),
		};
		const sessionFamilyIndex: SessionFamilyIndex = {
			kind: "memory",
			addFamilyId: vi.fn(async () => {}),
			listFamilyIds: vi.fn(async () => []),
			removeBySid: vi.fn(async () => {}),
		};
		const sessionFederationIndex: SessionFederationIndex = {
			kind: "memory",
			addFederation: vi.fn(async () => {}),
			listFederations: vi.fn(async () => ["google"]),
			removeFederation: vi.fn(async () => {}),
			removeBySid: vi.fn(async () => {}),
		};
		const fedTokenStore: FederationTokenStoreBase = {
			kind: "memory",
			attach: vi.fn(),
			get: vi.fn().mockResolvedValue({ idToken: "id-token-hint" }),
			update: vi.fn(),
			deleteBySession: vi.fn().mockResolvedValue(undefined),
			delete: vi.fn().mockResolvedValue(undefined),
		};
		const refreshTokenStore: RefreshTokenStoreBase = {
			kind: "memory",
			rotate: vi.fn(),
			isFamilyRevoked: vi.fn(async () => false),
			revokeFamily: vi.fn(),
		};

		const endSessionUrl = new URL("https://accounts.google.com/logout?hint=id-token-hint");
		const googleProvider: FederationProviderHandle & {
			endSession: (req: unknown) => Promise<{ url: URL; method: "GET" }>;
		} = {
			name: "google",
			endSession: vi.fn().mockResolvedValue({ url: endSessionUrl, method: "GET" }),
		};

		// Modules providing the optional stores
		const userSessionStoreModule = defineModule({
			name: "test:user-session-store",
			provides: { userSessionStore: () => sessionStore },
		});
		const sessionRPRegistryModule = defineModule({
			name: "test:session-rp-registry",
			provides: { sessionRPRegistry: () => sessionRPRegistry },
		});
		const sessionFamilyIndexModule = defineModule({
			name: "test:session-family-index",
			provides: { sessionFamilyIndex: () => sessionFamilyIndex },
		});
		const sessionFederationIndexModule = defineModule({
			name: "test:session-federation-index",
			provides: { sessionFederationIndex: () => sessionFederationIndex },
		});
		const federationTokenStoreModule = defineModule({
			name: "test:federation-token-store",
			provides: { federationTokenStore: () => fedTokenStore },
		});
		const refreshTokenStoreModule = defineModule({
			name: "test:refresh-token-store",
			provides: { refreshTokenStore: () => refreshTokenStore },
		});
		// federationProviders is SYNTHETIC — built from the "federations" collector.
		// Contribute the google provider via a federation module; the boot planner
		// then injects it as deps.federationProviders in the route factory.
		// Theme E structural fix: no lazy () => ctx.federationProviders closure.
		//
		// Note: every federations[name] contribution requires a paired
		// federationRedirectPolicies[name] contribution (boot invariant §7.5).
		// Both FederationProvider and FederationRedirectPolicy are `unknown`
		// placeholders in contributes-map (Phase 9); `as never` at the contributes
		// boundary is the plan-sanctioned escape hatch for stub module fixtures.
		const federationModule = defineModule({
			name: "test:google-federation",
			contributes: {
				federations: { google: () => googleProvider },
				federationRedirectPolicies: {
					google: () => ({
						validateRedirect: () => ({ ok: true as const, value: undefined }),
						resolveCallbackRedirect: () => ({ ok: true as const, value: "/" }),
					}),
				},
			} as never,
		});
		const keyStoreWithSecret = defineModule({
			name: "test:key-store-logout",
			provides: { keyStore: () => createSymmetricKeyStore(SECRET) },
		});

		const base = makeValidAppConfig();
		const config = {
			...base,
			oauth: {
				...base.oauth,
				jwt: { ...base.oauth.jwt, issuer: "https://auth.example.com" },
			},
		};

		const handle = await createTestApp({
			modules: [
				oauthModule({ config }),
				clientRepositoryModule,
				codeRepositoryModule,
				keyStoreWithSecret,
				userSessionStoreModule,
				sessionRPRegistryModule,
				sessionFamilyIndexModule,
				sessionFederationIndexModule,
				federationTokenStoreModule,
				refreshTokenStoreModule,
				federationModule,
			],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});

		const app = express();
		app.use(express.json());
		app.use(express.urlencoded({ extended: false }));
		for (const route of handle.inspect.routes) {
			app.use(route.contribution.mountPath, route.contribution.handler);
		}

		const res = await request(app)
			.post("/oauth/federation/google/logout")
			.type("form")
			.set("Authorization", `Bearer ${accessToken}`)
			.send({});

		// The typed deps resolved the provider → endSession redirect
		expect(res.status).toBe(303);
		expect(res.headers.location).toContain("accounts.google.com");
		expect(googleProvider.endSession).toHaveBeenCalledOnce();

		await handle.dispose();
	});

	it("federation-token endpoint is mounted even when issuer is absent (returns 401, not 404)", async () => {
		// federationTokenSupported in routes.mts (lines 627-633) gates on the
		// 4-store split + federationTokenStore + refreshTokenStore. Issuer
		// absence must NOT break this gate — that is what the test asserts.
		const sessionStore: UserSessionStore = {
			kind: "memory",
			create: vi.fn(),
			get: vi.fn(),
			delete: vi.fn(),
		};
		const sessionRPRegistry: SessionRPRegistry = {
			kind: "memory",
			registerRP: vi.fn(async () => {}),
			listRPs: vi.fn(async () => []),
			removeBySid: vi.fn(async () => {}),
		};
		const sessionFamilyIndex: SessionFamilyIndex = {
			kind: "memory",
			addFamilyId: vi.fn(async () => {}),
			listFamilyIds: vi.fn(async () => []),
			removeBySid: vi.fn(async () => {}),
		};
		const sessionFederationIndex: SessionFederationIndex = {
			kind: "memory",
			addFederation: vi.fn(async () => {}),
			listFederations: vi.fn(async () => []),
			removeFederation: vi.fn(async () => {}),
			removeBySid: vi.fn(async () => {}),
		};
		const fedTokenStore: FederationTokenStoreBase = {
			kind: "memory",
			attach: vi.fn(),
			get: vi.fn(),
			update: vi.fn(),
			deleteBySession: vi.fn(),
			delete: vi.fn(),
		};
		const refreshTokenStore: RefreshTokenStoreBase = {
			kind: "memory",
			rotate: vi.fn(),
			isFamilyRevoked: vi.fn(async () => false),
			revokeFamily: vi.fn(),
		};

		const userSessionStoreModule = defineModule({
			name: "test:user-session-store-noissuer",
			provides: { userSessionStore: () => sessionStore },
		});
		const sessionRPRegistryModule = defineModule({
			name: "test:session-rp-registry-noissuer",
			provides: { sessionRPRegistry: () => sessionRPRegistry },
		});
		const sessionFamilyIndexModule = defineModule({
			name: "test:session-family-index-noissuer",
			provides: { sessionFamilyIndex: () => sessionFamilyIndex },
		});
		const sessionFederationIndexModule = defineModule({
			name: "test:session-federation-index-noissuer",
			provides: { sessionFederationIndex: () => sessionFederationIndex },
		});
		const federationTokenStoreModule = defineModule({
			name: "test:federation-token-store-noissuer",
			provides: { federationTokenStore: () => fedTokenStore },
		});
		const refreshTokenStoreModule = defineModule({
			name: "test:refresh-token-store-noissuer",
			provides: { refreshTokenStore: () => refreshTokenStore },
		});

		const config = makeValidAppConfig();
		// No issuer — oidc-discovery not mounted, but /oauth/federation/* must be mounted

		const handle = await createTestApp({
			modules: [
				oauthModule({ config }),
				clientRepositoryModule,
				codeRepositoryModule,
				keyStoreModule,
				userSessionStoreModule,
				sessionRPRegistryModule,
				sessionFamilyIndexModule,
				sessionFederationIndexModule,
				federationTokenStoreModule,
				refreshTokenStoreModule,
			],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});

		const app = express();
		app.use(express.json());
		app.use(express.urlencoded({ extended: false }));
		for (const route of handle.inspect.routes) {
			app.use(route.contribution.mountPath, route.contribution.handler);
		}

		// No Authorization header → should get 401 (route is mounted) not 404 (route missing)
		const res = await request(app).post("/oauth/federation/google/token").send({});
		expect(res.status).toBe(401);

		await handle.dispose();
	});
});
