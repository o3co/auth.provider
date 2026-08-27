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
	type AuditSink,
	type ClientRepository,
	type CodeRepository,
	createAsymmetricKeyStore,
	createSymmetricKeyStore,
	defineModule,
	type FederationProviderHandle,
	type FederationTokenStore,
	jwksModule,
	memoryAccessTokenDenylistModule,
	type RateLimiter,
	type RefreshTokenFamilyRevocation,
	type SessionFamilyIndex,
	type SessionFederationIndex,
	type SessionRPRegistry,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { createTestApp, makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import express from "express";
import { exportPKCS8, exportSPKI, generateKeyPair, SignJWT } from "jose";
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
	// D-1: Code requires client_id + redirect_uri.
	createCode: async () => ({
		code: "fake-code",
		client_id: "client1",
		redirect_uri: "https://rp.example/cb",
	}),
	findByCode: async () => null,
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

// #282: the JWKS route refuses to publish an empty key set, so the
// discovery/JWKS path-agreement tests below need a keystore that actually has
// public key material. EdDSA is the shipped default.
const eddsaPair = await generateKeyPair("EdDSA", { extractable: true });
const eddsaKeyStore = await createAsymmetricKeyStore({
	algorithm: "EdDSA",
	kid: "oauth-module-test",
	privateKeyPem: await exportPKCS8(eddsaPair.privateKey),
	publicKeyPem: await exportSPKI(eddsaPair.publicKey),
});

const asymmetricKeyStoreModule = defineModule({
	name: "test:key-store-asymmetric",
	provides: {
		keyStore: () => eddsaKeyStore,
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

	it("declares a configSchema for boot-time config validation", () => {
		const config = makeValidAppConfig();
		const module = oauthModule({ config });
		expect(module.configSchema).toBeDefined();
	});

	it("configSchema rejects a config missing endpoints.login.url", () => {
		const config = makeValidAppConfig();
		const module = oauthModule({ config });
		const schema = module.configSchema;
		if (!schema) throw new Error("configSchema must be defined");
		// The base schema marks endpoints.login.url optional, but oauthConfigSchema
		// must tighten it to z.string().min(1) so boot fails before /authorize is hit.
		const result = schema.safeParse({ endpoints: { login: {} } });
		expect(result.success).toBe(false);
	});

	it("configSchema rejects an empty endpoints.login.url", () => {
		const config = makeValidAppConfig();
		const module = oauthModule({ config });
		const schema = module.configSchema;
		if (!schema) throw new Error("configSchema must be defined");
		const result = schema.safeParse({ endpoints: { login: { url: "" } } });
		expect(result.success).toBe(false);
	});

	it("configSchema accepts a non-empty endpoints.login.url", () => {
		const config = makeValidAppConfig();
		const module = oauthModule({ config });
		const schema = module.configSchema;
		if (!schema) throw new Error("configSchema must be defined");
		const result = schema.safeParse({ endpoints: { login: { url: "/login" } } });
		expect(result.success).toBe(true);
	});

	it("includes only oauth-endpoints when issuer is absent (JWKS moved to core jwksModule)", () => {
		const base = makeValidAppConfig();
		// No issuer set — only oauth-endpoints is contributed. oidc-discovery is
		// issuer-gated; JWKS is no longer an oauth contribution (core jwksModule
		// owns it now).
		const module = oauthModule({ config: base });
		const routes = module.contributes?.routes;
		expect(Array.isArray(routes)).toBe(true);
		expect((routes as unknown[]).length).toBe(1);
	});

	it("contributes a single oauth-endpoints route regardless of issuer (discovery is core-aggregated)", () => {
		// Discovery is no longer an oauth ROUTE; oauth contributes a
		// `discoveryMetadata` slice instead, which core's assembleApp aggregates
		// into `/.well-known/openid-configuration`. So oauth always contributes
		// exactly one route (oauth-endpoints), issuer or not.
		const base = makeValidAppConfig();
		const config = {
			...base,
			oauth: { ...base.oauth, jwt: { ...base.oauth.jwt, issuer: "https://auth.example.com" } },
		};
		const module = oauthModule({ config });
		const routes = module.contributes?.routes;
		expect(Array.isArray(routes)).toBe(true);
		expect((routes as unknown[]).length).toBe(1);
	});

	it("contributes a single discoveryMetadata factory (issuer-independent; core gates emission)", () => {
		const config = makeValidAppConfig();
		const module = oauthModule({ config });
		const discoveryMetadata = module.contributes?.discoveryMetadata;
		expect(Array.isArray(discoveryMetadata)).toBe(true);
		expect((discoveryMetadata as unknown[]).length).toBe(1);
	});
});

// ---------------------------------------------------------------------------
// createTestApp integration tests (§7.3 — boot + inspect)
// ---------------------------------------------------------------------------

describe("oauthModule — createTestApp boot failure", () => {
	it("fails boot with config-validation-failed when endpoints.login.url is missing", async () => {
		const { BootError } = await import("@o3co/auth-provider-core");
		const base = makeValidAppConfig();
		const config = {
			...base,
			endpoints: {
				...base.endpoints,
				login: {}, // tighten path: drop the url that valid-config now provides
			},
		};
		await expect(
			createTestApp({
				modules: [
					oauthModule({ config }),
					// #277: oauthModule mounts /oauth/revoke, so the boot validator requires a
					// denylist behind it. Memory is right here — one process, one test.
					memoryAccessTokenDenylistModule,
					clientRepositoryModule,
					codeRepositoryModule,
					keyStoreModule,
				],
				bootstrapComponents: { config, pathResolver: (s) => s },
			}),
		).rejects.toMatchObject({
			name: "BootError",
			reason: "config-validation-failed",
		} satisfies Partial<InstanceType<typeof BootError>>);
	});
});

describe("oauthModule — createTestApp route inspection", () => {
	it("contributes no oidc-discovery route even with an issuer; core mounts discovery from aggregated metadata", async () => {
		// Discovery is now mounted by core's assembleApp from the aggregated
		// `discoveryMetadata` collector — it is NOT an oauth route contribution,
		// so it never appears in the inspected route ids. jwksModule is co-installed
		// so the issuer-enabled composition forms a valid discovery document
		// (jwks owns `jwks_uri`); without it boot fails the presence contract.
		const base = makeValidAppConfig();
		const config = {
			...base,
			oauth: { ...base.oauth, jwt: { ...base.oauth.jwt, issuer: "https://auth.example.com" } },
		};
		const handle = await createTestApp({
			modules: [
				oauthModule({ config }),
				// #277: oauthModule mounts /oauth/revoke, so the boot validator requires a
				// denylist behind it. Memory is right here — one process, one test.
				memoryAccessTokenDenylistModule,
				jwksModule,
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

	it("oauth-endpoints is mounted at /oauth", async () => {
		const config = makeValidAppConfig();
		// jwksModule is co-installed because every config now carries an issuer
		// (#266), so the provider-root contribution always activates discovery —
		// which requires a module owning `jwks_uri` to form a valid document.
		const handle = await createTestApp({
			modules: [
				oauthModule({ config }),
				// #277: oauthModule mounts /oauth/revoke, so the boot validator requires a
				// denylist behind it. Memory is right here — one process, one test.
				memoryAccessTokenDenylistModule,
				jwksModule,
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

	it("core serves the spec-fixed /.well-known/openid-configuration when oauth + jwks + issuer compose", async () => {
		// End-to-end: oauth contributes its endpoints + metadata, jwks contributes
		// `jwks_uri`, core aggregates and mounts the document at the spec-fixed
		// path (no path-doubling). Probes the actual path.
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
				// #277: oauthModule mounts /oauth/revoke, so the boot validator requires a
				// denylist behind it. Memory is right here — one process, one test.
				memoryAccessTokenDenylistModule,
				jwksModule,
				clientRepositoryModule,
				codeRepositoryModule,
				keyStoreModule,
			],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		const app = express();
		app.use(handle.router);
		const res = await request(app).get("/.well-known/openid-configuration");
		expect(res.status).toBe(200);
		expect(res.body.issuer).toBe("https://auth.example.com");
		await handle.dispose();
	});
});

// ---------------------------------------------------------------------------
// Discovery <-> JWKS path agreement (presence + config-drift contract).
//
// JWKS is now contributed by the core `jwksModule`, while oidc-discovery
// (which advertises `jwks_uri`) is contributed by oauth. They live in
// different modules, so an issuer-enabled composition MUST co-install both
// or discovery publishes a dangling `jwks_uri`. These tests pin that
// cross-module contract end-to-end: the advertised `jwks_uri` must resolve
// to a mounted JWKS route, including under an `oauth.jwt.jwksPath` override
// (both endpoints resolve the path via the shared `resolveJwksPath`, so
// they cannot drift).
// ---------------------------------------------------------------------------

describe("oauthModule + jwksModule — discovery/JWKS path agreement", () => {
	function issuerConfig(extraJwt: Record<string, unknown> = {}) {
		const base = makeValidAppConfig();
		return {
			...base,
			oauth: {
				...base.oauth,
				jwt: { ...base.oauth.jwt, issuer: "https://auth.example.com", ...extraJwt },
			},
		} as ReturnType<typeof makeValidAppConfig>;
	}

	it("advertised jwks_uri resolves to a mounted JWKS route (default path)", async () => {
		const config = issuerConfig();
		const handle = await createTestApp({
			modules: [
				oauthModule({ config }),
				// #277: oauthModule mounts /oauth/revoke, so the boot validator requires a
				// denylist behind it. Memory is right here — one process, one test.
				memoryAccessTokenDenylistModule,
				jwksModule,
				clientRepositoryModule,
				codeRepositoryModule,
				// Asymmetric: since #282 the JWKS route refuses to publish an
				// empty key set, so "resolves to a mounted route" is only
				// observable with a keystore that has public material.
				asymmetricKeyStoreModule,
			],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		const app = express();
		app.use(handle.router);
		const disco = await request(app).get("/.well-known/openid-configuration");
		expect(disco.status).toBe(200);
		const jwksPath = new URL(disco.body.jwks_uri as string).pathname;
		expect(jwksPath).toBe("/.well-known/jwks.json");
		const res = await request(app).get(jwksPath);
		expect(res.status).toBe(200);
		expect(Array.isArray(res.body.keys)).toBe(true);
		expect(res.body.keys).toHaveLength(1);
		await handle.dispose();
	});

	it("aggregated discovery document matches the pre-refactor golden field set (no-logout composition)", async () => {
		// Equivalence guard for the oauth-owned → aggregator migration: with oauth
		// + jwks + issuer (and no session stores → logout omitted), the assembled
		// `/.well-known/openid-configuration` must carry exactly the fields the
		// legacy oauth-owned `OpenidConfiguration.createRouter` produced.
		const config = issuerConfig();
		const handle = await createTestApp({
			modules: [
				oauthModule({ config }),
				// #277: oauthModule mounts /oauth/revoke, so the boot validator requires a
				// denylist behind it. Memory is right here — one process, one test.
				memoryAccessTokenDenylistModule,
				jwksModule,
				clientRepositoryModule,
				codeRepositoryModule,
				keyStoreModule,
			],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		const app = express();
		app.use(handle.router);
		const { body } = await request(app).get("/.well-known/openid-configuration");
		const iss = "https://auth.example.com";
		expect(body).toEqual({
			issuer: iss,
			authorization_endpoint: `${iss}/oauth/authorize`,
			token_endpoint: `${iss}/oauth/token`,
			userinfo_endpoint: `${iss}/oauth/userinfo`,
			jwks_uri: `${iss}/.well-known/jwks.json`,
			introspection_endpoint: `${iss}/oauth/introspect`,
			response_types_supported: ["code"],
			subject_types_supported: ["public"],
			// keyStoreModule signs HS256, so the aggregator advertises exactly that.
			id_token_signing_alg_values_supported: ["HS256"],
			scopes_supported: ["openid", "profile", "email", "groups"],
			token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
			code_challenge_methods_supported: ["S256"],
		});
		await handle.dispose();
	});

	it("honors oauth.jwt.jwksPath for BOTH the advertised jwks_uri and the mounted route", async () => {
		const config = issuerConfig({ jwksPath: "/keys/jwks.json" });
		const handle = await createTestApp({
			modules: [
				oauthModule({ config }),
				// #277: oauthModule mounts /oauth/revoke, so the boot validator requires a
				// denylist behind it. Memory is right here — one process, one test.
				memoryAccessTokenDenylistModule,
				jwksModule,
				clientRepositoryModule,
				codeRepositoryModule,
				asymmetricKeyStoreModule,
			],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		const app = express();
		app.use(handle.router);
		const disco = await request(app).get("/.well-known/openid-configuration");
		expect(disco.body.jwks_uri).toBe("https://auth.example.com/keys/jwks.json");
		const jwksPath = new URL(disco.body.jwks_uri as string).pathname;
		expect((await request(app).get(jwksPath)).status).toBe(200);
		// The old default path is no longer served under the override.
		expect((await request(app).get("/.well-known/jwks.json")).status).toBe(404);
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

		const rateLimiter: RateLimiter = {
			kind: "spy",
			check: vi.fn().mockResolvedValue({ allowed: false, reason: "limit:token" }),
		};
		const events: AuditEvent[] = [];
		const auditSink: AuditSink = {
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
				// #277: oauthModule mounts /oauth/revoke, so the boot validator requires a
				// denylist behind it. Memory is right here — one process, one test.
				memoryAccessTokenDenylistModule,
				jwksModule,
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
			.setIssuer("https://auth.example.com")
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
		const fedTokenStore: FederationTokenStore = {
			kind: "memory",
			attach: vi.fn(),
			get: vi.fn().mockResolvedValue({ idToken: "id-token-hint" }),
			update: vi.fn(),
			removeBySid: vi.fn().mockResolvedValue(undefined),
			delete: vi.fn().mockResolvedValue(undefined),
		};
		const refreshTokenFamilyRevocation: RefreshTokenFamilyRevocation = {
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
		const refreshTokenFamilyRevocationModule = defineModule({
			name: "test:refresh-token-family-revocation",
			provides: { refreshTokenFamilyRevocation: () => refreshTokenFamilyRevocation },
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
				// #277: oauthModule mounts /oauth/revoke, so the boot validator requires a
				// denylist behind it. Memory is right here — one process, one test.
				memoryAccessTokenDenylistModule,
				// Issuer is configured, so the discovery presence contract requires
				// the JWKS-owning module to be co-installed (it contributes jwks_uri).
				jwksModule,
				clientRepositoryModule,
				codeRepositoryModule,
				keyStoreWithSecret,
				userSessionStoreModule,
				sessionRPRegistryModule,
				sessionFamilyIndexModule,
				sessionFederationIndexModule,
				federationTokenStoreModule,
				refreshTokenFamilyRevocationModule,
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

	it("federation-token endpoint is mounted from the store wiring alone (returns 401, not 404)", async () => {
		// federationTokenSupported in routes.mts gates on the 4-store split +
		// federationTokenStore + refreshTokenFamilyRevocation, and on nothing
		// else — the endpoint forwards upstream and never mints our own `iss`.
		// It used to be worth asserting that an absent issuer did not break the
		// gate; since #266 an issuer is always configured, so what this pins is
		// that the gate is the store wiring.
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
		const fedTokenStore: FederationTokenStore = {
			kind: "memory",
			attach: vi.fn(),
			get: vi.fn(),
			update: vi.fn(),
			removeBySid: vi.fn(),
			delete: vi.fn(),
		};
		const refreshTokenFamilyRevocation: RefreshTokenFamilyRevocation = {
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
		const refreshTokenFamilyRevocationModule = defineModule({
			name: "test:refresh-token-family-revocation-noissuer",
			provides: { refreshTokenFamilyRevocation: () => refreshTokenFamilyRevocation },
		});

		const config = makeValidAppConfig();

		const handle = await createTestApp({
			modules: [
				oauthModule({ config }),
				// #277: oauthModule mounts /oauth/revoke, so the boot validator requires a
				// denylist behind it. Memory is right here — one process, one test.
				memoryAccessTokenDenylistModule,
				jwksModule,
				clientRepositoryModule,
				codeRepositoryModule,
				keyStoreModule,
				userSessionStoreModule,
				sessionRPRegistryModule,
				sessionFamilyIndexModule,
				sessionFederationIndexModule,
				federationTokenStoreModule,
				refreshTokenFamilyRevocationModule,
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
