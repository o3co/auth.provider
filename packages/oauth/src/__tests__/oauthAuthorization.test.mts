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
	type ClientRepository,
	type CodeRepository,
	createSymmetricKeyStore,
	defineModule,
	type GrantDependencies,
	type GrantPolicyHook,
	type Logger,
	type RefreshTokenFamilyRotation,
	type SessionFamilyIndex,
	type SessionRPRegistry,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { createTestApp, GrantRegistry, makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createAuthorizationGrant } from "#/grants/authorization.mjs";
import { createRefreshTokenGrant } from "#/grants/refreshToken.mjs";
import { oauthAuthorizationModule } from "#/oauthAuthorization.mjs";
import { createOAuthRouter } from "#/routes.mjs";
import { createMockLogger } from "./_helpers/mockLogger.mjs";

// ---------------------------------------------------------------------------
// Shared test-only stubs
// ---------------------------------------------------------------------------

// #273: PKCE/S256 is mandatory at /authorize for every client, so every
// request meant to get past the PKCE gate carries a valid S256 pair. The
// value is the RFC 7636 §4.4 appendix-B example challenge.
const AUTHORIZE_CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const AUTHORIZE_S256_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

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
		keyStore: () => createSymmetricKeyStore("test-secret-for-auth-grant!!!!!"),
	},
});

// ---------------------------------------------------------------------------
// Helper: build a minimal express app wired to createOAuthRouter.
// The session middleware injects the provided session fields into req.session.
// ---------------------------------------------------------------------------

const authorizeConfig = {
	oauth: {
		jwt: { issuer: "https://auth.example" },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		oidcMode: "oidc-required",
	},
	endpoints: {
		login: { url: "/login" },
	},
} as unknown as AppConfig;

const authorizeClientRepo: ClientRepository = {
	findById: async () => ({
		clientId: "client-1",
		allowedRedirectUris: ["https://example.test/cb"],
		firstParty: true,
		allowedScopes: ["openid", "profile"],
	}),
	authenticate: async () => null,
};

async function buildAuthorizeApp(opts: {
	sessionFields: Record<string, unknown>;
	captureCode: (params: Parameters<CodeRepository["createCode"]>[0]) => void;
	captureSession?: (session: Record<string, unknown>) => void;
	/**
	 * Optional config override merged into the default `authorizeConfig`.
	 * Used by IH-16 tests that need to set a non-default
	 * `oauth.nonce.maxLength` so the configurable code path is exercised
	 * (the no-override path uses the `?? 256` fallback only).
	 */
	configOverride?: Partial<AppConfig>;
	clientRepo?: ClientRepository;
	logger?: Logger;
}) {
	const app = express();
	app.use(express.json());
	app.use(express.urlencoded({ extended: false }));

	// Inline session substitute — minimal surface needed by the /authorize route.
	app.use((req, _res, next) => {
		const session: Record<string, unknown> = {
			isAuthenticated: true,
			user: { id: "user-1" },
			...opts.sessionFields,
		};
		(req as unknown as { session: Record<string, unknown> }).session = session;
		// CR-2: capture the session reference so the test can inspect post-route mutations.
		// The /authorize route writes req.session.code* synchronously before res.redirect,
		// so the captured reference reflects the route's writes after the request resolves.
		opts.captureSession?.(session);
		next();
	});

	const codeRepo: CodeRepository = {
		createCode: async (params) => {
			opts.captureCode(params);
			// D-1: echo back the required identity fields from params so the
			// returned `Code` satisfies the new shape (client_id + redirect_uri).
			return { code: "auth-code", client_id: params.client_id, redirect_uri: params.redirect_uri };
		},
		findByCode: async () => null,
		consumeByCode: async () => null,
		removeByCode: async () => {},
	};

	const mergedConfig = (
		opts.configOverride
			? {
					...authorizeConfig,
					...opts.configOverride,
					oauth: {
						...(authorizeConfig as unknown as { oauth: Record<string, unknown> }).oauth,
						...((opts.configOverride as { oauth?: Record<string, unknown> }).oauth ?? {}),
					},
				}
			: authorizeConfig
	) as AppConfig;

	const { router } = await createOAuthRouter(express, {
		registry: new GrantRegistry(),
		config: mergedConfig,
		clientRepository: opts.clientRepo ?? authorizeClientRepo,
		codeRepository: codeRepo,
		keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
		logger: opts.logger,
	});
	app.use("/oauth", router);
	return app;
}

// ---------------------------------------------------------------------------
// Module manifest structural tests (§7.1 — static, no createTestApp needed)
// ---------------------------------------------------------------------------

describe("oauthAuthorizationModule — manifest shape", () => {
	it("has name 'oauth-authorization'", () => {
		const config = makeValidAppConfig();
		const module = oauthAuthorizationModule({ config });
		expect(module.name).toBe("oauth-authorization");
	});

	it("contributes authorization_code grant when enabled", () => {
		const config = makeValidAppConfig();
		const module = oauthAuthorizationModule({ config });
		expect(module.contributes?.grants?.authorization_code).toBeDefined();
	});

	it("contributes refresh_token grant when enabled", () => {
		const config = makeValidAppConfig();
		const module = oauthAuthorizationModule({ config });
		expect(module.contributes?.grants?.refresh_token).toBeDefined();
	});

	it("contributes client_credentials grant when config explicitly sets enabled=true", () => {
		// Per-client AuthenticatedClient.allowedGrantTypes (§3.4.1 deny-by-absence)
		// is the authoritative access gate; the server-wide flag exists for
		// symmetric operational control with authorization_code / refresh_token.
		// client_credentials is NOT in the factory default (standalone template is
		// server/browser-only) — the deployment must opt in explicitly.
		const base = makeValidAppConfig();
		const config = {
			...base,
			oauth: {
				...base.oauth,
				grants: { ...base.oauth.grants, client_credentials: { enabled: true } },
			},
		};
		const module = oauthAuthorizationModule({ config });
		expect(module.contributes?.grants?.client_credentials).toBeDefined();
	});

	it("omits client_credentials grant when config says enabled=false", () => {
		const base = makeValidAppConfig();
		const config = {
			...base,
			oauth: {
				...base.oauth,
				grants: { ...base.oauth.grants, client_credentials: { enabled: false } },
			},
		};
		const module = oauthAuthorizationModule({ config });
		expect(module.contributes?.grants?.client_credentials).toBeUndefined();
	});

	it("omits client_credentials grant when factory default omits the enabled key", () => {
		// client_credentials is deliberately absent from makeValidAppConfig() —
		// the factory mirrors the standalone template where M2M is not enabled.
		// Under === true opt-in semantics, an absent key means "not registered".
		const module = oauthAuthorizationModule({ config: makeValidAppConfig() });
		expect(module.contributes?.grants?.client_credentials).toBeUndefined();
	});

	it("registers exactly the expected grant types (R8 snapshot)", () => {
		// Drift guard: an accidental addition or removal of a built-in grant
		// surfaces here before it ships in a release. client_credentials is not
		// in the factory default (standalone template) — only authorization_code
		// and refresh_token are enabled by default.
		const config = makeValidAppConfig();
		const module = oauthAuthorizationModule({ config });
		const keys = Object.keys(module.contributes?.grants ?? {}).sort();
		expect(keys).toEqual(["authorization_code", "refresh_token"]);
	});

	it("omits authorization_code grant when config says enabled=false", () => {
		const base = makeValidAppConfig();
		const config = {
			...base,
			oauth: {
				...base.oauth,
				grants: { ...base.oauth.grants, authorization_code: { enabled: false } },
			},
		};
		const module = oauthAuthorizationModule({ config });
		expect(module.contributes?.grants?.authorization_code).toBeUndefined();
	});

	it("omits refresh_token grant when config says enabled=false", () => {
		const base = makeValidAppConfig();
		const config = {
			...base,
			oauth: {
				...base.oauth,
				grants: { ...base.oauth.grants, refresh_token: { enabled: false } },
			},
		};
		const module = oauthAuthorizationModule({ config });
		expect(module.contributes?.grants?.refresh_token).toBeUndefined();
	});

	it("does NOT register authorization_code when config omits the enabled key entirely (=== true semantics)", () => {
		const base = makeValidAppConfig();
		const config = {
			...base,
			oauth: {
				...base.oauth,
				// Empty grants override — simulates a config where no built-in
				// is opted in. Under the strict `=== true` check, absent
				// `enabled` keys mean "not registered".
				grants: {} as Record<string, unknown>,
			},
		};
		const module = oauthAuthorizationModule({ config });
		expect(module.contributes?.grants?.authorization_code).toBeUndefined();
		expect(module.contributes?.grants?.refresh_token).toBeUndefined();
		expect(module.contributes?.grants?.client_credentials).toBeUndefined();
	});

	it("does NOT register a grant when enabled is the string 'false' (HOCON env-substitution outcome)", () => {
		// HOCON env-var substitution (`enabled = ${?OAUTH_GRANTS_X_ENABLED}`)
		// resolves the env value as a string — there is no schema coercion
		// to boolean on the `grants` passthrough sub-tree. Under the strict
		// opt-in check, a resolved `enabled: "false"` correctly evaluates
		// to not-enabled.
		const base = makeValidAppConfig();
		const config = {
			...base,
			oauth: {
				...base.oauth,
				grants: {
					authorization_code: { enabled: "false" as unknown as boolean },
				} as Record<string, unknown>,
			},
		};
		const module = oauthAuthorizationModule({ config });
		expect(module.contributes?.grants?.authorization_code).toBeUndefined();
	});

	it("registers a grant when enabled is the string 'true' (HOCON env-substitution outcome)", () => {
		// Mirror of the env-disable test for the env-enable path. An operator
		// setting `OAUTH_GRANTS_CLIENT_CREDENTIALS_ENABLED=true` produces a
		// resolved `enabled: "true"` (string) on the passthrough `grants`
		// sub-tree. The opt-in check accepts both boolean `true` and string
		// `"true"` so the documented env-enable pattern actually works.
		const base = makeValidAppConfig();
		const config = {
			...base,
			oauth: {
				...base.oauth,
				grants: {
					...base.oauth.grants,
					client_credentials: { enabled: "true" as unknown as boolean },
				},
			},
		};
		const module = oauthAuthorizationModule({ config });
		expect(module.contributes?.grants?.client_credentials).toBeDefined();
	});

	it("does NOT register a grant for unrelated truthy strings like 'yes' / '1'", () => {
		// Strictness check: only the canonical forms (boolean `true`,
		// string `"true"`) opt in. Other truthy values do not — this
		// keeps misconfigurations loud rather than silently enabling
		// something via, e.g., a copy-paste from a different bool encoding.
		const base = makeValidAppConfig();
		for (const value of ["yes", "1", "TRUE", "True", 1] as unknown[]) {
			const config = {
				...base,
				oauth: {
					...base.oauth,
					grants: {
						client_credentials: { enabled: value as boolean },
					} as Record<string, unknown>,
				},
			};
			const module = oauthAuthorizationModule({ config });
			expect(module.contributes?.grants?.client_credentials).toBeUndefined();
		}
	});

	// Boot planner only injects keys listed in `requires` ∪ `optional` into
	// contribution-factory `deps`. Both grant factories read
	// `deps.refreshTokenFamilyRotation` (A3 §5.2 rotation persistence) and
	// `deps.grantPolicy` (CP-18 fail-closed gate). If they are not declared
	// here, a composition root that wires either component will see it
	// silently dropped at the grant boundary — refresh-token rotation stops
	// recording, and grantPolicy enforcement becomes dead code.
	it("declares refreshTokenFamilyRotation + grantPolicy in optional so deps reach the grants", () => {
		const config = makeValidAppConfig();
		const module = oauthAuthorizationModule({ config });
		expect(module.optional).toContain("refreshTokenFamilyRotation");
		expect(module.optional).toContain("grantPolicy");
	});
});

// ---------------------------------------------------------------------------
// createTestApp integration tests (§7.3 — boot + inspect)
// ---------------------------------------------------------------------------

describe("oauthAuthorizationModule — createTestApp integration", () => {
	it("registers authorization_code and refresh_token grants at boot (factory default)", async () => {
		// Factory default does not include client_credentials — see makeValidCoreConfig()
		// for the rationale (standalone template is server/browser-only).
		const config = makeValidAppConfig();
		const handle = await createTestApp({
			modules: [
				oauthAuthorizationModule({ config }),
				clientRepositoryModule,
				codeRepositoryModule,
				keyStoreModule,
			],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		expect(handle.inspect.grants.has("authorization_code")).toBe(true);
		expect(handle.inspect.grants.has("refresh_token")).toBe(true);
		expect(handle.inspect.grants.has("client_credentials")).toBe(false);
		await handle.dispose();
	});

	it("registers client_credentials grant at boot when explicitly enabled", async () => {
		const base = makeValidAppConfig();
		const config = {
			...base,
			oauth: {
				...base.oauth,
				grants: { ...base.oauth.grants, client_credentials: { enabled: true } },
			},
		};
		const handle = await createTestApp({
			modules: [
				oauthAuthorizationModule({ config }),
				clientRepositoryModule,
				codeRepositoryModule,
				keyStoreModule,
			],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		expect(handle.inspect.grants.has("authorization_code")).toBe(true);
		expect(handle.inspect.grants.has("refresh_token")).toBe(true);
		expect(handle.inspect.grants.has("client_credentials")).toBe(true);
		await handle.dispose();
	});

	it("does not register authorization_code grant when config says enabled=false", async () => {
		const base = makeValidAppConfig();
		const config = {
			...base,
			oauth: {
				...base.oauth,
				grants: {
					...base.oauth.grants,
					authorization_code: { enabled: false },
					refresh_token: { enabled: true },
				},
			},
		};
		const handle = await createTestApp({
			modules: [
				oauthAuthorizationModule({ config }),
				clientRepositoryModule,
				codeRepositoryModule,
				keyStoreModule,
			],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		expect(handle.inspect.grants.has("authorization_code")).toBe(false);
		expect(handle.inspect.grants.has("refresh_token")).toBe(true);
		// client_credentials is not in the factory default and not added here —
		// it must not be registered under === true opt-in semantics.
		expect(handle.inspect.grants.has("client_credentials")).toBe(false);
		await handle.dispose();
	});
});

// ---------------------------------------------------------------------------
// Grant factory unit tests — test createAuthorizationGrant / createRefreshTokenGrant
// directly with mock deps (not through the module manifest).
// These tests preserve the behavioral coverage that was previously embedded in
// the module-level tests via module.init(ctx).
// ---------------------------------------------------------------------------

describe("createRefreshTokenGrant — refreshTokenFamilyRotation forwarding", () => {
	it("calls refreshTokenFamilyRotation.rotate when a valid refresh_token is presented", async () => {
		const rotateSpy = vi.fn().mockResolvedValue({ outcome: "rotated" });
		const refreshTokenFamilyRotation: RefreshTokenFamilyRotation = {
			register: vi.fn(async () => {}),
			rotate: rotateSpy,
		};
		const keyStore = createSymmetricKeyStore("test-secret-at-least-32-chars!!");
		const baseDeps: GrantDependencies = {
			config: {
				oauth: {
					jwt: { secret: "test-secret" },
					accessToken: { expiresIn: 3600 },
					refreshToken: { expiresIn: 86400 },
				},
			} as unknown as GrantDependencies["config"],
			keyStore,
			refreshTokenFamilyRotation,
		};

		const handler = createRefreshTokenGrant(baseDeps);

		// Build a real refresh token so rotate() is reached
		const { generateToken } = await import("@o3co/auth-provider-core");
		const rt = await generateToken(
			{ family_id: "fam-1" },
			{
				expiresIn: 3600,
				keyStore,
				issuer: "test-issuer",
				audience: "client-1",
				subject: "user-1",
				authorizedParty: "client-1",
				scope: null,
				tokenType: "rt+jwt",
			},
		);

		await handler.handle({
			body: { refresh_token: rt.token },
			session: {},
			issuer: "test-issuer",
			metadata: {},
			authenticatedClient: { clientId: "client-1", tokenEndpointAuthMethod: "client_secret_basic" },
		});

		expect(rotateSpy).toHaveBeenCalled();
	});
});

describe("createAuthorizationGrant — userSessionStore forwarding", () => {
	it("calls userSessionStore.get when a valid code exchange includes a sid", async () => {
		const getSpy = vi.fn().mockResolvedValue({
			sid: "sid-wired",
			sub: "u1",
			authTime: new Date(),
			createdAt: new Date(),
			expiresAt: new Date(Date.now() + 3600_000),
			claims: {},
		});
		const userSessionStore: UserSessionStore = {
			kind: "spy",
			get: getSpy,
			create: vi.fn(),
			delete: vi.fn(),
		};
		const sessionRPRegistry: SessionRPRegistry = {
			kind: "spy",
			registerRP: vi.fn(async () => {}),
			listRPs: vi.fn(async () => []),
			removeBySid: vi.fn(async () => {}),
		};
		const sessionFamilyIndex: SessionFamilyIndex = {
			kind: "spy",
			addFamilyId: vi.fn(async () => {}),
			listFamilyIds: vi.fn(async () => []),
			removeBySid: vi.fn(async () => {}),
		};
		const keyStore = createSymmetricKeyStore("test-secret-at-least-32-chars!!");
		const consumeByCode = vi.fn().mockResolvedValue({
			code: "auth-code",
			sid: "sid-wired",
			client_id: "client1",
			redirect_uri: "https://rp.example/cb",
			// #273: a redeemable code always carries an S256 challenge.
			code_challenge: AUTHORIZE_S256_CHALLENGE,
			code_challenge_method: "S256",
		});

		const deps: GrantDependencies & {
			codeRepository: CodeRepository;
			clientRepository: ClientRepository;
		} = {
			config: {
				oauth: {
					jwt: { secret: "test-secret" },
					accessToken: { expiresIn: 3600 },
					refreshToken: { expiresIn: 86400 },
				},
			} as unknown as GrantDependencies["config"],
			keyStore,
			userSessionStore,
			sessionRPRegistry,
			sessionFamilyIndex,
			codeRepository: {
				consumeByCode,
				createCode: vi.fn(),
				findByCode: vi.fn(),
				removeByCode: vi.fn(),
			} as unknown as CodeRepository,
			clientRepository: {
				findById: vi.fn().mockResolvedValue(null),
				authenticate: vi.fn().mockResolvedValue(null),
			},
		};

		const handler = createAuthorizationGrant(deps);
		const { result } = await handler.handle({
			body: {
				code: "auth-code",
				client_id: "client1",
				redirect_uri: "https://rp.example/cb",
				code_verifier: AUTHORIZE_CODE_VERIFIER,
			},
			session: {
				code: "auth-code",
				code_client_id: "client1",
				granted_scopes: ["read"],
				user: { id: "u1" },
			},
			issuer: "localhost",
			metadata: {},
			authenticatedClient: { clientId: "client1", tokenEndpointAuthMethod: "client_secret_basic" },
		});

		expect(result.status).toBe(200);
		expect(getSpy).toHaveBeenCalledWith("sid-wired");
	});
});

describe("createAuthorizationGrant — grantPolicy forwarding", () => {
	it("calls grantPolicy.evaluate during refresh_token grant", async () => {
		const keyStore = createSymmetricKeyStore("test-secret-at-least-32-chars!!");
		const grantPolicy: GrantPolicyHook = {
			kind: "spy",
			evaluate: vi.fn().mockResolvedValue({ outcome: "allow" }),
		};

		// Build a valid refresh token first via authorization grant
		const consumeByCode = vi.fn().mockResolvedValue({ code: "auth-code" });
		const authDeps: GrantDependencies & {
			codeRepository: CodeRepository;
			clientRepository: ClientRepository;
		} = {
			config: {
				oauth: {
					jwt: { secret: "test-secret" },
					accessToken: { expiresIn: 3600 },
					refreshToken: { expiresIn: 86400 },
				},
			} as unknown as GrantDependencies["config"],
			keyStore,
			codeRepository: {
				consumeByCode,
				createCode: vi.fn(),
				findByCode: vi.fn(),
				removeByCode: vi.fn(),
			} as unknown as CodeRepository,
			clientRepository: {
				findById: vi.fn().mockResolvedValue(null),
				authenticate: vi.fn().mockResolvedValue(null),
			},
		};

		const authHandler = createAuthorizationGrant(authDeps);
		const authResult = await authHandler.handle({
			body: { code: "auth-code", client_id: "client1" },
			session: {
				code: "auth-code",
				code_client_id: "client1",
				granted_scopes: ["read"],
				user: { id: "u1" },
			},
			issuer: "localhost",
			metadata: {},
			authenticatedClient: { clientId: "client1", tokenEndpointAuthMethod: "client_secret_basic" },
		});

		// Pluck the refresh_token from the authorization code response
		const tokens = (authResult.result as { status: number; tokens?: { refresh_token?: string } })
			.tokens;
		const refreshTokenValue = tokens?.refresh_token;
		if (!refreshTokenValue) return; // skip if no token

		// Now test the refresh grant with grantPolicy
		const rtDeps: GrantDependencies = {
			config: {
				oauth: {
					jwt: { secret: "test-secret" },
					accessToken: { expiresIn: 3600 },
					refreshToken: { expiresIn: 86400 },
				},
			} as unknown as GrantDependencies["config"],
			keyStore,
			grantPolicy,
		};

		const rtHandler = createRefreshTokenGrant(rtDeps);
		await rtHandler.handle({
			body: { refresh_token: refreshTokenValue, client_id: "client1" },
			session: {},
			issuer: "localhost",
			metadata: {},
			authenticatedClient: { clientId: "client1", tokenEndpointAuthMethod: "client_secret_basic" },
		});

		expect(grantPolicy.evaluate).toHaveBeenCalled();
	});
});

describe("createAuthorizationGrant — returns 400 for invalid code", () => {
	it("registered authorization handler returns 400 for invalid code", async () => {
		const keyStore = createSymmetricKeyStore("test-secret-at-least-32-chars!!");
		const consumeByCode = vi.fn().mockResolvedValue(null);
		const deps: GrantDependencies & {
			codeRepository: CodeRepository;
			clientRepository: ClientRepository;
		} = {
			config: {
				oauth: {
					jwt: { secret: "test-secret" },
					accessToken: { expiresIn: 3600 },
					refreshToken: { expiresIn: 86400 },
				},
			} as unknown as GrantDependencies["config"],
			keyStore,
			codeRepository: {
				consumeByCode,
				createCode: vi.fn(),
				findByCode: vi.fn(),
				removeByCode: vi.fn(),
			} as unknown as CodeRepository,
			clientRepository: {
				findById: vi.fn().mockResolvedValue(null),
				authenticate: vi.fn().mockResolvedValue(null),
			},
		};

		const handler = createAuthorizationGrant(deps);
		const { result } = await handler.handle({
			body: { code: "bad-code", client_id: "c1" },
			session: { code: "different-code", code_client_id: "c1" },
			issuer: "localhost",
			metadata: {},
			authenticatedClient: { clientId: "client1", tokenEndpointAuthMethod: "client_secret_basic" },
		});

		expect(result.status).toBe(400);
	});
});

// ---------------------------------------------------------------------------
// authorize persists OIDC round-trip state on code record (TODO-F-3)
// These tests use the route layer directly — they do NOT use the module
// manifest system and remain unchanged from v0.4.x since they test the
// /authorize route behavior, not the module shape.
// ---------------------------------------------------------------------------

describe("authorize persists OIDC round-trip state on code record (TODO-F-3)", () => {
	it("captures nonce + sid on createCode when both are present", async () => {
		let captured: Parameters<CodeRepository["createCode"]>[0] | undefined;

		const app = await buildAuthorizeApp({
			sessionFields: { sid: "sid-abc" },
			captureCode: (p) => {
				captured = p;
			},
		});

		await request(app).get("/oauth/authorize").query({
			response_type: "code",
			client_id: "client-1",
			redirect_uri: "https://example.test/cb",
			code_challenge: AUTHORIZE_S256_CHALLENGE,
			code_challenge_method: "S256",
			scope: "openid profile",
			nonce: "nonce-xyz",
		});

		expect(captured).toBeDefined();
		expect(captured?.nonce).toBe("nonce-xyz");
		expect(captured?.sid).toBe("sid-abc");
	});

	it("omits nonce on createCode when query.nonce is not provided", async () => {
		let captured: Parameters<CodeRepository["createCode"]>[0] | undefined;

		const app = await buildAuthorizeApp({
			sessionFields: { sid: "sid-1" },
			captureCode: (p) => {
				captured = p;
			},
		});

		await request(app).get("/oauth/authorize").query({
			response_type: "code",
			client_id: "client-1",
			redirect_uri: "https://example.test/cb",
			code_challenge: AUTHORIZE_S256_CHALLENGE,
			code_challenge_method: "S256",
			scope: "openid profile",
			// no nonce
		});

		expect(captured).toBeDefined();
		expect(captured?.nonce).toBeUndefined();
		// sid is still captured even without nonce
		expect(captured?.sid).toBe("sid-1");
	});
});

describe("IH-6: /authorize openid scope gate", () => {
	it("rejects missing openid in oidc-required mode when issuer is configured", async () => {
		const captureCode = vi.fn();
		const logger = createMockLogger();
		const app = await buildAuthorizeApp({
			sessionFields: { sid: "sid-oidc-required" },
			captureCode,
			logger,
		});

		const res = await request(app).get("/oauth/authorize").query({
			response_type: "code",
			client_id: "client-1",
			redirect_uri: "https://example.test/cb",
			code_challenge: AUTHORIZE_S256_CHALLENGE,
			code_challenge_method: "S256",
			state: "state-missing-openid",
			scope: "profile",
		});

		expect(res.status).toBe(302);
		const location = new URL(res.headers.location);
		expect(location.origin + location.pathname).toBe("https://example.test/cb");
		expect(location.searchParams.get("error")).toBe("invalid_scope");
		expect(location.searchParams.get("error_description")).toMatch(/openid scope is required/i);
		expect(location.searchParams.get("state")).toBe("state-missing-openid");
		expect(captureCode).not.toHaveBeenCalled();
		expect(logger.warn).toHaveBeenCalledWith(
			{
				clientId: "client-1",
				requestedScopes: ["profile"],
				allowedFilteredScopes: ["profile"],
			},
			"authorize_rejected_missing_openid_scope",
		);
	});

	it("rejects when openid is requested but client allowlist filters it out (oidc-required bypass guard)", async () => {
		// Regression: previously the gate only checked requestedScopes, so a
		// client whose allowedScopes did not include `openid` would silently
		// pass the gate even when the server is `oidc-required` and the
		// request asked for openid — the request would then proceed as
		// OAuth-only because allowedFilteredScopes drops openid.
		const captureCode = vi.fn();
		const logger = createMockLogger();
		const restrictedClientRepo: ClientRepository = {
			findById: async () => ({
				clientId: "client-1",
				allowedRedirectUris: ["https://example.test/cb"],
				firstParty: true,
				// openid is intentionally absent — emulates a non-OIDC client.
				allowedScopes: ["profile"],
			}),
			authenticate: async () => null,
		};
		const app = await buildAuthorizeApp({
			sessionFields: { sid: "sid-oidc-bypass" },
			captureCode,
			clientRepo: restrictedClientRepo,
			logger,
		});

		const res = await request(app).get("/oauth/authorize").query({
			response_type: "code",
			client_id: "client-1",
			redirect_uri: "https://example.test/cb",
			code_challenge: AUTHORIZE_S256_CHALLENGE,
			code_challenge_method: "S256",
			state: "state-bypass",
			scope: "openid profile",
		});

		expect(res.status).toBe(302);
		const location = new URL(res.headers.location);
		expect(location.searchParams.get("error")).toBe("invalid_scope");
		expect(location.searchParams.get("error_description")).toMatch(/openid scope is required/i);
		expect(location.searchParams.get("state")).toBe("state-bypass");
		expect(captureCode).not.toHaveBeenCalled();
		expect(logger.warn).toHaveBeenCalledWith(
			{
				clientId: "client-1",
				requestedScopes: ["openid", "profile"],
				allowedFilteredScopes: ["profile"],
			},
			"authorize_rejected_missing_openid_scope",
		);
	});

	it("allows oidc-required requests that include openid", async () => {
		let captured: Parameters<CodeRepository["createCode"]>[0] | undefined;
		const app = await buildAuthorizeApp({
			sessionFields: { sid: "sid-oidc-ok" },
			captureCode: (p) => {
				captured = p;
			},
		});

		const res = await request(app).get("/oauth/authorize").query({
			response_type: "code",
			client_id: "client-1",
			redirect_uri: "https://example.test/cb",
			code_challenge: AUTHORIZE_S256_CHALLENGE,
			code_challenge_method: "S256",
			scope: "openid profile",
		});

		expect(res.status).toBe(302);
		const location = new URL(res.headers.location);
		expect(location.searchParams.get("code")).toBe("auth-code");
		expect(location.searchParams.get("error")).toBeNull();
		expect(captured?.grantedScope).toEqual(["openid", "profile"]);
	});

	it("allows OAuth-only requests in dual mode", async () => {
		let captured: Parameters<CodeRepository["createCode"]>[0] | undefined;
		const app = await buildAuthorizeApp({
			sessionFields: { sid: "sid-dual-oauth" },
			captureCode: (p) => {
				captured = p;
			},
			configOverride: {
				oauth: {
					oidcMode: "dual",
				},
			} as unknown as Partial<AppConfig>,
		});

		const res = await request(app).get("/oauth/authorize").query({
			response_type: "code",
			client_id: "client-1",
			redirect_uri: "https://example.test/cb",
			code_challenge: AUTHORIZE_S256_CHALLENGE,
			code_challenge_method: "S256",
			scope: "profile",
		});

		expect(res.status).toBe(302);
		const location = new URL(res.headers.location);
		expect(location.searchParams.get("code")).toBe("auth-code");
		expect(location.searchParams.get("error")).toBeNull();
		expect(captured?.grantedScope).toEqual(["profile"]);
	});

	it("allows OIDC requests in dual mode", async () => {
		let captured: Parameters<CodeRepository["createCode"]>[0] | undefined;
		const app = await buildAuthorizeApp({
			sessionFields: { sid: "sid-dual-oidc" },
			captureCode: (p) => {
				captured = p;
			},
			configOverride: {
				oauth: {
					oidcMode: "dual",
				},
			} as unknown as Partial<AppConfig>,
		});

		const res = await request(app).get("/oauth/authorize").query({
			response_type: "code",
			client_id: "client-1",
			redirect_uri: "https://example.test/cb",
			code_challenge: AUTHORIZE_S256_CHALLENGE,
			code_challenge_method: "S256",
			scope: "openid profile",
		});

		expect(res.status).toBe(302);
		const location = new URL(res.headers.location);
		expect(location.searchParams.get("code")).toBe("auth-code");
		expect(location.searchParams.get("error")).toBeNull();
		expect(captured?.grantedScope).toEqual(["openid", "profile"]);
	});

	it("rejects when requested scopes are all outside the client allowance", async () => {
		const captureCode = vi.fn();
		const app = await buildAuthorizeApp({
			sessionFields: { sid: "sid-scope-filter-empty" },
			captureCode,
			configOverride: {
				oauth: {
					oidcMode: "dual",
				},
			} as unknown as Partial<AppConfig>,
		});

		const res = await request(app).get("/oauth/authorize").query({
			response_type: "code",
			client_id: "client-1",
			redirect_uri: "https://example.test/cb",
			code_challenge: AUTHORIZE_S256_CHALLENGE,
			code_challenge_method: "S256",
			state: "state-outside-scope",
			scope: "email",
		});

		expect(res.status).toBe(302);
		const location = new URL(res.headers.location);
		expect(location.searchParams.get("error")).toBe("invalid_scope");
		expect(location.searchParams.get("error_description")).toMatch(/no requested scopes/i);
		expect(location.searchParams.get("state")).toBe("state-outside-scope");
		expect(captureCode).not.toHaveBeenCalled();
	});
});

// IH-16 (v0.5.1): /authorize must bound the `nonce` query parameter.
//
// Pre-IH-16 the route accepted any-length nonce verbatim and stored it on
// the code record + echoed it into the id_token. A malicious RP sending
// nonce=<huge-string> could exhaust per-request memory or amplify the
// id_token payload. The route now enforces a default 256-char ceiling
// (configurable via `oauth.nonce.maxLength`) and rejects non-printable
// ASCII via `redirectError` — the redirect_uri is already client-allowlisted
// at this point in the route, so RFC 6749 §4.1.2.1 redirect-based errors
// apply (Codex calibration delta 2).
describe("IH-16: /authorize nonce length + character-set validation", () => {
	it("accepts a normal-sized printable nonce (32 chars)", async () => {
		let captured: Parameters<CodeRepository["createCode"]>[0] | undefined;
		const app = await buildAuthorizeApp({
			sessionFields: { sid: "sid-1" },
			captureCode: (p) => {
				captured = p;
			},
		});

		const nonce = "a".repeat(32);
		const res = await request(app).get("/oauth/authorize").query({
			response_type: "code",
			client_id: "client-1",
			redirect_uri: "https://example.test/cb",
			code_challenge: AUTHORIZE_S256_CHALLENGE,
			code_challenge_method: "S256",
			scope: "openid profile",
			nonce,
		});

		// Successful /authorize redirects (302) to redirect_uri with `code` —
		// the absence of an `error` parameter confirms the gate passed.
		expect(res.status).toBe(302);
		const location = new URL(res.headers.location);
		expect(location.searchParams.get("error")).toBeNull();
		expect(captured?.nonce).toBe(nonce);
	});

	it("accepts a nonce at the boundary (256 chars exactly)", async () => {
		let captured: Parameters<CodeRepository["createCode"]>[0] | undefined;
		const app = await buildAuthorizeApp({
			sessionFields: { sid: "sid-1" },
			captureCode: (p) => {
				captured = p;
			},
		});

		const nonce = "a".repeat(256);
		const res = await request(app).get("/oauth/authorize").query({
			response_type: "code",
			client_id: "client-1",
			redirect_uri: "https://example.test/cb",
			code_challenge: AUTHORIZE_S256_CHALLENGE,
			code_challenge_method: "S256",
			scope: "openid profile",
			nonce,
		});

		expect(res.status).toBe(302);
		const location = new URL(res.headers.location);
		expect(location.searchParams.get("error")).toBeNull();
		expect(captured?.nonce).toBe(nonce);
	});

	it("rejects an oversized nonce (257 chars) with redirect-based invalid_request", async () => {
		const captureCode = vi.fn();
		const app = await buildAuthorizeApp({
			sessionFields: { sid: "sid-1" },
			captureCode,
		});

		const res = await request(app)
			.get("/oauth/authorize")
			.query({
				response_type: "code",
				client_id: "client-1",
				redirect_uri: "https://example.test/cb",
				code_challenge: AUTHORIZE_S256_CHALLENGE,
				code_challenge_method: "S256",
				state: "client-state-xyz",
				nonce: "a".repeat(257),
			});

		expect(res.status).toBe(302);
		const location = new URL(res.headers.location);
		expect(location.origin + location.pathname).toBe("https://example.test/cb");
		expect(location.searchParams.get("error")).toBe("invalid_request");
		expect(location.searchParams.get("error_description")).toMatch(/nonce/i);
		// `state` MUST round-trip on error redirects per RFC 6749 §4.1.2.1.
		expect(location.searchParams.get("state")).toBe("client-state-xyz");
		expect(captureCode).not.toHaveBeenCalled();
	});

	it("rejects a non-printable nonce with redirect-based invalid_request", async () => {
		const captureCode = vi.fn();
		const app = await buildAuthorizeApp({
			sessionFields: { sid: "sid-1" },
			captureCode,
		});

		// `\x00` is below the printable ASCII range (0x20-0x7E).
		const res = await request(app).get("/oauth/authorize").query({
			response_type: "code",
			client_id: "client-1",
			redirect_uri: "https://example.test/cb",
			code_challenge: AUTHORIZE_S256_CHALLENGE,
			code_challenge_method: "S256",
			nonce: "a\x00b",
		});

		expect(res.status).toBe(302);
		const location = new URL(res.headers.location);
		expect(location.origin + location.pathname).toBe("https://example.test/cb");
		expect(location.searchParams.get("error")).toBe("invalid_request");
		expect(location.searchParams.get("error_description")).toMatch(/non-printable|character/i);
		expect(captureCode).not.toHaveBeenCalled();
	});

	it("honours an operator-configured `oauth.nonce.maxLength` (not just the default 256)", async () => {
		// Without this test, the configurable code path was completely
		// untested — the other IH-16 tests exercise only the `?? 256`
		// fallback. Drop the limit to 10 and verify both an 11-char nonce
		// rejects and a 10-char nonce passes; this proves
		// `config.oauth.nonce.maxLength` actually flows through to the gate.
		const captureCode = vi.fn();
		const app = await buildAuthorizeApp({
			sessionFields: { sid: "sid-1" },
			captureCode,
			configOverride: {
				oauth: {
					jwt: { issuer: "https://auth.example" },
					accessToken: { expiresIn: 3600 },
					refreshToken: { expiresIn: 86400 },
					nonce: { maxLength: 10 },
				},
			} as unknown as Partial<AppConfig>,
		});

		// Over the operator limit — must redirect-error with the configured value.
		const res = await request(app)
			.get("/oauth/authorize")
			.query({
				response_type: "code",
				client_id: "client-1",
				redirect_uri: "https://example.test/cb",
				code_challenge: AUTHORIZE_S256_CHALLENGE,
				code_challenge_method: "S256",
				nonce: "a".repeat(11),
			});
		expect(res.status).toBe(302);
		const location = new URL(res.headers.location);
		expect(location.searchParams.get("error")).toBe("invalid_request");
		// The error description must echo the OPERATOR's value (not 256) —
		// proves the override took effect.
		expect(location.searchParams.get("error_description")).toMatch(/maximum length of 10\b/);
		expect(captureCode).not.toHaveBeenCalled();
	});
});

// D-1 / CR-2: /authorize MUST embed the identity binding in the code record,
// not in the Express session. Pre-fix, four session writes (req.session.code,
// req.session.code_client_id, req.session.code_redirect_uri,
// req.session.granted_scopes) at routes.mts:572-575 created a last-write-wins
// race when concurrent /authorize requests shared a session — the losing
// request's code was orphaned in the repository because session.code had been
// overwritten by the winning request and the /token gate would reject it.
//
// Per spec Codex calibration: prefer structural assertion (session writes are
// gone) as a regression guard alongside the functional check (createCode is
// called with client_id + redirect_uri).
describe("D-1 / CR-2: /authorize binds identity to code record, not Express session", () => {
	it("does NOT write code, code_client_id, code_redirect_uri, granted_scopes to req.session", async () => {
		let capturedCode: Parameters<CodeRepository["createCode"]>[0] | undefined;
		let capturedSession: Record<string, unknown> | undefined;

		const app = await buildAuthorizeApp({
			sessionFields: { sid: "sid-cr2" },
			captureCode: (p) => {
				capturedCode = p;
			},
			captureSession: (s) => {
				capturedSession = s;
			},
		});

		await request(app).get("/oauth/authorize").query({
			response_type: "code",
			client_id: "client-1",
			redirect_uri: "https://example.test/cb",
			code_challenge: AUTHORIZE_S256_CHALLENGE,
			code_challenge_method: "S256",
			scope: "openid profile",
		});

		// The route must have called createCode with the identity binding embedded.
		expect(capturedCode).toBeDefined();
		expect(capturedCode?.client_id).toBe("client-1");
		expect(capturedCode?.redirect_uri).toBe("https://example.test/cb");

		// And the session must NOT carry any code* identity binding — otherwise
		// concurrent /authorize requests could race on session.code overwrite.
		expect(capturedSession).toBeDefined();
		expect(capturedSession).not.toHaveProperty("code");
		expect(capturedSession).not.toHaveProperty("code_client_id");
		expect(capturedSession).not.toHaveProperty("code_redirect_uri");
		expect(capturedSession).not.toHaveProperty("granted_scopes");
	});

	it("two concurrent /authorize requests sharing a session both produce a code with intact identity binding", async () => {
		// Functional verification: with no session writes, two concurrent
		// authorize calls cannot clobber each other. Both createCode calls
		// receive distinct client_id + redirect_uri arguments and the captured
		// session shows neither overwrote the other.
		const capturedCodes: Parameters<CodeRepository["createCode"]>[0][] = [];
		const capturedSessions: Record<string, unknown>[] = [];

		const app = await buildAuthorizeApp({
			sessionFields: { sid: "sid-concurrent" },
			captureCode: (p) => {
				capturedCodes.push(p);
			},
			captureSession: (s) => {
				capturedSessions.push(s);
			},
		});

		await Promise.all([
			request(app).get("/oauth/authorize").query({
				response_type: "code",
				client_id: "client-1",
				redirect_uri: "https://example.test/cb",
				code_challenge: AUTHORIZE_S256_CHALLENGE,
				code_challenge_method: "S256",
				scope: "openid profile",
			}),
			request(app).get("/oauth/authorize").query({
				response_type: "code",
				client_id: "client-1",
				redirect_uri: "https://example.test/cb",
				code_challenge: AUTHORIZE_S256_CHALLENGE,
				code_challenge_method: "S256",
				scope: "openid profile",
			}),
		]);

		expect(capturedCodes).toHaveLength(2);
		for (const params of capturedCodes) {
			expect(params.client_id).toBe("client-1");
			expect(params.redirect_uri).toBe("https://example.test/cb");
		}
		// Neither captured session should carry a code identity binding.
		for (const session of capturedSessions) {
			expect(session).not.toHaveProperty("code");
			expect(session).not.toHaveProperty("code_client_id");
		}
	});
});

// D-6 (RFC 9700 §2.1.1): for public clients (`tokenEndpointAuthMethod === "none"`)
// PKCE/S256 is the ONLY authenticity gate on the code redemption — Basic/Post
// client auth is not available, so accepting `plain` or no code_challenge would
// allow anyone with the code to redeem it. The route must enforce these even
// when operator config sets `pkce.required = false`.
describe("D-6 (RFC 9700 §2.1.1): /authorize public-client PKCE/S256 mandatory", () => {
	// Canonical RFC 7636 example pair — a 43-char base64url-encoded SHA-256
	// digest of `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`. Using a
	// spec-valid challenge here means a future PKCE syntax check (e.g.,
	// "must be 43-128 chars from [A-Z][a-z][0-9]-._~") would not break
	// these tests — only the gate logic they target.
	const VALID_S256_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

	const publicClientRepo: ClientRepository = {
		findById: async () => ({
			clientId: "public-app",
			tokenEndpointAuthMethod: "none",
			allowedRedirectUris: ["https://spa.example.test/cb"],
			firstParty: true,
			allowedScopes: ["openid", "profile"],
		}),
		authenticate: async () => null,
	};

	async function buildPublicAuthorizeApp(opts: {
		captureCode?: (params: Parameters<CodeRepository["createCode"]>[0]) => void;
	}) {
		const app = express();
		app.use(express.json());
		app.use(express.urlencoded({ extended: false }));
		app.use((req, _res, next) => {
			(req as unknown as { session: Record<string, unknown> }).session = {
				isAuthenticated: true,
				user: { id: "user-1" },
			};
			next();
		});

		const codeRepo: CodeRepository = {
			createCode: async (params) => {
				opts.captureCode?.(params);
				return {
					code: "auth-code-public",
					client_id: params.client_id,
					redirect_uri: params.redirect_uri,
				};
			},
			findByCode: async () => null,
			consumeByCode: async () => null,
			removeByCode: async () => {},
		};

		const { router } = await createOAuthRouter(express, {
			registry: new GrantRegistry(),
			config: authorizeConfig,
			clientRepository: publicClientRepo,
			codeRepository: codeRepo,
			keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
		});
		app.use("/oauth", router);
		return app;
	}

	it("rejects public client when code_challenge is missing → invalid_request redirect", async () => {
		const app = await buildPublicAuthorizeApp({});
		const res = await request(app).get("/oauth/authorize").query({
			response_type: "code",
			client_id: "public-app",
			redirect_uri: "https://spa.example.test/cb",
			state: "state-abc",
			scope: "openid profile",
			// no code_challenge
		});
		expect(res.status).toBe(302);
		const location = new URL(res.headers.location);
		expect(location.origin + location.pathname).toBe("https://spa.example.test/cb");
		expect(location.searchParams.get("error")).toBe("invalid_request");
		expect(location.searchParams.get("error_description")).toBe(
			// #273: same message for every client — the public-client special
			// case became the universal rule.
			"code_challenge is required",
		);
		expect(location.searchParams.get("state")).toBe("state-abc");
	});

	it('rejects public client when code_challenge_method is "plain" → invalid_request redirect', async () => {
		const app = await buildPublicAuthorizeApp({});
		const res = await request(app).get("/oauth/authorize").query({
			response_type: "code",
			client_id: "public-app",
			redirect_uri: "https://spa.example.test/cb",
			state: "state-plain",
			scope: "openid profile",
			code_challenge: VALID_S256_CHALLENGE,
			code_challenge_method: "plain",
		});
		expect(res.status).toBe(302);
		const location = new URL(res.headers.location);
		expect(location.searchParams.get("error")).toBe("invalid_request");
		expect(location.searchParams.get("error_description")).toBe(
			// #273: `plain` is refused for every client that has not been opted
			// into it by registration — the message names the method it refused.
			'code_challenge_method "plain" is not supported',
		);
		expect(location.searchParams.get("state")).toBe("state-plain");
	});

	it("rejects public client when code_challenge_method is omitted (defaults to plain) → invalid_request redirect", async () => {
		// #273: RFC 7636 §4.3 makes an omitted method `plain`, and the resolver
		// reads it that way rather than quietly upgrading it to S256 — so
		// absence is refused exactly as an explicit `plain` is. (Pre-#273 this
		// was a public-client-only rule guarding against the operator-
		// configured `defaultMethod`; that knob is gone.)
		const app = await buildPublicAuthorizeApp({});
		const res = await request(app).get("/oauth/authorize").query({
			response_type: "code",
			client_id: "public-app",
			redirect_uri: "https://spa.example.test/cb",
			state: "state-omit",
			scope: "openid profile",
			code_challenge: VALID_S256_CHALLENGE,
			// no code_challenge_method → routes.mts treats absence as "plain"
		});
		expect(res.status).toBe(302);
		const location = new URL(res.headers.location);
		expect(location.searchParams.get("error")).toBe("invalid_request");
		expect(location.searchParams.get("error_description")).toBe(
			'code_challenge_method is required and must be "S256"',
		);
	});

	it("accepts public client with S256 + code_challenge → 302 redirect with code (happy path)", async () => {
		let captured: Parameters<CodeRepository["createCode"]>[0] | undefined;
		const app = await buildPublicAuthorizeApp({
			captureCode: (p) => {
				captured = p;
			},
		});
		const res = await request(app).get("/oauth/authorize").query({
			response_type: "code",
			client_id: "public-app",
			redirect_uri: "https://spa.example.test/cb",
			state: "state-ok",
			scope: "openid profile",
			code_challenge: VALID_S256_CHALLENGE,
			code_challenge_method: "S256",
		});
		expect(res.status).toBe(302);
		const location = new URL(res.headers.location);
		expect(location.origin + location.pathname).toBe("https://spa.example.test/cb");
		expect(location.searchParams.get("code")).toBe("auth-code-public");
		expect(location.searchParams.get("state")).toBe("state-ok");
		expect(location.searchParams.get("error")).toBeNull();
		expect(captured?.client_id).toBe("public-app");
		expect(captured?.redirect_uri).toBe("https://spa.example.test/cb");
		// The /authorize gate is only the first half of the public-client
		// protection. The verifier check at /token requires the challenge to
		// have been persisted on the Code record — if a future refactor drops
		// either field from `createCode`, the public-client gate would still
		// pass requests through but `/token` would have no verifier to check
		// against. Asserting persistence here closes that regression window.
		expect(captured?.code_challenge).toBe(VALID_S256_CHALLENGE);
		expect(captured?.code_challenge_method).toBe("S256");
	});
});

/*
 * #406 — this module reads `subjectRevocation` on its own.
 *
 * `oauthModule` got the policy first, but a composition can mount the grants
 * without the routes, and that composition would then still boot with the
 * watermark unfilled and undeclared: `verifyJwt` skips the check, the #376
 * refresh-redemption gate is inert, and nothing says so. That is the hole
 * #406 exists to close, one module over — found in review on the PR that
 * closed it everywhere else.
 */
describe("oauthAuthorizationModule — declared absence for subjectRevocation (#406)", () => {
	const withoutDeclaration = () => {
		const base = makeValidAppConfig() as Record<string, unknown> & {
			oauth: Record<string, unknown>;
		};
		const revocation = { ...(base.oauth.revocation as Record<string, unknown>) };
		delete revocation.subject;
		return { ...base, oauth: { ...base.oauth, revocation } } as ReturnType<
			typeof makeValidAppConfig
		>;
	};

	it("refuses boot when the slot is unfilled and undeclared", async () => {
		const config = withoutDeclaration();
		await expect(
			createTestApp({
				modules: [oauthAuthorizationModule({ config })],
				bootstrapComponents: {
					config,
					pathResolver: (s: string) => s,
					clientRepository: { findById: async () => null, authenticate: async () => null },
					codeRepository: {
						createCode: async () => ({}),
						findByCode: async () => null,
						consumeByCode: async () => null,
						removeByCode: async () => {},
					},
					keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
				} as never,
			}),
		).rejects.toMatchObject({
			reason: "component-absence-undeclared",
			details: { componentKey: "subjectRevocation" },
		});
	});

	it("boots once the deployment declares the capability absent", async () => {
		const config = makeValidAppConfig();
		await expect(
			createTestApp({
				modules: [oauthAuthorizationModule({ config })],
				bootstrapComponents: {
					config,
					pathResolver: (s: string) => s,
					clientRepository: { findById: async () => null, authenticate: async () => null },
					codeRepository: {
						createCode: async () => ({}),
						findByCode: async () => null,
						consumeByCode: async () => null,
						removeByCode: async () => {},
					},
					keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
				} as never,
			}),
		).resolves.toBeDefined();
	});
});
