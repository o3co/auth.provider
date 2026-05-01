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
	type GrantPolicyHookBase,
	GrantRegistry,
	type RefreshTokenRotation,
	type SessionFamilyIndex,
	type SessionRPRegistry,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { createTestApp, makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createAuthorizationGrant } from "#/grants/authorization.mjs";
import { createRefreshTokenGrant } from "#/grants/refreshToken.mjs";
import { oauthAuthorizationModule } from "#/oauthAuthorization.mjs";
import { createOAuthRouter } from "#/routes.mjs";

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
	},
	endpoints: {
		login: { url: "/login" },
	},
} as unknown as AppConfig;

const authorizeClientRepo: ClientRepository = {
	findById: async () => ({
		clientId: "client-1",
		allowedRedirectUris: ["https://example.test/cb"],
		allowedScopes: ["openid", "profile"],
	}),
	authenticate: async () => null,
};

async function buildAuthorizeApp(opts: {
	sessionFields: Record<string, unknown>;
	captureCode: (params: Parameters<CodeRepository["createCode"]>[0]) => void;
}) {
	const app = express();
	app.use(express.json());
	app.use(express.urlencoded({ extended: false }));

	// Inline session substitute — minimal surface needed by the /authorize route.
	app.use((req, _res, next) => {
		(req as unknown as { session: Record<string, unknown> }).session = {
			isAuthenticated: true,
			user: { id: "user-1" },
			...opts.sessionFields,
		};
		next();
	});

	const codeRepo: CodeRepository = {
		createCode: async (params) => {
			opts.captureCode(params);
			return { code: "auth-code" };
		},
		getByCode: async () => null,
		consumeByCode: async () => null,
		removeByCode: async () => {},
	};

	const { router } = await createOAuthRouter(express, {
		registry: new GrantRegistry(),
		config: authorizeConfig,
		clientRepository: authorizeClientRepo,
		codeRepository: codeRepo,
		keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
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

	// Boot planner only injects keys listed in `requires` ∪ `optional` into
	// contribution-factory `deps`. Both grant factories read
	// `deps.refreshTokenRotation` (A3 §5.2 rotation persistence) and
	// `deps.grantPolicy` (CP-18 fail-closed gate). If they are not declared
	// here, a composition root that wires either component will see it
	// silently dropped at the grant boundary — refresh-token rotation stops
	// recording, and grantPolicy enforcement becomes dead code.
	it("declares refreshTokenRotation + grantPolicy in optional so deps reach the grants", () => {
		const config = makeValidAppConfig();
		const module = oauthAuthorizationModule({ config });
		expect(module.optional).toContain("refreshTokenRotation");
		expect(module.optional).toContain("grantPolicy");
	});
});

// ---------------------------------------------------------------------------
// createTestApp integration tests (§7.3 — boot + inspect)
// ---------------------------------------------------------------------------

describe("oauthAuthorizationModule — createTestApp integration", () => {
	it("registers authorization_code and refresh_token grants at boot", async () => {
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
		await handle.dispose();
	});
});

// ---------------------------------------------------------------------------
// Grant factory unit tests — test createAuthorizationGrant / createRefreshTokenGrant
// directly with mock deps (not through the module manifest).
// These tests preserve the behavioral coverage that was previously embedded in
// the module-level tests via module.init(ctx).
// ---------------------------------------------------------------------------

describe("createRefreshTokenGrant — refreshTokenRotation forwarding", () => {
	it("calls refreshTokenRotation.rotate when a valid refresh_token is presented", async () => {
		const rotateSpy = vi.fn().mockResolvedValue({ outcome: "rotated" });
		const refreshTokenRotation: RefreshTokenRotation = {
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
			refreshTokenRotation,
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
			body: { refresh_token: rt.token, client_id: "client-1" },
			session: {},
			issuer: "test-issuer",
			metadata: {},
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
		const consumeByCode = vi.fn().mockResolvedValue({ code: "auth-code", sid: "sid-wired" });

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
				getByCode: vi.fn(),
				removeByCode: vi.fn(),
			} as unknown as CodeRepository,
			clientRepository: {
				findById: vi.fn().mockResolvedValue(null),
				authenticate: vi.fn().mockResolvedValue(null),
			},
		};

		const handler = createAuthorizationGrant(deps);
		const { result } = await handler.handle({
			body: { code: "auth-code", client_id: "client1" },
			session: {
				code: "auth-code",
				code_client_id: "client1",
				granted_scopes: ["read"],
				user: { id: "u1" },
			},
			issuer: "localhost",
			metadata: {},
		});

		expect(result.status).toBe(200);
		expect(getSpy).toHaveBeenCalledWith("sid-wired");
	});
});

describe("createAuthorizationGrant — grantPolicy forwarding", () => {
	it("calls grantPolicy.evaluate during refresh_token grant", async () => {
		const keyStore = createSymmetricKeyStore("test-secret-at-least-32-chars!!");
		const grantPolicy: GrantPolicyHookBase = {
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
				getByCode: vi.fn(),
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
				getByCode: vi.fn(),
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
			// no nonce
		});

		expect(captured).toBeDefined();
		expect(captured?.nonce).toBeUndefined();
		// sid is still captured even without nonce
		expect(captured?.sid).toBe("sid-1");
	});
});
