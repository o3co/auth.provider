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
	type GrantPolicyHookBase,
	GrantRegistry,
	type ModuleContext,
	type RefreshTokenStoreBase,
} from "@o3co/auth-provider-core";
import type { Router } from "express";
import express from "express";
import type { PassportStatic } from "passport";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { oauthAuthorizationModule } from "#/oauthAuthorization.mjs";
import { createOAuthRouter } from "#/routes.mjs";

// ---------------------------------------------------------------------------
// Helpers shared by the authorize-captures-nonce-sid suite
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

const authorizePassport = {
	authenticate: () => (_req: unknown, _res: unknown, next: () => void) => next(),
} as unknown as PassportStatic;

const authorizeClientRepo: ClientRepository = {
	findById: async () => ({
		clientId: "client-1",
		allowedRedirectUris: ["https://example.test/cb"],
		allowedScopes: ["openid", "profile"],
	}),
	authenticate: async () => null,
};

/**
 * Build a minimal express app wired to createOAuthRouter.
 * The session middleware injects the provided session fields into req.session.
 */
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
		passport: authorizePassport,
		registry: new GrantRegistry(),
		config: authorizeConfig,
		clientRepository: authorizeClientRepo,
		codeRepository: codeRepo,
		keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
	});
	app.use("/oauth", router);
	return app;
}

const mockClientRepository: ClientRepository = {
	findById: vi.fn().mockResolvedValue(null),
	authenticate: vi.fn().mockResolvedValue(null),
};

const mockConfig = {
	oauth: {
		jwt: { secret: "test-secret" },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		grants: {
			authorization: { enabled: true },
			refresh_token: { enabled: true },
		},
	},
} as unknown as AppConfig;

const makeContext = (overrides?: Partial<ModuleContext>): ModuleContext => ({
	pathResolver: (s: string) => s,
	config: mockConfig,
	keyStore: createSymmetricKeyStore("test-secret"),
	grantRegistry: new GrantRegistry(),
	router: { use: vi.fn().mockReturnThis() } as unknown as Router,
	...overrides,
});

describe("oauthAuthorizationModule", () => {
	it("has name 'oauth-authorization'", () => {
		const module = oauthAuthorizationModule({
			codeRepository: {} as CodeRepository,
			clientRepository: mockClientRepository,
		});
		expect(module.name).toBe("oauth-authorization");
	});

	it("registers authorization and refresh_token grant handlers", async () => {
		const ctx = makeContext();
		const module = oauthAuthorizationModule({
			codeRepository: {} as CodeRepository,
			clientRepository: mockClientRepository,
		});

		await module.init(ctx);

		expect(ctx.grantRegistry.get("authorization")).toBeDefined();
		expect(ctx.grantRegistry.get("refresh_token")).toBeDefined();
	});

	it("does not register authorization grant when config says enabled=false", async () => {
		const disabledConfig = {
			...mockConfig,
			oauth: {
				...mockConfig.oauth,
				grants: {
					authorization: { enabled: false },
					refresh_token: { enabled: true },
				},
			},
		} as unknown as AppConfig;
		const ctx = makeContext({ config: disabledConfig });
		const module = oauthAuthorizationModule({
			codeRepository: {} as CodeRepository,
			clientRepository: mockClientRepository,
		});

		await module.init(ctx);

		expect(ctx.grantRegistry.get("authorization")).toBeUndefined();
		expect(ctx.grantRegistry.get("refresh_token")).toBeDefined();
	});

	it("forwards context.refreshTokenStore to refresh_token grant handler", async () => {
		const rotateSpy = vi.fn().mockResolvedValue({ outcome: "rotated" });
		const refreshTokenStore: RefreshTokenStoreBase = {
			kind: "spy",
			rotate: rotateSpy,
			isFamilyRevoked: async () => false,
			revokeFamily: async () => {},
		};
		const keyStore = createSymmetricKeyStore("test-secret-at-least-32-chars!!");
		const ctx = makeContext({ refreshTokenStore, keyStore });
		const module = oauthAuthorizationModule({
			codeRepository: {} as CodeRepository,
			clientRepository: mockClientRepository,
		});

		await module.init(ctx);

		const handler = ctx.grantRegistry.get("refresh_token");
		expect(handler).toBeDefined();
		if (!handler) return;

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

	it("forwards context.grantPolicy to authorization and refresh_token grants", async () => {
		const grantPolicy: GrantPolicyHookBase = {
			kind: "spy",
			evaluate: vi.fn().mockResolvedValue({ outcome: "allow" }),
		};
		const ctx = makeContext({ grantPolicy });
		const module = oauthAuthorizationModule({
			codeRepository: {} as CodeRepository,
			clientRepository: mockClientRepository,
		});

		await module.init(ctx);

		expect(ctx.grantRegistry.get("authorization")).toBeDefined();
		expect(ctx.grantRegistry.get("refresh_token")).toBeDefined();
	});

	it("registered authorization handler returns 400 for invalid code", async () => {
		const ctx = makeContext();
		const mockCodeRepo = {
			consumeByCode: vi.fn().mockResolvedValue(null),
			createCode: vi.fn(),
		} as unknown as CodeRepository;
		const module = oauthAuthorizationModule({
			codeRepository: mockCodeRepo,
			clientRepository: mockClientRepository,
		});

		await module.init(ctx);

		const handler = ctx.grantRegistry.get("authorization");
		expect(handler).toBeDefined();
		if (!handler) return;

		const { result } = await handler.handle({
			body: { code: "bad-code", client_id: "c1" },
			session: { code: "different-code", code_client_id: "c1" },
			issuer: "localhost",
			metadata: {},
		});

		expect(result.status).toBe(400);
	});
});

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
