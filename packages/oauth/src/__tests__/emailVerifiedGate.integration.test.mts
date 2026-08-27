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

/**
 * Issue #297 — `oauth.requireEmailVerified` gates token issuance for an
 * end-user subject on the verification state the Store published.
 *
 * Two enforcement points, because they are the two that hold the user's
 * session at issuance: `/authorize` (before a code is minted) and the
 * `session` grant (which mints straight from the browser session). Gating one
 * and not the other would leave the deployment believing it had a gate.
 */

import {
	type AppConfig,
	type ClientRepository,
	type CodeRepository,
	createSymmetricKeyStore,
	type GrantHandler,
	type PublicClient,
} from "@o3co/auth-provider-core";
import { GrantRegistry } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createOAuthRouter } from "#/routes.mjs";

const CLIENT_ID = "client-a";
const REDIRECT_URI = "https://app.example/cb";

const makeConfig = (requireEmailVerified: boolean): AppConfig =>
	({
		oauth: {
			jwt: { issuer: "https://issuer.example" },
			accessToken: { expiresIn: 300 },
			authorize: { allowUnmarkedClients: false },
			requireEmailVerified,
			grants: { authorization_code: { pkce: { requireS256: false } } },
		},
		rateLimit: { failMode: "open" as const },
		endpoints: { login: { url: "/login" } },
	}) as unknown as AppConfig;

const okGrant = (): GrantHandler => ({
	async handle() {
		return { result: { status: 200, tokens: { access_token: "at", token_type: "Bearer" } } };
	},
});

const makeApp = async (opts: { requireEmailVerified: boolean; user: Record<string, unknown> }) => {
	const record = {
		clientId: CLIENT_ID,
		tokenEndpointAuthMethod: "none" as const,
		allowedRedirectUris: [REDIRECT_URI],
		allowedScopes: ["read"],
		firstParty: true,
	} as unknown as PublicClient;

	const clientRepository: ClientRepository = {
		findById: async (id) => (id === CLIENT_ID ? record : null),
		authenticate: async () => null,
	};
	const codeRepository: CodeRepository = {
		createCode: async () => ({ code: "code-x", client_id: CLIENT_ID, redirect_uri: REDIRECT_URI }),
		findByCode: async () => null,
		consumeByCode: async () => null,
		removeByCode: async () => {},
	};

	const registry = new GrantRegistry();
	registry.register("authorization_code", okGrant());

	const { router } = await createOAuthRouter(express, {
		registry,
		config: makeConfig(opts.requireEmailVerified),
		clientRepository,
		codeRepository,
		keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
	});

	const app = express();
	app.use(express.json());
	app.use((req, _res, next) => {
		(req as unknown as { session: Record<string, unknown> }).session = {
			isAuthenticated: true,
			user: opts.user,
		};
		next();
	});
	app.use("/oauth", router);
	return app;
};

const authorize = (app: express.Express) =>
	request(app).get("/oauth/authorize").query({
		response_type: "code",
		client_id: CLIENT_ID,
		redirect_uri: REDIRECT_URI,
		state: "xyz",
		code_challenge: "abc",
		code_challenge_method: "plain",
	});

const errorOf = (res: request.Response): string | null => {
	const location = res.headers.location as string | undefined;
	if (location !== undefined) {
		try {
			return new URL(location).searchParams.get("error");
		} catch {
			return null;
		}
	}
	return typeof res.body?.error === "string" ? res.body.error : null;
};

describe("/authorize email-verified gate (#297)", () => {
	it("refuses when the gate is on and the Store published no verification", async () => {
		const app = await makeApp({ requireEmailVerified: true, user: { id: "u1" } });
		expect(errorOf(await authorize(app))).toBe("access_denied");
	});

	it("refuses when the Store published an explicit false", async () => {
		const app = await makeApp({
			requireEmailVerified: true,
			user: { id: "u1", emailVerified: false },
		});
		expect(errorOf(await authorize(app))).toBe("access_denied");
	});

	it("admits when the Store published true", async () => {
		const app = await makeApp({
			requireEmailVerified: true,
			user: { id: "u1", emailVerified: true },
		});
		expect(errorOf(await authorize(app))).not.toBe("access_denied");
	});

	it("is inert when the gate is off, whatever the Store published", async () => {
		// Off is the default, and a deployment whose Store does not model the
		// field must be entirely unaffected.
		const app = await makeApp({ requireEmailVerified: false, user: { id: "u1" } });
		expect(errorOf(await authorize(app))).not.toBe("access_denied");
	});

	it("refuses before minting a code, and keeps state on the redirect", async () => {
		const app = await makeApp({ requireEmailVerified: true, user: { id: "u1" } });
		const res = await authorize(app);
		expect(res.status).toBe(302);
		const location = new URL(res.headers.location as string);
		expect(location.origin + location.pathname).toBe(REDIRECT_URI);
		expect(location.searchParams.get("code")).toBeNull();
		expect(location.searchParams.get("state")).toBe("xyz");
	});
});
