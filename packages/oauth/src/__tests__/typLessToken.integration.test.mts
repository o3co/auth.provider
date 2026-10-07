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
 * A token with no `typ` header is refused on every route that verifies a
 * token this provider signed: the refresh grant answers `400 invalid_grant`,
 * a protected resource `401`, introspection `active: false`, RP-initiated
 * logout `400`. No setting admits one: the module's schema refuses the
 * former switch, and a section handed to the router by hand that still
 * carries it is not obeyed either.
 *
 * Driven through the real router (`createOAuthRouter`) and the real refresh
 * grant, with a token signed by the router's own key, so the missing `typ`
 * is the only thing wrong with it.
 */

import { createSecretKey } from "node:crypto";
import {
	type AppConfig,
	type ClientRepository,
	type CodeRepository,
	createMemoryAccessTokenDenylist,
	createSymmetricKeyStore,
	type FederationTokenStore,
	type RefreshTokenFamilyRevocation,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { GrantRegistry, resolverForTests } from "@o3co/auth-provider-core/testing";
import express from "express";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createRefreshTokenGrant } from "#/grants/refreshToken.mjs";
import { createOAuthRouter } from "#/routes.mjs";
import { codeRecord } from "./_helpers/codeRecord.mjs";
import { grantSettingsFrom } from "./_helpers/grantSettings.mjs";
import { routerInputsOf } from "./_helpers/sections.mjs";
import { lifecycleStoreOver, livenessOver } from "./_helpers/sessionLifecycle.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const ISSUER = "https://auth.example.com";
const CLIENT_ID = "rp";
const CLIENT_SECRET = "rp-secret";
const SID = "sid-1";
const SUB = "user-1";
const FAMILY = "fam-1";
const FEDERATION = "google";

/** Built by hand, past the module's schema: it still carries the removed switch. */
const config = {
	oauth: {
		jwt: { issuer: ISSUER, legacyTypAccept: true },
		accessToken: { defaultExpiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		grants: { refresh_token: { enabled: true } },
	},
	rateLimit: { failMode: "open" as const },
	endpoints: { login: { url: "/login" } },
} as unknown as AppConfig;

const clientRecord = {
	clientId: CLIENT_ID,
	tokenEndpointAuthMethod: "client_secret_basic" as const,
	allowedRedirectUris: [],
	allowedScopes: ["openid", "profile"],
	allowedGrantTypes: ["refresh_token"],
	postLogoutRedirectUris: [],
	allowedAzpForFederationToken: true,
};

const clientRepository: ClientRepository = {
	findById: async (id) => (id === CLIENT_ID ? clientRecord : null),
	authenticate: async (id, secret) =>
		id === CLIENT_ID && secret === CLIENT_SECRET ? clientRecord : null,
};

const codeRepository: CodeRepository = {
	createCode: async () => codeRecord({ code: "unused", client_id: CLIENT_ID, redirect_uri: "" }),
	findByCode: async () => null,
	consumeByCode: async () => null,
	removeByCode: async () => {},
};

async function buildApp(): Promise<express.Express> {
	const keyStore = createSymmetricKeyStore(SECRET, "v0");
	const session: UserSession = {
		sid: SID,
		sub: SUB,
		authTime: new Date(),
		createdAt: new Date(),
		expiresAt: new Date(Date.now() + 3_600_000),
		claims: { name: "User" },
		amr: undefined,
		authentication: undefined,
	};
	const userSessionStore: UserSessionStore = {
		kind: "memory",
		create: async () => {},
		get: async (sid) => (sid === SID ? session : null),
		delete: async () => {},
	};
	const registry = new GrantRegistry();
	registry.register(
		"refresh_token",
		createRefreshTokenGrant({
			...grantSettingsFrom(config),
			keyStore,
			sessionRequirementResolver: resolverForTests([]),
		}),
	);

	const { router } = await createOAuthRouter(express, {
		requirements: resolverForTests([]),
		registry,
		...routerInputsOf(config),
		clientRepository,
		codeRepository,
		keyStore,
		accessTokenDenylist: createMemoryAccessTokenDenylist(),
		userSessionStore,
		sessionLifecycle: livenessOver(userSessionStore, [FEDERATION]),
		sessionLifecycleStore: lifecycleStoreOver(userSessionStore),
		federationTokenStore: {
			kind: "memory",
			attach: async () => {},
			get: async () => null,
			delete: async () => {},
			removeBySid: async () => {},
		} as unknown as FederationTokenStore,
		refreshTokenFamilyRevocation: {
			isFamilyRevoked: async () => false,
			revokeFamily: async () => {},
		} as unknown as RefreshTokenFamilyRevocation,
	});
	const app = express();
	app.use("/oauth", router);
	return app;
}

/** A token signed by the router's key, its protected header carrying no `typ`. */
async function mintTypLess(claims: Record<string, unknown>): Promise<string> {
	const now = Math.floor(Date.now() / 1000);
	return new SignJWT({ sub: SUB, ...claims })
		.setProtectedHeader({ alg: "HS256", kid: "v0" })
		.setIssuer(ISSUER)
		.setIssuedAt(now)
		.setExpirationTime(now + 600)
		.sign(createSecretKey(Buffer.from(SECRET)));
}

const accessTokenClaims = {
	aud: CLIENT_ID,
	azp: CLIENT_ID,
	client_id: CLIENT_ID,
	sid: SID,
	family_id: FAMILY,
	jti: "at-1",
};

type Call = (app: express.Express, token: string) => request.Test;

const ROUTES: ReadonlyArray<{
	readonly name: string;
	readonly call: Call;
	readonly claims: Record<string, unknown>;
	readonly refused: { readonly status: number; readonly body?: Record<string, unknown> };
}> = [
	{
		name: "POST /oauth/token (refresh_token)",
		call: (app, token) =>
			request(app)
				.post("/oauth/token")
				.auth(CLIENT_ID, CLIENT_SECRET)
				.type("form")
				.send({ grant_type: "refresh_token", refresh_token: token }),
		// No `payload.type` either: nothing about it marks it as anything.
		claims: { aud: CLIENT_ID, azp: CLIENT_ID, family_id: FAMILY, jti: "rt-1" },
		refused: { status: 400, body: { error: "invalid_grant" } },
	},
	{
		name: "POST /oauth/token (refresh_token), the token carrying payload.type refresh",
		call: (app, token) =>
			request(app)
				.post("/oauth/token")
				.auth(CLIENT_ID, CLIENT_SECRET)
				.type("form")
				.send({ grant_type: "refresh_token", refresh_token: token }),
		claims: { type: "refresh", aud: CLIENT_ID, azp: CLIENT_ID, family_id: FAMILY, jti: "rt-1" },
		refused: { status: 400, body: { error: "invalid_grant" } },
	},
	{
		name: "POST /oauth/introspect (client authentication)",
		call: (app, token) =>
			request(app)
				.post("/oauth/introspect")
				.auth(CLIENT_ID, CLIENT_SECRET)
				.type("form")
				.send({ token }),
		claims: accessTokenClaims,
		refused: { status: 200, body: { active: false } },
	},
	{
		name: "POST /oauth/introspect (bearer self-introspection)",
		call: (app, token) =>
			request(app)
				.post("/oauth/introspect")
				.set("Authorization", `Bearer ${token}`)
				.type("form")
				.send({ token }),
		claims: accessTokenClaims,
		refused: { status: 200, body: { active: false } },
	},
	{
		name: "GET /oauth/userinfo",
		call: (app, token) =>
			request(app).get("/oauth/userinfo").set("Authorization", `Bearer ${token}`),
		claims: accessTokenClaims,
		refused: { status: 401, body: { error: "invalid_token" } },
	},
	{
		name: "POST /oauth/federation/:name/token",
		call: (app, token) =>
			request(app)
				.post(`/oauth/federation/${FEDERATION}/token`)
				.set("Authorization", `Bearer ${token}`),
		claims: accessTokenClaims,
		refused: { status: 401 },
	},
	{
		name: "POST /oauth/federation/:name/logout",
		call: (app, token) =>
			request(app)
				.post(`/oauth/federation/${FEDERATION}/logout`)
				.set("Authorization", `Bearer ${token}`)
				.type("form")
				.send({}),
		claims: accessTokenClaims,
		refused: { status: 401 },
	},
	{
		name: "POST /oauth/logout (id_token_hint)",
		call: (app, token) =>
			request(app).post("/oauth/logout").type("form").send({ id_token_hint: token }),
		claims: { aud: CLIENT_ID, sid: SID },
		refused: { status: 400 },
	},
];

describe("a token with no typ header is refused on every route that verifies one", () => {
	it.each(ROUTES)("$name", async ({ call, claims, refused }) => {
		const app = await buildApp();

		const res = await call(app, await mintTypLess(claims));

		expect(res.status).toBe(refused.status);
		if (refused.body !== undefined) expect(res.body).toMatchObject(refused.body);
	});
});
