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
 * R3 — logout must reach the `session` grant's access token.
 *
 * The grant mints straight from an authenticated browser session, which is
 * the BFF / proxy topology: the browser holds the cookie, the BFF holds the
 * access token. Until this fix the token carried no `sid`, so none of the
 * liveness machinery could see it — `/oauth/logout` deleted the `UserSession`
 * record and revoked every refresh family, and this token went on working for
 * the rest of its lifetime (3600s by default).
 *
 * The unit tests in `session.test.mts` pin the claim; this file pins the
 * consequence, through the real router: after a logout, the same token is
 * refused at `/oauth/userinfo` and reports `active: false` at
 * `/oauth/introspect`.
 */

import { createSecretKey } from "node:crypto";
import {
	type AppConfig,
	type ClientRepository,
	type CodeRepository,
	createSymmetricKeyStore,
	type FederationTokenStore,
	type GrantDependencies,
	type RefreshTokenFamilyRevocation,
	type SessionFamilyIndex,
	type SessionFederationIndex,
	type SessionRPRegistry,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { GrantRegistry } from "@o3co/auth-provider-core/testing";
import express from "express";
import { decodeJwt, SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createSessionGrant } from "#/grants/session.mjs";
import { createOAuthRouter } from "#/routes.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const ISSUER = "https://auth.example.com";
const CLIENT_ID = "bff-app";
const CLIENT_SECRET = "bff-secret";
const BASIC = `Basic ${Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64")}`;
const SID = "sid-bff";
const SUB = "user-bff";

const keyStore = createSymmetricKeyStore(SECRET);
const secretKey = createSecretKey(Buffer.from(SECRET));

const config = {
	oauth: {
		jwt: { issuer: ISSUER },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		grants: { session: { enabled: true } },
	},
	rateLimit: { failMode: "open" as const },
	endpoints: { login: { url: "/login" } },
} as unknown as AppConfig;

const clientRecord = {
	clientId: CLIENT_ID,
	tokenEndpointAuthMethod: "client_secret_basic" as const,
	allowedRedirectUris: [],
	allowedScopes: ["profile"],
	allowedGrantTypes: ["session"],
	postLogoutRedirectUris: [],
};

const clientRepository: ClientRepository = {
	findById: async (id) => (id === CLIENT_ID ? clientRecord : null),
	authenticate: async (id, secret) =>
		id === CLIENT_ID && secret === CLIENT_SECRET ? clientRecord : null,
};

const codeRepository: CodeRepository = {
	createCode: async () => ({ code: "unused", client_id: CLIENT_ID, redirect_uri: "" }),
	findByCode: async () => null,
	consumeByCode: async () => null,
	removeByCode: async () => {},
};

/** A `UserSessionStore` backed by a real Map, so the logout cascade's delete is observable. */
function makeUserSessionStore(): UserSessionStore {
	const sessions = new Map<string, UserSession>([
		[
			SID,
			{
				sid: SID,
				sub: SUB,
				authTime: new Date(),
				createdAt: new Date(),
				expiresAt: new Date(Date.now() + 3_600_000),
				claims: { email: "bff@example.com", name: "Bff User" },
			},
		],
	]);
	return {
		kind: "memory",
		create: async () => {},
		get: async (sid: string) => sessions.get(sid) ?? null,
		delete: async (sid: string) => {
			sessions.delete(sid);
		},
	};
}

async function buildApp(userSessionStore: UserSessionStore) {
	const registry = new GrantRegistry();
	registry.register(
		"session",
		createSessionGrant({ config, keyStore } as unknown as GrantDependencies),
	);

	const { router } = await createOAuthRouter(express, {
		registry,
		config,
		clientRepository,
		codeRepository,
		keyStore,
		userSessionStore,
		sessionRPRegistry: {
			kind: "memory",
			registerRP: vi.fn(async () => {}),
			listRPs: vi.fn(async () => []),
			removeBySid: vi.fn(async () => {}),
		} as unknown as SessionRPRegistry,
		sessionFamilyIndex: {
			kind: "memory",
			addFamilyId: vi.fn(async () => {}),
			listFamilyIds: vi.fn(async () => []),
			removeBySid: vi.fn(async () => {}),
		} as unknown as SessionFamilyIndex,
		sessionFederationIndex: {
			kind: "memory",
			addFederation: vi.fn(async () => {}),
			listFederations: vi.fn(async () => []),
			removeFederation: vi.fn(async () => {}),
			removeBySid: vi.fn(async () => {}),
		} as unknown as SessionFederationIndex,
		federationTokenStore: {
			kind: "memory",
			attach: vi.fn(async () => {}),
			get: vi.fn(async () => null),
			update: vi.fn(async () => {}),
			delete: vi.fn(async () => {}),
			removeBySid: vi.fn(async () => {}),
		} as unknown as FederationTokenStore,
		refreshTokenFamilyRevocation: {
			isFamilyRevoked: vi.fn(async () => false),
			revokeFamily: vi.fn(async () => {}),
		} as unknown as RefreshTokenFamilyRevocation,
	});

	const app = express();
	app.use((req, _res, next) => {
		(req as unknown as { session: Record<string, unknown> }).session = {
			isAuthenticated: true,
			user: { id: SUB },
			sid: SID,
		};
		next();
	});
	app.use("/oauth", router);
	return app;
}

/** The id_token an RP presents as `id_token_hint` at the end-session endpoint. */
async function mintIdTokenHint(): Promise<string> {
	return new SignJWT({ sub: SUB, aud: CLIENT_ID, sid: SID })
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "JWT" })
		.setIssuer(ISSUER)
		.setIssuedAt()
		.setExpirationTime("1h")
		.sign(secretKey);
}

describe("session grant + logout (R3)", () => {
	it("the minted access token carries the browser session's sid", async () => {
		const app = await buildApp(makeUserSessionStore());

		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", BASIC)
			.type("form")
			.send({ grant_type: "session" });

		expect(res.status).toBe(200);
		const claims = decodeJwt(res.body.access_token as string) as Record<string, unknown>;
		expect(claims.sid).toBe(SID);
		expect(claims.sub).toBe(SUB);
	});

	it("the token works before logout and is refused after it", async () => {
		const store = makeUserSessionStore();
		const app = await buildApp(store);

		const tokenRes = await request(app)
			.post("/oauth/token")
			.set("Authorization", BASIC)
			.type("form")
			.send({ grant_type: "session", scope: "profile" });
		expect(tokenRes.status).toBe(200);
		const accessToken = tokenRes.body.access_token as string;

		// Before: the token is a live credential at both surfaces.
		const beforeUserinfo = await request(app)
			.get("/oauth/userinfo")
			.set("Authorization", `Bearer ${accessToken}`);
		expect(beforeUserinfo.status).toBe(200);
		expect(beforeUserinfo.body.sub).toBe(SUB);

		const beforeIntrospect = await request(app)
			.post("/oauth/introspect")
			.set("Authorization", `Bearer ${accessToken}`)
			.type("form")
			.send({ token: accessToken });
		expect(beforeIntrospect.status).toBe(200);
		expect(beforeIntrospect.body.active).toBe(true);

		// The logout an RP initiates: the cascade deletes the UserSession.
		const logoutRes = await request(app)
			.post("/oauth/logout")
			.type("form")
			.send({ id_token_hint: await mintIdTokenHint() });
		expect(logoutRes.status).toBe(200);
		expect(await store.get(SID)).toBeNull();

		// After: the same token no longer authorizes anything.
		const afterUserinfo = await request(app)
			.get("/oauth/userinfo")
			.set("Authorization", `Bearer ${accessToken}`);
		expect(afterUserinfo.status).toBe(401);
		expect(afterUserinfo.body.error_description).toBe("session_invalid");

		const afterIntrospect = await request(app)
			.post("/oauth/introspect")
			.set("Authorization", `Bearer ${accessToken}`)
			.type("form")
			.send({ token: accessToken });
		expect(afterIntrospect.status).toBe(200);
		expect(afterIntrospect.body.active).toBe(false);
	});
});
