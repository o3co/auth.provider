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
 * End-to-end coverage for the canonical confidential-client shape: the
 * authorization code is exchanged over a back channel, so the `/token` request
 * carries no end-user cookie.
 *
 * The unit tests for the grant all inject `session: { user: { id: "u1" } }`
 * into the grant context, which only models the same-browser / BFF topology.
 * That masked a defect where the access token's `sub` was read from the
 * token-request session instead of the UserSession the code is bound to: with
 * no cookie the claim was simply absent, and every consumer of `sub`
 * downstream broke. This file exercises the grant and the userinfo route
 * together so the two stay consistent.
 */

import {
	type ClientRepository,
	type CodeRepository,
	createSymmetricKeyStore,
	type GrantDependencies,
	type RefreshTokenFamilyRevocation,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createAuthorizationGrant } from "#/grants/authorization.mjs";
import { createRouter } from "#/routes/userinfo.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const ISSUER = "https://auth.example.com";
const RP_URI = "https://rp.example/cb";
const CLIENT_ID = "confidential-client";
const SID = "sid-backchannel";
const SUB = "u-backchannel";

const keyStore = createSymmetricKeyStore(SECRET);

const userSession: UserSession = {
	sid: SID,
	sub: SUB,
	authTime: new Date("2026-04-21T00:00:00Z"),
	createdAt: new Date(),
	expiresAt: new Date(Date.now() + 3_600_000),
	claims: {
		email: "alice@example.com",
		emailVerified: true,
		name: "Alice",
	},
};

const config = {
	oauth: {
		jwt: { secret: SECRET, issuer: ISSUER },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		grants: { authorization_code: { enabled: true } },
	},
} as unknown as GrantDependencies["config"];

const clientRepository: ClientRepository = {
	findById: vi.fn().mockResolvedValue(null),
	authenticate: vi.fn().mockResolvedValue(null),
};

const userSessionStore = {
	kind: "memory",
	create: vi.fn(async () => {}),
	get: vi.fn(async (sid: string) => (sid === SID ? userSession : null)),
	delete: vi.fn(async () => {}),
} as unknown as UserSessionStore;

const refreshTokenFamilyRevocation = {
	isFamilyRevoked: vi.fn(async () => false),
	revokeFamily: vi.fn(async () => {}),
} as unknown as RefreshTokenFamilyRevocation;

/** Exchange a code the way a confidential client does: no cookie on the request. */
async function exchangeCodeWithoutCookie() {
	const handler = createAuthorizationGrant({
		config,
		keyStore,
		clientRepository,
		codeRepository: {
			consumeByCode: vi.fn().mockResolvedValue({
				code: "the-code",
				client_id: CLIENT_ID,
				redirect_uri: RP_URI,
				sid: SID,
				grantedScope: ["openid", "email"],
			}),
			createCode: vi.fn(),
			findByCode: vi.fn(),
			removeByCode: vi.fn(),
		} as unknown as CodeRepository,
		userSessionStore,
		sessionFamilyIndex: {
			kind: "memory",
			addFamilyId: vi.fn(async () => {}),
			listFamilyIds: vi.fn(async () => []),
			removeBySid: vi.fn(async () => {}),
		},
		sessionRPRegistry: {
			kind: "memory",
			registerRP: vi.fn(async () => {}),
			listRPs: vi.fn(async () => []),
			removeBySid: vi.fn(async () => {}),
		},
	} as unknown as GrantDependencies);

	// The session object a back-channel /token call sees: the code correlation
	// keys written at /authorize, and no `user` — there is no browser here.
	return handler.handle({
		body: { code: "the-code", client_id: CLIENT_ID, redirect_uri: RP_URI },
		session: { code: "the-code", code_client_id: CLIENT_ID },
		issuer: ISSUER,
		metadata: { ip: "127.0.0.1" },
		authenticatedClient: {
			clientId: CLIENT_ID,
			tokenEndpointAuthMethod: "client_secret_basic" as const,
		},
	});
}

function buildUserinfoApp() {
	const app = express();
	app.use(express.json());
	app.use(
		"/oauth",
		createRouter(express, {
			keyStore,
			issuer: ISSUER,
			userSessionStore,
			refreshTokenFamilyRevocation,
		}),
	);
	return app;
}

describe("authorization_code → userinfo over a back channel", () => {
	it("serves claims for an access token minted without a token-request cookie", async () => {
		const { result } = await exchangeCodeWithoutCookie();

		expect(result.status).toBe(200);
		if (!("tokens" in result)) throw new Error("expected tokens");

		const res = await request(buildUserinfoApp())
			.get("/oauth/userinfo")
			.set("Authorization", `Bearer ${result.tokens.access_token}`);

		expect(res.status).toBe(200);
		expect(res.body.sub).toBe(SUB);
		expect(res.body.email).toBe("alice@example.com");
	});
});
