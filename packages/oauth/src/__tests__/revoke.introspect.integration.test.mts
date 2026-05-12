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
 * Integration test: revoke → introspect chain (C3 + C4 fix verification).
 *
 * Validates that:
 *  1. When `accessTokenDenylist` is wired through `createOAuthRouter`, a
 *     revoked AT is reported `active: false` by `/oauth/introspect`.
 *  2. The denylist is consulted by the introspect body handler AND by the
 *     bearer-credential path, so a revoked AT cannot even serve as its own
 *     self-introspection credential.
 */

import { createSecretKey } from "node:crypto";
import {
	type ClientRepository,
	type CodeRepository,
	createMemoryAccessTokenDenylist,
	createSymmetricKeyStore,
} from "@o3co/auth-provider-core";
import { GrantRegistry, makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import express from "express";
import { SignJWT } from "jose";
import request from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import { createOAuthRouter } from "#/routes.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const keyStore = createSymmetricKeyStore(SECRET);
const secretKey = createSecretKey(Buffer.from(SECRET));

const ISSUER = "https://auth.example";
const CLIENT_ID = "c-1";
const CLIENT_SECRET = "c-1-secret";

const clientRepository: ClientRepository = {
	findById: async (id) => {
		if (id === CLIENT_ID) {
			return {
				clientId: id,
				tokenEndpointAuthMethod: "client_secret_basic",
				allowedRedirectUris: [],
				allowedScopes: [],
			};
		}
		return null;
	},
	authenticate: async (id, secret) => {
		if (id === CLIENT_ID && secret === CLIENT_SECRET) {
			return {
				clientId: CLIENT_ID,
				tokenEndpointAuthMethod: "client_secret_basic",
				allowedRedirectUris: [],
				allowedScopes: [],
			};
		}
		return null;
	},
};

const codeRepository: CodeRepository = {
	createCode: async () => ({
		code: "test-code",
		client_id: CLIENT_ID,
		redirect_uri: "https://rp.example/cb",
	}),
	findByCode: async () => null,
	consumeByCode: async () => null,
	removeByCode: async () => {},
};

const baseConfig = {
	...makeValidAppConfig(),
	oauth: {
		jwt: { issuer: ISSUER },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		grants: {},
	},
	endpoints: { login: { url: "/login" } },
} as unknown as import("@o3co/auth-provider-core").AppConfig;

async function mintAccessToken(jti: string, clientId = CLIENT_ID): Promise<string> {
	const exp = Math.floor(Date.now() / 1000) + 3600;
	return new SignJWT({
		sub: "u1",
		scope: "read",
		client_id: clientId,
		jti,
		exp,
	})
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "at+jwt" })
		.setIssuer(ISSUER)
		.setAudience(clientId)
		.sign(secretKey);
}

describe("revoke → introspect end-to-end (C3 + C4 denylist wiring)", () => {
	let denylist: ReturnType<typeof createMemoryAccessTokenDenylist>;
	let app: express.Express;

	beforeEach(async () => {
		denylist = createMemoryAccessTokenDenylist();

		const { router } = await createOAuthRouter(express, {
			registry: new GrantRegistry(),
			config: baseConfig,
			clientRepository,
			codeRepository,
			keyStore,
			accessTokenDenylist: denylist,
		});

		app = express();
		app.set("trust proxy", 1);
		app.use(express.json());
		app.use(express.urlencoded({ extended: false }));
		app.use("/oauth", router);
	});

	it("AT introspects as active:true before revocation", async () => {
		const at = await mintAccessToken("jti-c4-1");

		// Introspect using Bearer self-introspection pattern (same token as credential)
		const res = await request(app)
			.post("/oauth/introspect")
			.set("Authorization", `Bearer ${at}`)
			.type("form")
			.send({ token: at });

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(true);
	});

	it("AT introspects as active:false after revocation via /oauth/revoke", async () => {
		const at = await mintAccessToken("jti-c4-2");

		// Step 1: revoke the AT
		const revokeRes = await request(app)
			.post("/oauth/revoke")
			.auth(CLIENT_ID, CLIENT_SECRET)
			.type("form")
			.send({ token: at, token_type_hint: "access_token" });
		expect(revokeRes.status).toBe(200);

		// Verify denylist was populated
		expect(await denylist.has("jti-c4-2")).toBe(true);

		// Step 2: introspect with the same AT — must report active:false
		// Uses confidential-client path (clientAuth middleware) with the revoked AT as body token
		const introspectRes = await request(app)
			.post("/oauth/introspect")
			.auth(CLIENT_ID, CLIENT_SECRET)
			.type("form")
			.send({ token: at });

		expect(introspectRes.status).toBe(200);
		expect(introspectRes.body.active).toBe(false);
	});

	it("revoked AT returns active:false even via Bearer self-introspection path", async () => {
		const at = await mintAccessToken("jti-c4-3");

		// Revoke first
		await request(app)
			.post("/oauth/revoke")
			.auth(CLIENT_ID, CLIENT_SECRET)
			.type("form")
			.send({ token: at, token_type_hint: "access_token" });

		// Bearer self-introspect: same token as both credential and body
		const res = await request(app)
			.post("/oauth/introspect")
			.set("Authorization", `Bearer ${at}`)
			.type("form")
			.send({ token: at });

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(false);
	});

	it("non-revoked AT still introspects as active:true when denylist is wired", async () => {
		const at1 = await mintAccessToken("jti-c4-other-1");
		const at2 = await mintAccessToken("jti-c4-other-2");

		// Revoke only at1
		await request(app)
			.post("/oauth/revoke")
			.auth(CLIENT_ID, CLIENT_SECRET)
			.type("form")
			.send({ token: at1, token_type_hint: "access_token" });

		// at2 should still be active
		const res = await request(app)
			.post("/oauth/introspect")
			.set("Authorization", `Bearer ${at2}`)
			.type("form")
			.send({ token: at2 });

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(true);
	});
});
