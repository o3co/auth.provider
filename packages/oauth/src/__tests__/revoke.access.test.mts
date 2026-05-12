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
	type ClientRepository,
	createMemoryAccessTokenDenylist,
	createSymmetricKeyStore,
} from "@o3co/auth-provider-core";
import express from "express";
import { SignJWT } from "jose";
import request from "supertest";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createRevokeRouter } from "#/routes/revoke.mjs";
import { createMockLogger } from "./_helpers/mockLogger.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const keyStore = createSymmetricKeyStore(SECRET);
const secretKey = createSecretKey(Buffer.from(SECRET));

const ISSUER = "https://auth.example";
const CLIENT_ID = "c-1";
const CLIENT_SECRET = "c-1-secret";
const OTHER_CLIENT_ID = "c-other";

const clientRepository: ClientRepository = {
	findById: async (id) => {
		if (id === CLIENT_ID || id === OTHER_CLIENT_ID) {
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

const stubRevocation = {
	revokeFamily: vi.fn(async () => {}),
	isFamilyRevoked: vi.fn(async () => false),
};

async function mintAccessToken(opts: {
	jti: string;
	clientId: string;
	/** Seconds offset from now. Negative values produce an already-expired token. */
	offsetSeconds?: number;
}): Promise<string> {
	// Use a numeric exp (Unix seconds) so negative offsets produce truly expired tokens.
	const exp = Math.floor(Date.now() / 1000) + (opts.offsetSeconds ?? 3600);
	return new SignJWT({
		sub: "u1",
		scope: "read",
		client_id: opts.clientId,
		jti: opts.jti,
		exp,
	})
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "at+jwt" })
		.setIssuer(ISSUER)
		.setAudience(opts.clientId)
		.sign(secretKey);
}

describe("POST /oauth/revoke — access token path", () => {
	let denylist: ReturnType<typeof createMemoryAccessTokenDenylist>;
	let app: express.Express;

	beforeEach(() => {
		denylist = createMemoryAccessTokenDenylist();

		const router = createRevokeRouter(express, {
			clientRepository,
			keyStore,
			refreshTokenFamilyRevocation: stubRevocation,
			accessTokenDenylist: denylist,
			logger: createMockLogger(),
			issuer: ISSUER,
		});
		app = express();
		app.use("/oauth", router);
	});

	it("revokes a valid AT (adds to denylist), responds 200", async () => {
		const at = await mintAccessToken({ jti: "j-1", clientId: CLIENT_ID });
		const res = await request(app)
			.post("/oauth/revoke")
			.auth(CLIENT_ID, CLIENT_SECRET)
			.type("form")
			.send({ token: at, token_type_hint: "access_token" });
		expect(res.status).toBe(200);
		expect(await denylist.has("j-1")).toBe(true);
	});

	it("accepts already-expired AT (ignoreExpiration), responds 200", async () => {
		// offsetSeconds = -3600 → expired 1 hour ago (beyond default 5-min clock skew).
		// The jti is added to the denylist with the token's (past) exp; denylist.has()
		// will GC-evict it immediately since the exp is already past. The contract being
		// tested is that the revoke endpoint does NOT return an error for an expired token —
		// it accepts the revocation attempt and returns 200 silently.
		const at = await mintAccessToken({ jti: "j-2", clientId: CLIENT_ID, offsetSeconds: -3600 });
		await request(app)
			.post("/oauth/revoke")
			.auth(CLIENT_ID, CLIENT_SECRET)
			.type("form")
			.send({ token: at })
			.expect(200);
		// The jti was added to the denylist; denylist.has() returns false only because
		// the stored expiresAtMs is already past (lazy GC). This is expected behavior.
		// The important guarantee is that no 4xx/5xx was returned.
	});

	it("silently 200 when client_id mismatch", async () => {
		const at = await mintAccessToken({ jti: "j-3", clientId: OTHER_CLIENT_ID });
		const res = await request(app)
			.post("/oauth/revoke")
			.auth(CLIENT_ID, CLIENT_SECRET)
			.type("form")
			.send({ token: at });
		expect(res.status).toBe(200);
		expect(await denylist.has("j-3")).toBe(false);
	});

	it("silently 200 for invalid signature", async () => {
		const res = await request(app)
			.post("/oauth/revoke")
			.auth(CLIENT_ID, CLIENT_SECRET)
			.type("form")
			.send({ token: "garbage.token.here" });
		expect(res.status).toBe(200);
	});

	it("responds 200 and emits warn log when denylist slot is unwired", async () => {
		const logger = createMockLogger();
		const router = createRevokeRouter(express, {
			clientRepository,
			keyStore,
			refreshTokenFamilyRevocation: stubRevocation,
			accessTokenDenylist: undefined,
			logger,
			issuer: ISSUER,
		});
		const localApp = express();
		localApp.use("/oauth", router);
		const at = await mintAccessToken({ jti: "j-4", clientId: CLIENT_ID });
		await request(localApp)
			.post("/oauth/revoke")
			.auth(CLIENT_ID, CLIENT_SECRET)
			.type("form")
			.send({ token: at })
			.expect(200);
		expect(logger.warn).toHaveBeenCalled();
	});
});
