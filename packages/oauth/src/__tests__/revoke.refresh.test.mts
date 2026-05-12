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
	createSymmetricKeyStore,
	type RefreshTokenFamilyRevocation,
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

async function mintRefreshToken(opts: {
	familyId: string;
	clientId: string;
	expiresIn?: string;
}): Promise<string> {
	return new SignJWT({
		sub: "u1",
		scope: "read",
		family_id: opts.familyId,
		azp: opts.clientId,
	})
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
		.setIssuer(ISSUER)
		.setAudience(opts.clientId)
		.setExpirationTime(opts.expiresIn ?? "24h")
		.sign(secretKey);
}

describe("POST /oauth/revoke — refresh token path", () => {
	let revocations: string[];
	let refreshTokenFamilyRevocation: RefreshTokenFamilyRevocation;
	let app: express.Express;

	beforeEach(() => {
		revocations = [];
		refreshTokenFamilyRevocation = {
			revokeFamily: vi.fn(async (id: string) => {
				revocations.push(id);
			}),
			isFamilyRevoked: vi.fn(async () => false),
		};

		const router = createRevokeRouter(express, {
			clientRepository,
			keyStore,
			refreshTokenFamilyRevocation,
			accessTokenDenylist: undefined,
			logger: createMockLogger(),
			issuer: ISSUER,
		});
		app = express();
		app.use("/oauth", router);
	});

	it("revokes a refresh token and responds 200", async () => {
		const rt = await mintRefreshToken({ familyId: "fam-1", clientId: CLIENT_ID });
		const res = await request(app)
			.post("/oauth/revoke")
			.auth(CLIENT_ID, CLIENT_SECRET)
			.type("form")
			.send({ token: rt, token_type_hint: "refresh_token" });
		expect(res.status).toBe(200);
		expect(revocations).toContain("fam-1");
	});

	it("silently 200 when client_id does not own the token", async () => {
		// Mint an RT for a different client
		const rt = await mintRefreshToken({ familyId: "fam-2", clientId: OTHER_CLIENT_ID });
		const res = await request(app)
			.post("/oauth/revoke")
			.auth(CLIENT_ID, CLIENT_SECRET)
			.type("form")
			.send({ token: rt });
		expect(res.status).toBe(200);
		expect(revocations).toEqual([]);
	});

	it("silently 200 for a token with no family_id claim", async () => {
		// Token without family_id — cannot revoke by family
		const rt = await new SignJWT({ sub: "u1", azp: CLIENT_ID })
			.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
			.setIssuer(ISSUER)
			.setAudience(CLIENT_ID)
			.setExpirationTime("24h")
			.sign(secretKey);
		const res = await request(app)
			.post("/oauth/revoke")
			.auth(CLIENT_ID, CLIENT_SECRET)
			.type("form")
			.send({ token: rt, token_type_hint: "refresh_token" });
		expect(res.status).toBe(200);
		expect(revocations).toEqual([]);
	});

	it("responds 400 invalid_request when token form param is missing", async () => {
		const res = await request(app)
			.post("/oauth/revoke")
			.auth(CLIENT_ID, CLIENT_SECRET)
			.type("form")
			.send({});
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_request");
	});

	it("responds 400 unsupported_token_type for unknown hint", async () => {
		const res = await request(app)
			.post("/oauth/revoke")
			.auth(CLIENT_ID, CLIENT_SECRET)
			.type("form")
			.send({ token: "x", token_type_hint: "id_token" });
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("unsupported_token_type");
	});

	it("silently 200 for an invalid token string", async () => {
		const res = await request(app)
			.post("/oauth/revoke")
			.auth(CLIENT_ID, CLIENT_SECRET)
			.type("form")
			.send({ token: "garbage.token.here", token_type_hint: "refresh_token" });
		expect(res.status).toBe(200);
		expect(revocations).toEqual([]);
	});
});
