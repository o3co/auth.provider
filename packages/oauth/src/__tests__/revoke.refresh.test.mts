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

import { createSecretKey, randomUUID } from "node:crypto";
import {
	type ClientRepository,
	createMemoryAccessTokenDenylist,
	createMemoryReplaySeenSet,
	createSymmetricKeyStore,
	type RefreshTokenFamilyRevocation,
	type ReplaySeenSet,
} from "@o3co/auth-provider-core";
import express from "express";
import { exportJWK, generateKeyPair, type JWK, SignJWT } from "jose";
import request from "supertest";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { JWT_BEARER_CLIENT_ASSERTION_TYPE } from "#/middleware/clientAssertion.mjs";
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

		// #277: refresh-token revocation needs no denylist and must keep working
		// without one. The whole suite runs on a deployment that has declared
		// access-token revocation unsupported — if that ever stops being a
		// buildable composition, this fixture fails to construct and says so.
		const router = createRevokeRouter(express, {
			clientRepository,
			keyStore,
			refreshTokenFamilyRevocation,
			accessTokenRevocation: "unsupported",
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

	it("revokes an already-expired RT (Copilot review #1: ignoreExpiration idempotency)", async () => {
		// RFC 7009 §2.1: revoking an expired-but-valid-signature RT is harmless
		// idempotency — the family-revocation primitive is idempotent and keeps
		// cascade checks correct. Without ignoreExpiration the verify would throw
		// and the family would never be revoked.
		const pastExp = Math.floor(Date.now() / 1000) - 3600;
		const rt = await new SignJWT({
			sub: "u1",
			family_id: "fam-expired",
			azp: CLIENT_ID,
			exp: pastExp,
		})
			.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
			.setIssuer(ISSUER)
			.setAudience(CLIENT_ID)
			.sign(secretKey);
		const res = await request(app)
			.post("/oauth/revoke")
			.auth(CLIENT_ID, CLIENT_SECRET)
			.type("form")
			.send({ token: rt, token_type_hint: "refresh_token" });
		expect(res.status).toBe(200);
		expect(revocations).toContain("fam-expired");
	});
});

// ---------------------------------------------------------------------------
// C1: RFC 7009 §2.1 cross-type fallback — hint=refresh_token with actual AT
// ---------------------------------------------------------------------------

async function mintAccessTokenForCrossType(opts: {
	jti: string;
	clientId: string;
}): Promise<string> {
	const exp = Math.floor(Date.now() / 1000) + 3600;
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
		.sign(createSecretKey(Buffer.from(SECRET)));
}

describe("POST /oauth/revoke — C1: cross-type fallback (hint=refresh_token + AT-shaped token)", () => {
	let crossDenylist: ReturnType<typeof createMemoryAccessTokenDenylist>;
	let crossRevocations: string[];
	let crossRevocation: RefreshTokenFamilyRevocation;
	let crossApp: express.Express;

	beforeEach(() => {
		crossRevocations = [];
		crossRevocation = {
			revokeFamily: vi.fn(async (id: string) => {
				crossRevocations.push(id);
			}),
			isFamilyRevoked: vi.fn(async () => false),
		};
		crossDenylist = createMemoryAccessTokenDenylist();

		const router = createRevokeRouter(express, {
			clientRepository,
			keyStore,
			refreshTokenFamilyRevocation: crossRevocation,
			accessTokenDenylist: crossDenylist,
			logger: createMockLogger(),
			issuer: ISSUER,
		});
		crossApp = express();
		crossApp.use("/oauth", router);
	});

	it("RFC 7009 §2.1: hint=refresh_token with actual AT — AT is still denylisted (cross-type fallback)", async () => {
		// Client passes hint=refresh_token but the token is actually an access_token.
		// Per RFC 7009 §2.1 the server MUST extend the search; the AT path should run.
		const at = await mintAccessTokenForCrossType({ jti: "cross-jti-1", clientId: CLIENT_ID });

		const res = await request(crossApp)
			.post("/oauth/revoke")
			.auth(CLIENT_ID, CLIENT_SECRET)
			.type("form")
			.send({ token: at, token_type_hint: "refresh_token" });

		expect(res.status).toBe(200);
		// Cross-type fallback: AT must be denylisted even though hint said RT
		expect(await crossDenylist.has("cross-jti-1")).toBe(true);
		// RT family must NOT have been "revoked" for the AT
		expect(crossRevocations).toEqual([]);
	});
});

describe("POST /oauth/revoke — private_key_jwt client authentication (#484)", () => {
	let privateKey: CryptoKey;
	let publicJwk: JWK;
	beforeAll(async () => {
		const pair = await generateKeyPair("ES256");
		privateKey = pair.privateKey;
		publicJwk = { ...(await exportJWK(pair.publicKey)), kid: "k1" };
	});
	const jwtRepository: ClientRepository = {
		findById: async (id) =>
			id === "rp"
				? {
						clientId: "rp",
						tokenEndpointAuthMethod: "private_key_jwt",
						allowedRedirectUris: [],
						allowedScopes: [],
						jwks: { keys: [publicJwk] },
					}
				: null,
		authenticate: async () => null,
	};
	const assertion = async (): Promise<string> => {
		const now = Math.floor(Date.now() / 1000);
		return new SignJWT({
			iss: "rp",
			sub: "rp",
			aud: `${ISSUER}/oauth/token`,
			iat: now,
			exp: now + 60,
			jti: randomUUID(),
		})
			.setProtectedHeader({ alg: "ES256", kid: "k1" })
			.sign(privateKey);
	};
	const buildApp = (replaySeenSet?: ReplaySeenSet) => {
		const router = createRevokeRouter(express, {
			clientRepository: jwtRepository,
			keyStore,
			refreshTokenFamilyRevocation: {
				revokeFamily: vi.fn(async () => {}),
				isFamilyRevoked: vi.fn(async () => false),
			},
			accessTokenRevocation: "unsupported",
			accessTokenDenylist: undefined,
			logger: createMockLogger(),
			issuer: ISSUER,
			...(replaySeenSet === undefined
				? {}
				: { replaySeenSet, tokenEndpoint: `${ISSUER}/oauth/token` }),
		});
		const app = express();
		app.use("/oauth", router);
		return app;
	};

	it("verifies the assertion against the composition's replay store, and refuses its replay", async () => {
		// The discovery document advertises private_key_jwt for revocation, so
		// the endpoint must reach the verifier with the store the composition
		// wired — the same jti must not be usable here after /token spent it,
		// or twice here.
		const app = buildApp(createMemoryReplaySeenSet());
		const jwt = await assertion();
		const form = {
			client_assertion_type: JWT_BEARER_CLIENT_ASSERTION_TYPE,
			client_assertion: jwt,
			token: "not-a-token",
		};
		// A silent 200 for an unparseable token is the authenticated answer.
		const first = await request(app).post("/oauth/revoke").type("form").send(form);
		expect(first.status).toBe(200);

		const replay = await request(app).post("/oauth/revoke").type("form").send(form);
		expect(replay.status).toBe(401);
		expect(replay.body.error).toBe("invalid_client");
	});

	it("answers server_error without a replay store rather than accepting an unchecked jti", async () => {
		const res = await request(buildApp())
			.post("/oauth/revoke")
			.type("form")
			.send({
				client_assertion_type: JWT_BEARER_CLIENT_ASSERTION_TYPE,
				client_assertion: await assertion(),
				token: "not-a-token",
			});
		expect(res.status).toBe(500);
		expect(res.body.error).toBe("server_error");
	});
});
