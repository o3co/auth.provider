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

const stubRevocation: RefreshTokenFamilyRevocation = {
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

	it("fail-closed: AT with no client_id/azp/aud claim is NOT denylisted (Copilot review #2)", async () => {
		// SECURITY: when ownership cannot be resolved from any of client_id /
		// azp / aud claims, the previous logic let the denylist.add proceed
		// (any authenticated client could revoke any AT). Fail-closed: treat
		// missing-owner as ownership-failure and silent-200 without denylisting.
		const noOwnerAt = await new SignJWT({
			sub: "u1",
			jti: "j-no-owner",
			exp: Math.floor(Date.now() / 1000) + 3600,
		})
			.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "at+jwt" })
			.setIssuer(ISSUER)
			// no setAudience, no client_id claim, no azp claim
			.sign(secretKey);
		const res = await request(app)
			.post("/oauth/revoke")
			.auth(CLIENT_ID, CLIENT_SECRET)
			.type("form")
			.send({ token: noOwnerAt, token_type_hint: "access_token" });
		expect(res.status).toBe(200);
		expect(await denylist.has("j-no-owner")).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// C1: RFC 7009 §2.1 cross-type fallback — hint=access_token with an actual RT
// ---------------------------------------------------------------------------

async function mintRefreshTokenForCrossType(opts: {
	familyId: string;
	clientId: string;
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
		.setExpirationTime("24h")
		.sign(createSecretKey(Buffer.from("test-secret-at-least-32-chars!!")));
}

describe("POST /oauth/revoke — C1: cross-type fallback (hint=access_token + RT-shaped token)", () => {
	let revocations: string[];
	let crossTypeRevocation: RefreshTokenFamilyRevocation;
	let crossTypeDenylist: ReturnType<typeof createMemoryAccessTokenDenylist>;
	let crossTypeApp: express.Express;

	beforeEach(() => {
		revocations = [];
		crossTypeRevocation = {
			revokeFamily: vi.fn(async (id: string) => {
				revocations.push(id);
			}),
			isFamilyRevoked: vi.fn(async () => false),
		};
		crossTypeDenylist = createMemoryAccessTokenDenylist();

		const router = createRevokeRouter(express, {
			clientRepository,
			keyStore,
			refreshTokenFamilyRevocation: crossTypeRevocation,
			accessTokenDenylist: crossTypeDenylist,
			logger: createMockLogger(),
			issuer: ISSUER,
		});
		crossTypeApp = express();
		crossTypeApp.use("/oauth", router);
	});

	it("RFC 7009 §2.1: hint=access_token with actual RT — RT family is still revoked (cross-type fallback)", async () => {
		// Client passes hint=access_token but the token is actually a refresh_token.
		// Per RFC 7009 §2.1 the server MUST extend the search; the RT path should run.
		const rt = await mintRefreshTokenForCrossType({ familyId: "fam-cross-1", clientId: CLIENT_ID });

		const res = await request(crossTypeApp)
			.post("/oauth/revoke")
			.auth(CLIENT_ID, CLIENT_SECRET)
			.type("form")
			.send({ token: rt, token_type_hint: "access_token" });

		expect(res.status).toBe(200);
		// Cross-type fallback: RT family must be revoked even though hint said AT
		expect(revocations).toContain("fam-cross-1");
	});
});

// ---------------------------------------------------------------------------
// C2: Public-client revocation (RFC 7009 §2.1 + spec §4.4)
// ---------------------------------------------------------------------------

const publicClientId = "pub-client-1";

const publicClientRepository: ClientRepository = {
	findById: async (id) => {
		if (id === CLIENT_ID) {
			return {
				clientId: id,
				tokenEndpointAuthMethod: "client_secret_basic",
				allowedRedirectUris: [],
				allowedScopes: [],
			};
		}
		if (id === publicClientId) {
			return {
				clientId: id,
				tokenEndpointAuthMethod: "none",
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

describe("POST /oauth/revoke — C2: public client support", () => {
	let pubDenylist: ReturnType<typeof createMemoryAccessTokenDenylist>;
	let pubRevocation: RefreshTokenFamilyRevocation;
	let pubRevocations: string[];
	let pubApp: express.Express;

	beforeEach(() => {
		pubRevocations = [];
		pubRevocation = {
			revokeFamily: vi.fn(async (id: string) => {
				pubRevocations.push(id);
			}),
			isFamilyRevoked: vi.fn(async () => false),
		};
		pubDenylist = createMemoryAccessTokenDenylist();

		const router = createRevokeRouter(express, {
			clientRepository: publicClientRepository,
			keyStore,
			refreshTokenFamilyRevocation: pubRevocation,
			accessTokenDenylist: pubDenylist,
			logger: createMockLogger(),
			issuer: ISSUER,
		});
		pubApp = express();
		pubApp.use("/oauth", router);
	});

	it("C2: public client can revoke its own AT — denylist updated, 200", async () => {
		const at = await mintAccessToken({ jti: "pub-j-1", clientId: publicClientId });
		const res = await request(pubApp)
			.post("/oauth/revoke")
			.type("form")
			.send({ client_id: publicClientId, token: at, token_type_hint: "access_token" });

		expect(res.status).toBe(200);
		expect(await pubDenylist.has("pub-j-1")).toBe(true);
	});

	it("C2: public client can revoke its own RT — family revoked, 200", async () => {
		const rt = await mintRefreshTokenForCrossType({
			familyId: "pub-fam-1",
			clientId: publicClientId,
		});
		const res = await request(pubApp)
			.post("/oauth/revoke")
			.type("form")
			.send({ client_id: publicClientId, token: rt, token_type_hint: "refresh_token" });

		expect(res.status).toBe(200);
		expect(pubRevocations).toContain("pub-fam-1");
	});

	it("C2: public client revoking another client's token — silent 200, no revocation", async () => {
		// Mint an AT owned by the confidential client (CLIENT_ID), but public client tries to revoke it
		const at = await mintAccessToken({ jti: "pub-j-cross", clientId: CLIENT_ID });
		const res = await request(pubApp)
			.post("/oauth/revoke")
			.type("form")
			.send({ client_id: publicClientId, token: at, token_type_hint: "access_token" });

		expect(res.status).toBe(200);
		// Ownership check: token's client_id (CLIENT_ID) != req.oauthClient.clientId (publicClientId)
		expect(await pubDenylist.has("pub-j-cross")).toBe(false);
	});
});
