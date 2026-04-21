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
	createSymmetricKeyStore,
	type RefreshTokenStoreBase,
	type UserSession,
	type UserSessionStoreBase,
} from "@o3co/auth-provider-core";
import express from "express";
import { SignJWT } from "jose";
import { createSecretKey } from "node:crypto";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createRouter } from "#/routes/userinfo.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const keyStore = createSymmetricKeyStore(SECRET);
const secretKey = createSecretKey(Buffer.from(SECRET));

/**
 * Mint a signed access token with the given extra claims.
 * Uses the same symmetric key as the keyStore so verification succeeds.
 */
async function mintAT(extra: Record<string, unknown> = {}): Promise<string> {
	return new SignJWT({ sub: "u-1", aud: "client", scope: "openid email", ...extra })
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "at+jwt" })
		.setExpirationTime("1h")
		.setIssuedAt()
		.sign(secretKey);
}

interface CallOptions {
	token: string | null;
	userSessionStore?: Partial<UserSessionStoreBase>;
	refreshTokenStore?: Partial<RefreshTokenStoreBase>;
}

function buildApp(opts: {
	userSessionStore?: Partial<UserSessionStoreBase>;
	refreshTokenStore?: Partial<RefreshTokenStoreBase>;
}) {
	const app = express();
	app.use(express.json());

	const router = createRouter(express, {
		keyStore,
		userSessionStore: opts.userSessionStore as UserSessionStoreBase | undefined,
		refreshTokenStore: opts.refreshTokenStore as RefreshTokenStoreBase | undefined,
	});
	// Mount at /oauth to match the convention in module.mts
	app.use("/oauth", router);
	return app;
}

async function callUserinfo(opts: CallOptions) {
	const app = buildApp({
		userSessionStore: opts.userSessionStore,
		refreshTokenStore: opts.refreshTokenStore,
	});
	const req = request(app).get("/oauth/userinfo");
	if (opts.token !== null) {
		req.set("Authorization", `Bearer ${opts.token}`);
	}
	return req;
}

// A minimal but valid UserSession fixture
const baseSession: UserSession = {
	sid: "sid-1",
	sub: "u-1",
	authTime: new Date(),
	createdAt: new Date(),
	expiresAt: new Date(Date.now() + 3_600_000),
	federations: [],
	activeRPs: [],
	familyIds: ["fam-1"],
	claims: {
		email: "alice@example.com",
		emailVerified: true,
		name: "Alice",
		picture: "https://example.com/pic",
	},
};

describe("GET /oauth/userinfo", () => {
	it("returns sub + scope-filtered claims for a valid Bearer access_token", async () => {
		const token = await mintAT({ family_id: "fam-1", sid: "sid-1", scope: "openid email" });

		const res = await callUserinfo({
			token,
			userSessionStore: {
				kind: "memory",
				get: vi.fn().mockResolvedValue(baseSession),
				create: vi.fn(),
				registerRP: vi.fn(),
				linkFamily: vi.fn(),
				updateClaims: vi.fn(),
				removeFederation: vi.fn(),
				delete: vi.fn(),
			},
			refreshTokenStore: {
				kind: "memory",
				isFamilyRevoked: vi.fn().mockResolvedValue(false),
				rotate: vi.fn(),
				revokeFamily: vi.fn(),
			},
		});

		expect(res.status).toBe(200);
		// scope=openid email → email + email_verified, not name/picture
		expect(res.body).toEqual({
			sub: "u-1",
			email: "alice@example.com",
			email_verified: true,
		});
	});

	it("returns 401 invalid_token when JWT signature is invalid", async () => {
		const res = await callUserinfo({
			token: "not.a.valid.jwt",
			userSessionStore: undefined,
			refreshTokenStore: undefined,
		});

		expect(res.status).toBe(401);
		expect(res.body.error).toBe("invalid_token");
		expect(res.headers["www-authenticate"]).toBeDefined();
	});

	it("returns 401 invalid_token when family is revoked", async () => {
		const token = await mintAT({ family_id: "fam-revoked", sid: "sid-1" });

		const res = await callUserinfo({
			token,
			refreshTokenStore: {
				kind: "memory",
				isFamilyRevoked: vi.fn().mockResolvedValue(true),
				rotate: vi.fn(),
				revokeFamily: vi.fn(),
			},
			userSessionStore: {
				kind: "memory",
				get: vi.fn().mockResolvedValue(baseSession),
				create: vi.fn(),
				registerRP: vi.fn(),
				linkFamily: vi.fn(),
				updateClaims: vi.fn(),
				removeFederation: vi.fn(),
				delete: vi.fn(),
			},
		});

		expect(res.status).toBe(401);
		expect(res.body.error).toBe("invalid_token");
	});

	it("returns 401 invalid_token when sid's UserSession is gone", async () => {
		const token = await mintAT({ family_id: "fam-1", sid: "sid-dead" });

		const res = await callUserinfo({
			token,
			userSessionStore: {
				kind: "memory",
				get: vi.fn().mockResolvedValue(null),
				create: vi.fn(),
				registerRP: vi.fn(),
				linkFamily: vi.fn(),
				updateClaims: vi.fn(),
				removeFederation: vi.fn(),
				delete: vi.fn(),
			},
			refreshTokenStore: {
				kind: "memory",
				isFamilyRevoked: vi.fn().mockResolvedValue(false),
				rotate: vi.fn(),
				revokeFamily: vi.fn(),
			},
		});

		expect(res.status).toBe(401);
		expect(res.body.error).toBe("invalid_token");
	});

	it("only emits claims whose scope was granted (profile scope → name only, no email)", async () => {
		const token = await mintAT({ family_id: "fam-1", sid: "sid-1", scope: "openid profile" });

		const res = await callUserinfo({
			token,
			userSessionStore: {
				kind: "memory",
				get: vi.fn().mockResolvedValue(baseSession),
				create: vi.fn(),
				registerRP: vi.fn(),
				linkFamily: vi.fn(),
				updateClaims: vi.fn(),
				removeFederation: vi.fn(),
				delete: vi.fn(),
			},
			refreshTokenStore: {
				kind: "memory",
				isFamilyRevoked: vi.fn().mockResolvedValue(false),
				rotate: vi.fn(),
				revokeFamily: vi.fn(),
			},
		});

		expect(res.status).toBe(200);
		// scope=openid profile → name + picture, no email
		expect(res.body).toEqual({
			sub: "u-1",
			name: "Alice",
			picture: "https://example.com/pic",
		});
		expect(res.body).not.toHaveProperty("email");
	});

	it("missing Authorization header returns 401 with WWW-Authenticate Bearer", async () => {
		const res = await callUserinfo({
			token: null,
			userSessionStore: undefined,
			refreshTokenStore: undefined,
		});

		expect(res.status).toBe(401);
		expect(res.headers["www-authenticate"]).toMatch(/^Bearer/);
		expect(res.body.error).toBe("invalid_token");
	});

	it("returns {sub} only when userSessionStore is not wired (backward compat)", async () => {
		const token = await mintAT({ family_id: "fam-1", sid: "sid-1", scope: "openid email" });

		const res = await callUserinfo({
			token,
			userSessionStore: undefined,
			refreshTokenStore: {
				kind: "memory",
				isFamilyRevoked: vi.fn().mockResolvedValue(false),
				rotate: vi.fn(),
				revokeFamily: vi.fn(),
			},
		});

		expect(res.status).toBe(200);
		expect(res.body).toEqual({ sub: "u-1" });
	});

	it("returns 401 invalid_token when userSessionStore.get throws (fail-closed)", async () => {
		const token = await mintAT({ family_id: "fam-1", sid: "sid-1", scope: "openid email" });

		const res = await callUserinfo({
			token,
			userSessionStore: {
				kind: "memory",
				get: vi.fn().mockRejectedValue(new Error("redis unavailable")),
				create: vi.fn(),
				registerRP: vi.fn(),
				linkFamily: vi.fn(),
				updateClaims: vi.fn(),
				removeFederation: vi.fn(),
				delete: vi.fn(),
			},
			refreshTokenStore: {
				kind: "memory",
				isFamilyRevoked: vi.fn().mockResolvedValue(false),
				rotate: vi.fn(),
				revokeFamily: vi.fn(),
			},
		});

		expect(res.status).toBe(401);
		expect(res.body.error).toBe("invalid_token");
		expect(res.body.error_description).toBe("session lookup unavailable");
		expect(res.headers["www-authenticate"]).toMatch(/^Bearer/);
	});

	it("rejects refresh_token (typ: rt+jwt) presented as Bearer (security)", async () => {
		// Refresh tokens are signed by the same KeyStore and carry sub/sid/scope
		// claims, so without a typ check they would also pass signature verification.
		// userinfo MUST accept access tokens only (OIDC Core §5.3.1 + RFC 9068).
		const rtLikeToken = await new SignJWT({
			sub: "u-1",
			aud: "client",
			scope: "openid email",
			family_id: "fam-1",
			sid: "sid-1",
		})
			.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
			.setExpirationTime("1h")
			.setIssuedAt()
			.sign(secretKey);

		const res = await callUserinfo({
			token: rtLikeToken,
			userSessionStore: {
				kind: "memory",
				get: vi.fn().mockResolvedValue(baseSession),
				create: vi.fn(),
				registerRP: vi.fn(),
				linkFamily: vi.fn(),
				updateClaims: vi.fn(),
				removeFederation: vi.fn(),
				delete: vi.fn(),
			},
			refreshTokenStore: {
				kind: "memory",
				isFamilyRevoked: vi.fn().mockResolvedValue(false),
				rotate: vi.fn(),
				revokeFamily: vi.fn(),
			},
		});

		expect(res.status).toBe(401);
		expect(res.body.error).toBe("invalid_token");
		expect(res.headers["www-authenticate"]).toMatch(/^Bearer/);
	});

	it("rejects id_token (typ: id+jwt) presented as Bearer", async () => {
		// id_tokens also share the signing key and can carry sub/sid. Belt-and-
		// suspenders: even if a client misuses an id_token as a bearer, reject it.
		const idLikeToken = await new SignJWT({
			sub: "u-1",
			aud: "client",
			sid: "sid-1",
		})
			.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "id+jwt" })
			.setExpirationTime("1h")
			.setIssuedAt()
			.sign(secretKey);

		const res = await callUserinfo({ token: idLikeToken });

		expect(res.status).toBe(401);
		expect(res.body.error).toBe("invalid_token");
	});

	it("sets Cache-Control: no-store on all responses (RFC 6750 §5.3)", async () => {
		// Success path
		const token = await mintAT({ family_id: "fam-1", sid: "sid-1", scope: "openid" });
		const okRes = await callUserinfo({
			token,
			userSessionStore: {
				kind: "memory",
				get: vi.fn().mockResolvedValue(baseSession),
				create: vi.fn(),
				registerRP: vi.fn(),
				linkFamily: vi.fn(),
				updateClaims: vi.fn(),
				removeFederation: vi.fn(),
				delete: vi.fn(),
			},
			refreshTokenStore: {
				kind: "memory",
				isFamilyRevoked: vi.fn().mockResolvedValue(false),
				rotate: vi.fn(),
				revokeFamily: vi.fn(),
			},
		});
		expect(okRes.status).toBe(200);
		expect(okRes.headers["cache-control"]).toBe("no-store");
		expect(okRes.headers.pragma).toBe("no-cache");

		// Error path (no auth header)
		const errRes = await callUserinfo({ token: null });
		expect(errRes.status).toBe(401);
		expect(errRes.headers["cache-control"]).toBe("no-store");
		expect(errRes.headers.pragma).toBe("no-cache");
	});
});
