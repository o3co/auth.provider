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
 * A keystore that cannot answer is the server's outage, on every route that
 * verifies a token this provider signed.
 *
 * The central verifier reported a failed key lookup as `kid_unknown` — a
 * fabricated header — so every route answered the client's fault: `401
 * invalid_token` at a protected resource (the client drops a good token),
 * `400 invalid_grant` at the refresh grant (RFC 6749 §5.2: the client discards
 * its refresh token, a forced logout for everyone who refreshed during the
 * outage), `active: false` at introspection, and a `200` at revocation that
 * revoked nothing. Each is now `503 temporarily_unavailable`, logged.
 *
 * Driven through the real router (`createOAuthRouter`) with the real
 * symmetric keystore, whose key lookup is made to fail the way a remote key
 * service does. The controls use the same routes with a working keystore and
 * a token whose `kid` it does not hold: that is still the client's fault.
 */

import { createSecretKey } from "node:crypto";
import {
	type AppConfig,
	type ClientRepository,
	type CodeRepository,
	createMemoryAccessTokenDenylist,
	createSymmetricKeyStore,
	type FederationTokenStore,
	type KeyStore,
	type RefreshTokenFamilyRevocation,
	type SessionFamilyIndex,
	type SessionFederationIndex,
	type SessionRPRegistry,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { GrantRegistry } from "@o3co/auth-provider-core/testing";
import express from "express";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createRefreshTokenGrant } from "#/grants/refreshToken.mjs";
import { createOAuthRouter } from "#/routes.mjs";
import { codeRecord } from "./_helpers/codeRecord.mjs";
import { createMockLogger, type MockLogger } from "./_helpers/mockLogger.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const ISSUER = "https://auth.example.com";
const CLIENT_ID = "rp";
const CLIENT_SECRET = "rp-secret";
const SID = "sid-1";
const SUB = "user-1";
const FAMILY = "fam-1";
const FEDERATION = "google";

const config = {
	oauth: {
		jwt: { issuer: ISSUER },
		accessToken: { expiresIn: 3600 },
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

/** The real keystore; `lookup: "down"` makes its key lookup fail like a remote key service. */
function keyStoreWith(lookup: "up" | "down"): KeyStore {
	const real = createSymmetricKeyStore(SECRET, "v0");
	return {
		algorithm: real.algorithm,
		sign: (o) => real.sign(o),
		getSigningKidFallback: () => real.getSigningKidFallback(),
		getVerificationKeys: () => real.getVerificationKeys(),
		getVerificationKey: async (kid) => {
			if (lookup === "down") {
				throw Object.assign(new Error("connect ECONNREFUSED 10.0.0.7:8200"), {
					code: "ECONNREFUSED",
				});
			}
			return real.getVerificationKey(kid);
		},
	};
}

interface Harness {
	readonly app: express.Express;
	readonly logger: MockLogger;
	readonly revokeFamily: ReturnType<typeof vi.fn>;
	readonly denylisted: (jti: string) => Promise<boolean>;
}

async function buildApp(lookup: "up" | "down"): Promise<Harness> {
	const keyStore = keyStoreWith(lookup);
	const logger = createMockLogger();
	const session: UserSession = {
		sid: SID,
		sub: SUB,
		authTime: new Date(),
		createdAt: new Date(),
		expiresAt: new Date(Date.now() + 3_600_000),
		claims: { name: "User" },
		amr: undefined,
	};
	const userSessionStore: UserSessionStore = {
		kind: "memory",
		create: async () => {},
		get: async (sid) => (sid === SID ? session : null),
		delete: async () => {},
	};
	const revokeFamily = vi.fn(async () => {});
	const denylist = createMemoryAccessTokenDenylist();
	const registry = new GrantRegistry();
	registry.register("refresh_token", createRefreshTokenGrant({ config, keyStore, logger }));

	const { router } = await createOAuthRouter(express, {
		registry,
		config,
		clientRepository,
		codeRepository,
		keyStore,
		logger,
		accessTokenDenylist: denylist,
		userSessionStore,
		sessionRPRegistry: {
			kind: "memory",
			registerRP: async () => {},
			listRPs: async () => [],
			removeBySid: async () => {},
		} as unknown as SessionRPRegistry,
		sessionFamilyIndex: {
			kind: "memory",
			addFamilyId: async () => {},
			listFamilyIds: async () => [],
			removeBySid: async () => {},
		} as unknown as SessionFamilyIndex,
		sessionFederationIndex: {
			kind: "memory",
			addFederation: async () => {},
			listFederations: async () => [FEDERATION],
			removeFederation: async () => {},
			removeBySid: async () => {},
		} as unknown as SessionFederationIndex,
		federationTokenStore: {
			kind: "memory",
			attach: async () => {},
			get: async () => null,
			update: async () => {},
			delete: async () => {},
			removeBySid: async () => {},
		} as unknown as FederationTokenStore,
		refreshTokenFamilyRevocation: {
			isFamilyRevoked: async () => false,
			revokeFamily,
		} as unknown as RefreshTokenFamilyRevocation,
	});
	const app = express();
	app.use("/oauth", router);
	return { app, logger, revokeFamily, denylisted: (jti) => denylist.has(jti) };
}

/**
 * A token this provider signed (`kid: "v0"`), or — `kid: "fabricated"` — one
 * whose header names a key the keystore does not hold. Signed with the same
 * secret either way, so the kid is the only thing that differs.
 */
async function mint(
	typ: "at+jwt" | "rt+jwt" | "JWT",
	claims: Record<string, unknown>,
	kid: "v0" | "fabricated" = "v0",
): Promise<string> {
	const now = Math.floor(Date.now() / 1000);
	return new SignJWT({ sub: SUB, ...claims })
		.setProtectedHeader({ alg: "HS256", kid, typ })
		.setIssuer(ISSUER)
		.setIssuedAt(now)
		.setExpirationTime(now + 600)
		.sign(createSecretKey(Buffer.from(SECRET)));
}

const accessToken = (kid?: "v0" | "fabricated") =>
	mint(
		"at+jwt",
		{
			aud: CLIENT_ID,
			azp: CLIENT_ID,
			client_id: CLIENT_ID,
			sid: SID,
			family_id: FAMILY,
			jti: "at-1",
		},
		kid,
	);
const refreshToken = (kid?: "v0" | "fabricated") =>
	mint("rt+jwt", { aud: CLIENT_ID, azp: CLIENT_ID, family_id: FAMILY, jti: "rt-1" }, kid);
const idTokenHint = (kid?: "v0" | "fabricated") => mint("JWT", { aud: CLIENT_ID, sid: SID }, kid);

type Call = (app: express.Express, token: string) => request.Test;

/** /oauth/revoke words every 503 alike: RFC 7009 §2.2.1's "retry later". */
const REVOCATION_UNAVAILABLE = "token revocation is temporarily unavailable; retry the request";

const introspectAsClient: Call = (app, token) =>
	request(app)
		.post("/oauth/introspect")
		.auth(CLIENT_ID, CLIENT_SECRET)
		.type("form")
		.send({ token });
const introspectAsBearer: Call = (app, token) =>
	request(app)
		.post("/oauth/introspect")
		.set("Authorization", `Bearer ${token}`)
		.type("form")
		.send({ token });
const userinfo: Call = (app, token) =>
	request(app).get("/oauth/userinfo").set("Authorization", `Bearer ${token}`);
const federationToken: Call = (app, token) =>
	request(app)
		.post(`/oauth/federation/${FEDERATION}/token`)
		.set("Authorization", `Bearer ${token}`);
const federationLogout: Call = (app, token) =>
	request(app)
		.post(`/oauth/federation/${FEDERATION}/logout`)
		.set("Authorization", `Bearer ${token}`)
		.type("form")
		.send({});
const rpLogout: Call = (app, token) =>
	request(app).post("/oauth/logout").type("form").send({ id_token_hint: token });
const refresh: Call = (app, token) =>
	request(app)
		.post("/oauth/token")
		.auth(CLIENT_ID, CLIENT_SECRET)
		.type("form")
		.send({ grant_type: "refresh_token", refresh_token: token });
const revokeRefreshToken: Call = (app, token) =>
	request(app)
		.post("/oauth/revoke")
		.auth(CLIENT_ID, CLIENT_SECRET)
		.type("form")
		.send({ token, token_type_hint: "refresh_token" });
const revokeAccessToken: Call = (app, token) =>
	request(app)
		.post("/oauth/revoke")
		.auth(CLIENT_ID, CLIENT_SECRET)
		.type("form")
		.send({ token, token_type_hint: "access_token" });

/** Every route that verifies a token, with the token it verifies and what an unknown kid still gets. */
const ROUTES: ReadonlyArray<{
	readonly name: string;
	readonly call: Call;
	readonly token: (kid?: "v0" | "fabricated") => Promise<string>;
	readonly unknownKid: { readonly status: number; readonly body?: unknown };
	/** The 503's description, where the route words its own. */
	readonly unavailableDescription?: string;
}> = [
	{
		name: "POST /oauth/introspect (client authentication)",
		call: introspectAsClient,
		token: accessToken,
		unknownKid: { status: 200, body: { active: false } },
	},
	{
		name: "POST /oauth/introspect (bearer self-introspection)",
		call: introspectAsBearer,
		token: accessToken,
		unknownKid: { status: 200, body: { active: false } },
	},
	{ name: "GET /oauth/userinfo", call: userinfo, token: accessToken, unknownKid: { status: 401 } },
	{
		name: "POST /oauth/federation/:name/token",
		call: federationToken,
		token: accessToken,
		unknownKid: { status: 401 },
	},
	{
		name: "POST /oauth/federation/:name/logout",
		call: federationLogout,
		token: accessToken,
		unknownKid: { status: 401 },
	},
	{ name: "POST /oauth/logout", call: rpLogout, token: idTokenHint, unknownKid: { status: 400 } },
	{
		name: "POST /oauth/token (refresh_token)",
		call: refresh,
		token: refreshToken,
		unknownKid: { status: 400, body: { error: "invalid_grant" } },
	},
	{
		name: "POST /oauth/revoke (a refresh token)",
		call: revokeRefreshToken,
		token: refreshToken,
		unknownKid: { status: 200 },
		unavailableDescription: REVOCATION_UNAVAILABLE,
	},
	{
		name: "POST /oauth/revoke (an access token)",
		call: revokeAccessToken,
		token: accessToken,
		unknownKid: { status: 200 },
		unavailableDescription: REVOCATION_UNAVAILABLE,
	},
];

describe("a keystore that cannot answer is 503 on every route that verifies a token", () => {
	for (const route of ROUTES) {
		describe(route.name, () => {
			it("answers 503 temporarily_unavailable, with no invalid_token challenge", async () => {
				const { app } = await buildApp("down");
				const res = await route.call(app, await route.token());
				expect(res.status).toBe(503);
				expect(res.body).toEqual({
					error: "temporarily_unavailable",
					error_description: route.unavailableDescription ?? "verification key unavailable",
				});
				expect(res.headers["www-authenticate"] ?? "").not.toContain("invalid_token");
			});

			it("logs the outage with the keystore's error as its cause", async () => {
				const { app, logger } = await buildApp("down");
				await route.call(app, await route.token());
				const line = logger.error.mock.calls.find(
					([, event]) => event === "token_verification_unavailable",
				);
				expect(line, "a token_verification_unavailable error line").toBeDefined();
				expect(line?.[0]).toMatchObject({
					reason: "key_unavailable",
					err: {
						name: "JwtVerificationError",
						cause: { name: "Error", code: "ECONNREFUSED" },
					},
				});
				expect(line?.[0].err).not.toBeInstanceOf(Error);
			});

			it("still answers an unknown kid from a working keystore as the client's fault", async () => {
				const { app } = await buildApp("up");
				const res = await route.call(app, await route.token("fabricated"));
				expect(res.status).toBe(route.unknownKid.status);
				if (route.unknownKid.body !== undefined) {
					expect(res.body).toMatchObject(route.unknownKid.body as object);
				}
			});
		});
	}

	it("revokes nothing it could not verify, and says so instead of answering 200", async () => {
		const down = await buildApp("down");
		expect((await revokeRefreshToken(down.app, await refreshToken())).status).toBe(503);
		expect(down.revokeFamily).not.toHaveBeenCalled();
		expect((await revokeAccessToken(down.app, await accessToken())).status).toBe(503);
		expect(await down.denylisted("at-1")).toBe(false);

		// The same requests with the keystore back revoke what they name.
		const up = await buildApp("up");
		expect((await revokeRefreshToken(up.app, await refreshToken())).status).toBe(200);
		expect(up.revokeFamily).toHaveBeenCalledWith(FAMILY);
		expect((await revokeAccessToken(up.app, await accessToken())).status).toBe(200);
		expect(await up.denylisted("at-1")).toBe(true);
	});
});
