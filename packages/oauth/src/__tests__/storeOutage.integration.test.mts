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
 * A store that cannot answer is the server's outage on every route that
 * accepts a token, never a verdict on the token.
 *
 * RFC 6750 §3.1's `invalid_token` describes the token — "expired, revoked,
 * malformed, or invalid for other reasons" — and invites the client to get a
 * new one; RFC 7662 §2.2's `active: false` tells a resource server the token
 * is not active. A refresh-token family store or a session store that did not
 * answer says neither. `userinfo`, the federation token route and federation
 * logout answered a family-store outage `401 invalid_token`, introspection
 * answered a family- or session-store outage `active: false`, and userinfo a
 * session-store outage `401`, while every other route answers a store outage
 * `503 temporarily_unavailable`.
 *
 * Driven through the real router (`createOAuthRouter`) with the real keystore,
 * one route per case, and a control for each: the same route with the store
 * answering "revoked" or "gone" is still the token's fault.
 */

import { createSecretKey } from "node:crypto";
import {
	type AppConfig,
	type AuditEvent,
	type ClientRepository,
	type CodeRepository,
	createMemoryAccessTokenDenylist,
	createSymmetricKeyStore,
	type FederationTokenStore,
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
import { describe, expect, it } from "vitest";
import { createOAuthRouter } from "#/routes.mjs";
import { codeRecord } from "./_helpers/codeRecord.mjs";
import { createMockLogger, type MockLogger } from "./_helpers/mockLogger.mjs";
import {
	REFUSED_COMMAND_MARKER,
	serialisedCalls,
	storeReplyError,
} from "./_helpers/projectedLog.mjs";

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
		grants: {},
	},
	rateLimit: { failMode: "open" as const },
	endpoints: { login: { url: "/login" } },
} as unknown as AppConfig;

const clientRecord = {
	clientId: CLIENT_ID,
	tokenEndpointAuthMethod: "client_secret_basic" as const,
	allowedRedirectUris: [],
	allowedScopes: ["openid", "profile"],
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

/** How each store answers: normally, with the finding, or not at all. */
interface Stores {
	readonly family?: "live" | "revoked" | "down";
	readonly session?: "live" | "gone" | "down";
}

interface Harness {
	readonly app: express.Express;
	readonly logger: MockLogger;
	readonly events: AuditEvent[];
}

async function buildApp(stores: Stores = {}): Promise<Harness> {
	const logger = createMockLogger();
	const events: AuditEvent[] = [];
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
		get: async (sid) => {
			if (stores.session === "down") throw storeReplyError();
			return stores.session === "gone" || sid !== SID ? null : session;
		},
		delete: async () => {},
	};
	const refreshTokenFamilyRevocation: RefreshTokenFamilyRevocation = {
		isFamilyRevoked: async () => {
			if (stores.family === "down") throw storeReplyError();
			return stores.family === "revoked";
		},
		revokeFamily: async () => {},
	};

	const { router } = await createOAuthRouter(express, {
		registry: new GrantRegistry(),
		config,
		clientRepository,
		codeRepository,
		keyStore: createSymmetricKeyStore(SECRET, "v0"),
		logger,
		auditSink: {
			kind: "test",
			record: async (event: AuditEvent) => {
				events.push(event);
			},
		},
		accessTokenDenylist: createMemoryAccessTokenDenylist(),
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
		refreshTokenFamilyRevocation,
	});
	const app = express();
	app.use("/oauth", router);
	return { app, logger, events };
}

async function mint(claims: Record<string, unknown>): Promise<string> {
	const now = Math.floor(Date.now() / 1000);
	return new SignJWT({ sub: SUB, aud: CLIENT_ID, azp: CLIENT_ID, family_id: FAMILY, ...claims })
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "at+jwt" })
		.setIssuer(ISSUER)
		.setIssuedAt(now)
		.setExpirationTime(now + 600)
		.sign(createSecretKey(Buffer.from(SECRET)));
}

const accessToken = () => mint({ client_id: CLIENT_ID, sid: SID, jti: "at-1" });

const userinfo = async (app: express.Express) =>
	request(app)
		.get("/oauth/userinfo")
		.set("Authorization", `Bearer ${await accessToken()}`);
const introspect = async (app: express.Express) =>
	request(app)
		.post("/oauth/introspect")
		.auth(CLIENT_ID, CLIENT_SECRET)
		.type("form")
		.send({ token: await accessToken() });
const federationToken = async (app: express.Express) =>
	request(app)
		.post(`/oauth/federation/${FEDERATION}/token`)
		.set("Authorization", `Bearer ${await accessToken()}`);
const federationLogout = async (app: express.Express) =>
	request(app)
		.post(`/oauth/federation/${FEDERATION}/logout`)
		.set("Authorization", `Bearer ${await accessToken()}`)
		.type("form")
		.send({});

const outage = (description: string) => ({
	error: "temporarily_unavailable",
	error_description: description,
});

/** The store's error reached no log as itself: its projection only. */
const expectNoRawStoreError = (logger: MockLogger): void => {
	expect(serialisedCalls(logger)).not.toContain(REFUSED_COMMAND_MARKER);
};

describe("a refresh-token family store that cannot answer", () => {
	it("GET /oauth/userinfo answers 503, not 401 invalid_token", async () => {
		const { app, logger } = await buildApp({ family: "down" });
		const res = await userinfo(app);
		expect(res.status).toBe(503);
		expect(res.body).toEqual(outage("refresh token store unavailable"));
		expect(res.headers["www-authenticate"]).toBeUndefined();
		expect(logger.error).toHaveBeenCalledWith(
			expect.objectContaining({
				store: "refresh_token_family",
				err: expect.objectContaining({ name: "ReplyError" }),
			}),
			"userinfo_store_unavailable",
		);
		expectNoRawStoreError(logger);
	});

	it("POST /oauth/federation/:name/token answers 503, not 401 invalid_token", async () => {
		const { app, logger } = await buildApp({ family: "down" });
		const res = await federationToken(app);
		expect(res.status).toBe(503);
		expect(res.body).toEqual(outage("refresh token store unavailable"));
		expect(res.headers["www-authenticate"]).toBeUndefined();
		expectNoRawStoreError(logger);
	});

	it("POST /oauth/federation/:name/logout answers 503, not 401 invalid_token", async () => {
		const { app, logger } = await buildApp({ family: "down" });
		const res = await federationLogout(app);
		expect(res.status).toBe(503);
		expect(res.body).toEqual(outage("refresh token store unavailable"));
		expect(res.headers["www-authenticate"]).toBeUndefined();
		expectNoRawStoreError(logger);
	});

	it("POST /oauth/introspect answers 503, not active:false, and audits the outage", async () => {
		const { app, logger, events } = await buildApp({ family: "down" });
		const res = await introspect(app);
		expect(res.status).toBe(503);
		expect(res.body).toEqual(outage("refresh token store unavailable"));
		expect(events.find((e) => e.type === "introspect.store_unavailable")?.details).toMatchObject({
			family_id: FAMILY,
		});
		expect(logger.error).toHaveBeenCalledWith(
			expect.objectContaining({
				store: "refresh_token_family",
				err: expect.objectContaining({ name: "ReplyError" }),
			}),
			"introspect_store_unavailable",
		);
		expectNoRawStoreError(logger);
	});

	it("still refuses a revoked family as the token's fault on each route", async () => {
		const { app } = await buildApp({ family: "revoked" });
		expect((await userinfo(app)).status).toBe(401);
		expect((await federationToken(app)).status).toBe(401);
		expect((await federationLogout(app)).status).toBe(401);
		const res = await introspect(app);
		expect(res.status).toBe(200);
		expect(res.body).toEqual({ active: false });
	});
});

describe("a session store that cannot answer", () => {
	it("GET /oauth/userinfo answers 503, not 401 invalid_token", async () => {
		const { app, logger } = await buildApp({ session: "down" });
		const res = await userinfo(app);
		expect(res.status).toBe(503);
		expect(res.body).toEqual(outage("session store unavailable"));
		expect(res.headers["www-authenticate"]).toBeUndefined();
		expect(logger.error).toHaveBeenCalledWith(
			expect.objectContaining({
				store: "user_session",
				err: expect.objectContaining({ name: "ReplyError" }),
			}),
			"userinfo_store_unavailable",
		);
		expectNoRawStoreError(logger);
	});

	it("POST /oauth/introspect answers 503, not active:false", async () => {
		const { app, logger } = await buildApp({ session: "down" });
		const res = await introspect(app);
		expect(res.status).toBe(503);
		expect(res.body).toEqual(outage("session store unavailable"));
		expect(logger.error).toHaveBeenCalledWith(
			expect.objectContaining({ store: "user_session" }),
			"introspect_store_unavailable",
		);
		expectNoRawStoreError(logger);
	});

	it("still refuses a session that is gone as the token's fault", async () => {
		const { app } = await buildApp({ session: "gone" });
		expect((await userinfo(app)).status).toBe(401);
		expect((await introspect(app)).body).toEqual({ active: false });
	});
});
