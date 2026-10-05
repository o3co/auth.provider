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
 * Where core's session lifecycle is installed, introspection, userinfo and the
 * federation-token route ask it whether a token's session is live: a session
 * whose close has committed is not, while its user session is still there.
 */

import { createSecretKey } from "node:crypto";
import {
	type AppConfig,
	type AuditEvent,
	type AuditSink,
	type ClientRepository,
	type CodeRepository,
	createSymmetricKeyStore,
	type FederationTokenStore,
	type FederationTokens,
	type SessionFederationIndex,
	type SessionLifecycle,
	type SessionLiveness,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { GrantRegistry, resolverForTests } from "@o3co/auth-provider-core/testing";
import express from "express";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { oauthEndpointsModule } from "#/module.mjs";
import * as federationTokenRoute from "#/routes/federationToken.mjs";
import * as userinfoRoute from "#/routes/userinfo.mjs";
import { createOAuthRouter } from "#/routes.mjs";
import { codeRecord } from "./_helpers/codeRecord.mjs";
import { createMockLogger } from "./_helpers/mockLogger.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const ISSUER = "https://auth.example";
const SID = "sid-1";
const keyStore = createSymmetricKeyStore(SECRET);
const secretKey = createSecretKey(Buffer.from(SECRET));

const liveSession: UserSession = {
	sid: SID,
	sub: "u-1",
	authTime: new Date(),
	createdAt: new Date(),
	expiresAt: new Date(Date.now() + 3_600_000),
	claims: { email: "alice@example.com" },
	amr: undefined,
	authentication: undefined,
};

async function mintAccessToken(extra: Record<string, unknown> = {}): Promise<string> {
	return new SignJWT({ sub: "u-1", sid: SID, scope: "openid email", ...extra })
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "at+jwt" })
		.setIssuer(ISSUER)
		.setExpirationTime("1h")
		.setIssuedAt()
		.sign(secretKey);
}

/** A lifecycle answering `answer` for liveness; every member a spy. */
function lifecycleAnswering(answer: SessionLiveness) {
	return {
		join: vi.fn<SessionLifecycle["join"]>(async () => ({ outcome: "joined" })),
		close: vi.fn<SessionLifecycle["close"]>(async () => ({
			outcome: "done",
			rps: [],
			federations: [],
		})),
		liveness: vi.fn<SessionLifecycle["liveness"]>(async () => answer),
		federations: vi.fn<SessionLifecycle["federations"]>(async () => ({
			outcome: "listed",
			federations: [],
		})),
		resumePending: vi.fn<SessionLifecycle["resumePending"]>(async () => ({
			done: 0,
			pending: 0,
			unavailable: 0,
		})),
	} satisfies SessionLifecycle;
}

/** A user session store that still holds the session: the lifecycle's answer must decide. */
function holdingStore(): UserSessionStore {
	return {
		kind: "memory",
		create: vi.fn(async () => {}),
		get: vi.fn(async () => liveSession),
		delete: vi.fn(async () => {}),
	} as unknown as UserSessionStore;
}

function recordingSink() {
	const events: AuditEvent[] = [];
	const sink: AuditSink = {
		kind: "memory",
		record: async (event) => {
			events.push(event);
		},
	};
	return { sink, events };
}

describe("/oauth/introspect through the session lifecycle", () => {
	const config = {
		oauth: { jwt: { issuer: ISSUER }, accessToken: { expiresIn: 3600 }, grants: {} },
		rateLimit: { failMode: "open" as const },
		endpoints: { login: { url: "/login" } },
	} as unknown as AppConfig;
	const clientRepository: ClientRepository = {
		findById: async () => null,
		authenticate: async () => null,
	};
	const codeRepository: CodeRepository = {
		createCode: async () => codeRecord({ code: "c", client_id: "x", redirect_uri: "" }),
		findByCode: async () => null,
		consumeByCode: async () => null,
		removeByCode: async () => {},
	};

	async function buildApp(opts: {
		readonly lifecycle: SessionLifecycle;
		readonly userSessionStore: UserSessionStore;
		readonly auditSink?: AuditSink;
		readonly logger?: ReturnType<typeof createMockLogger>;
	}) {
		const app = express();
		const { router } = await createOAuthRouter(express, {
			requirements: resolverForTests([]),
			registry: new GrantRegistry(),
			config,
			clientRepository,
			codeRepository,
			keyStore,
			userSessionStore: opts.userSessionStore,
			sessionLifecycle: opts.lifecycle,
			...(opts.auditSink ? { auditSink: opts.auditSink } : {}),
			...(opts.logger ? { logger: opts.logger } : {}),
		});
		app.use("/oauth", router);
		return app;
	}

	const introspect = (app: express.Express, token: string) =>
		request(app)
			.post("/oauth/introspect")
			.set("Authorization", `Bearer ${token}`)
			.type("form")
			.send({ token });

	it("active while the lifecycle answers the session live, read from it alone", async () => {
		const lifecycle = lifecycleAnswering({ outcome: "live", session: liveSession });
		const userSessionStore = holdingStore();
		const app = await buildApp({ lifecycle, userSessionStore });

		const res = await introspect(app, await mintAccessToken());

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(true);
		expect(lifecycle.liveness).toHaveBeenCalledExactlyOnceWith(SID);
		expect(userSessionStore.get).not.toHaveBeenCalled();
	});

	it("inactive once the session's close has committed, while its user session is still there", async () => {
		const { sink, events } = recordingSink();
		const app = await buildApp({
			lifecycle: lifecycleAnswering({ outcome: "not_live" }),
			userSessionStore: holdingStore(),
			auditSink: sink,
		});

		const res = await introspect(app, await mintAccessToken());

		expect(res.status).toBe(200);
		expect(res.body).toEqual({ active: false });
		expect(events.map((e) => [e.type, e.details])).toEqual([
			["introspect.session_invalid", { sid: SID }],
		]);
	});

	it("a derived token's liveness_sid is the session asked about", async () => {
		const lifecycle = lifecycleAnswering({ outcome: "not_live" });
		const app = await buildApp({ lifecycle, userSessionStore: holdingStore() });

		const res = await introspect(
			app,
			await mintAccessToken({ sid: undefined, liveness_sid: "sid-origin" }),
		);

		expect(res.body).toEqual({ active: false });
		expect(lifecycle.liveness).toHaveBeenCalledExactlyOnceWith("sid-origin");
	});

	it("a lifecycle that cannot answer: 503, one error line, audited as a store outage", async () => {
		const { sink, events } = recordingSink();
		const logger = createMockLogger();
		const app = await buildApp({
			lifecycle: lifecycleAnswering({ outcome: "unavailable" }),
			userSessionStore: holdingStore(),
			auditSink: sink,
			logger,
		});

		const res = await introspect(app, await mintAccessToken());

		expect(res.status).toBe(503);
		expect(res.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "session store unavailable",
		});
		expect(logger.error).toHaveBeenCalledExactlyOnceWith(
			{ store: "session_lifecycle" },
			"introspect_store_unavailable",
		);
		expect(events.map((e) => [e.type, e.details])).toEqual([
			["introspect.store_unavailable", { sid: SID }],
		]);
	});
});

describe("/oauth/userinfo through the session lifecycle", () => {
	function buildApp(opts: {
		readonly lifecycle: SessionLifecycle;
		readonly userSessionStore: UserSessionStore;
		readonly logger?: ReturnType<typeof createMockLogger>;
	}) {
		const app = express();
		app.use(
			"/oauth",
			userinfoRoute.createRouter(express, {
				keyStore,
				issuer: ISSUER,
				userSessionStore: opts.userSessionStore,
				sessionLifecycle: opts.lifecycle,
				...(opts.logger ? { logger: opts.logger } : {}),
			}),
		);
		return app;
	}

	const userinfo = async (app: express.Express, extra: Record<string, unknown> = {}) =>
		request(app)
			.get("/oauth/userinfo")
			.set("Authorization", `Bearer ${await mintAccessToken(extra)}`);

	it("releases the claims of the session the lifecycle answers live", async () => {
		const lifecycle = lifecycleAnswering({ outcome: "live", session: liveSession });
		const userSessionStore = holdingStore();
		const res = await userinfo(buildApp({ lifecycle, userSessionStore }));

		expect(res.status).toBe(200);
		expect(res.body).toEqual({ sub: "u-1", email: "alice@example.com" });
		expect(lifecycle.liveness).toHaveBeenCalledExactlyOnceWith(SID);
		expect(userSessionStore.get).not.toHaveBeenCalled();
	});

	it("refuses once the session's close has committed, while its user session is still there", async () => {
		const res = await userinfo(
			buildApp({
				lifecycle: lifecycleAnswering({ outcome: "not_live" }),
				userSessionStore: holdingStore(),
			}),
		);

		expect(res.status).toBe(401);
		expect(res.body).toEqual({ error: "invalid_token", error_description: "session_invalid" });
		expect(res.headers["www-authenticate"]).toBe('Bearer realm="userinfo", error="invalid_token"');
	});

	it("a liveness-only link refused the same way", async () => {
		const lifecycle = lifecycleAnswering({ outcome: "not_live" });
		const res = await userinfo(buildApp({ lifecycle, userSessionStore: holdingStore() }), {
			sid: undefined,
			liveness_sid: "sid-origin",
		});

		expect(res.status).toBe(401);
		expect(lifecycle.liveness).toHaveBeenCalledExactlyOnceWith("sid-origin");
	});

	it("a lifecycle that cannot answer: 503 with no claims, one error line", async () => {
		const logger = createMockLogger();
		const res = await userinfo(
			buildApp({
				lifecycle: lifecycleAnswering({ outcome: "unavailable" }),
				userSessionStore: holdingStore(),
				logger,
			}),
		);

		expect(res.status).toBe(503);
		expect(res.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "session store unavailable",
		});
		expect(logger.error).toHaveBeenCalledExactlyOnceWith(
			{ store: "session_lifecycle" },
			"userinfo_store_unavailable",
		);
	});
});

describe("POST /oauth/federation/:name/token through the session lifecycle", () => {
	const fedTokens: FederationTokens = {
		accessToken: "upstream-at",
		refreshToken: "upstream-rt",
		idToken: undefined,
		expiresAt: new Date(Date.now() + 3_600_000),
		tokenType: "Bearer",
		scope: "openid",
		grantedScope: undefined,
		obtainedAt: undefined,
	};

	function buildApp(opts: {
		readonly lifecycle: SessionLifecycle;
		readonly userSessionStore: UserSessionStore;
		readonly logger?: ReturnType<typeof createMockLogger>;
	}) {
		const app = express();
		app.use(
			"/oauth",
			federationTokenRoute.createRouter(express, {
				keyStore,
				issuer: ISSUER,
				userSessionStore: opts.userSessionStore,
				sessionLifecycle: opts.lifecycle,
				sessionFederationIndex: {
					kind: "memory",
					addFederation: vi.fn(async () => {}),
					listFederations: vi.fn(async () => ["google"]),
					removeFederation: vi.fn(async () => {}),
					removeBySid: vi.fn(async () => {}),
				} as unknown as SessionFederationIndex,
				refreshTokenFamilyRevocation: {
					isFamilyRevoked: vi.fn(async () => false),
					revokeFamily: vi.fn(async () => undefined),
				},
				federationTokenStore: {
					kind: "memory",
					attach: vi.fn(),
					get: vi.fn(async () => fedTokens),
					getVersioned: vi.fn(async () => ({ value: fedTokens, generation: "g" })),
					replaceIf: vi.fn(),
					removeIf: vi.fn(),
					removeBySid: vi.fn(),
					delete: vi.fn(),
				} as unknown as FederationTokenStore,
				clientRepository: {
					findById: vi.fn(async () => ({
						clientId: "client-1",
						allowedRedirectUris: [],
						allowedScopes: [],
						allowedAzpForFederationToken: true,
					})),
					authenticate: vi.fn(),
				} as unknown as ClientRepository,
				getFederationProviders: () => undefined,
				...(opts.logger ? { logger: opts.logger } : {}),
			}),
		);
		return app;
	}

	const fedToken = async (app: express.Express) =>
		request(app)
			.post("/oauth/federation/google/token")
			.set(
				"Authorization",
				`Bearer ${await mintAccessToken({ azp: "client-1", family_id: "fam-1" })}`,
			)
			.send();

	it("serves while the lifecycle answers the session live, read from it alone", async () => {
		const lifecycle = lifecycleAnswering({ outcome: "live", session: liveSession });
		const userSessionStore = holdingStore();
		const res = await fedToken(buildApp({ lifecycle, userSessionStore }));

		expect(res.status).toBe(200);
		expect(res.body.access_token).toBe("upstream-at");
		expect(lifecycle.liveness).toHaveBeenCalledExactlyOnceWith(SID);
		expect(userSessionStore.get).not.toHaveBeenCalled();
	});

	it("refuses once the session's close has committed, while its user session is still there", async () => {
		const res = await fedToken(
			buildApp({
				lifecycle: lifecycleAnswering({ outcome: "not_live" }),
				userSessionStore: holdingStore(),
			}),
		);

		expect(res.status).toBe(401);
		expect(res.body).toEqual({ error: "invalid_token", error_description: "session not found" });
	});

	it("a lifecycle that cannot answer: 503, one error line", async () => {
		const logger = createMockLogger();
		const res = await fedToken(
			buildApp({
				lifecycle: lifecycleAnswering({ outcome: "unavailable" }),
				userSessionStore: holdingStore(),
				logger,
			}),
		);

		expect(res.status).toBe(503);
		expect(res.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "session store unavailable",
		});
		expect(logger.error).toHaveBeenCalledExactlyOnceWith(
			{ federation: "google", store: "session_lifecycle", step: "liveness" },
			"federation_token_store_unavailable",
		);
	});
});

describe("oauthEndpointsModule", () => {
	it("takes the session lifecycle as optional", () => {
		expect(oauthEndpointsModule.optional).toContain("sessionLifecycle");
		expect(oauthEndpointsModule.requires).not.toContain("sessionLifecycle");
	});
});
