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
 * #527 — the consent step for clients that are not first-party.
 *
 * Before this, `/authorize` refused every client not marked `firstParty` —
 * and the only way to serve a third-party client was to mark it first-party,
 * after which a code was minted with no consent step at all. Now the user is
 * asked, on the deployment's own page, and what they answered is recorded.
 */

import crypto from "node:crypto";
import {
	type AppConfig,
	type AuditEvent,
	type AuditSink,
	type ClientRepository,
	type CodeRepository,
	type ConsentStore,
	createMemoryConsentStore,
	createMemoryPendingConsentStore,
	createSymmetricKeyStore,
	type PendingConsentRecord,
	type PendingConsentStore,
	type PublicClient,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { GrantRegistry } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { PENDING_CONSENT_TTL_MS } from "#/routes/consent.mjs";
import { createOAuthRouter } from "#/routes.mjs";
import { createMockLogger } from "./_helpers/mockLogger.mjs";

const CLIENT_ID = "third-party-chat";
const REDIRECT_URI = "https://chat.example/cb";
const VERIFIER = "pkce-verifier".padEnd(43, "x");
const S256_CHALLENGE = crypto.createHash("sha256").update(VERIFIER).digest("base64url");

const makeConfig = (consentUrl?: string): AppConfig =>
	({
		oauth: {
			jwt: { issuer: "https://issuer.example" },
			oidcMode: "dual",
			grants: {},
		},
		rateLimit: { failMode: "open" as const },
		endpoints: {
			login: { url: "/login" },
			...(consentUrl === undefined ? {} : { consent: { url: consentUrl } }),
		},
	}) as unknown as AppConfig;

type Session = Record<string, unknown>;

const makeApp = async (opts: {
	client?: Record<string, unknown>;
	consentStore?: ConsentStore;
	/**
	 * #552: where a parked request waits for its answer. Defaults to the
	 * memory store; `null` wires none, for the composition check.
	 */
	pendingConsentStore?: PendingConsentStore | null;
	/** #552: the express-session id the middleware reports, per request. */
	sessionId?: () => string | undefined;
	session?: Session;
	consentUrl?: string;
	auditSink?: AuditSink;
	/** #527 review: the durable session behind the cookie, when a test needs one. */
	userSessionStore?: UserSessionStore;
	/** #527 review: a registry that fails, or forgets the client, mid-flow. */
	clientRepository?: ClientRepository;
}) => {
	const record = {
		clientId: CLIENT_ID,
		tokenEndpointAuthMethod: "none" as const,
		allowedRedirectUris: [REDIRECT_URI],
		allowedScopes: ["read", "write"],
		defaultScopes: ["read"],
		clientName: "Acme Chat",
		clientUri: "https://chat.example",
		firstParty: false,
		...(opts.client ?? {}),
	} as unknown as PublicClient;
	const clientRepository: ClientRepository = opts.clientRepository ?? {
		findById: async (id) => (id === CLIENT_ID ? record : null),
		authenticate: async () => null,
	};
	const createCode = vi.fn(async () => ({
		code: "code-x",
		client_id: CLIENT_ID,
		redirect_uri: REDIRECT_URI,
	}));
	const codeRepository: CodeRepository = {
		createCode: async (params) => createCode(params) as ReturnType<CodeRepository["createCode"]>,
		findByCode: async () => null,
		consumeByCode: async () => null,
		removeByCode: async () => {},
	};
	const pending = opts.pendingConsentStore ?? createMemoryPendingConsentStore();
	const { router } = await createOAuthRouter(express, {
		registry: new GrantRegistry(),
		config: makeConfig(opts.consentUrl),
		clientRepository,
		codeRepository,
		keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
		...(opts.consentStore ? { consentStore: opts.consentStore } : {}),
		...(opts.pendingConsentStore === null ||
		(opts.consentStore === undefined && opts.pendingConsentStore === undefined)
			? {}
			: { pendingConsentStore: pending }),
		...(opts.auditSink ? { auditSink: opts.auditSink } : {}),
		...(opts.userSessionStore ? { userSessionStore: opts.userSessionStore } : {}),
		logger: createMockLogger(),
	});
	// One session object for the whole test, so what `/authorize` parks is
	// what `/oauth/consent` finds — the way express-session persists it.
	const session: Session = opts.session ?? { isAuthenticated: true, user: { id: "user-1" } };
	const app = express();
	app.use((req, _res, next) => {
		(req as unknown as { session: Session }).session = session;
		// What express-session would report as this session's id (#552).
		(req as unknown as { sessionID?: string }).sessionID = opts.sessionId
			? opts.sessionId()
			: "sess-1";
		next();
	});
	app.use("/oauth", router);
	return { app, session, createCode, pending };
};

/** The registered third-party client, for a test that supplies its own registry. */
const THIRD_PARTY_CLIENT = {
	clientId: CLIENT_ID,
	tokenEndpointAuthMethod: "none" as const,
	allowedRedirectUris: [REDIRECT_URI],
	allowedScopes: ["read", "write"],
	defaultScopes: ["read"],
	clientName: "Acme Chat",
	clientUri: "https://chat.example",
	firstParty: false,
} as unknown as PublicClient;

const baseQuery = {
	response_type: "code",
	client_id: CLIENT_ID,
	redirect_uri: REDIRECT_URI,
	state: "xyz",
	code_challenge: S256_CHALLENGE,
	code_challenge_method: "S256",
	scope: "read",
};

const authorize = (app: express.Express, extra: Record<string, string> = {}) =>
	request(app)
		.get("/oauth/authorize")
		.query({ ...baseQuery, ...extra });

const atClient = (res: request.Response): URLSearchParams => {
	expect(res.status).toBe(302);
	const location = new URL(res.headers.location as string);
	expect(location.origin + location.pathname).toBe(REDIRECT_URI);
	return location.searchParams;
};

/** A 302 to the consent page; returns the challenge it carries. */
const atConsentPage = (res: request.Response, consentPath = "/consent"): string => {
	expect(res.status).toBe(302);
	const location = new URL(res.headers.location as string, "https://issuer.example");
	expect(location.pathname).toBe(consentPath);
	const challenge = location.searchParams.get("challenge");
	expect(challenge).toBeTruthy();
	return challenge as string;
};

const granted = async (store: ConsentStore, scopes: readonly string[]) =>
	store.grant({ sub: "user-1", clientId: CLIENT_ID, scopes, grantedAt: Date.now() });

const collectingSink = (): { sink: AuditSink; events: AuditEvent[] } => {
	const events: AuditEvent[] = [];
	return {
		sink: {
			kind: "collect",
			record: async (event) => {
				events.push(event);
			},
		} as unknown as AuditSink,
		events,
	};
};

describe("/authorize for a client that is not first-party (#527)", () => {
	it("refuses it when no consent store is wired — the #267 rule, unchanged", async () => {
		const { app, pending } = await makeApp({});
		const params = atClient(await authorize(app));
		expect(params.get("error")).toBe("unauthorized_client");
		expect(pending.size).toBe(0);
	});

	it("parks the request under a challenge of its own and sends the browser to the consent page", async () => {
		const { app, pending, createCode } = await makeApp({
			consentStore: createMemoryConsentStore(),
		});
		const challenge = atConsentPage(await authorize(app));

		expect(createCode).not.toHaveBeenCalled();
		const parked = await pending.get(challenge);
		// Bound to the session that parked it and the subject it was asked
		// of, so only they can answer (#552).
		expect(parked).toMatchObject({
			challenge,
			sessionId: "sess-1",
			sub: "user-1",
			clientId: CLIENT_ID,
			scopes: ["read"],
			grantedScopes: [],
			redirectUri: REDIRECT_URI,
			state: "xyz",
		});
		expect(parked?.authorizeUrl).toMatch(/^https:\/\/issuer\.example\/oauth\/authorize\?/);
		expect(parked?.expiresAt).toBe((parked?.createdAt ?? 0) + PENDING_CONSENT_TTL_MS);
		// Unguessable, and different every time.
		expect(challenge.length).toBeGreaterThanOrEqual(43);
		const again = atConsentPage(await authorize(app));
		expect(again).not.toBe(challenge);
	});

	it("honours a consent URL that already carries a query string", async () => {
		const { app } = await makeApp({
			consentStore: createMemoryConsentStore(),
			consentUrl: "/consent?tenant=acme",
		});
		const res = await authorize(app);
		expect(res.status).toBe(302);
		expect(res.headers.location).toMatch(/^\/consent\?tenant=acme&challenge=/);
	});

	it("skips the page when a live record covers the request", async () => {
		const store = createMemoryConsentStore();
		await granted(store, ["read", "write"]);
		const { app, pending, createCode } = await makeApp({ consentStore: store });
		const params = atClient(await authorize(app));
		expect(params.get("code")).toBe("code-x");
		expect(createCode).toHaveBeenCalledTimes(1);
		expect(pending.size).toBe(0);
	});

	it("asks again for a superset of what was granted, telling the page what was", async () => {
		const store = createMemoryConsentStore();
		await granted(store, ["read"]);
		const { app, pending } = await makeApp({ consentStore: store });
		const challenge = atConsentPage(await authorize(app, { scope: "read write" }));
		expect(await pending.get(challenge)).toMatchObject({
			scopes: ["read", "write"],
			grantedScopes: ["read"],
		});
	});

	it("prompt=consent forces the page even when a record covers the request", async () => {
		const store = createMemoryConsentStore();
		await granted(store, ["read", "write"]);
		const { app } = await makeApp({ consentStore: store });
		atConsentPage(await authorize(app, { prompt: "consent" }));
	});

	it("prompt=none without a covering record answers consent_required at the client", async () => {
		const { app, pending } = await makeApp({ consentStore: createMemoryConsentStore() });
		const params = atClient(await authorize(app, { prompt: "none" }));
		expect(params.get("error")).toBe("consent_required");
		expect(params.get("state")).toBe("xyz");
		expect(pending.size).toBe(0);
	});

	it("never consults the store for a first-party client, and prompt=consent is a no-op there", async () => {
		const store = createMemoryConsentStore();
		const find = vi.spyOn(store, "find");
		const { app } = await makeApp({ consentStore: store, client: { firstParty: true } });
		expect(atClient(await authorize(app)).get("code")).toBe("code-x");
		expect(atClient(await authorize(app, { prompt: "consent" })).get("code")).toBe("code-x");
		expect(find).not.toHaveBeenCalled();
	});

	it("answers temporarily_unavailable when the store cannot answer — an outage is not a decision", async () => {
		const store: ConsentStore = {
			kind: "down",
			find: async () => {
				throw new Error("consent store unreachable");
			},
			grant: async () => {},
			revoke: async () => false,
		};
		const { app, createCode } = await makeApp({ consentStore: store });
		expect(atClient(await authorize(app)).get("error")).toBe("temporarily_unavailable");
		expect(createCode).not.toHaveBeenCalled();
	});

	it("cannot ask a session that names no subject", async () => {
		const { app } = await makeApp({
			consentStore: createMemoryConsentStore(),
			session: { isAuthenticated: true, user: {} },
		});
		expect(atClient(await authorize(app)).get("error")).toBe("access_denied");
	});
});

describe("GET /oauth/consent (#527)", () => {
	it("tells the page what is being asked, uncacheably", async () => {
		const store = createMemoryConsentStore();
		await granted(store, ["read"]);
		const { app } = await makeApp({ consentStore: store });
		const challenge = atConsentPage(await authorize(app, { scope: "read write" }));

		const res = await request(app).get("/oauth/consent").query({ challenge });
		expect(res.status).toBe(200);
		expect(res.headers["cache-control"]).toBe("no-store");
		expect(res.body).toMatchObject({
			challenge,
			client_id: CLIENT_ID,
			client_name: "Acme Chat",
			client_uri: "https://chat.example",
			scopes: ["read", "write"],
			granted_scopes: ["read"],
			redirect_uri: REDIRECT_URI,
		});
		expect(res.body.expires_in).toBeGreaterThan(0);
		expect(res.body.expires_in).toBeLessThanOrEqual(PENDING_CONSENT_TTL_MS / 1000);
	});

	it("refuses a missing, foreign or expired challenge, and an unauthenticated session", async () => {
		const { app, session, pending } = await makeApp({ consentStore: createMemoryConsentStore() });
		const challenge = atConsentPage(await authorize(app));

		expect((await request(app).get("/oauth/consent")).status).toBe(400);
		expect((await request(app).get("/oauth/consent").query({ challenge: "not-mine" })).status).toBe(
			400,
		);

		// The parked request expires with its record: past the TTL the store
		// no longer has it, and the page is told there is nothing to answer.
		vi.useFakeTimers({ toFake: ["Date"] });
		try {
			vi.setSystemTime(Date.now() + PENDING_CONSENT_TTL_MS + 1);
			const expired = await request(app).get("/oauth/consent").query({ challenge });
			expect(expired.status).toBe(400);
			expect(expired.body.error_description).toMatch(/no pending consent/);
			expect(expired.body.error_description).toMatch(/expired/);
			expect(await pending.get(challenge)).toBeNull();
		} finally {
			vi.useRealTimers();
		}

		session.isAuthenticated = false;
		expect((await request(app).get("/oauth/consent").query({ challenge })).status).toBe(401);
	});

	it("is not mounted at all when no consent store is wired", async () => {
		const { app } = await makeApp({});
		expect((await request(app).get("/oauth/consent").query({ challenge: "x" })).status).toBe(404);
	});
});

describe("POST /oauth/consent (#527)", () => {
	it("accept records the consent, sends the browser back to the parked request, and the request then mints", async () => {
		const store = createMemoryConsentStore();
		const { sink, events } = collectingSink();
		const { app, pending, createCode } = await makeApp({ consentStore: store, auditSink: sink });
		const challenge = atConsentPage(await authorize(app));
		const parked = (await pending.get(challenge)) as PendingConsentRecord;

		const res = await request(app).post("/oauth/consent").send({ challenge, decision: "accept" });
		expect(res.status).toBe(303);
		expect(res.headers.location).toBe(parked.authorizeUrl);
		expect(pending.size).toBe(0);
		expect(await store.find("user-1", CLIENT_ID)).toMatchObject({ scopes: ["read"] });
		expect(events.map((e) => e.type)).toContain("consent.granted");
		expect(events.find((e) => e.type === "consent.granted")).toMatchObject({
			subject: "user-1",
			clientId: CLIENT_ID,
			details: { scopes: ["read"] },
		});

		// The browser follows the 303 to the parked request: covered now.
		expect(atClient(await authorize(app)).get("code")).toBe("code-x");
		expect(createCode).toHaveBeenCalledTimes(1);
	});

	it("accept unions with what was already granted — consenting to write does not withdraw read", async () => {
		const store = createMemoryConsentStore();
		await granted(store, ["read"]);
		const { app } = await makeApp({ consentStore: store });
		const challenge = atConsentPage(await authorize(app, { scope: "write" }));
		await request(app).post("/oauth/consent").send({ challenge, decision: "accept" });
		expect((await store.find("user-1", CLIENT_ID))?.scopes).toEqual(["read", "write"]);
	});

	it("accepts a form post as well as JSON", async () => {
		const store = createMemoryConsentStore();
		const { app } = await makeApp({ consentStore: store });
		const challenge = atConsentPage(await authorize(app));
		const res = await request(app)
			.post("/oauth/consent")
			.type("form")
			.send({ challenge, decision: "accept" });
		expect(res.status).toBe(303);
		expect(await store.find("user-1", CLIENT_ID)).not.toBeNull();
	});

	it("deny sends the browser to the client with access_denied and the state, and records nothing", async () => {
		const store = createMemoryConsentStore();
		const { sink, events } = collectingSink();
		const { app, pending } = await makeApp({ consentStore: store, auditSink: sink });
		const challenge = atConsentPage(await authorize(app));

		const res = await request(app).post("/oauth/consent").send({ challenge, decision: "deny" });
		expect(res.status).toBe(303);
		const location = new URL(res.headers.location as string);
		expect(location.origin + location.pathname).toBe(REDIRECT_URI);
		expect(location.searchParams.get("error")).toBe("access_denied");
		expect(location.searchParams.get("state")).toBe("xyz");
		expect(pending.size).toBe(0);
		expect(await store.find("user-1", CLIENT_ID)).toBeNull();
		expect(events.map((e) => e.type)).toContain("consent.denied");
	});

	it("refuses a foreign challenge, an unknown decision (keeping the parked request), and a replayed answer", async () => {
		const store = createMemoryConsentStore();
		const { app, pending } = await makeApp({ consentStore: store });
		const challenge = atConsentPage(await authorize(app));

		expect(
			(
				await request(app)
					.post("/oauth/consent")
					.send({ challenge: "not-mine", decision: "accept" })
			).status,
		).toBe(400);
		expect(
			(await request(app).post("/oauth/consent").send({ challenge, decision: "maybe" })).status,
		).toBe(400);
		expect(await pending.get(challenge)).not.toBeNull();

		expect(
			(await request(app).post("/oauth/consent").send({ challenge, decision: "accept" })).status,
		).toBe(303);
		// One answer per challenge.
		expect(
			(await request(app).post("/oauth/consent").send({ challenge, decision: "accept" })).status,
		).toBe(400);
	});

	it("answers 503 when the store cannot record, leaving nothing half done", async () => {
		const store: ConsentStore = {
			...createMemoryConsentStore(),
			grant: async () => {
				throw new Error("consent store unreachable");
			},
		};
		const { app } = await makeApp({ consentStore: store });
		const challenge = atConsentPage(await authorize(app));
		const res = await request(app).post("/oauth/consent").send({ challenge, decision: "accept" });
		expect(res.status).toBe(503);
		expect(res.body.error).toBe("temporarily_unavailable");
	});
});

describe("the parked request resumes as the request that was made (#527 review)", () => {
	it("drops prompt=consent from the URL it returns to, so an accepted request does not park again", async () => {
		// Carried back, `prompt=consent` parks the request a second time, and a
		// third: every forced-consent request would loop forever.
		const { app, pending } = await makeApp({ consentStore: createMemoryConsentStore() });
		const challenge = atConsentPage(await authorize(app, { prompt: "consent" }));
		const parked = new URL((await pending.get(challenge))?.authorizeUrl as string);
		expect(parked.searchParams.get("prompt")).toBeNull();
		expect(parked.searchParams.get("client_id")).toBe(CLIENT_ID);
	});

	it("does not reach the consent step while a re-authentication is outstanding", async () => {
		// `prompt=login consent` is answered by #481's re-authentication first —
		// here by `invalid_request`, because this composition wires no user
		// session store — so nothing is parked and the one-shot `consent` is
		// still to be spent on the way back.
		const { app, pending } = await makeApp({ consentStore: createMemoryConsentStore() });
		const res = await authorize(app, { prompt: "login consent" });
		expect(atClient(res).get("error")).toBe("invalid_request");
		expect(pending.size).toBe(0);
	});

	it("carries a POST's form parameters into the URL it returns to", async () => {
		// `authorizeParams` reads a POST from the body, so `req.originalUrl` is
		// bare `/oauth/authorize`: resumed from it, the request would name no
		// client and no redirect_uri.
		const { app, pending } = await makeApp({ consentStore: createMemoryConsentStore() });
		const res = await request(app).post("/oauth/authorize").type("form").send(baseQuery);
		const challenge = atConsentPage(res);
		const parked = new URL((await pending.get(challenge))?.authorizeUrl as string);
		expect(parked.pathname).toBe("/oauth/authorize");
		expect(parked.searchParams.get("client_id")).toBe(CLIENT_ID);
		expect(parked.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);
		expect(parked.searchParams.get("code_challenge")).toBe(S256_CHALLENGE);
		expect(parked.searchParams.get("code_challenge_method")).toBe("S256");
		expect(parked.searchParams.get("state")).toBe("xyz");
		expect(parked.searchParams.get("scope")).toBe("read");
	});
});

describe("the consent endpoints answer only for a live session (#527 review)", () => {
	/** A store that knows `sid` only while `alive` says so. */
	const storeFor = (alive: () => boolean): UserSessionStore =>
		({
			kind: "memory",
			create: vi.fn(async () => {}),
			get: vi.fn(async (sid: string) =>
				alive() && sid === "sid-1"
					? {
							sid: "sid-1",
							sub: "user-1",
							authTime: new Date(),
							createdAt: new Date(),
							expiresAt: new Date(Date.now() + 3_600_000),
							claims: {},
						}
					: null,
			),
			delete: vi.fn(async () => {}),
		}) as unknown as UserSessionStore;

	const parked = async (alive: () => boolean) => {
		const consentStore = createMemoryConsentStore();
		const harness = await makeApp({
			consentStore,
			session: { isAuthenticated: true, sid: "sid-1", user: { id: "user-1" } } as Session,
			userSessionStore: storeFor(alive),
		});
		const challenge = atConsentPage(await authorize(harness.app));
		return { ...harness, challenge, consentStore };
	};

	it("refuses the page when the durable session was revoked behind the cookie", async () => {
		let alive = true;
		const { app, challenge } = await parked(() => alive);
		alive = false;
		const res = await request(app).get("/oauth/consent").query({ challenge });
		expect(res.status).toBe(401);
		expect(res.body.error).toBe("login_required");
	});

	it("refuses the answer too, and records nothing", async () => {
		let alive = true;
		const { app, challenge, consentStore } = await parked(() => alive);
		alive = false;
		const res = await request(app)
			.post("/oauth/consent")
			.type("form")
			.send({ challenge, decision: "accept" });
		expect(res.status).toBe(401);
		expect(res.body.error).toBe("login_required");
		expect(await consentStore.find("user-1", CLIENT_ID)).toBeNull();
	});

	it("accepts while the session is live", async () => {
		const { app, challenge, consentStore } = await parked(() => true);
		const res = await request(app)
			.post("/oauth/consent")
			.type("form")
			.send({ challenge, decision: "accept" });
		expect(res.status).toBe(303);
		expect((await consentStore.find("user-1", CLIENT_ID))?.scopes).toEqual(["read"]);
	});
});

describe("the consent page and its answer, on the edges (#527 review)", () => {
	const parkedWith = async (extra: Parameters<typeof makeApp>[0] = {}) => {
		const consentStore = createMemoryConsentStore();
		const harness = await makeApp({ consentStore, ...extra });
		const challenge = atConsentPage(await authorize(harness.app));
		return { ...harness, challenge, consentStore };
	};

	it("answers 503 when the client registry cannot be reached", async () => {
		const consentStore = createMemoryConsentStore();
		let fail = false;
		const harness = await makeApp({
			consentStore,
			clientRepository: {
				findById: async (id: string) => {
					if (fail) throw new Error("registry down");
					return id === CLIENT_ID ? THIRD_PARTY_CLIENT : null;
				},
				authenticate: async () => null,
			},
		});
		const challenge = atConsentPage(await authorize(harness.app));
		fail = true;
		const res = await request(harness.app).get("/oauth/consent").query({ challenge });
		expect(res.status).toBe(503);
		expect(res.body.error).toBe("temporarily_unavailable");
	});

	it("drops the parked request when the client is no longer registered", async () => {
		const consentStore = createMemoryConsentStore();
		let registered = true;
		const harness = await makeApp({
			consentStore,
			clientRepository: {
				findById: async (id: string) =>
					registered && id === CLIENT_ID ? THIRD_PARTY_CLIENT : null,
				authenticate: async () => null,
			},
		});
		const challenge = atConsentPage(await authorize(harness.app));
		registered = false;
		const res = await request(harness.app).get("/oauth/consent").query({ challenge });
		expect(res.status).toBe(400);
		expect(res.body.error_description).toMatch(/no longer registered/);
		expect(harness.pending.size).toBe(0);
	});

	it("refuses an answer from a session that names no subject", async () => {
		const { app, challenge, session } = await parkedWith({});
		session.user = {};
		const res = await request(app)
			.post("/oauth/consent")
			.type("form")
			.send({ challenge, decision: "accept" });
		expect(res.status).toBe(400);
		expect(res.body.error_description).toMatch(/names no subject/);
	});

	it("fails closed when the session store cannot answer", async () => {
		// `/authorize` reads the same store, so it has to answer while the
		// request is being parked and fail only afterwards.
		let down = false;
		const flaky = {
			kind: "memory",
			create: vi.fn(async () => {}),
			get: vi.fn(async (sid: string) => {
				if (down) throw new Error("session store down");
				return {
					sid,
					sub: "user-1",
					authTime: new Date(),
					createdAt: new Date(),
					expiresAt: new Date(Date.now() + 3_600_000),
					claims: {},
				};
			}),
			delete: vi.fn(async () => {}),
		} as unknown as UserSessionStore;
		const { app, challenge } = await parkedWith({
			session: { isAuthenticated: true, sid: "sid-1", user: { id: "user-1" } } as Session,
			userSessionStore: flaky,
		});
		down = true;
		const res = await request(app).get("/oauth/consent").query({ challenge });
		expect(res.status).toBe(401);
		expect(res.body.error).toBe("login_required");
	});

	it("carries a repeated resource parameter into the parked URL", async () => {
		// RFC 8707 allows more than one `resource`; the single-valued guard does
		// not cover it, so the parked URL has to keep both.
		const { app, pending } = await makeApp({ consentStore: createMemoryConsentStore() });
		const challenge = atConsentPage(
			await request(app)
				.get("/oauth/authorize")
				.query({ ...baseQuery, resource: ["https://api.example/a", "https://api.example/b"] }),
		);
		const parked = new URL((await pending.get(challenge))?.authorizeUrl as string);
		expect(parked.searchParams.getAll("resource")).toEqual([
			"https://api.example/a",
			"https://api.example/b",
		]);
	});
});

describe("one challenge, one answer (#552)", () => {
	/** A user-session store whose reads wait until the test lets them through. */
	const gatedSessionStore = () => {
		let release: () => void = () => {};
		let gate: Promise<void> = Promise.resolve();
		const get = vi.fn(async (sid: string) => {
			await gate;
			return {
				sid,
				sub: "user-1",
				authTime: new Date(),
				createdAt: new Date(),
				expiresAt: new Date(Date.now() + 3_600_000),
				claims: {},
			};
		});
		const store = {
			kind: "memory",
			create: vi.fn(async () => {}),
			get,
			delete: vi.fn(async () => {}),
		} as unknown as UserSessionStore;
		return {
			store,
			get,
			hold: () => {
				gate = new Promise<void>((resolve) => {
					release = resolve;
				});
			},
			release: () => release(),
		};
	};

	it("applies exactly one of two answers in flight for the same challenge", async () => {
		// Both answers name the same parked request, both pass every check, and
		// both are waiting on the session store when it answers — the shape a
		// duplicated tab or a double submit produces. The record used to be a
		// field on the session snapshot each request had already read, so both
		// went on to apply: an accept and a deny for one challenge, and the
		// accept's grant stood although the user had denied. Now the answer
		// consumes the record in one step, and the second finds nothing.
		const consentStore = createMemoryConsentStore();
		const { sink, events } = collectingSink();
		const gated = gatedSessionStore();
		const { app, pending } = await makeApp({
			consentStore,
			auditSink: sink,
			session: { isAuthenticated: true, sid: "sid-1", user: { id: "user-1" } },
			userSessionStore: gated.store,
		});
		const challenge = atConsentPage(await authorize(app));
		const readsSoFar = gated.get.mock.calls.length;

		gated.hold();
		const accept = request(app)
			.post("/oauth/consent")
			.send({ challenge, decision: "accept" })
			.then((res) => res);
		const deny = request(app)
			.post("/oauth/consent")
			.send({ challenge, decision: "deny" })
			.then((res) => res);
		// Both requests are past the challenge check and parked on the store.
		await vi.waitFor(() => expect(gated.get).toHaveBeenCalledTimes(readsSoFar + 2));
		gated.release();
		const [accepted, denied] = await Promise.all([accept, deny]);

		expect([accepted.status, denied.status].sort()).toEqual([303, 400]);
		expect(pending.size).toBe(0);
		const decided = events.filter(
			(e) => e.type === "consent.granted" || e.type === "consent.denied",
		);
		expect(decided).toHaveLength(1);
		// Whichever answer was handed the record is the one on record.
		const record = await consentStore.find("user-1", CLIENT_ID);
		expect(record !== null).toBe(decided[0]?.type === "consent.granted");
	});

	it("refuses an answer from a session other than the one that parked the request", async () => {
		// The challenge is unguessable, but it is not a bearer token: the record
		// names the session it was issued to, and another session presenting it
		// — a leaked redirect URL — is told there is nothing to answer.
		let sessionId = "sess-1";
		const { app, pending } = await makeApp({
			consentStore: createMemoryConsentStore(),
			sessionId: () => sessionId,
		});
		const challenge = atConsentPage(await authorize(app));
		sessionId = "sess-2";
		const res = await request(app).post("/oauth/consent").send({ challenge, decision: "accept" });
		expect(res.status).toBe(400);
		expect(res.body.error_description).toMatch(/no pending consent/);
		expect(await pending.get(challenge)).not.toBeNull();
	});

	it("lets the page read the request more than once; only the answer spends it", async () => {
		const { app, pending } = await makeApp({ consentStore: createMemoryConsentStore() });
		const challenge = atConsentPage(await authorize(app));
		expect((await request(app).get("/oauth/consent").query({ challenge })).status).toBe(200);
		expect((await request(app).get("/oauth/consent").query({ challenge })).status).toBe(200);
		expect(await pending.get(challenge)).not.toBeNull();
		expect(
			(await request(app).post("/oauth/consent").send({ challenge, decision: "deny" })).status,
		).toBe(303);
		expect(pending.size).toBe(0);
	});

	it("cannot park a request for a session that reports no id to bind the challenge to", async () => {
		const { app, pending } = await makeApp({
			consentStore: createMemoryConsentStore(),
			sessionId: () => undefined,
		});
		expect(atClient(await authorize(app)).get("error")).toBe("access_denied");
		expect(pending.size).toBe(0);
	});

	it("refuses a composition that wires the consent store without the store its challenges live in, and the reverse", async () => {
		await expect(
			makeApp({ consentStore: createMemoryConsentStore(), pendingConsentStore: null }),
		).rejects.toThrow(/consentStore is wired but pendingConsentStore is not/);
		// The other half alone mounts nothing and would refuse every third-party
		// client at /authorize with no hint of why; the mismatch is the fault,
		// whichever side is missing.
		await expect(
			makeApp({ pendingConsentStore: createMemoryPendingConsentStore() }),
		).rejects.toThrow(/pendingConsentStore is wired but consentStore is not/);
	});
});

describe("the parked request and its store, on the edges (#552 review)", () => {
	/** A pending-consent store whose operations fail on demand. */
	const flakyPending = () => {
		const inner = createMemoryPendingConsentStore();
		const down = { set: false, get: false, consume: false };
		const store: PendingConsentStore = {
			kind: "flaky",
			set: async (record) => {
				if (down.set) throw new Error("pending store down");
				return inner.set(record);
			},
			get: async (challenge) => {
				if (down.get) throw new Error("pending store down");
				return inner.get(challenge);
			},
			consume: async (challenge) => {
				if (down.consume) throw new Error("pending store down");
				return inner.consume(challenge);
			},
		};
		return { store, inner, down };
	};

	const parkedOn = async (extra: Parameters<typeof makeApp>[0] = {}) => {
		const consentStore = createMemoryConsentStore();
		const flaky = flakyPending();
		const harness = await makeApp({ consentStore, pendingConsentStore: flaky.store, ...extra });
		const challenge = atConsentPage(await authorize(harness.app));
		return { ...harness, challenge, consentStore, ...flaky };
	};

	it("/authorize answers temporarily_unavailable when the request cannot be parked", async () => {
		const flaky = flakyPending();
		const { app, createCode } = await makeApp({
			consentStore: createMemoryConsentStore(),
			pendingConsentStore: flaky.store,
		});
		flaky.down.set = true;
		expect(atClient(await authorize(app)).get("error")).toBe("temporarily_unavailable");
		expect(createCode).not.toHaveBeenCalled();
		expect(flaky.inner.size).toBe(0);
	});

	it("the page answers 503 when the store cannot say what is parked", async () => {
		const { app, challenge, down } = await parkedOn();
		down.get = true;
		const res = await request(app).get("/oauth/consent").query({ challenge });
		expect(res.status).toBe(503);
		expect(res.body.error).toBe("temporarily_unavailable");
	});

	it("the answer is 503, and records nothing, when the record cannot be consumed", async () => {
		const { app, challenge, down, inner, consentStore } = await parkedOn();
		down.consume = true;
		const res = await request(app).post("/oauth/consent").send({ challenge, decision: "accept" });
		expect(res.status).toBe(503);
		expect(await consentStore.find("user-1", CLIENT_ID)).toBeNull();
		// Still parked: the outage decided nothing.
		expect(await inner.get(challenge)).not.toBeNull();
	});

	it("refuses an answer from the parking session on behalf of another subject", async () => {
		const { app, challenge, session, inner, consentStore } = await parkedOn();
		session.user = { id: "user-2" };
		const res = await request(app).post("/oauth/consent").send({ challenge, decision: "accept" });
		expect(res.status).toBe(400);
		expect(res.body.error_description).toMatch(/no pending consent/);
		expect(await consentStore.find("user-2", CLIENT_ID)).toBeNull();
		expect(await inner.get(challenge)).not.toBeNull();
	});

	it("an answer for a client removed since the page was shown drops the request and records nothing", async () => {
		// The page may have been rendered while the client existed; the answer
		// arrives after an operator removed it. A grant under that id would
		// greet whoever registers under it next.
		let registered = true;
		const { app, challenge, inner, consentStore } = await parkedOn({
			clientRepository: {
				findById: async (id: string) =>
					registered && id === CLIENT_ID ? THIRD_PARTY_CLIENT : null,
				authenticate: async () => null,
			},
		});
		registered = false;
		const res = await request(app).post("/oauth/consent").send({ challenge, decision: "accept" });
		expect(res.status).toBe(400);
		expect(res.body.error_description).toMatch(/no longer registered/);
		expect(await consentStore.find("user-1", CLIENT_ID)).toBeNull();
		expect(inner.size).toBe(0);
	});

	it("an answer is 503 when the registry cannot say whether the client still exists", async () => {
		let fail = false;
		const { app, challenge, inner } = await parkedOn({
			clientRepository: {
				findById: async (id: string) => {
					if (fail) throw new Error("registry down");
					return id === CLIENT_ID ? THIRD_PARTY_CLIENT : null;
				},
				authenticate: async () => null,
			},
		});
		fail = true;
		const res = await request(app).post("/oauth/consent").send({ challenge, decision: "accept" });
		expect(res.status).toBe(503);
		expect(await inner.get(challenge)).not.toBeNull();
	});

	it("fails closed when a request for a removed client cannot be dropped", async () => {
		// A 400 here would report the request gone while the record stayed for
		// an answer to spend.
		let registered = true;
		const { app, challenge, down, inner } = await parkedOn({
			clientRepository: {
				findById: async (id: string) =>
					registered && id === CLIENT_ID ? THIRD_PARTY_CLIENT : null,
				authenticate: async () => null,
			},
		});
		registered = false;
		down.consume = true;
		const res = await request(app).get("/oauth/consent").query({ challenge });
		expect(res.status).toBe(503);
		expect(res.body.error).toBe("temporarily_unavailable");
		expect(await inner.get(challenge)).not.toBeNull();
	});
});

describe("the challenge's bindings, on the edges (#552 review)", () => {
	it("refuses an answer from a request that reports no session id, keeping the request parked", async () => {
		let sessionId: string | undefined = "sess-1";
		const { app, pending } = await makeApp({
			consentStore: createMemoryConsentStore(),
			sessionId: () => sessionId,
		});
		const challenge = atConsentPage(await authorize(app));
		sessionId = undefined;
		const res = await request(app).post("/oauth/consent").send({ challenge, decision: "accept" });
		expect(res.status).toBe(400);
		expect(res.body.error_description).toMatch(/no pending consent/);
		expect(await pending.get(challenge)).not.toBeNull();
	});

	it("parks a request that carries no state, and denies it without one", async () => {
		const { app, pending } = await makeApp({ consentStore: createMemoryConsentStore() });
		const { state: _omitted, ...withoutState } = baseQuery;
		const challenge = atConsentPage(await request(app).get("/oauth/authorize").query(withoutState));
		expect((await pending.get(challenge))?.state).toBeUndefined();
		const res = await request(app).post("/oauth/consent").send({ challenge, decision: "deny" });
		expect(res.status).toBe(303);
		const location = new URL(res.headers.location as string);
		expect(location.searchParams.get("error")).toBe("access_denied");
		expect(location.searchParams.has("state")).toBe(false);
	});
});
