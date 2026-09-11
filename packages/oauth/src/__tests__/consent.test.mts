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
	createSymmetricKeyStore,
	type PublicClient,
} from "@o3co/auth-provider-core";
import { GrantRegistry } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { PENDING_CONSENT_TTL_MS, type PendingConsent } from "#/routes/consent.mjs";
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

type Session = Record<string, unknown> & { pendingConsent?: PendingConsent };

const makeApp = async (opts: {
	client?: Record<string, unknown>;
	consentStore?: ConsentStore;
	session?: Session;
	consentUrl?: string;
	auditSink?: AuditSink;
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
	const clientRepository: ClientRepository = {
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
	const { router } = await createOAuthRouter(express, {
		registry: new GrantRegistry(),
		config: makeConfig(opts.consentUrl),
		clientRepository,
		codeRepository,
		keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
		...(opts.consentStore ? { consentStore: opts.consentStore } : {}),
		...(opts.auditSink ? { auditSink: opts.auditSink } : {}),
		logger: createMockLogger(),
	});
	// One session object for the whole test, so what `/authorize` parks is
	// what `/oauth/consent` finds — the way express-session persists it.
	const session: Session = opts.session ?? { isAuthenticated: true, user: { id: "user-1" } };
	const app = express();
	app.use((req, _res, next) => {
		(req as unknown as { session: Session }).session = session;
		next();
	});
	app.use("/oauth", router);
	return { app, session, createCode };
};

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
		const { app, session } = await makeApp({});
		const params = atClient(await authorize(app));
		expect(params.get("error")).toBe("unauthorized_client");
		expect(session.pendingConsent).toBeUndefined();
	});

	it("parks the request in the session and sends the browser to the consent page", async () => {
		const { app, session, createCode } = await makeApp({
			consentStore: createMemoryConsentStore(),
		});
		const challenge = atConsentPage(await authorize(app));

		expect(createCode).not.toHaveBeenCalled();
		expect(session.pendingConsent).toMatchObject({
			challenge,
			clientId: CLIENT_ID,
			scopes: ["read"],
			grantedScopes: [],
			redirectUri: REDIRECT_URI,
			state: "xyz",
		});
		expect(session.pendingConsent?.authorizeUrl).toMatch(
			/^https:\/\/issuer\.example\/oauth\/authorize\?/,
		);
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
		const { app, session, createCode } = await makeApp({ consentStore: store });
		const params = atClient(await authorize(app));
		expect(params.get("code")).toBe("code-x");
		expect(createCode).toHaveBeenCalledTimes(1);
		expect(session.pendingConsent).toBeUndefined();
	});

	it("asks again for a superset of what was granted, telling the page what was", async () => {
		const store = createMemoryConsentStore();
		await granted(store, ["read"]);
		const { app, session } = await makeApp({ consentStore: store });
		atConsentPage(await authorize(app, { scope: "read write" }));
		expect(session.pendingConsent).toMatchObject({
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
		const { app, session } = await makeApp({ consentStore: createMemoryConsentStore() });
		const params = atClient(await authorize(app, { prompt: "none" }));
		expect(params.get("error")).toBe("consent_required");
		expect(params.get("state")).toBe("xyz");
		expect(session.pendingConsent).toBeUndefined();
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
		const { app, session } = await makeApp({ consentStore: createMemoryConsentStore() });
		const challenge = atConsentPage(await authorize(app));

		expect((await request(app).get("/oauth/consent")).status).toBe(400);
		expect((await request(app).get("/oauth/consent").query({ challenge: "not-mine" })).status).toBe(
			400,
		);

		const pending = session.pendingConsent as PendingConsent;
		session.pendingConsent = { ...pending, createdAt: Date.now() - PENDING_CONSENT_TTL_MS - 1 };
		const expired = await request(app).get("/oauth/consent").query({ challenge });
		expect(expired.status).toBe(400);
		expect(expired.body.error_description).toMatch(/expired/);
		expect(session.pendingConsent).toBeUndefined();

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
		const { app, session, createCode } = await makeApp({ consentStore: store, auditSink: sink });
		const challenge = atConsentPage(await authorize(app));
		const parked = session.pendingConsent as PendingConsent;

		const res = await request(app).post("/oauth/consent").send({ challenge, decision: "accept" });
		expect(res.status).toBe(303);
		expect(res.headers.location).toBe(parked.authorizeUrl);
		expect(session.pendingConsent).toBeUndefined();
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
		const { app, session } = await makeApp({ consentStore: store, auditSink: sink });
		const challenge = atConsentPage(await authorize(app));

		const res = await request(app).post("/oauth/consent").send({ challenge, decision: "deny" });
		expect(res.status).toBe(303);
		const location = new URL(res.headers.location as string);
		expect(location.origin + location.pathname).toBe(REDIRECT_URI);
		expect(location.searchParams.get("error")).toBe("access_denied");
		expect(location.searchParams.get("state")).toBe("xyz");
		expect(session.pendingConsent).toBeUndefined();
		expect(await store.find("user-1", CLIENT_ID)).toBeNull();
		expect(events.map((e) => e.type)).toContain("consent.denied");
	});

	it("refuses a foreign challenge, an unknown decision (keeping the parked request), and a replayed answer", async () => {
		const store = createMemoryConsentStore();
		const { app, session } = await makeApp({ consentStore: store });
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
		expect(session.pendingConsent).toBeDefined();

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
