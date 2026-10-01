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
 * `/authorize` on session admission (ADR 2026-09-28-session-admission, D8,
 * the `/authorize` row): the cookie flag first, with no store read; one
 * `admitSession` after the client and the parameters are validated; freshness
 * (`max_age`, `prompt=login`) decided on the session the verdict carries
 * before the verdict is acted on; each outcome mapped to the protocol's
 * answer. Every change D8 makes to `/authorize` has a session-read test named
 * for it. The step-up trip is driven with a fixture requirement through
 * `resolverForTests`.
 */

import crypto from "node:crypto";
import {
	type AppConfig,
	type AuditEvent,
	type AuditSink,
	type ClientRepository,
	type CodeRepository,
	createInMemorySubjectRevocation,
	createMemoryConsentStore,
	createMemoryPendingConsentStore,
	createSymmetricKeyStore,
	type PublicClient,
	type RequirementInput,
	type RequirementVerdict,
	type SessionRequirement,
	type SubjectRevocation,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { createTestLoginEntry, resolverForTests } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createOAuthRouter } from "#/routes.mjs";
import { OAUTH_ADMISSION_ACTIONS } from "./_helpers/admissionActions.mjs";
import { authorizationServerRegistry } from "./_helpers/authorizationServerRegistry.mjs";
import { createMockLogger } from "./_helpers/mockLogger.mjs";

const CLIENT_ID = "client-a";
const REDIRECT_URI = "https://app.example/cb";
const ISSUER = "https://issuer.example";
const SID = "sid-1";
const SUBJECT = "user-1";
const VERIFIER = "pkce-verifier".padEnd(43, "x");
const S256_CHALLENGE = crypto.createHash("sha256").update(VERIFIER).digest("base64url");

const baseQuery: Record<string, string> = {
	response_type: "code",
	client_id: CLIENT_ID,
	redirect_uri: REDIRECT_URI,
	state: "xyz",
	code_challenge: S256_CHALLENGE,
	code_challenge_method: "S256",
};

const makeConfig = (oauthOverrides: Record<string, unknown> = {}): AppConfig =>
	({
		oauth: {
			jwt: { issuer: ISSUER },
			accessToken: { expiresIn: 300 },
			oidcMode: "dual",
			grants: {},
			...oauthOverrides,
		},
		rateLimit: { failMode: "open" as const },
		endpoints: { login: { url: "/login" }, consent: { url: "/consent" } },
	}) as unknown as AppConfig;

const minutesAgo = (minutes: number): Date => new Date(Date.now() - minutes * 60_000);

/** A live record, as the bundled stores answer one. */
const record = (over: Partial<UserSession> = {}): UserSession => ({
	sid: SID,
	sub: SUBJECT,
	authTime: minutesAgo(5),
	createdAt: minutesAgo(5),
	expiresAt: new Date(Date.now() + 3_600_000),
	claims: {},
	amr: ["pwd"],
	authentication: {
		primary: "pwd",
		federation: undefined,
		upstreamAmr: undefined,
		mfaAt: undefined,
	},
	...over,
});

const storeAnswering = (
	impl: (sid: string) => Promise<UserSession | null>,
): UserSessionStore & { get: ReturnType<typeof vi.fn> } =>
	({
		kind: "memory",
		create: vi.fn(async () => {}),
		get: vi.fn(impl),
		delete: vi.fn(async () => {}),
		// A store that can record a second factor: the second-factor authority's step-up is answered as a trip, not a new login.
		recordSecondFactor: vi.fn(async () => null),
	}) as unknown as UserSessionStore & { get: ReturnType<typeof vi.fn> };

const storeWith = (session: UserSession | null) =>
	storeAnswering(async (sid) => (sid === SID ? session : null));

/**
 * A fixture requirement: what it answers `/authorize` is a knob the test
 * turns between two requests, as a real step-up changes the session's
 * answer. `reach` is empty (only the requirement that declares the
 * second-factor authority may reach), and a page may stand with an empty
 * reach.
 */
const fixture = (
	name: string,
	verdict: () => RequirementVerdict,
	page: SessionRequirement["stepUpPage"] = { url: "/step-up", params: { kind: name } },
): SessionRequirement & { readonly inputs: RequirementInput[] } => {
	const inputs: RequirementInput[] = [];
	return {
		name,
		reach: new Set(),
		stepUpPage: page,
		remediations: [`${name}.step_up`],
		hintKeys: [],
		inputs,
		async admit(input) {
			inputs.push(input);
			return verdict();
		},
	};
};

type Session = Record<string, unknown>;

const makeApp = async (opts: {
	session?: Session;
	userSessionStore?: UserSessionStore;
	subjectRevocation?: SubjectRevocation;
	requirements?: readonly SessionRequirement[];
	auditSink?: AuditSink;
	logger?: ReturnType<typeof createMockLogger>;
	oauth?: Record<string, unknown>;
	clientNotFound?: boolean;
	/** The express-session store fails on one operation. */
	sessionStoreFail?: "set" | "get";
	/** The cookie session's `regenerate` fails, as a store outage makes it. */
	regenerateFails?: boolean;
	/** The cookie session has no `regenerate` at all, as a session middleware that is not express-session hands one over. */
	cannotRegenerate?: boolean;
	/** Register the requirements without holding their pages to the issuer's origin, as a hand-built resolver may. */
	anyPageOrigin?: boolean;
	/** Compose without an express-session store (no ask can be recorded). */
	sessionStore?: false;
	/** The client is not first-party: the consent step, over the memory consent stores, asks for it. */
	consent?: boolean;
	/**
	 * Called on each read of an ask record (`n` from 1): `"spend"` removes the
	 * record once it is handed back, as another pass consuming it right after
	 * would; `"fail"` answers an outage.
	 */
	onAskGet?: (n: number) => "spend" | "fail" | undefined;
}) => {
	const client = {
		clientId: CLIENT_ID,
		tokenEndpointAuthMethod: "client_secret_basic" as const,
		allowedRedirectUris: [REDIRECT_URI],
		allowedScopes: ["read"],
		defaultScopes: ["read"],
		firstParty: opts.consent !== true,
	} as unknown as PublicClient;
	const consentStore = createMemoryConsentStore();
	const pendingConsentStore = createMemoryPendingConsentStore();
	const clientRepository: ClientRepository = {
		findById: async (id) => (opts.clientNotFound ? null : id === CLIENT_ID ? client : null),
		authenticate: async () => null,
	};
	const createCode = vi.fn(async (_params: unknown) => ({
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
	const logger = opts.logger ?? createMockLogger();
	const { router } = await createOAuthRouter(express, {
		loginEntry: createTestLoginEntry(),
		registry: authorizationServerRegistry(),
		config: makeConfig(opts.oauth),
		clientRepository,
		codeRepository,
		keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
		logger,
		requirements: resolverForTests(opts.requirements ?? [], {
			...(opts.anyPageOrigin === true ? {} : { issuer: ISSUER }),
			actions: OAUTH_ADMISSION_ACTIONS,
		}),
		...(opts.userSessionStore ? { userSessionStore: opts.userSessionStore } : {}),
		...(opts.subjectRevocation ? { subjectRevocation: opts.subjectRevocation } : {}),
		...(opts.auditSink ? { auditSink: opts.auditSink } : {}),
		...(opts.consent === true ? { consentStore, pendingConsentStore } : {}),
	});

	const app = express();
	// The cookie session as express-session hands it to a route: one object
	// per app, `regenerate` replacing it with a fresh, unauthenticated one —
	// what the middleware does when a route asks for a new id.
	const state: { session: Session; regenerated: number; afterResponse?: unknown } = {
		session: { ...(opts.session ?? { isAuthenticated: true, user: { id: SUBJECT }, sid: SID }) },
		regenerated: 0,
	};
	const cookieSession = (holder: { session?: unknown }): Session => {
		const session = state.session;
		if (opts.cannotRegenerate === true) return session;
		Object.defineProperty(session, "regenerate", {
			enumerable: false,
			configurable: true,
			value: (cb: (err?: unknown) => void) => {
				if (opts.regenerateFails) return cb(new Error("session store unavailable"));
				state.regenerated++;
				state.session = {};
				holder.session = cookieSession(holder);
				cb();
			},
		});
		return session;
	};
	const records = new Map<string, unknown>();
	const storeDown = new Error("session store unavailable");
	let askGets = 0;
	const sessionStore = {
		get: (sid: string, cb: (err: unknown, rec?: unknown) => void) => {
			if (opts.sessionStoreFail === "get") return cb(storeDown);
			const found = records.get(sid);
			if (sid.startsWith("reauth:") && opts.onAskGet !== undefined) {
				const step = opts.onAskGet(++askGets);
				if (step === "fail") return cb(storeDown);
				if (step === "spend") records.delete(sid);
			}
			cb(null, found);
		},
		set: (sid: string, rec: unknown, cb?: (err?: unknown) => void) => {
			if (opts.sessionStoreFail === "set") return cb?.(storeDown);
			records.set(sid, rec);
			cb?.();
		},
		destroy: (sid: string, cb?: (err?: unknown) => void) => {
			records.delete(sid);
			cb?.();
		},
	};
	app.use((req, res, next) => {
		const holder = req as unknown as {
			session?: unknown;
			sessionStore?: unknown;
			sessionID?: string;
		};
		holder.session = cookieSession(holder);
		holder.sessionID = "cookie-session-1";
		if (opts.sessionStore !== false) holder.sessionStore = sessionStore;
		// What express-session would save when the response ends: the
		// request's session as the route left it.
		res.on("finish", () => {
			state.afterResponse = holder.session;
		});
		next();
	});
	app.use("/oauth", router);
	return {
		app,
		createCode,
		logger,
		records,
		consentStore,
		pendingConsentStore,
		get session() {
			return state.session;
		},
		get regenerated() {
			return state.regenerated;
		},
		/** The request's session when the response finished: `undefined` once a route abandoned it. */
		sessionAfterResponse: () => state.afterResponse,
		/** Replace the session object wholesale, as `/session/login` does when it regenerates. */
		login(next: Session) {
			state.session = next;
		},
	};
};

const authorize = (app: express.Express, query: Record<string, string>) =>
	request(app).get("/oauth/authorize").query(query);

/** The login-page redirect, with the round-tripped authorize URL parsed. */
const loginRedirectTo = (res: request.Response): URL => {
	expect(res.status).toBe(302);
	const location = res.headers.location as string;
	expect(location.startsWith("/login?redirect_to=")).toBe(true);
	return new URL(decodeURIComponent(location.split("redirect_to=")[1] as string));
};

/** The error redirect this endpoint answers once `redirect_uri` is trusted. */
const redirectParams = (res: request.Response): URLSearchParams => {
	expect(res.status).toBe(302);
	const location = new URL(res.headers.location as string);
	expect(location.origin + location.pathname).toBe(REDIRECT_URI);
	return location.searchParams;
};

const codeOf = (res: request.Response): string | null => redirectParams(res).get("code");

const recordingSink = () => {
	const events: AuditEvent[] = [];
	const sink: AuditSink = { kind: "recording", record: async (event) => void events.push(event) };
	return { sink, events };
};

describe("/authorize on admission — the session read", () => {
	it("a cookie with isAuthenticated but no sid, while a store is wired, is not_live: the login redirect, no code", async () => {
		const store = storeWith(record());
		const harness = await makeApp({
			userSessionStore: store,
			session: { isAuthenticated: true, user: { id: SUBJECT } },
		});
		const res = await authorize(harness.app, baseQuery);
		loginRedirectTo(res);
		expect(harness.createCode).not.toHaveBeenCalled();
		// Nothing to read: no sid names a record.
		expect(store.get).not.toHaveBeenCalled();
	});

	it("a store outage is temporarily_unavailable on the validated redirect URI, not the login page, logged as admission's line", async () => {
		const harness = await makeApp({
			userSessionStore: storeAnswering(async () => {
				throw new Error("redis down");
			}),
		});
		const params = redirectParams(await authorize(harness.app, baseQuery));
		expect(params.get("error")).toBe("temporarily_unavailable");
		expect(params.get("error_description")).toBe("session store unavailable");
		expect(harness.createCode).not.toHaveBeenCalled();
		// The consumer's own line is gone; admission's names the store and the
		// action, never the sid.
		expect(harness.logger.error).toHaveBeenCalledTimes(1);
		expect(harness.logger.error).toHaveBeenCalledWith(
			{
				store: "user_session",
				action: "oauth.authorize",
				err: expect.objectContaining({ name: "Error" }),
			},
			"session_admission_unavailable",
		);
	});

	it("a cookie without user.id is not_live: the login redirect, with no store read", async () => {
		const store = storeWith(record());
		const harness = await makeApp({
			userSessionStore: store,
			session: { isAuthenticated: true, sid: SID },
		});
		loginRedirectTo(await authorize(harness.app, baseQuery));
		expect(harness.createCode).not.toHaveBeenCalled();
		expect(store.get).not.toHaveBeenCalled();
		expect(harness.logger.warn).toHaveBeenCalledWith(
			{ action: "oauth.authorize" },
			"session_admission_no_subject",
		);
	});

	it("a record whose sub differs from the cookie's user.id is not_live: the login redirect, audited", async () => {
		const { sink, events } = recordingSink();
		const harness = await makeApp({
			userSessionStore: storeWith(record({ sub: "someone-else" })),
			auditSink: sink,
		});
		loginRedirectTo(await authorize(harness.app, baseQuery));
		expect(harness.createCode).not.toHaveBeenCalled();
		expect(events.map((e) => e.type)).toEqual(["session.admission.subject_mismatch"]);
		expect(events[0]?.details).toEqual({
			sid: SID,
			carrier: "cookie",
			claimedSubject: SUBJECT,
			recordSubject: "someone-else",
		});
	});

	it("the subject-revocation boundary applies when subjectRevocation is wired: a session established before it is refused", async () => {
		const revocation = createInMemorySubjectRevocation();
		await revocation.revokeBefore(SUBJECT, new Date(), new Date(Date.now() + 3_600_000));
		const harness = await makeApp({
			userSessionStore: storeWith(record({ authTime: minutesAgo(5) })),
			subjectRevocation: revocation,
		});
		loginRedirectTo(await authorize(harness.app, baseQuery));
		expect(harness.createCode).not.toHaveBeenCalled();
	});

	it("a session established after the boundary is admitted", async () => {
		const revocation = createInMemorySubjectRevocation();
		await revocation.revokeBefore(SUBJECT, minutesAgo(10), new Date(Date.now() + 3_600_000));
		const harness = await makeApp({
			userSessionStore: storeWith(record({ authTime: minutesAgo(5) })),
			subjectRevocation: revocation,
		});
		expect(codeOf(await authorize(harness.app, baseQuery))).toBe("code-x");
	});

	it("a boundary that cannot be read is temporarily_unavailable on the redirect URI, named for the revocation store, logged as admission's line", async () => {
		const harness = await makeApp({
			userSessionStore: storeWith(record()),
			subjectRevocation: {
				kind: "failing",
				revokeBefore: async () => {},
				revokedBefore: async () => {
					throw new Error("redis down");
				},
			},
		});
		const params = redirectParams(await authorize(harness.app, baseQuery));
		expect(params.get("error")).toBe("temporarily_unavailable");
		expect(params.get("error_description")).toBe("revocation store unavailable");
		expect(harness.createCode).not.toHaveBeenCalled();
		// An outage is not a login: the cookie session is left as it was.
		expect(harness.regenerated).toBe(0);
		expect(harness.logger.error).toHaveBeenCalledTimes(1);
		expect(harness.logger.error).toHaveBeenCalledWith(
			{
				store: "revocation_boundary",
				action: "oauth.authorize",
				err: expect.objectContaining({ name: "Error" }),
			},
			"session_admission_unavailable",
		);
	});

	it("a record past its expiresAt is not_live: the login redirect", async () => {
		const harness = await makeApp({
			userSessionStore: storeWith(record({ expiresAt: minutesAgo(1) })),
		});
		loginRedirectTo(await authorize(harness.app, baseQuery));
		expect(harness.createCode).not.toHaveBeenCalled();
	});

	it("the cookie session is regenerated before the login redirect, so the flag does not survive the refusal", async () => {
		const harness = await makeApp({ userSessionStore: storeWith(null) });
		loginRedirectTo(await authorize(harness.app, baseQuery));
		expect(harness.regenerated).toBe(1);
		expect(harness.session).not.toHaveProperty("isAuthenticated");
		expect(harness.session).not.toHaveProperty("sid");
	});

	it("a regeneration that fails is temporarily_unavailable on the redirect URI, logged as a cookie-session outage", async () => {
		const harness = await makeApp({ userSessionStore: storeWith(null), regenerateFails: true });
		const params = redirectParams(await authorize(harness.app, baseQuery));
		expect(params.get("error")).toBe("temporarily_unavailable");
		expect(harness.createCode).not.toHaveBeenCalled();
		expect(harness.logger.error).toHaveBeenCalledWith(
			{
				store: "cookie_session",
				step: "regenerate",
				err: expect.objectContaining({ name: "Error" }),
			},
			"authorize_cookie_session_unavailable",
		);
	});

	it("a cookie session that cannot regenerate at all — not express-session's — fails as a regeneration does, and is abandoned", async () => {
		const harness = await makeApp({ userSessionStore: storeWith(null), cannotRegenerate: true });
		const params = redirectParams(await authorize(harness.app, baseQuery));
		// Never the login page: nothing here could drop the refused session's
		// authentication, so a login page that forwards signed-in users would loop.
		expect(params.get("error")).toBe("temporarily_unavailable");
		expect(params.get("error_description")).toBe("session store unavailable");
		expect(harness.createCode).not.toHaveBeenCalled();
		expect(harness.logger.error).toHaveBeenCalledWith(
			{
				store: "cookie_session",
				step: "regenerate",
				err: expect.objectContaining({ name: "TypeError" }),
			},
			"authorize_cookie_session_unavailable",
		);
		expect(harness.sessionAfterResponse()).toBeUndefined();
	});

	it("a dead session sent with an invalid client is the client's 400 after the lookup, not the login redirect", async () => {
		const store = storeWith(null);
		const harness = await makeApp({ userSessionStore: store, clientNotFound: true });
		const res = await authorize(harness.app, baseQuery);
		expect(res.status).toBe(400);
		expect(res.body).toEqual({ error: "invalid_client", error_description: "client not found" });
		// The client is looked up first; the session is never read for it.
		expect(store.get).not.toHaveBeenCalled();
	});

	it("still sends an unauthenticated cookie to the login page before the client is looked up, with no store read", async () => {
		const store = storeWith(record());
		const harness = await makeApp({
			userSessionStore: store,
			session: { isAuthenticated: false, sid: SID },
			clientNotFound: true,
		});
		loginRedirectTo(await authorize(harness.app, baseQuery));
		expect(store.get).not.toHaveBeenCalled();
		expect(harness.regenerated).toBe(0);
	});

	it("reads the session once, and mints from it", async () => {
		const store = storeWith(record());
		const harness = await makeApp({ userSessionStore: store });
		expect(codeOf(await authorize(harness.app, baseQuery))).toBe("code-x");
		expect(store.get).toHaveBeenCalledTimes(1);
		expect(harness.createCode).toHaveBeenCalledWith(expect.objectContaining({ sid: SID }));
	});

	it("answers prompt=none with login_required for a dead session, without regenerating", async () => {
		const harness = await makeApp({ userSessionStore: storeWith(null) });
		const params = redirectParams(await authorize(harness.app, { ...baseQuery, prompt: "none" }));
		expect(params.get("error")).toBe("login_required");
		expect(harness.regenerated).toBe(0);
	});
});

describe("/authorize on admission — a requirement's verdicts", () => {
	it("reauthenticate: the cookie is regenerated and the browser sent to log in; prompt=none is login_required", async () => {
		const requirement = fixture("fixture", () => ({ outcome: "reauthenticate" }));
		const harness = await makeApp({
			userSessionStore: storeWith(record()),
			requirements: [requirement],
		});
		loginRedirectTo(await authorize(harness.app, baseQuery));
		expect(harness.regenerated).toBe(1);
		expect(requirement.inputs[0]?.action).toEqual({ name: "oauth.authorize", grade: "use" });

		const silent = await makeApp({
			userSessionStore: storeWith(record()),
			requirements: [fixture("fixture", () => ({ outcome: "reauthenticate" }))],
		});
		const params = redirectParams(await authorize(silent.app, { ...baseQuery, prompt: "none" }));
		expect(params.get("error")).toBe("login_required");
		expect(silent.regenerated).toBe(0);
	});

	it("unmet by a requirement: login_required naming it, on the redirect URI", async () => {
		const harness = await makeApp({
			userSessionStore: storeWith(record()),
			requirements: [fixture("fixture", () => ({ outcome: "unmet" }))],
		});
		const params = redirectParams(await authorize(harness.app, baseQuery));
		expect(params.get("error")).toBe("login_required");
		expect(params.get("error_description")).toMatch(/fixture/);
		expect(harness.createCode).not.toHaveBeenCalled();
	});

	it("unmet acr: unmet_authentication_requirements naming it, on the redirect URI", async () => {
		const harness = await makeApp({
			userSessionStore: storeWith(record()),
			oauth: { authorize: { acrValues: { "urn:example:mfa": ["pwd", "mfa"] } } },
		});
		const params = redirectParams(
			await authorize(harness.app, { ...baseQuery, acr_values: "urn:example:mfa" }),
		);
		expect(params.get("error")).toBe("unmet_authentication_requirements");
		expect(params.get("error_description")).toMatch(/urn:example:mfa/);
	});

	it("a requirement that throws is temporarily_unavailable, logged once by admission under its name", async () => {
		const harness = await makeApp({
			userSessionStore: storeWith(record()),
			requirements: [
				fixture("fixture", () => {
					throw new Error("policy service down");
				}),
			],
		});
		const params = redirectParams(await authorize(harness.app, baseQuery));
		expect(params.get("error")).toBe("temporarily_unavailable");
		expect(harness.logger.error).toHaveBeenCalledWith(
			expect.objectContaining({ store: "fixture", action: "oauth.authorize" }),
			"session_admission_unavailable",
		);
	});
});

describe("/authorize on admission — the step-up trip", () => {
	/** A requirement that steps `/authorize` up until the test flips it to met. */
	const steppingUp = (
		whenStillUnmet: "reauthenticate" | "unmet" = "reauthenticate",
		page?: SessionRequirement["stepUpPage"],
	) => {
		const state = { met: false };
		const requirement = fixture(
			"fixture",
			() => (state.met ? { outcome: "met" } : { outcome: "step_up", whenStillUnmet }),
			page,
		);
		return { requirement, state };
	};

	/** The step-up page redirect, parsed. */
	const stepUpRedirect = (res: request.Response): URL => {
		expect(res.status).toBe(302);
		const location = new URL(res.headers.location as string);
		expect(location.origin).toBe(ISSUER);
		expect(location.pathname).toBe("/step-up");
		return location;
	};

	it("redirects to the requirement's page with its params and redirect_to carrying the ask, then admits once the fixture answers met", async () => {
		const { requirement, state } = steppingUp();
		const harness = await makeApp({
			userSessionStore: storeWith(record()),
			requirements: [requirement],
		});
		const first = stepUpRedirect(await authorize(harness.app, baseQuery));
		expect(first.searchParams.get("kind")).toBe("fixture");
		const back = new URL(first.searchParams.get("redirect_to") as string);
		expect(back.origin + back.pathname).toBe(`${ISSUER}/oauth/authorize`);
		expect(back.searchParams.get("client_id")).toBe(CLIENT_ID);
		const askId = back.searchParams.get("reauth_ask") as string;
		expect(askId.length).toBeGreaterThanOrEqual(43);
		// The ask records the trip per requirement, not a login.
		const ask = (harness.records.get(`reauth:${askId}`) as { reauth: Record<string, unknown> })
			.reauth;
		expect(ask.stepUpAskedAt).toEqual({ fixture: expect.any(Number) });
		expect(ask.loginAskedAt).toBeUndefined();
		expect(harness.createCode).not.toHaveBeenCalled();

		// The page finished what it asked: the session now meets it.
		state.met = true;
		const query = Object.fromEntries(back.searchParams.entries());
		expect(codeOf(await authorize(harness.app, query))).toBe("code-x");
	});

	it("prompt=none is interaction_required: no trip can be sent silently", async () => {
		const { requirement } = steppingUp();
		const harness = await makeApp({
			userSessionStore: storeWith(record()),
			requirements: [requirement],
		});
		const params = redirectParams(await authorize(harness.app, { ...baseQuery, prompt: "none" }));
		expect(params.get("error")).toBe("interaction_required");
		expect(harness.records.size).toBe(0);
	});

	it("a session that comes back from the trip still unmet is refused, not sent again: login_required when the requirement re-authenticates", async () => {
		const { requirement } = steppingUp("reauthenticate");
		const harness = await makeApp({
			userSessionStore: storeWith(record()),
			requirements: [requirement],
		});
		const first = stepUpRedirect(await authorize(harness.app, baseQuery));
		const back = new URL(first.searchParams.get("redirect_to") as string);
		const params = redirectParams(
			await authorize(harness.app, Object.fromEntries(back.searchParams.entries())),
		);
		expect(params.get("error")).toBe("login_required");
		// Left for a replay to be refused by again; only the pass that mints spends it.
		expect(harness.records.size).toBe(1);
	});

	it("a session that comes back still unmet is unmet_authentication_requirements when the requirement says so", async () => {
		const { requirement } = steppingUp("unmet");
		const harness = await makeApp({
			userSessionStore: storeWith(record()),
			requirements: [requirement],
		});
		const first = stepUpRedirect(await authorize(harness.app, baseQuery));
		const back = new URL(first.searchParams.get("redirect_to") as string);
		const params = redirectParams(
			await authorize(harness.app, Object.fromEntries(back.searchParams.entries())),
		);
		expect(params.get("error")).toBe("unmet_authentication_requirements");
	});

	it("a session established after the ask may make one more trip", async () => {
		const { requirement } = steppingUp();
		const clock = { authTime: minutesAgo(5) };
		const harness = await makeApp({
			userSessionStore: storeAnswering(async () => record({ authTime: clock.authTime })),
			requirements: [requirement],
		});
		const first = stepUpRedirect(await authorize(harness.app, baseQuery));
		const back = new URL(first.searchParams.get("redirect_to") as string);
		// A new login during the trip: the session is younger than the ask.
		await new Promise((resolve) => setTimeout(resolve, 2));
		clock.authTime = new Date();
		const second = stepUpRedirect(
			await authorize(harness.app, Object.fromEntries(back.searchParams.entries())),
		);
		expect(second.searchParams.get("redirect_to")).toBeTruthy();
	});

	it("freshness first: prompt=none with a stale max_age answers login_required even when the verdict is step_up", async () => {
		const { requirement } = steppingUp();
		const harness = await makeApp({
			userSessionStore: storeWith(record({ authTime: minutesAgo(5) })),
			requirements: [requirement],
		});
		const params = redirectParams(
			await authorize(harness.app, { ...baseQuery, prompt: "none", max_age: "60" }),
		);
		expect(params.get("error")).toBe("login_required");
	});

	it("freshness first: a stale max_age sends the browser to log in before any step-up, and the login ask carries no step-up", async () => {
		const { requirement } = steppingUp();
		const harness = await makeApp({
			userSessionStore: storeWith(record({ authTime: minutesAgo(5) })),
			requirements: [requirement],
		});
		const back = loginRedirectTo(await authorize(harness.app, { ...baseQuery, max_age: "60" }));
		const askId = back.searchParams.get("reauth_ask") as string;
		const ask = (harness.records.get(`reauth:${askId}`) as { reauth: Record<string, unknown> })
			.reauth;
		expect(ask.loginAskedAt).toEqual(expect.any(Number));
		expect(ask.stepUpAskedAt).toEqual({});
	});

	it("max_age and a step-up in one ask: login trip, step-up trip, code (the login time is carried through the step-up ask)", async () => {
		const { requirement, state } = steppingUp();
		const clock = { authTime: minutesAgo(5) };
		const harness = await makeApp({
			userSessionStore: storeAnswering(async () => record({ authTime: clock.authTime })),
			requirements: [requirement],
		});
		const toLogin = loginRedirectTo(await authorize(harness.app, { ...baseQuery, max_age: "60" }));
		// The user logs in: a session younger than the ask.
		await new Promise((resolve) => setTimeout(resolve, 2));
		clock.authTime = new Date();
		const toStepUp = stepUpRedirect(
			await authorize(harness.app, Object.fromEntries(toLogin.searchParams.entries())),
		);
		const back = new URL(toStepUp.searchParams.get("redirect_to") as string);
		expect(back.searchParams.get("max_age")).toBe("60");
		// The user steps up; the login asked earlier still stands as the
		// freshness reference, so max_age is met by the login, not refused.
		state.met = true;
		expect(
			codeOf(await authorize(harness.app, Object.fromEntries(back.searchParams.entries()))),
		).toBe("code-x");
	});

	it("prompt=login and a step-up in one ask: login trip, step-up trip, code — the login is not asked for again on the way back", async () => {
		const { requirement, state } = steppingUp();
		const clock = { authTime: minutesAgo(5) };
		const harness = await makeApp({
			userSessionStore: storeAnswering(async () => record({ authTime: clock.authTime })),
			requirements: [requirement],
		});
		const toLogin = loginRedirectTo(
			await authorize(harness.app, { ...baseQuery, prompt: "login" }),
		);
		await new Promise((resolve) => setTimeout(resolve, 2));
		clock.authTime = new Date();
		const toStepUp = stepUpRedirect(
			await authorize(harness.app, Object.fromEntries(toLogin.searchParams.entries())),
		);
		const back = new URL(toStepUp.searchParams.get("redirect_to") as string);
		expect(back.searchParams.get("prompt")).toBe("login");
		// The step-up ask carries the login ask's time: prompt=login is met by
		// the login made during this request, not sent round again.
		state.met = true;
		expect(
			codeOf(await authorize(harness.app, Object.fromEntries(back.searchParams.entries()))),
		).toBe("code-x");
	});

	it("a session whose authentication is exactly as old as the trip was sent is refused, not sent again", async () => {
		// "Not later than" the ask, to the millisecond: an authentication made
		// at the instant the trip was recorded is not one made after it.
		const { requirement } = steppingUp();
		const clock = { authTime: minutesAgo(5) };
		const harness = await makeApp({
			userSessionStore: storeAnswering(async () => record({ authTime: clock.authTime })),
			requirements: [requirement],
		});
		const first = stepUpRedirect(await authorize(harness.app, baseQuery));
		const back = new URL(first.searchParams.get("redirect_to") as string);
		const askId = back.searchParams.get("reauth_ask") as string;
		const ask = (harness.records.get(`reauth:${askId}`) as { reauth: Record<string, unknown> })
			.reauth as { stepUpAskedAt: Record<string, number> };
		clock.authTime = new Date(ask.stepUpAskedAt.fixture as number);
		const params = redirectParams(
			await authorize(harness.app, Object.fromEntries(back.searchParams.entries())),
		);
		expect(params.get("error")).toBe("login_required");
	});

	it("freshness first: an acr nothing can meet, asked with a stale max_age, is sent to log in before it is refused", async () => {
		const harness = await makeApp({
			userSessionStore: storeWith(record({ authTime: minutesAgo(5) })),
			oauth: { authorize: { acrValues: { "urn:example:mfa": ["pwd", "mfa"] } } },
		});
		const back = loginRedirectTo(
			await authorize(harness.app, {
				...baseQuery,
				acr_values: "urn:example:mfa",
				max_age: "60",
			}),
		);
		expect(back.searchParams.get("reauth_ask")).toBeTruthy();
	});

	it("the page's URL is built with searchParams: a page whose url already carries a query keeps it, and redirect_to is one parameter", async () => {
		const { requirement } = steppingUp("reauthenticate", {
			url: `${ISSUER}/step-up?tenant=x`,
			params: { kind: "fixture" },
		});
		const harness = await makeApp({
			userSessionStore: storeWith(record()),
			requirements: [requirement],
		});
		const page = stepUpRedirect(await authorize(harness.app, baseQuery));
		expect(page.searchParams.get("tenant")).toBe("x");
		expect(page.searchParams.get("kind")).toBe("fixture");
		expect([...page.searchParams.keys()].filter((k) => k === "redirect_to")).toHaveLength(1);
	});

	it("an acr a step-up can meet is a trip through the requirement that reaches it, with the reachable values as the hint", async () => {
		const mfa: SessionRequirement = {
			name: "mfa",
			secondFactorAuthority: true,
			reach: new Set(["otp", "mfa"]),
			stepUpPage: { url: "/mfa", params: {} },
			remediations: ["mfa.step_up"],
			hintKeys: [],
			admit: async () => ({ outcome: "met" }),
		};
		const harness = await makeApp({
			userSessionStore: storeWith(record()),
			requirements: [mfa],
			oauth: { authorize: { acrValues: { "urn:o3co:acr:mfa": ["pwd", "mfa"] } } },
		});
		const res = await authorize(harness.app, { ...baseQuery, acr_values: "urn:o3co:acr:mfa" });
		expect(res.status).toBe(302);
		const page = new URL(res.headers.location as string);
		expect(page.pathname).toBe("/mfa");
		expect(page.searchParams.get("acr_values")).toBe("urn:o3co:acr:mfa");
		const back = new URL(page.searchParams.get("redirect_to") as string);
		expect(back.searchParams.get("acr_values")).toBe("urn:o3co:acr:mfa");
	});

	it("a step-up with no express-session store to record the ask in is refused as a composition error", async () => {
		const { requirement } = steppingUp();
		const harness = await makeApp({
			userSessionStore: storeWith(record()),
			requirements: [requirement],
			sessionStore: false,
		});
		const params = redirectParams(await authorize(harness.app, baseQuery));
		expect(params.get("error")).toBe("invalid_request");
	});

	it("an ask store that cannot record the trip is temporarily_unavailable", async () => {
		const { requirement } = steppingUp();
		const harness = await makeApp({
			userSessionStore: storeWith(record()),
			requirements: [requirement],
			sessionStoreFail: "set",
		});
		const params = redirectParams(await authorize(harness.app, baseQuery));
		expect(params.get("error")).toBe("temporarily_unavailable");
	});
});

describe("/authorize on admission — the ask is read until the code is minted", () => {
	/** A requirement that steps `/authorize` up until the test flips it to met. */
	const steppingUp = (whenStillUnmet: "reauthenticate" | "unmet" = "reauthenticate") => {
		const state = { met: false };
		const requirement = fixture("fixture", () =>
			state.met ? { outcome: "met" } : { outcome: "step_up", whenStillUnmet },
		);
		return { requirement, state };
	};

	/** The page `/authorize` sent the browser to, parsed against the issuer. */
	const sentTo = (res: request.Response): URL => {
		expect(res.status).toBe(302);
		return new URL(res.headers.location as string, ISSUER);
	};

	/** The request a page hands back, as a query. */
	const queryOf = (url: URL): Record<string, string> => Object.fromEntries(url.searchParams.entries());

	/** The request a step-up page returns to. */
	const returnOf = (page: URL): URL => new URL(page.searchParams.get("redirect_to") as string);

	/** A login made after everything before it, to the millisecond. */
	const loggedInNow = async (clock: { authTime: Date }) => {
		await new Promise((resolve) => setTimeout(resolve, 2));
		clock.authTime = new Date();
	};

	it("consent after a login trip and a step-up trip resumes with the ask still readable, and mints without a second login", async () => {
		const { requirement, state } = steppingUp();
		const clock = { authTime: minutesAgo(5) };
		const harness = await makeApp({
			userSessionStore: storeAnswering(async () => record({ authTime: clock.authTime })),
			requirements: [requirement],
			consent: true,
		});
		const toLogin = loginRedirectTo(await authorize(harness.app, { ...baseQuery, prompt: "login" }));
		await loggedInNow(clock);
		const toStepUp = sentTo(await authorize(harness.app, queryOf(toLogin)));
		expect(toStepUp.pathname).toBe("/step-up");
		state.met = true;
		const back = returnOf(toStepUp);
		const toConsent = sentTo(await authorize(harness.app, queryOf(back)));
		expect(toConsent.pathname).toBe("/consent");
		expect(harness.createCode).not.toHaveBeenCalled();

		// The consent page records the answer and returns to the parked request.
		const parked = await harness.pendingConsentStore.consume(
			toConsent.searchParams.get("challenge") as string,
		);
		expect(parked).not.toBeNull();
		await harness.consentStore.grant({
			sub: SUBJECT,
			clientId: CLIENT_ID,
			scopes: [...(parked?.scopes ?? [])],
			grantedAt: Date.now(),
			expiresAt: undefined,
		});
		const resumed = new URL(parked?.authorizeUrl as string);
		expect(resumed.searchParams.get("reauth_ask")).toBe(back.searchParams.get("reauth_ask"));
		const done = sentTo(await authorize(harness.app, queryOf(resumed)));
		expect(done.origin + done.pathname).toBe(REDIRECT_URI);
		expect(done.searchParams.get("code")).toBe("code-x");
		expect(harness.regenerated).toBe(0);
	});

	it("spends the ask on the pass that mints: replaying the returned URL asks for the login again", async () => {
		const { requirement, state } = steppingUp();
		const clock = { authTime: minutesAgo(5) };
		const harness = await makeApp({
			userSessionStore: storeAnswering(async () => record({ authTime: clock.authTime })),
			requirements: [requirement],
		});
		const toLogin = loginRedirectTo(await authorize(harness.app, { ...baseQuery, prompt: "login" }));
		await loggedInNow(clock);
		const back = returnOf(sentTo(await authorize(harness.app, queryOf(toLogin))));
		state.met = true;
		expect(codeOf(await authorize(harness.app, queryOf(back)))).toBe("code-x");
		expect(harness.records.size).toBe(0);

		const again = loginRedirectTo(await authorize(harness.app, queryOf(back)));
		expect(again.searchParams.get("reauth_ask")).not.toBe(back.searchParams.get("reauth_ask"));
		expect(harness.createCode).toHaveBeenCalledTimes(1);
	});

	it("each trip's write spends the ask it was presented: one record stands for the request", async () => {
		const { requirement } = steppingUp();
		const clock = { authTime: minutesAgo(5) };
		const harness = await makeApp({
			userSessionStore: storeAnswering(async () => record({ authTime: clock.authTime })),
			requirements: [requirement],
		});
		const toLogin = loginRedirectTo(await authorize(harness.app, { ...baseQuery, max_age: "60" }));
		await loggedInNow(clock);
		const back = returnOf(sentTo(await authorize(harness.app, queryOf(toLogin))));
		expect([...harness.records.keys()]).toEqual([`reauth:${back.searchParams.get("reauth_ask")}`]);
	});

	it("an ask another pass spent between this pass's read and its mint is login_required when the login it asked for was what made the session fresh", async () => {
		const clock = { authTime: minutesAgo(5) };
		const harness = await makeApp({
			userSessionStore: storeAnswering(async () => record({ authTime: clock.authTime })),
			// The first read hands the ask back and another pass spends it straight after.
			onAskGet: (n) => (n === 1 ? "spend" : undefined),
		});
		const toLogin = loginRedirectTo(await authorize(harness.app, { ...baseQuery, prompt: "login" }));
		await loggedInNow(clock);
		const params = redirectParams(await authorize(harness.app, queryOf(toLogin)));
		expect(params.get("error")).toBe("login_required");
		expect(params.get("error_description")).toBe("the re-authentication ask was already used");
		expect(harness.createCode).not.toHaveBeenCalled();
	});

	it("an ask already spent when freshness did not rest on it is no reason to refuse: the code is minted", async () => {
		const { requirement, state } = steppingUp();
		const harness = await makeApp({
			userSessionStore: storeWith(record()),
			requirements: [requirement],
		});
		const back = returnOf(sentTo(await authorize(harness.app, baseQuery)));
		harness.records.clear();
		state.met = true;
		expect(codeOf(await authorize(harness.app, queryOf(back)))).toBe("code-x");
	});

	it("an ask store that cannot spend the ask at the mint is temporarily_unavailable, with no code", async () => {
		const clock = { authTime: minutesAgo(5) };
		const harness = await makeApp({
			userSessionStore: storeAnswering(async () => record({ authTime: clock.authTime })),
			onAskGet: (n) => (n === 2 ? "fail" : undefined),
		});
		const toLogin = loginRedirectTo(await authorize(harness.app, { ...baseQuery, prompt: "login" }));
		await loggedInNow(clock);
		const params = redirectParams(await authorize(harness.app, queryOf(toLogin)));
		expect(params.get("error")).toBe("temporarily_unavailable");
		expect(harness.createCode).not.toHaveBeenCalled();
		expect(harness.logger.error).toHaveBeenCalledWith(
			{ err: expect.objectContaining({ name: "Error" }) },
			"authorize_reauth_ask_store_unavailable",
		);
	});

	it("a refused return replayed is refused again, not sent on another trip", async () => {
		const { requirement } = steppingUp("unmet");
		const harness = await makeApp({
			userSessionStore: storeWith(record()),
			requirements: [requirement],
		});
		const back = returnOf(sentTo(await authorize(harness.app, baseQuery)));
		for (let pass = 0; pass < 2; pass++) {
			const params = redirectParams(await authorize(harness.app, queryOf(back)));
			expect(params.get("error")).toBe("unmet_authentication_requirements");
		}
		expect(harness.createCode).not.toHaveBeenCalled();
	});
});

describe("/authorize on admission — prompt=login from a browser that is not signed in", () => {
	const askOf = (harness: { records: Map<string, unknown> }, url: URL) =>
		(
			harness.records.get(`reauth:${url.searchParams.get("reauth_ask")}`) as
				| { reauth: Record<string, unknown> }
				| undefined
		)?.reauth;

	it("records the login ask before the login, so the browser logs in once and gets its code", async () => {
		const clock = { authTime: minutesAgo(5) };
		const harness = await makeApp({
			userSessionStore: storeAnswering(async () => record({ authTime: clock.authTime })),
			session: { isAuthenticated: false },
		});
		const back = loginRedirectTo(await authorize(harness.app, { ...baseQuery, prompt: "login" }));
		expect(back.searchParams.get("prompt")).toBe("login");

		// The login the page performs: a new session, authenticated after the ask.
		await new Promise((resolve) => setTimeout(resolve, 2));
		clock.authTime = new Date();
		harness.login({ isAuthenticated: true, user: { id: SUBJECT }, sid: SID });
		const res = await authorize(harness.app, Object.fromEntries(back.searchParams.entries()));
		const done = new URL(res.headers.location as string, ISSUER);
		expect(done.origin + done.pathname).toBe(REDIRECT_URI);
		expect(done.searchParams.get("code")).toBe("code-x");
		expect(askOf(harness, back)).toBeUndefined();
	});

	it("records it before the client is looked up, as every unauthenticated request is answered", async () => {
		const harness = await makeApp({
			userSessionStore: storeWith(record()),
			session: { isAuthenticated: false },
			clientNotFound: true,
		});
		const back = loginRedirectTo(await authorize(harness.app, { ...baseQuery, prompt: "login" }));
		expect(askOf(harness, back)).toMatchObject({
			loginAskedAt: expect.any(Number),
			stepUpAskedAt: {},
		});
	});

	it("an ask store that cannot record it falls back to the plain login redirect, logged", async () => {
		const harness = await makeApp({
			userSessionStore: storeWith(record()),
			session: { isAuthenticated: false },
			sessionStoreFail: "set",
		});
		const back = loginRedirectTo(await authorize(harness.app, { ...baseQuery, prompt: "login" }));
		expect(back.searchParams.has("reauth_ask")).toBe(false);
		expect(back.searchParams.get("prompt")).toBe("login");
		expect(harness.logger.error).toHaveBeenCalledWith(
			{ err: expect.objectContaining({ name: "Error" }) },
			"authorize_reauth_ask_store_unavailable",
		);
	});

	it("records nothing without prompt=login, under prompt=none, or with no session store", async () => {
		const plain = await makeApp({ session: { isAuthenticated: false } });
		expect(loginRedirectTo(await authorize(plain.app, baseQuery)).searchParams.has("reauth_ask")).toBe(
			false,
		);
		expect(plain.records.size).toBe(0);

		const silent = await makeApp({ session: { isAuthenticated: false } });
		expect(redirectParams(await authorize(silent.app, { ...baseQuery, prompt: "none" })).get("error")).toBe(
			"login_required",
		);
		expect(silent.records.size).toBe(0);

		const storeless = await makeApp({ session: { isAuthenticated: false }, sessionStore: false });
		const back = loginRedirectTo(await authorize(storeless.app, { ...baseQuery, prompt: "login" }));
		expect(back.searchParams.has("reauth_ask")).toBe(false);
	});
});

describe("/authorize on admission — a POST's parameters survive every trip", () => {
	// OIDC Core §3.1.2.1: a POST carries the authorization request in its form
	// body. Every page the browser is sent to must return it to the same
	// request, written as a GET URL, or it comes back to `400 client_id is
	// required`.
	const authorizePost = (app: express.Express, body: Record<string, string>) =>
		request(app).post("/oauth/authorize").type("form").send(body);

	const steppingUp = () => {
		const state = { met: false };
		const requirement = fixture("fixture", () =>
			state.met ? { outcome: "met" } : { outcome: "step_up", whenStillUnmet: "reauthenticate" },
		);
		return { requirement, state };
	};

	it("the step-up trip: POST, the page, back with its parameters, and a code", async () => {
		const { requirement, state } = steppingUp();
		const harness = await makeApp({
			userSessionStore: storeWith(record()),
			requirements: [requirement],
		});
		const first = await authorizePost(harness.app, baseQuery);
		expect(first.status).toBe(302);
		const page = new URL(first.headers.location as string);
		expect(page.pathname).toBe("/step-up");
		const back = new URL(page.searchParams.get("redirect_to") as string);
		expect(back.origin + back.pathname).toBe(`${ISSUER}/oauth/authorize`);
		expect(back.searchParams.get("client_id")).toBe(CLIENT_ID);
		expect(back.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);
		expect(back.searchParams.get("code_challenge")).toBe(baseQuery.code_challenge);
		expect(back.searchParams.get("reauth_ask")).toBeTruthy();

		state.met = true;
		expect(
			codeOf(await authorize(harness.app, Object.fromEntries(back.searchParams.entries()))),
		).toBe("code-x");
	});

	it("the login trip for a stale max_age: POST, the login page, back with its parameters, and a code", async () => {
		const clock = { authTime: minutesAgo(5) };
		const harness = await makeApp({
			userSessionStore: storeAnswering(async () => record({ authTime: clock.authTime })),
		});
		const back = loginRedirectTo(await authorizePost(harness.app, { ...baseQuery, max_age: "60" }));
		expect(back.searchParams.get("client_id")).toBe(CLIENT_ID);
		expect(back.searchParams.get("max_age")).toBe("60");
		expect(back.searchParams.get("reauth_ask")).toBeTruthy();

		await new Promise((resolve) => setTimeout(resolve, 2));
		clock.authTime = new Date();
		expect(
			codeOf(await authorize(harness.app, Object.fromEntries(back.searchParams.entries()))),
		).toBe("code-x");
	});

	it("the login page for an unauthenticated POST carries the request's parameters back", async () => {
		const harness = await makeApp({ session: { isAuthenticated: false } });
		const back = loginRedirectTo(await authorizePost(harness.app, baseQuery));
		expect(back.origin + back.pathname).toBe(`${ISSUER}/oauth/authorize`);
		expect(back.searchParams.get("client_id")).toBe(CLIENT_ID);
		expect(back.searchParams.get("state")).toBe("xyz");
	});

	it("the login page after a dead session is refused carries a POST's parameters back", async () => {
		const harness = await makeApp({ userSessionStore: storeWith(null) });
		const back = loginRedirectTo(await authorizePost(harness.app, baseQuery));
		expect(back.searchParams.get("client_id")).toBe(CLIENT_ID);
		expect(back.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);
	});
});

describe("/authorize on admission — the trip's own guards", () => {
	it("never sends the browser to a step-up page off the issuer's origin: server_error at the redirect_uri, logged", async () => {
		// Registration holds a page to the issuer's origin; a resolver built
		// without an issuer does not. The trip checks the URL it built anyway.
		const requirement = fixture(
			"fixture",
			() => ({ outcome: "step_up", whenStillUnmet: "reauthenticate" }),
			{ url: "https://evil.example/step-up", params: {} },
		);
		const harness = await makeApp({
			userSessionStore: storeWith(record()),
			requirements: [requirement],
			anyPageOrigin: true,
		});
		const params = redirectParams(await authorize(harness.app, baseQuery));
		expect(params.get("error")).toBe("server_error");
		expect(harness.logger.error).toHaveBeenCalledWith(
			{ requirement: "fixture" },
			"authorize_step_up_page_off_origin",
		);
		expect(harness.records.size).toBe(0);
	});

	it("keeps the ask's createdAt across the login trip and the step-up trip that follows it", async () => {
		const state = { met: false };
		const requirement = fixture("fixture", () =>
			state.met ? { outcome: "met" } : { outcome: "step_up", whenStillUnmet: "reauthenticate" },
		);
		const clock = { authTime: minutesAgo(5) };
		const harness = await makeApp({
			userSessionStore: storeAnswering(async () => record({ authTime: clock.authTime })),
			requirements: [requirement],
		});
		const askOf = (url: URL) =>
			(
				harness.records.get(`reauth:${url.searchParams.get("reauth_ask")}`) as {
					reauth: Record<string, unknown>;
				}
			).reauth;
		const toLogin = loginRedirectTo(await authorize(harness.app, { ...baseQuery, max_age: "60" }));
		const createdAt = askOf(toLogin).createdAt;
		expect(createdAt).toEqual(expect.any(Number));

		await new Promise((resolve) => setTimeout(resolve, 5));
		clock.authTime = new Date();
		const toStepUp = await authorize(
			harness.app,
			Object.fromEntries(toLogin.searchParams.entries()),
		);
		const back = new URL(
			new URL(toStepUp.headers.location as string).searchParams.get("redirect_to") as string,
		);
		expect(askOf(back).createdAt).toBe(createdAt);
		expect(askOf(back).loginAskedAt).toBe(createdAt);
	});

	it("puts no acr_values on the page when the request asked for none", async () => {
		const requirement = fixture("fixture", () => ({
			outcome: "step_up",
			whenStillUnmet: "reauthenticate",
		}));
		const harness = await makeApp({
			userSessionStore: storeWith(record()),
			requirements: [requirement],
		});
		const res = await authorize(harness.app, baseQuery);
		expect(res.status).toBe(302);
		expect(new URL(res.headers.location as string).searchParams.has("acr_values")).toBe(false);
	});
});

describe("/authorize on admission — what the new order changes, pinned", () => {
	it("reads the flag as exactly true: a truthy isAuthenticated is sent to log in, with no store read", async () => {
		const store = storeWith(record());
		const harness = await makeApp({
			userSessionStore: store,
			session: { isAuthenticated: "true", user: { id: SUBJECT }, sid: SID },
		});
		loginRedirectTo(await authorize(harness.app, baseQuery));
		expect(store.get).not.toHaveBeenCalled();
		expect(harness.createCode).not.toHaveBeenCalled();
	});

	it("answers a malformed parameter on a prompt=none request with invalid_request, before the dead session is read", async () => {
		// The session is read once the parameters are parsed: a `prompt=none`
		// request with a malformed `max_age` is the request's fault first.
		const store = storeWith(null);
		const harness = await makeApp({ userSessionStore: store });
		const params = redirectParams(
			await authorize(harness.app, { ...baseQuery, prompt: "none", max_age: "soon" }),
		);
		expect(params.get("error")).toBe("invalid_request");
		expect(store.get).not.toHaveBeenCalled();
	});

	it("refuses a malformed acr_values before a prompt=login trip", async () => {
		const harness = await makeApp({ userSessionStore: storeWith(record()) });
		const params = redirectParams(
			await authorize(harness.app, { ...baseQuery, prompt: "login", acr_values: "a\tb" }),
		);
		expect(params.get("error")).toBe("invalid_request");
		expect(harness.records.size).toBe(0);
	});

	it("records no ask for a reauthenticate verdict: the login it sends to is a new session's", async () => {
		const harness = await makeApp({
			userSessionStore: storeWith(record()),
			requirements: [fixture("fixture", () => ({ outcome: "reauthenticate" }))],
		});
		loginRedirectTo(await authorize(harness.app, { ...baseQuery, max_age: "3600" }));
		expect(harness.records.size).toBe(0);
	});

	it("abandons the cookie session after a regeneration fails, so express-session writes nothing on the way out", async () => {
		const harness = await makeApp({ userSessionStore: storeWith(null), regenerateFails: true });
		const res = await authorize(harness.app, baseQuery);
		expect(redirectParams(res).get("error")).toBe("temporarily_unavailable");
		expect(harness.sessionAfterResponse()).toBeUndefined();
	});
});
