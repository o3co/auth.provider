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
 * The browser half of acquisition (the federation-grants ADR, D7 and D8):
 * `GET /connect` and the consent the deployment's page reads and answers.
 *
 * Mounted for real, behind a stand-in for express-session, over the real
 * lodging function and the real in-memory stores. What is faked is the world
 * outside the provider: which browser is asking, the durable sessions, the
 * subject's boundary, the upstream's authorization endpoint, and the
 * deployment's CSRF policy (core's `csrfGuard` double, which keeps the slot's
 * contract). The app sits behind a proxy it trusts, as a deployment does, so
 * a request carries the origin the browser addressed: the issuer's.
 */

import { randomUUID } from "node:crypto";
import {
	type AuditEvent,
	auditErrorText,
	type CsrfGuard,
	createMemoryFederationGrantIntentStore,
	createMemoryFederationGrantStore,
	createMemoryRateLimiter,
	type FederatedIdentityLookup,
	type FederatedIdentityLookupResult,
	type FederationGrantAcquisitionConnection,
	InMemoryUserRepository,
	type LoginEntry,
	lodgeFederationGrantIntent,
	lodgeFederationGrantReauthorization,
	passwordSessionAuthentication,
	type RateLimiter,
	type RequirementInput,
	type RequirementVerdict,
	type SessionRequirement,
	type UserSession,
	validatedClientRepository,
} from "@o3co/auth-provider-core";
import {
	createTestCsrfGuard,
	createTestLoginEntry,
	resolverForTests,
} from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { FEDERATION_GRANTS_ADMISSION_ACTIONS } from "#/admissionActions.mjs";
import { createFederationGrantBackground, type FederationGrantBackground } from "#/background.mjs";
import {
	createFederationGrantBrowserRouter,
	FEDERATION_GRANTS_BROWSER_MOUNT_PATH,
	type FederationGrantBrowserRouterOptions,
	type FederationGrantDelegatedAuthorizer,
} from "#/browserRoutes.mjs";
import { brokenLimiter, refusingLimiter } from "./harness.mjs";
import { createLogSpy, payloadOf, written } from "./logSpy.mjs";

const ISSUER = "https://auth.test";
const REDIRECT = "https://client.test/connected";
const DAY = 86_400_000;

/** A sibling host the deployment lists on `session.csrf.trustedOrigins`. */
const TRUSTED_SIBLING = "https://account.auth.test";

/** What the deployment's proxy forwards: the request as the browser addressed it. */
const FORWARDED = { "X-Forwarded-Proto": "https", "X-Forwarded-Host": new URL(ISSUER).host };

/** What a browser adds to a form post from the deployment's own consent page. */
const FROM_THE_PAGE: Readonly<Record<string, string>> = {
	Origin: ISSUER,
	"Sec-Fetch-Site": "same-origin",
};

const CONNECTION: FederationGrantAcquisitionConnection = {
	name: "calendar",
	federation: "upstream",
	upstreamIssuer: "https://issuer.example",
	upstreamClientId: "provider-client",
	scopes: ["openid", "offline_access", "calendar.read"],
	boundary: "production",
	maxAccessTokenLifetime: 3600,
	callbackUri: `${ISSUER}/session/federation-grants/callback/calendar`,
	resource: "https://calendar.example/",
	authorizationParams: { access_type: "offline" },
};

const CLIENT = {
	clientId: "worker",
	tokenEndpointAuthMethod: "client_secret_basic" as const,
	clientName: "Calendar Agent",
	allowedFederationGrantConnections: ["calendar"],
	federationGrantRedirectUris: [REDIRECT],
};

interface Browser {
	readonly isAuthenticated: boolean;
	readonly user?: { readonly id: string };
	readonly sid?: string;
}

/**
 * The Store the callback asks by default, written as a class: its lookup reads
 * its own fields, so a call detached from the instance fails every flow — a
 * bug an arrow-function stub would hide. It covers every registration and
 * answers what `owners` says for a subject, `unlinked` otherwise; a value there
 * need not be a valid answer, so that a malformed one can be tested.
 */
class Directory {
	constructor(
		private readonly owners: Map<string, unknown>,
		private readonly lookups: Record<string, unknown>[],
		private readonly intercept: (name: string) => Promise<void>,
	) {}

	supportsFederatedIdentityLookup(): boolean {
		return true;
	}

	async findSubjectByFederatedIdentity(
		identity: FederatedIdentityLookup,
	): Promise<FederatedIdentityLookupResult> {
		await this.intercept("findSubjectByFederatedIdentity");
		this.lookups.push({ ...identity });
		return (
			this.owners.has(identity.sub) ? this.owners.get(identity.sub) : { kind: "unlinked" }
		) as FederatedIdentityLookupResult;
	}
}

interface WorldOptions {
	readonly rateLimiter?: RateLimiter;
	readonly identityLookup?: FederationGrantBrowserRouterOptions["identityLookup"];
	/** Replaces the repository whose lookup records into `state.lookups`. */
	readonly userRepository?: FederationGrantBrowserRouterOptions["userRepository"];
	/** Replaces the drain registry: a composition's own, which may fail. */
	readonly background?: FederationGrantBackground;
	/** Wires no logger: what the router and admission write goes to core's console logger. */
	readonly withoutLogger?: boolean;
	/** The session requirements admission asks (the session-admission ADR's D3); none by default. */
	readonly requirements?: readonly SessionRequirement[];
	/** The router's `issuer`; {@link ISSUER} by default. */
	readonly issuer?: string;
	/** The `loginEntry` slot: core's double for `/login` by default. */
	readonly login?: LoginEntry;
	/** The `csrfGuard` slot: core's double, trusting {@link TRUSTED_SIBLING}, by default. */
	readonly csrfGuard?: CsrfGuard;
}

function world(options: WorldOptions = {}) {
	const grants = createMemoryFederationGrantStore();
	const intents = createMemoryFederationGrantIntentStore();
	const background = options.background ?? createFederationGrantBackground();
	const events: AuditEvent[] = [];
	const browsers = new Map<string, Browser>();
	const durable = new Map<string, UserSession>();
	const authorized: Parameters<
		FederationGrantDelegatedAuthorizer["buildDelegatedAuthorizationUrl"]
	>[0][] = [];
	const state = {
		now: new Date(Date.now() + 3 * DAY),
		sessionsBoundary: null as Date | null | Error,
		client: { ...CLIENT } as typeof CLIENT | null,
		connections: new Map<string, FederationGrantAcquisitionConnection>([
			[CONNECTION.name, CONNECTION],
		]),
		authorizerThrows: false,
		grantsBoundary: null as Date | null | Error,
		/** What the Store answers for an upstream subject; `unlinked` when absent. */
		owners: new Map<string, unknown>(),
		/** What the identity lookup was asked. */
		lookups: [] as Record<string, unknown>[],
		/** What the upstream's token endpoint answers the next exchange with. */
		exchange: {
			upstream: { issuer: CONNECTION.upstreamIssuer, subject: "00u-alice" },
			tokens: {
				accessToken: "upstream-access",
				refreshToken: "upstream-refresh",
				expiresIn: 3600,
				tokenType: "bearer",
			},
		} as {
			upstream: { issuer: string; subject: string };
			tokens: Record<string, unknown>;
		},
		/** Whether the exchange adds an `expiresAt` from a numeric `expiresIn` when the answer names none. */
		exchangeFillsExpiresAt: true,
		/** When set, the token answer the exchange returns as it is, uncopied: getters and proxies reach the callback. */
		exchangeTokens: undefined as (() => object) | undefined,
		exchangeThrows: undefined as Error | undefined,
		exchanged: [] as Record<string, unknown>[],
		/**
		 * An outage on cue: a method's name, and how many calls to it still
		 * succeed before it — and every call after — throws. Applied to what the
		 * router is handed, never to the stores a test reads directly.
		 */
		faults: new Map<string, number>(),
		/** Run once, just before the named method: another request landing in between. */
		before: new Map<string, () => Promise<unknown>>(),
		/** Ids the router draws, in order, before it falls back to random ones. */
		ids: [] as string[],
		auditFails: false,
		/** Held until released, by event type: an audit write still in flight when the drain begins. */
		auditGates: new Map<string, Promise<void>>(),
		/** Browsers whose requests carry their cookie session without the express session's id. */
		withoutSessionId: new Set<string>(),
		authorizerMissing: false,
		configurationThrows: false,
	};
	const now = () => state.now;
	// Every line the router writes, with its level (`logSpy.mts`).
	const spy = createLogSpy();

	const intercept = async (name: string): Promise<void> => {
		const hook = state.before.get(name);
		if (hook !== undefined) {
			state.before.delete(name);
			await hook();
		}
		const passes = state.faults.get(name);
		if (passes === undefined) return;
		if (passes > 0) {
			state.faults.set(name, passes - 1);
			return;
		}
		throw new Error(`injected outage: ${name}`);
	};
	const faulty = <T extends object>(target: T): T =>
		new Proxy(target, {
			get(object, key) {
				const value = Reflect.get(object, key);
				if (typeof value !== "function") return value;
				return async (...args: unknown[]) => {
					await intercept(String(key));
					return await value.apply(object, args);
				};
			},
		});

	const csrfGuard = options.csrfGuard ?? createTestCsrfGuard({ trustedOrigins: [TRUSTED_SIBLING] });
	const app = express();
	// Behind the deployment's proxy: `X-Forwarded-Proto` and `-Host` name the
	// origin the browser addressed, which the guard compares an `Origin` with.
	app.set("trust proxy", "loopback");
	// A stand-in for the deployment's token endpoint (`GET /session/csrf`):
	// the guard's `issue`, which sets the token's cookie and answers it.
	app.get("/csrf", (_req, res) => {
		res.json({ csrf_token: csrfGuard.issue(res) });
	});
	// A stand-in for express-session: which browser this is comes from a header.
	app.use((req, _res, next) => {
		const id = req.get("x-browser");
		if (id !== undefined && browsers.has(id)) {
			if (!state.withoutSessionId.has(id)) {
				(req as unknown as { sessionID: string }).sessionID = id;
			}
			(req as unknown as { session: Browser }).session = browsers.get(id) as Browser;
		}
		next();
	});
	app.use(
		FEDERATION_GRANTS_BROWSER_MOUNT_PATH,
		createFederationGrantBrowserRouter({
			intentStore: faulty(intents),
			grantStore: faulty(grants),
			// Behind core's client-record boundary, as boot installs it in the
			// `clientRepository` slot the module hands the router.
			clientRepository: validatedClientRepository(
				{
					findById: async (id: string) => {
						await intercept("findById");
						return id === CLIENT.clientId ? (state.client as never) : null;
					},
					authenticate: async () => null,
				},
				{ logger: spy.logger },
			),
			userSessionStore: {
				get: async (sid: string) => {
					await intercept("userSessionStore.get");
					return durable.get(sid) ?? null;
				},
			} as never,
			// The subject's sessions boundary, as admission reads it (the
			// session-admission ADR's D2, step 4).
			subjectRevocation: {
				kind: "test",
				revokeBefore: async () => undefined,
				revokedBefore: async () => {
					if (state.sessionsBoundary instanceof Error) throw state.sessionsBoundary;
					return state.sessionsBoundary;
				},
			},
			requirements: resolverForTests(options.requirements ?? [], {
				issuer: ISSUER,
				actions: FEDERATION_GRANTS_ADMISSION_ACTIONS,
			}),
			revocationSkewMs: 1000,
			connections: {
				get: (name: string) => {
					if (state.configurationThrows) throw new Error("injected: configuration unreadable");
					return state.connections.get(name);
				},
			} as ReadonlyMap<string, FederationGrantAcquisitionConnection>,
			authorizerFor: (federation) =>
				federation === "upstream" && !state.authorizerMissing
					? {
							buildDelegatedAuthorizationUrl: (params) => {
								if (state.authorizerThrows) throw new Error("reserved parameter");
								authorized.push(params);
								const url = new URL("https://issuer.example/authorize");
								url.searchParams.set("state", params.state);
								return url;
							},
							exchangeDelegatedCode: async (params) => {
								state.exchanged.push(params as unknown as Record<string, unknown>);
								if (state.exchangeThrows !== undefined) throw state.exchangeThrows;
								const tokens = { ...state.exchange.tokens };
								if (
									state.exchangeFillsExpiresAt &&
									typeof tokens.expiresIn === "number" &&
									!("expiresAt" in tokens)
								) {
									tokens.expiresAt = new Date(state.now.getTime() + tokens.expiresIn * 1000);
								}
								return {
									upstream: { ...state.exchange.upstream },
									tokens: state.exchangeTokens === undefined ? tokens : state.exchangeTokens(),
								} as never;
							},
						}
					: undefined,
			consentUrl: "/consent/grants",
			login: options.login ?? createTestLoginEntry("/login"),
			csrfGuard,
			issuer: options.issuer ?? ISSUER,
			grantsBoundary: async () => {
				if (state.grantsBoundary instanceof Error) throw state.grantsBoundary;
				return state.grantsBoundary;
			},
			identityLookup: options.identityLookup ?? "required",
			userRepository:
				"userRepository" in options
					? options.userRepository
					: new Directory(state.owners, state.lookups, intercept),
			...(options.withoutLogger === true ? {} : { logger: spy.logger }),
			upstreamTimeoutMs: 5_000,
			rateLimiter:
				options.rateLimiter ??
				createMemoryRateLimiter({ limits: {}, defaultLimit: { limit: 1000, windowSeconds: 60 } }),
			background,
			now,
			randomId: () => state.ids.shift() ?? randomUUID(),
			auditSink: {
				kind: "test",
				record: async (event) => {
					await state.auditGates.get(event.type);
					if (state.auditFails) throw new Error("injected: the audit sink is down");
					events.push(event);
				},
			},
		}),
	);

	const deps = {
		grantStore: grants,
		intentStore: intents,
		connections: state.connections,
		limits: { defaultLifetimeMs: 30 * DAY, maxLifetimeMs: 30 * DAY },
		now,
		grantsRevokedBefore: async () => null,
		revocationSkewMs: 1000,
		maxExpiresInMs: 30 * DAY,
	};

	/** A client lodges an intent for `subject`; the handle is what `connect_uri` carries. */
	const lodge = async (subject = "alice") => {
		const lodged = await lodgeFederationGrantIntent(deps, {
			client: CLIENT,
			connection: CONNECTION.name,
			subject,
			redirectUri: REDIRECT,
			clientState: "client-state-1",
			correlationId: "corr-1",
		});
		if (!lodged.ok) throw new Error(`fixture: ${lodged.reason}`);
		return lodged;
	};

	/** A signed-in browser for `subject`, with a live durable session authenticated at `authTime`. */
	const signIn = (browser: string, subject = "alice", authTime = state.now) => {
		const sid = `sid-${browser}`;
		browsers.set(browser, { isAuthenticated: true, user: { id: subject }, sid });
		durable.set(sid, {
			sid,
			sub: subject,
			authTime,
			createdAt: authTime,
			expiresAt: new Date(state.now.getTime() + DAY),
			claims: {},
			// A password login's record (the MFA ADR's D9).
			...passwordSessionAuthentication(),
		});
		return sid;
	};

	const connect = (handle: string, browser?: string) => {
		const call = request(app)
			.get(`${FEDERATION_GRANTS_BROWSER_MOUNT_PATH}/connect`)
			.query({ request: handle });
		return browser === undefined ? call : call.set("x-browser", browser);
	};

	/** Connect, and read the challenge off the redirect to the consent page. */
	const challengeFor = async (handle: string, browser: string): Promise<string> => {
		const response = await connect(handle, browser);
		expect(response.status).toBe(303);
		return new URL(response.headers.location as string, ISSUER).searchParams.get("challenge") ?? "";
	};

	const page = (challenge: string, browser?: string) => {
		const call = request(app)
			.get(`${FEDERATION_GRANTS_BROWSER_MOUNT_PATH}/consent`)
			.query({ challenge });
		return browser === undefined ? call : call.set("x-browser", browser);
	};

	/**
	 * The answer, carrying `headers` — by default what a browser adds to a post
	 * from the deployment's own page — as JSON, or as the page's form post.
	 */
	const answer = (
		body: Record<string, unknown>,
		browser: string,
		headers: Readonly<Record<string, string>> = FROM_THE_PAGE,
		as: "json" | "form" = "json",
	) =>
		request(app)
			.post(`${FEDERATION_GRANTS_BROWSER_MOUNT_PATH}/consent`)
			.set("x-browser", browser)
			.set(FORWARDED)
			.set({ ...headers })
			.type(as)
			.send(body);

	/** A token the guard issued, and the `Cookie` header that carries it back. */
	const csrfToken = async (): Promise<{ readonly token: string; readonly cookie: string }> => {
		const issued = await request(app).get("/csrf");
		const [cookie] = (issued.headers["set-cookie"] as unknown as string[])[0]?.split(";") ?? [];
		return { token: issued.body.csrf_token as string, cookie: cookie ?? "" };
	};

	return {
		app,
		grants,
		intents,
		background,
		events,
		lines: spy.lines,
		browsers,
		durable,
		authorized,
		state,
		deps,
		lodge,
		signIn,
		connect,
		challengeFor,
		page,
		answer,
		csrfGuard,
		csrfToken,
	};
}

const isPlain = (response: { headers: Record<string, string> }) =>
	expect(response.headers["content-type"]).toMatch(/^text\/plain/);

describe("GET /session/federation-grants/connect — the start a client sends the user to", () => {
	it("sends a browser that is not signed in to the login page, and back to exactly this link", async () => {
		const w = world();
		const { handle } = await w.lodge();
		const response = await w.connect(handle);
		expect(response.status).toBe(303);
		const location = new URL(response.headers.location as string, ISSUER);
		expect(location.pathname).toBe("/login");
		const back = new URL(location.searchParams.get("redirect_to") ?? "");
		expect(back.origin).toBe(ISSUER);
		expect([...back.searchParams.keys()]).toEqual(["request"]);
		expect(back.searchParams.get("request")).toBe(handle);
		// Nothing was parked for a browser that has not signed in.
		expect(w.intents.size).toBe(1);
	});

	it("builds that trip with the loginEntry it is handed", async () => {
		// The login page and its `redirect_to` protocol are the session
		// module's: the router asks the entry, and builds no URL of its own.
		const asked: string[] = [];
		const w = world({
			login: Object.freeze({
				url: "/sign-in?tenant=a",
				urlFor: (returnTo: string) => {
					asked.push(returnTo);
					return `/sign-in?tenant=a&back=${encodeURIComponent(returnTo)}`;
				},
			}),
		});
		const { handle } = await w.lodge();
		const response = await w.connect(handle);
		expect(response.status).toBe(303);
		expect(asked).toHaveLength(1);
		expect(response.headers.location).toBe(
			`/sign-in?tenant=a&back=${encodeURIComponent(asked[0] as string)}`,
		);
		expect(new URL(asked[0] as string).searchParams.get("request")).toBe(handle);
	});

	it("sends a login page with a fragment its redirect_to in the page's query, before the fragment", async () => {
		// `?redirect_to=…` goes before the page's fragment: after it, the page
		// would never read it. Through the entry the connect flow follows core's
		// login-page rule, as `/authorize` does.
		const w = world({ login: createTestLoginEntry("/login?tenant=a#pane") });
		const { handle } = await w.lodge();
		const response = await w.connect(handle);
		expect(response.status).toBe(303);
		const sent = response.headers.location as string;
		expect(sent.endsWith("#pane")).toBe(true);
		const location = new URL(sent, ISSUER);
		expect(location.pathname).toBe("/login");
		expect(location.hash).toBe("#pane");
		expect(location.searchParams.get("tenant")).toBe("a");
		expect(location.searchParams.getAll("redirect_to")).toHaveLength(1);
		const back = new URL(location.searchParams.get("redirect_to") ?? "");
		expect(back.searchParams.get("request")).toBe(handle);
	});

	it("parks one challenge for the subject's own browser, and sends it to the consent page", async () => {
		const w = world();
		const { handle } = await w.lodge();
		w.signIn("b-1");
		const response = await w.connect(handle, "b-1");
		expect(response.status).toBe(303);
		expect(response.headers["referrer-policy"]).toBe("no-referrer");
		expect(response.headers["cache-control"]).toContain("no-store");
		const location = new URL(response.headers.location as string, ISSUER);
		expect(location.pathname).toBe("/consent/grants");
		const challenge = location.searchParams.get("challenge") ?? "";
		expect(challenge.length).toBeGreaterThan(20);
		// A reload is given the same challenge, not a second one.
		expect(await w.challengeFor(handle, "b-1")).toBe(challenge);
	});

	it("refuses another account's browser with a plain 403, and redirects it nowhere", async () => {
		const w = world();
		const { handle, grantId } = await w.lodge("alice");
		w.signIn("b-2", "mallory");
		const response = await w.connect(handle, "b-2");
		expect(response.status).toBe(403);
		isPlain(response);
		expect(response.headers.location).toBeUndefined();
		await w.background.drain();
		expect(w.events.find((e) => e.type === "federation.grant.authorization_failed")).toMatchObject({
			details: { grantId, outcome: "subject_mismatch" },
		});
	});

	it("asks the user to sign in again when the session is gone, expired, or older than the sessions boundary", async () => {
		const w = world();
		const { handle } = await w.lodge();
		const sid = w.signIn("b-1");
		w.durable.delete(sid);
		const gone = await w.connect(handle, "b-1");
		expect(gone.status).toBe(403);
		isPlain(gone);
		expect(gone.text).toMatch(/sign in again/i);

		w.signIn("b-2", "alice", new Date(w.state.now.getTime() - 60_000));
		w.state.sessionsBoundary = new Date(w.state.now.getTime() - 30_000);
		const covered = await w.connect(handle, "b-2");
		expect(covered.status).toBe(403);
		expect(covered.text).toMatch(/sign in again/i);
	});

	it("fails closed on a boundary it cannot read", async () => {
		const w = world();
		const { handle } = await w.lodge();
		w.signIn("b-1");
		w.state.sessionsBoundary = new Error("down");
		const response = await w.connect(handle, "b-1");
		expect(response.status).toBe(503);
		isPlain(response);
	});

	it("refuses a link that is unknown, missing, already superseded, or for a connection that changed", async () => {
		const w = world();
		w.signIn("b-1");
		for (const response of [
			await w.connect("no-such-handle", "b-1"),
			await request(w.app).get("/session/federation-grants/connect").set("x-browser", "b-1"),
		]) {
			expect(response.status).toBe(400);
			isPlain(response);
		}
		const { handle, grantId } = await w.lodge();
		await w.grants.revoke(grantId, "operator", w.state.now);
		expect((await w.connect(handle, "b-1")).status).toBe(400);

		const fresh = await w.lodge();
		w.state.connections.set(CONNECTION.name, {
			...CONNECTION,
			scopes: [...CONNECTION.scopes, "contacts.read"],
		});
		const changed = await w.connect(fresh.handle, "b-1");
		expect(changed.status).toBe(400);
		expect(changed.text).toMatch(/changed/i);
	});

	it("parks nothing for a prefetch", async () => {
		const w = world();
		const { handle } = await w.lodge();
		w.signIn("b-1");
		const response = await w.connect(handle, "b-1").set("Sec-Purpose", "prefetch");
		expect(response.status).toBe(204);
		const real = await w.challengeFor(handle, "b-1");
		expect(real.length).toBeGreaterThan(20);
	});

	it("answers every exit of a navigation without a JSON body — the throttle and an unknown path included", async () => {
		const refusing: RateLimiter = {
			kind: "refusing",
			check: async () => ({ allowed: false, reason: "x" }),
		};
		const w = world({ rateLimiter: refusing });
		const { handle } = await w.lodge();
		const throttled = await w.connect(handle);
		expect(throttled.status).toBe(429);
		isPlain(throttled);
		const unknown = await request(w.app).get("/session/federation-grants/nothing-here");
		expect(unknown.status).toBe(404);
		isPlain(unknown);
	});
});

describe("GET /session/federation-grants/consent — what the page reads", () => {
	it("tells the page the client, the connection, the scopes, the duration, and that it outlives logout", async () => {
		const w = world();
		const { handle } = await w.lodge();
		w.signIn("b-1");
		const challenge = await w.challengeFor(handle, "b-1");
		const response = await w.page(challenge, "b-1");
		expect(response.status).toBe(200);
		expect(response.body).toEqual({
			challenge,
			client_id: "worker",
			client_name: "Calendar Agent",
			connection: "calendar",
			scopes: CONNECTION.scopes,
			resource: "https://calendar.example/",
			grant_expires_in: 30 * 86_400,
			continues_after_logout: true,
			expires_in: 600,
		});
		// Read twice: showing the question does not spend it.
		expect((await w.page(challenge, "b-1")).status).toBe(200);
	});

	it("answers as /oauth/consent does for everything it may not show", async () => {
		const w = world();
		const { handle } = await w.lodge();
		w.signIn("b-1");
		const challenge = await w.challengeFor(handle, "b-1");

		expect((await w.page(challenge)).status).toBe(401);
		expect((await w.page(challenge)).body.error).toBe("login_required");
		expect((await w.page("", "b-1")).body).toEqual({
			error: "invalid_request",
			error_description: "challenge is required",
		});
		// Another browser of the same user: the challenge is not a bearer token.
		w.signIn("b-2");
		const foreign = await w.page(challenge, "b-2");
		expect(foreign.status).toBe(400);
		// RFC 6749 Appendix A.8: printable ASCII only, so no em dash.
		expect(foreign.body.error_description).toBe(
			"no pending consent for this challenge: it was answered, has expired, or was not issued to this session; start again",
		);
		expect((await w.page("no-such-challenge", "b-1")).body).toEqual(foreign.body);
	});

	it("asks the user to sign in again when the session was revoked after the question was parked", async () => {
		const w = world();
		const { handle } = await w.lodge();
		const sid = w.signIn("b-1");
		const challenge = await w.challengeFor(handle, "b-1");
		w.durable.delete(sid);
		const response = await w.page(challenge, "b-1");
		expect(response.status).toBe(403);
		expect(response.body.error).toBe("reauthentication_required");
	});
});

describe("POST /session/federation-grants/consent — the answer", () => {
	it("sends an approval upstream with the intent's own parameters, and a transaction for the callback", async () => {
		const w = world();
		const { handle, grantId } = await w.lodge();
		w.signIn("b-1");
		const challenge = await w.challengeFor(handle, "b-1");
		const response = await w.answer({ challenge, decision: "accept" }, "b-1");
		expect(response.status).toBe(303);
		const upstream = new URL(response.headers.location as string);
		expect(upstream.origin).toBe("https://issuer.example");

		const sent = w.authorized.at(-1);
		expect(sent).toMatchObject({
			redirectUri: CONNECTION.callbackUri,
			scopes: CONNECTION.scopes,
			resource: "https://calendar.example/",
			authorizationParams: { access_type: "offline" },
		});
		const transaction = await w.intents.consumeTransaction({
			state: upstream.searchParams.get("state") ?? "",
			connection: CONNECTION.name,
			now: w.state.now,
		});
		expect(transaction).toMatchObject({
			intent: { grantId, handle },
			codeVerifier: sent?.codeVerifier,
			nonce: sent?.nonce,
			consent: { sid: "sid-b-1", scopes: CONNECTION.scopes },
		});
	});

	it("returns a refusal to the client with its own state and the grant, and spends the intent", async () => {
		const w = world();
		const { handle, grantId } = await w.lodge();
		w.signIn("b-1");
		const challenge = await w.challengeFor(handle, "b-1");
		const response = await w.answer({ challenge, decision: "deny" }, "b-1");
		expect(response.status).toBe(303);
		const back = new URL(response.headers.location as string);
		expect(`${back.origin}${back.pathname}`).toBe(REDIRECT);
		expect(back.searchParams.get("error")).toBe("access_denied");
		expect(back.searchParams.get("state")).toBe("client-state-1");
		expect(back.searchParams.get("grant_id")).toBe(grantId);
		expect(await w.intents.getIntent(handle, w.state.now)).toBeNull();
		// Answered once: a second answer finds nothing.
		expect((await w.answer({ challenge, decision: "accept" }, "b-1")).status).toBe(400);
	});

	it("retires a refused renewal's pointer, and only that one", async () => {
		const w = world();
		const first = await w.lodge();
		// Establish the grant the renewal is for.
		await w.grants.activate({
			grantId: first.grantId,
			intentHandle: first.handle,
			authorization: {
				identityRevision:
					(await w.intents.getIntent(first.handle, w.state.now))?.identityRevision ?? "",
				authorizationRevision:
					(await w.intents.getIntent(first.handle, w.state.now))?.authorizationRevision ?? "",
				upstream: { issuer: CONNECTION.upstreamIssuer, subject: "00u-alice" },
				scopes: [...CONNECTION.scopes],
				consent: { at: w.state.now, sid: "sid-x", scopes: [...CONNECTION.scopes] },
				authorizedAt: w.state.now,
				expiresAt: new Date(w.state.now.getTime() + 30 * DAY),
				resource: undefined,
			},
			credentials: {
				refreshToken: "rt",
				accessToken: {
					value: "at",
					tokenType: "Bearer",
					obtainedAt: w.state.now,
					issuedLifetime: 3600,
					effectiveExpiresAt: new Date(w.state.now.getTime() + 3_600_000),
					scopes: [...CONNECTION.scopes],
				},
			},
			now: w.state.now,
		});
		const renewal = await lodgeFederationGrantReauthorization(w.deps, {
			client: CLIENT,
			grantId: first.grantId,
			subject: "alice",
			redirectUri: REDIRECT,
			clientState: "client-state-2",
			correlationId: "corr-2",
		});
		if (!renewal.ok) throw new Error(`fixture: ${renewal.reason}`);
		w.signIn("b-1");
		const challenge = await w.challengeFor(renewal.handle, "b-1");
		expect(await w.grants.isCurrentIntent(first.grantId, renewal.handle, w.state.now)).toBe(true);
		await w.answer({ challenge, decision: "deny" }, "b-1");
		expect(await w.grants.isCurrentIntent(first.grantId, renewal.handle, w.state.now)).toBe(false);
		expect((await w.grants.find(first.grantId, w.state.now))?.status).toBe("active");
	});

	it("refuses a malformed decision and a cross-site answer without spending anything", async () => {
		const w = world();
		const { handle } = await w.lodge();
		w.signIn("b-1");
		const challenge = await w.challengeFor(handle, "b-1");
		const unknown = await w.answer({ challenge, decision: "maybe" }, "b-1");
		expect(unknown.status).toBe(400);
		// Appendix A.8 allows no `"`: the values are quoted with `'`.
		expect(unknown.body.error_description).toBe("decision must be 'accept' or 'deny'");
		const crossSite = await w.answer({ challenge, decision: "accept" }, "b-1", {
			Origin: "https://evil.test",
			"Sec-Fetch-Site": "cross-site",
		});
		expect(crossSite.status).toBe(403);
		expect((await w.answer({ challenge, decision: "accept" }, "b-1")).status).toBe(303);
	});

	it("keeps the consent when the upstream URL cannot be built: a configuration fault must not spend it", async () => {
		const w = world();
		const { handle } = await w.lodge();
		w.signIn("b-1");
		const challenge = await w.challengeFor(handle, "b-1");
		w.state.authorizerThrows = true;
		const refused = await w.answer({ challenge, decision: "accept" }, "b-1");
		expect(refused.status).toBe(503);
		w.state.authorizerThrows = false;
		expect((await w.answer({ challenge, decision: "accept" }, "b-1")).status).toBe(303);
	});

	it("will not let another browser answer, even the same user's", async () => {
		const w = world();
		const { handle } = await w.lodge();
		w.signIn("b-1");
		w.signIn("b-2");
		const challenge = await w.challengeFor(handle, "b-1");
		const foreign = await w.answer({ challenge, decision: "accept" }, "b-2");
		expect(foreign.status).toBe(400);
		expect((await w.answer({ challenge, decision: "accept" }, "b-1")).status).toBe(303);
	});
});

describe("POST /session/federation-grants/consent — held to the deployment's csrfGuard", () => {
	const CROSS_SITE_ANSWER = {
		error: "invalid_request",
		error_description: "cross-site answer refused",
	};
	const NO_ORIGIN_NO_TOKEN = {
		error: "invalid_request",
		error_description: "no origin and no valid csrf token",
	};

	/** A signed-in browser `b-1` with a question parked for it, and the challenge. */
	const parked = async (options: WorldOptions = {}) => {
		const w = world(options);
		const { handle } = await w.lodge();
		w.signIn("b-1");
		return { w, challenge: await w.challengeFor(handle, "b-1") };
	};

	/** The answer refused: nothing was spent, so the page's own answer still goes through. */
	const stillParked = async (w: World, challenge: string) => {
		expect((await w.answer({ challenge, decision: "accept" }, "b-1")).status).toBe(303);
	};

	it("accepts the page's answer: its Origin is the request's own, as the proxy forwards it", async () => {
		const { w, challenge } = await parked();
		const response = await w.answer({ challenge, decision: "accept" }, "b-1");
		expect(response.status).toBe(303);
		expect(new URL(response.headers.location as string).origin).toBe("https://issuer.example");
	});

	it("refuses a foreign Origin, even with a valid token, and spends nothing", async () => {
		const { w, challenge } = await parked();
		const { token, cookie } = await w.csrfToken();
		const attempts: readonly Readonly<Record<string, string>>[] = [
			{ Origin: "https://evil.test" },
			{ Origin: "https://evil.test", Cookie: cookie, "x-csrf-token": token },
		];
		for (const headers of attempts) {
			const refused = await w.answer({ challenge, decision: "accept" }, "b-1", headers);
			expect(refused.status).toBe(403);
			expect(refused.body).toEqual(CROSS_SITE_ANSWER);
		}
		await stillParked(w, challenge);
	});

	it("refuses a cross-site answer as a browser sends one", async () => {
		const { w, challenge } = await parked();
		const refused = await w.answer({ challenge, decision: "deny" }, "b-1", {
			Origin: "https://evil.test",
			"Sec-Fetch-Site": "cross-site",
		});
		expect(refused.status).toBe(403);
		expect(refused.body).toEqual(CROSS_SITE_ANSWER);
		await stillParked(w, challenge);
	});

	it("refuses Origin: null — a form post from a page served with Referrer-Policy: no-referrer — even with a valid token", async () => {
		const { w, challenge } = await parked();
		const { token, cookie } = await w.csrfToken();
		const attempts: readonly Readonly<Record<string, string>>[] = [
			{ Origin: "null", "Sec-Fetch-Site": "same-origin" },
			{ Origin: "null", "Sec-Fetch-Site": "same-origin", Cookie: cookie },
		];
		for (const headers of attempts) {
			const refused = await w.answer(
				{ challenge, decision: "accept", csrf_token: token },
				"b-1",
				headers,
				"form",
			);
			expect(refused.status).toBe(403);
			expect(refused.body).toEqual(CROSS_SITE_ANSWER);
		}
		await stillParked(w, challenge);
	});

	it("refuses an answer with no Origin, no Referer and no token", async () => {
		const { w, challenge } = await parked();
		const attempts: readonly Readonly<Record<string, string>>[] = [
			{},
			{ "Sec-Fetch-Site": "same-origin" },
		];
		for (const headers of attempts) {
			const refused = await w.answer({ challenge, decision: "accept" }, "b-1", headers);
			expect(refused.status).toBe(403);
			expect(refused.body).toEqual(NO_ORIGIN_NO_TOKEN);
		}
		await stillParked(w, challenge);
	});

	it("refuses an answer with no Origin and no Referer whose token does not match its cookie", async () => {
		const { w, challenge } = await parked();
		const first = await w.csrfToken();
		const second = await w.csrfToken();
		const refused = await w.answer({ challenge, decision: "accept" }, "b-1", {
			Cookie: first.cookie,
			"x-csrf-token": second.token,
		});
		expect(refused.status).toBe(403);
		expect(refused.body).toEqual(NO_ORIGIN_NO_TOKEN);
		await stillParked(w, challenge);
	});

	it("accepts an answer with no Origin and no Referer that echoes the guard's token in the form field", async () => {
		const { w, challenge } = await parked();
		const { token, cookie } = await w.csrfToken();
		const response = await w.answer(
			{ challenge, decision: "accept", [w.csrfGuard.bodyField as string]: token },
			"b-1",
			{ Cookie: cookie },
			"form",
		);
		expect(response.status).toBe(303);
	});

	it("accepts an answer with no Origin and no Referer that echoes the guard's token in the header", async () => {
		const { w, challenge } = await parked();
		const { token, cookie } = await w.csrfToken();
		const response = await w.answer({ challenge, decision: "deny" }, "b-1", {
			Cookie: cookie,
			[w.csrfGuard.headerName]: token,
		});
		expect(response.status).toBe(303);
		expect(new URL(response.headers.location as string).searchParams.get("error")).toBe(
			"access_denied",
		);
	});

	it("accepts an answer from a trusted sibling origin, which sends Sec-Fetch-Site: same-site", async () => {
		const { w, challenge } = await parked();
		const response = await w.answer({ challenge, decision: "accept" }, "b-1", {
			Origin: TRUSTED_SIBLING,
			"Sec-Fetch-Site": "same-site",
		});
		expect(response.status).toBe(303);
	});

	it("refuses a same-site sibling origin the guard does not trust", async () => {
		const { w, challenge } = await parked();
		const refused = await w.answer({ challenge, decision: "accept" }, "b-1", {
			Origin: "https://blog.auth.test",
			"Sec-Fetch-Site": "same-site",
		});
		expect(refused.status).toBe(403);
		expect(refused.body).toEqual(CROSS_SITE_ANSWER);
		await stillParked(w, challenge);
	});

	it("asks the guard it is handed, and nothing else: its verdict alone decides", async () => {
		const accepting: CsrfGuard = Object.freeze({
			...createTestCsrfGuard(),
			check: () => ({ outcome: "accepted" as const }),
		});
		const lenient = await parked({ csrfGuard: accepting });
		const accepted = await lenient.w.answer(
			{ challenge: lenient.challenge, decision: "accept" },
			"b-1",
			{ Origin: "https://evil.test", "Sec-Fetch-Site": "cross-site" },
		);
		expect(accepted.status).toBe(303);

		const refusing: CsrfGuard = Object.freeze({
			...createTestCsrfGuard(),
			check: () => ({ outcome: "refused" as const, reason: "token_invalid" as const }),
		});
		const strict = await parked({ csrfGuard: refusing });
		const refused = await strict.w.answer(
			{ challenge: strict.challenge, decision: "accept" },
			"b-1",
		);
		expect(refused.status).toBe(403);
		expect(refused.body).toEqual(NO_ORIGIN_NO_TOKEN);
	});

	it("asks the guard before the session: a refused answer from a browser that is not signed in is 403, not login_required", async () => {
		const w = world();
		const refused = await w.answer({ challenge: "c", decision: "accept" }, "nobody", {
			Origin: "null",
		});
		expect(refused.status).toBe(403);
		expect(refused.body).toEqual(CROSS_SITE_ANSWER);
		const unauthenticated = await w.answer({ challenge: "c", decision: "accept" }, "nobody");
		expect(unauthenticated.status).toBe(401);
	});

	it("asks the guard before the intent store: a refused answer is 403 while the store is down", async () => {
		const { w, challenge } = await parked();
		w.state.faults.set("getConsent", 0);
		const refused = await w.answer({ challenge, decision: "accept" }, "b-1", { Origin: "null" });
		expect(refused.status).toBe(403);
		expect(refused.body).toEqual(CROSS_SITE_ANSWER);
		expect((await w.answer({ challenge, decision: "accept" }, "b-1")).status).toBe(503);
	});

	it("accepts the request's own Origin, as the proxy forwards it, whatever Sec-Fetch-Site says, cross-site included", async () => {
		const { w, challenge } = await parked();
		const response = await w.answer({ challenge, decision: "accept" }, "b-1", {
			Origin: ISSUER,
			"Sec-Fetch-Site": "cross-site",
		});
		expect(response.status).toBe(303);
	});

	it("accepts an origin on the guard's trusted list whatever Sec-Fetch-Site says, cross-site included", async () => {
		const { w, challenge } = await parked();
		const response = await w.answer({ challenge, decision: "accept" }, "b-1", {
			Origin: TRUSTED_SIBLING,
			"Sec-Fetch-Site": "cross-site",
		});
		expect(response.status).toBe(303);
	});

	it.each([
		["a promise of acceptance", () => Promise.resolve({ outcome: "accepted" })],
		["a promise that rejects", () => Promise.reject(new Error("injected: async guard"))],
		["another outcome", () => ({ outcome: "reject" })],
		[
			"a refusal with a reason outside the contract",
			() => ({ outcome: "refused", reason: "nope" }),
		],
		["nothing", () => undefined],
	])(
		"refuses the answer when the guard's verdict is %s, as cross-site, and spends nothing",
		async (_label, verdict) => {
			const { w, challenge } = await parked({
				csrfGuard: Object.freeze({
					...createTestCsrfGuard(),
					check: verdict as unknown as CsrfGuard["check"],
				}),
			});
			const refused = await w.answer({ challenge, decision: "accept" }, "b-1");
			expect(refused.status).toBe(403);
			expect(refused.body).toEqual(CROSS_SITE_ANSWER);
			expect(payloadOf(w.lines, "federation_grant_consent_csrf_refused")).toMatchObject({
				reason: "unrecognized",
			});
			expect(await w.intents.getConsent(challenge, w.state.now)).not.toBeNull();
		},
	);

	it("answers 500 when the guard's check throws, logged as an unexpected error, and spends nothing", async () => {
		const { w, challenge } = await parked({
			csrfGuard: Object.freeze({
				...createTestCsrfGuard(),
				check: () => {
					throw new Error("injected: the guard threw");
				},
			}),
		});
		const response = await w.answer({ challenge, decision: "accept" }, "b-1");
		expect(response.status).toBe(500);
		expect(response.body).toEqual({ error: "server_error", error_description: "unexpected_error" });
		expect(written(w.lines)).toEqual(["error federation_grants_unexpected_error"]);
		expect(payloadOf(w.lines, "federation_grants_unexpected_error")).toMatchObject({
			site: "consent",
		});
		expect(await w.intents.getConsent(challenge, w.state.now)).not.toBeNull();
	});

	it("logs a refused answer as one warn line with the guard's reason, the request's id and the Origin it named", async () => {
		const { w, challenge } = await parked();
		const foreign = await w.answer({ challenge, decision: "accept" }, "b-1", {
			Origin: "https://evil.test",
			"Sec-Fetch-Site": "cross-site",
		});
		expect(foreign.status).toBe(403);
		expect(written(w.lines)).toEqual(["warn federation_grant_consent_csrf_refused"]);
		expect(payloadOf(w.lines, "federation_grant_consent_csrf_refused")).toEqual({
			reason: "foreign_origin",
			correlationId: foreign.headers["x-request-id"],
			origin: "https://evil.test",
		});

		w.lines.length = 0;
		const bare = await w.answer({ challenge, decision: "accept" }, "b-1", {});
		expect(bare.status).toBe(403);
		expect(payloadOf(w.lines, "federation_grant_consent_csrf_refused")).toEqual({
			reason: "token_absent",
			correlationId: bare.headers["x-request-id"],
		});
	});

	it("logs the Origin a refused answer named sanitised and capped", async () => {
		const { w, challenge } = await parked();
		const hostile = `https://evil.test/\t${"h".repeat(10_000)}`;
		const refused = await w.answer({ challenge, decision: "accept" }, "b-1", { Origin: hostile });
		expect(refused.status).toBe(403);
		expect(payloadOf(w.lines, "federation_grant_consent_csrf_refused").origin).toBe(
			auditErrorText(hostile),
		);
	});
});

// ---------------------------------------------------------------------------
// The callback (the federation-grants ADR, D7): eight checks, then the activation.
// ---------------------------------------------------------------------------

type World = ReturnType<typeof world>;

/** Lodge, sign in, connect and approve — the state a browser comes back from the upstream in. */
async function approved(w: World, browser = "b-1", subject = "alice") {
	const lodged = await w.lodge(subject);
	w.signIn(browser, subject);
	const challenge = await w.challengeFor(lodged.handle, browser);
	const response = await w.answer({ challenge, decision: "accept" }, browser);
	expect(response.status).toBe(303);
	const state = new URL(response.headers.location as string).searchParams.get("state") ?? "";
	return { ...lodged, state };
}

const callback = (
	w: World,
	query: Record<string, string>,
	browser?: string,
	connection = CONNECTION.name,
) => {
	const call = request(w.app)
		.get(`${FEDERATION_GRANTS_BROWSER_MOUNT_PATH}/callback/${connection}`)
		.query(query);
	return browser === undefined ? call : call.set("x-browser", browser);
};

/** Where a callback sent the browser back to, and what it said. */
const returned = (response: { status: number; headers: Record<string, string> }) => {
	expect(response.status).toBe(303);
	const back = new URL(response.headers.location as string);
	expect(`${back.origin}${back.pathname}`).toBe(REDIRECT);
	return back.searchParams;
};

describe("GET /session/federation-grants/callback/:connection — activating the grant", () => {
	it("activates the grant with what the user consented to and what the upstream verified, and returns the browser to the client", async () => {
		const w = world();
		const { state, grantId, handle } = await approved(w);
		const response = await callback(
			w,
			{ state, code: "code-1", iss: CONNECTION.upstreamIssuer },
			"b-1",
		);
		const back = returned(response);
		expect(back.get("grant_id")).toBe(grantId);
		expect(back.get("state")).toBe("client-state-1");
		expect(back.has("error")).toBe(false);

		const opened = await w.grants.open(grantId, w.state.now);
		expect(opened?.grant).toMatchObject({
			status: "active",
			upstream: { issuer: CONNECTION.upstreamIssuer, subject: "00u-alice" },
			resource: "https://calendar.example/",
			scopes: CONNECTION.scopes,
			consent: { sid: "sid-b-1", scopes: CONNECTION.scopes },
		});
		expect(opened?.credentials).toMatchObject({
			state: "ok",
			value: {
				refreshToken: "upstream-refresh",
				accessToken: { value: "upstream-access", issuedLifetime: 3600 },
			},
		});
		// The exchange was made at the grant's callback, with the flow's own
		// verifier and nonce, the resource, and `iss` forwarded — never code or state.
		expect(w.state.exchanged.at(-1)).toMatchObject({
			code: "code-1",
			redirectUri: CONNECTION.callbackUri,
			resource: "https://calendar.example/",
			callbackParams: { iss: CONNECTION.upstreamIssuer },
		});
		expect(w.state.exchanged.at(-1)?.signal).toBeInstanceOf(AbortSignal);
		// The flow is over: its place against the bound is free again.
		expect(w.intents.reservations("worker", "alice")).toBe(0);
		expect(await w.intents.getIntent(handle, w.state.now)).toBeNull();
		await w.background.drain();
		expect(w.events.find((e) => e.type === "federation.grant.authorized")).toMatchObject({
			clientId: "worker",
			subject: "alice",
			details: { grantId, connection: CONNECTION.name, outcome: "required/unlinked" },
		});
		expect(JSON.stringify(w.events)).not.toContain("upstream-refresh");
	});

	it("answers check 1's failures with a plain 400 and sends the browser nowhere", async () => {
		const w = world();
		const { state } = await approved(w);
		for (const response of [
			await callback(w, { state: "no-such-state", code: "c" }, "b-1"),
			await callback(w, { code: "c" }, "b-1"),
			// Another connection's path: refused, and the transaction left alone.
			await callback(w, { state, code: "c" }, "b-1", "other-connection"),
		]) {
			expect(response.status).toBe(400);
			isPlain(response);
			expect(response.headers.location).toBeUndefined();
		}
		expect(returned(await callback(w, { state, code: "c" }, "b-1")).has("error")).toBe(false);
		// Spent: a replay finds nothing.
		expect((await callback(w, { state, code: "c" }, "b-1")).status).toBe(400);
	});

	it("passes the upstream's refusal on, and names anything else it said as an upstream error", async () => {
		const w = world();
		const first = await approved(w);
		expect(
			returned(await callback(w, { state: first.state, error: "access_denied" }, "b-1")).get(
				"error",
			),
		).toBe("access_denied");
		const second = await approved(w, "b-2");
		const back = returned(
			await callback(
				w,
				{ state: second.state, error: "server_error", error_description: "<script>" },
				"b-2",
			),
		);
		expect(back.get("error")).toBe("upstream_error");
		expect([...back.keys()].sort()).toEqual(["error", "grant_id", "state"]);
	});

	it("refuses a browser that is not the one the flow started in, or no longer the right session", async () => {
		const w = world();
		const a = await approved(w, "b-1");
		w.signIn("b-9");
		expect(returned(await callback(w, { state: a.state, code: "c" }, "b-9")).get("error")).toBe(
			"reauthentication_required",
		);

		const b = await approved(w, "b-2");
		w.durable.delete("sid-b-2");
		expect(returned(await callback(w, { state: b.state, code: "c" }, "b-2")).get("error")).toBe(
			"reauthentication_required",
		);

		const c = await approved(w, "b-3");
		w.state.sessionsBoundary = new Date(w.state.now.getTime() + 5_000);
		expect(returned(await callback(w, { state: c.state, code: "c" }, "b-3")).get("error")).toBe(
			"reauthentication_required",
		);
		w.state.sessionsBoundary = null;

		const d = await approved(w, "b-4");
		w.browsers.set("b-4", { isAuthenticated: true, user: { id: "mallory" }, sid: "sid-b-4" });
		expect(returned(await callback(w, { state: d.state, code: "c" }, "b-4")).get("error")).toBe(
			"account_mismatch",
		);
		expect(w.intents.reservations("worker", "alice")).toBe(0);
	});

	it("tells an outage reaching the upstream from an upstream that answered badly", async () => {
		const w = world();
		const a = await approved(w, "b-1");
		w.state.exchangeThrows = Object.assign(new Error("the operation timed out"), {
			name: "TimeoutError",
		});
		expect(returned(await callback(w, { state: a.state, code: "c" }, "b-1")).get("error")).toBe(
			"temporarily_unavailable",
		);
		const b = await approved(w, "b-2");
		w.state.exchangeThrows = new Error("unexpected JWT nonce claim value");
		expect(returned(await callback(w, { state: b.state, code: "c" }, "b-2")).get("error")).toBe(
			"upstream_error",
		);
	});

	it("binds the upstream account: an expectation unmet, an account another user holds, another issuer", async () => {
		const w = world();
		// Linked to another local user.
		const a = await approved(w, "b-1");
		w.state.owners.set("00u-alice", { kind: "linked", subject: "bob" });
		expect(returned(await callback(w, { state: a.state, code: "c" }, "b-1")).get("error")).toBe(
			"identity_conflict",
		);
		// Linked to this very user is fine.
		const b = await approved(w, "b-2");
		w.state.owners.set("00u-alice", { kind: "linked", subject: "alice" });
		expect(returned(await callback(w, { state: b.state, code: "c" }, "b-2")).has("error")).toBe(
			false,
		);
		w.state.owners.clear();
		// Another issuer's identity, however it got here.
		const c = await approved(w, "b-3");
		w.state.exchange = {
			...w.state.exchange,
			upstream: { issuer: "https://attacker.test", subject: "x" },
		};
		expect(returned(await callback(w, { state: c.state, code: "c" }, "b-3")).get("error")).toBe(
			"upstream_error",
		);
	});

	it("refuses what cannot be disclosed, each for its own reason", async () => {
		const cases: [Record<string, unknown>, string][] = [
			[{ refreshToken: undefined }, "refresh_token_absent"],
			[{ expiresIn: 7200 }, "upstream_token_ineligible"],
			[{ tokenType: "dpop" }, "upstream_token_ineligible"],
			[{ expiresIn: undefined }, "upstream_token_ineligible"],
			[{ accessToken: undefined }, "upstream_token_ineligible"],
			// RFC 6749 §5.1: `token_type` is REQUIRED; an answer without one is not taken for Bearer.
			[{ tokenType: undefined }, "upstream_token_ineligible"],
			[{ scope: "openid offline_access calendar.read admin" }, "scope_exceeded"],
			// Scope is judged before the token type.
			[{ scope: "openid offline_access calendar.read admin", tokenType: "dpop" }, "scope_exceeded"],
			// Named, but naming no scope-token: not an answer, and not "as
			// requested" either.
			[{ scope: '\t"openid"' }, "upstream_token_ineligible"],
		];
		for (const [over, code] of cases) {
			const w = world();
			const a = await approved(w);
			const tokens = { ...w.state.exchange.tokens, ...over };
			for (const key of Object.keys(tokens)) if (tokens[key] === undefined) delete tokens[key];
			w.state.exchange = { ...w.state.exchange, tokens };
			const back = returned(await callback(w, { state: a.state, code: "c" }, "b-1"));
			expect(back.get("error"), JSON.stringify(over)).toBe(code);
			expect((await w.grants.find(a.grantId, w.state.now))?.status, JSON.stringify(over)).toBe(
				"pending",
			);
		}
	});

	it("reads the exchange's token answer once, each field on its own", async () => {
		const w = world();
		const a = await approved(w);
		const reads = new Map<PropertyKey, number>();
		w.state.exchangeTokens = () =>
			new Proxy(
				{
					...w.state.exchange.tokens,
					expiresAt: new Date(w.state.now.getTime() + 3_600_000),
				},
				{
					get(target, key, receiver) {
						reads.set(key, (reads.get(key) ?? 0) + 1);
						return Reflect.get(target, key, receiver);
					},
				},
			);
		const back = returned(await callback(w, { state: a.state, code: "c" }, "b-1"));
		expect(back.has("error")).toBe(false);
		expect(Object.fromEntries(reads)).toStrictEqual({
			refreshToken: 1,
			accessToken: 1,
			tokenType: 1,
			expiresIn: 1,
			expiresAt: 1,
			scope: 1,
		});
	});

	it("refuses an answer whose field throws when it is read as the answer it is, never as an outage, and activates nothing", async () => {
		const cases: [string, string][] = [
			["refreshToken", "refresh_token_absent"],
			["accessToken", "upstream_token_ineligible"],
			["tokenType", "upstream_token_ineligible"],
			["expiresIn", "upstream_token_ineligible"],
			["expiresAt", "upstream_token_ineligible"],
			["scope", "upstream_token_ineligible"],
		];
		for (const [field, code] of cases) {
			const w = world();
			const a = await approved(w);
			w.state.exchangeTokens = () => {
				const tokens = {
					...w.state.exchange.tokens,
					expiresAt: new Date(w.state.now.getTime() + 3_600_000),
				};
				Object.defineProperty(tokens, field, {
					get() {
						throw new Error("a getter that throws");
					},
				});
				return tokens;
			};
			const back = returned(await callback(w, { state: a.state, code: "c" }, "b-1"));
			expect(back.get("error"), field).toBe(code);
			expect((await w.grants.find(a.grantId, w.state.now))?.status, field).toBe("pending");
		}
	});

	it("refuses an answer whose expiresAt leaves no life, whatever its expiresIn says, and activates nothing", async () => {
		for (const expiresAt of [
			() => new Date(0),
			(now: number) => new Date(now - 1),
			(now: number) => new Date(now),
		]) {
			const w = world();
			const a = await approved(w);
			w.state.exchange = {
				...w.state.exchange,
				tokens: {
					...w.state.exchange.tokens,
					expiresIn: 3600,
					expiresAt: expiresAt(w.state.now.getTime()),
				},
			};
			const back = returned(await callback(w, { state: a.state, code: "c" }, "b-1"));
			expect(back.get("error")).toBe("upstream_token_ineligible");
			expect((await w.grants.find(a.grantId, w.state.now))?.status).toBe("pending");
		}
	});

	it("refuses a lifetime only one field states, or one the fields contradict, as retrieval does", async () => {
		const cases: Record<string, unknown>[] = [
			{ expiresIn: null },
			{ expiresIn: undefined },
			{ expiresAt: null },
			{ expiresIn: 1e306 },
			{ expiresIn: "3600" },
		];
		for (const over of cases) {
			const w = world();
			const a = await approved(w);
			const tokens: Record<string, unknown> = {
				...w.state.exchange.tokens,
				expiresAt: new Date(w.state.now.getTime() + 600_000),
				...over,
			};
			for (const key of Object.keys(tokens)) if (tokens[key] === undefined) delete tokens[key];
			w.state.exchange = { ...w.state.exchange, tokens };
			const back = returned(await callback(w, { state: a.state, code: "c" }, "b-1"));
			expect(back.get("error"), JSON.stringify(over)).toBe("upstream_token_ineligible");
			expect((await w.grants.find(a.grantId, w.state.now))?.status, JSON.stringify(over)).toBe(
				"pending",
			);
		}
	});

	it("refuses an answer that states expiresIn alone, as retrieval does", async () => {
		const w = world();
		const a = await approved(w);
		w.state.exchangeFillsExpiresAt = false;
		w.state.exchange = {
			...w.state.exchange,
			tokens: { ...w.state.exchange.tokens, expiresIn: 3600 },
		};
		const back = returned(await callback(w, { state: a.state, code: "c" }, "b-1"));
		expect(back.get("error")).toBe("upstream_token_ineligible");
		expect((await w.grants.find(a.grantId, w.state.now))?.status).toBe("pending");
	});

	it("stores the token dated from the exchange's start, ending at the earlier instant the answer names", async () => {
		for (const [expiresAtAfterCall, endsAfterCall] of [
			[600_000, 600_000],
			[7_200_000, 3_600_000],
		] as const) {
			const w = world();
			const a = await approved(w);
			const calledAt = w.state.now.getTime();
			// The upstream takes five seconds to answer: the clock moves while
			// the exchange reads the answer it returns.
			const tokens: Record<string, unknown> = { ...w.state.exchange.tokens, expiresIn: 3600 };
			Object.defineProperty(tokens, "expiresAt", {
				enumerable: true,
				get: () => {
					w.state.now = new Date(calledAt + 5_000);
					return new Date(calledAt + expiresAtAfterCall);
				},
			});
			w.state.exchange = { ...w.state.exchange, tokens };
			const back = returned(await callback(w, { state: a.state, code: "c" }, "b-1"));
			expect(back.has("error")).toBe(false);
			expect(w.state.now.getTime()).toBe(calledAt + 5_000);
			const opened = await w.grants.open(a.grantId, w.state.now);
			expect(opened?.credentials).toMatchObject({
				state: "ok",
				value: {
					accessToken: {
						value: "upstream-access",
						obtainedAt: new Date(calledAt),
						issuedLifetime: 3600,
						effectiveExpiresAt: new Date(calledAt + endsAfterCall),
					},
				},
			});
		}
	});

	it("keeps what the upstream narrowed to, and reads an omitted scope as the one requested", async () => {
		const w = world();
		const a = await approved(w, "b-1");
		w.state.exchange = {
			...w.state.exchange,
			tokens: { ...w.state.exchange.tokens, scope: "openid offline_access" },
		};
		returned(await callback(w, { state: a.state, code: "c" }, "b-1"));
		expect(await w.grants.find(a.grantId, w.state.now)).toMatchObject({
			scopes: ["openid", "offline_access"],
		});
	});

	it("reads a blank scope as an omitted one: the scopes requested", async () => {
		for (const scope of ["", " \t "]) {
			const w = world();
			const a = await approved(w, "b-1");
			w.state.exchange = {
				...w.state.exchange,
				tokens: { ...w.state.exchange.tokens, scope },
			};
			const back = returned(await callback(w, { state: a.state, code: "c" }, "b-1"));
			expect(back.has("error"), JSON.stringify(scope)).toBe(false);
			const grant = await w.grants.find(a.grantId, w.state.now);
			expect(grant?.status, JSON.stringify(scope)).toBe("active");
			expect(grant?.scopes, JSON.stringify(scope)).toStrictEqual(grant?.consent?.scopes);
			expect(grant?.scopes?.length, JSON.stringify(scope)).toBeGreaterThan(0);
		}
	});

	it("reads the upstream's scope by RFC 6749 §3.3's grammar: a tab separates, it does not join", async () => {
		// The upstream's answer is read tolerantly (parseScopeTokens, as every
		// upstream answer is): split on a single space, "openid\toffline_access"
		// read as one scope the user was never shown, and the grant was refused
		// as scope_exceeded.
		const w = world();
		const a = await approved(w, "b-1");
		w.state.exchange = {
			...w.state.exchange,
			tokens: { ...w.state.exchange.tokens, scope: "openid\toffline_access" },
		};
		returned(await callback(w, { state: a.state, code: "c" }, "b-1"));
		expect(await w.grants.find(a.grantId, w.state.now)).toMatchObject({
			status: "active",
			scopes: ["openid", "offline_access"],
		});
	});

	it("re-reads the session just before activating: a revocation that lands during the exchange stops it", async () => {
		// Check 3 passes before the exchange; the subject's sessions are then
		// revoked while the upstream is answering — what a "keep" does. The
		// mandatory re-read is the only thing between that and a new grant.
		const w = world();
		const a = await approved(w, "b-1");
		const real = w.state.exchange;
		w.state.exchangeThrows = undefined;
		const original = w.state.exchange.tokens;
		Object.defineProperty(w.state, "exchange", {
			configurable: true,
			get() {
				w.state.sessionsBoundary = new Date(w.state.now.getTime() + 5_000);
				return { ...real, tokens: original };
			},
		});
		const back = returned(await callback(w, { state: a.state, code: "c" }, "b-1"));
		expect(back.get("error")).toBe("reauthentication_required");
		expect((await w.grants.find(a.grantId, w.state.now))?.status).toBe("pending");
	});

	it("refuses to activate a consent the subject's GRANTS boundary covers", async () => {
		const w = world();
		const a = await approved(w, "b-1");
		w.state.grantsBoundary = new Date(w.state.now.getTime() + 5_000);
		expect(returned(await callback(w, { state: a.state, code: "c" }, "b-1")).get("error")).toBe(
			"grant_not_authorizable",
		);
		expect((await w.grants.find(a.grantId, w.state.now))?.status).toBe("pending");
	});
});

/** An active grant, then a renewal lodged and connected in a second browser: the question it parks. */
async function renewalChallenge(w: World) {
	const first = await approved(w, "b-1");
	returned(await callback(w, { state: first.state, code: "c" }, "b-1"));
	const lodged = await lodgeFederationGrantReauthorization(w.deps, {
		client: CLIENT,
		grantId: first.grantId,
		subject: "alice",
		redirectUri: REDIRECT,
		clientState: "client-state-2",
		correlationId: "corr-2",
	});
	if (!lodged.ok) throw new Error(`fixture: ${lodged.reason}`);
	w.signIn("b-2");
	return {
		grantId: first.grantId,
		handle: lodged.handle,
		challenge: await w.challengeFor(lodged.handle, "b-2"),
	};
}

/** The same renewal, approved: the state its browser comes back from the upstream in. */
async function renewal(w: World) {
	const { grantId, challenge } = await renewalChallenge(w);
	const answered = await w.answer({ challenge, decision: "accept" }, "b-2");
	const state = new URL(answered.headers.location as string).searchParams.get("state") ?? "";
	const before = await w.grants.find(grantId, w.state.now);
	return { grantId, state, before };
}

describe("the callback for a renewal", () => {
	it("replaces the authorization in place and audits it as a reauthorization", async () => {
		const w = world();
		const { grantId, state, before } = await renewal(w);
		const back = returned(await callback(w, { state, code: "c2" }, "b-2"));
		expect(back.get("grant_id")).toBe(grantId);
		expect(back.get("state")).toBe("client-state-2");
		const after = await w.grants.find(grantId, w.state.now);
		expect(after?.status).toBe("active");
		expect((after as { consent: { sid: string } }).consent.sid).toBe("sid-b-2");
		expect((after as { version: number }).version).toBeGreaterThan(
			(before as { version: number }).version,
		);
		await w.background.drain();
		expect(w.events.some((e) => e.type === "federation.grant.reauthorized")).toBe(true);
	});

	/** A renewal approved, on a grant left both starved of scope and asked for by the upstream. */
	const renewalOfAStarvedGrant = async (w: World) => {
		const { grantId, state } = await renewal(w);
		const grant = await w.grants.find(grantId, w.state.now);
		const marked = await w.grants.replaceCredentials({
			grantId,
			expectedVersion: grant?.version ?? -1,
			credentials: { refreshToken: "rt-starved", accessToken: undefined },
			ineligible: {
				reason: "scope_exceeded",
				at: w.state.now,
				judgedAgainst: CONNECTION.maxAccessTokenLifetime,
			},
			now: w.state.now,
		});
		if (!marked.ok) throw new Error("fixture: the marker was not left");
		const noted = await w.grants.noteRefreshFailure({
			grantId,
			expectedVersion: marked.grant.version,
			failure: { at: w.state.now, kind: "rejected", upstreamCode: "consent_required" },
			rowMs: 300_000,
			now: w.state.now,
		});
		if (!noted.ok) throw new Error("fixture: the stamp was not written");
		const before = await w.grants.find(grantId, w.state.now);
		expect(before).toMatchObject({
			ineligible: { reason: "scope_exceeded" },
			refreshFailure: { upstreamCode: "consent_required" },
		});
		return { grantId, state, before };
	};

	it("clears the stamp of the user's absence and the ineligibility marker together when the renewal activates", async () => {
		const w = world();
		const { grantId, state } = await renewalOfAStarvedGrant(w);
		returned(await callback(w, { state, code: "c2" }, "b-2"));
		const after = await w.grants.find(grantId, w.state.now);
		expect(after?.status).toBe("active");
		// Cleared: named, and `undefined`.
		expect(after).toHaveProperty("ineligible", undefined);
		expect(after).toHaveProperty("refreshFailure", undefined);
	});

	it("leaves both exactly as they were when the renewal is refused for another upstream account", async () => {
		const w = world();
		const { grantId, state, before } = await renewalOfAStarvedGrant(w);
		w.state.exchange = {
			...w.state.exchange,
			upstream: { issuer: CONNECTION.upstreamIssuer, subject: "00u-someone-else" },
		};
		expect(returned(await callback(w, { state, code: "c2" }, "b-2")).get("error")).toBe(
			"account_mismatch",
		);
		expect(await w.grants.find(grantId, w.state.now)).toStrictEqual(before);
	});

	it("refuses another upstream account and leaves the grant exactly as it was", async () => {
		const w = world();
		const { grantId, state, before } = await renewal(w);
		w.state.exchange = {
			...w.state.exchange,
			upstream: { issuer: CONNECTION.upstreamIssuer, subject: "00u-someone-else" },
		};
		expect(returned(await callback(w, { state, code: "c2" }, "b-2")).get("error")).toBe(
			"account_mismatch",
		);
		expect(await w.grants.find(grantId, w.state.now)).toStrictEqual(before);
	});

	it("revokes, durably and once, a grant the subject's grants boundary covers — the one failure meant to change it", async () => {
		const w = world();
		const { grantId, state } = await renewal(w);
		// The boundary covers the ORIGINAL consent, which predates the renewal's.
		w.state.grantsBoundary = new Date(w.state.now.getTime());
		expect(returned(await callback(w, { state, code: "c2" }, "b-2")).get("error")).toBe(
			"grant_not_authorizable",
		);
		expect((await w.grants.find(grantId, w.state.now))?.status).toBe("revoked");
		await w.background.drain();
		expect(w.events.filter((e) => e.type === "federation.grant.revoked")).toHaveLength(1);
		// The upstream was never asked: a revoked grant is not worth a code exchange.
		expect(w.state.exchanged).toHaveLength(1);
	});
});

/**
 * Each way the connection can stop being the one an intent was lodged against:
 * gone, another federation entry, another identity revision, another
 * authorization revision, or another callback.
 */
const CONNECTION_CHANGES: readonly (readonly [
	string,
	FederationGrantAcquisitionConnection | undefined,
])[] = [
	["removed", undefined],
	["re-pointed onto another federation", { ...CONNECTION, federation: "upstream-other" }],
	["moved to another upstream client", { ...CONNECTION, upstreamClientId: "provider-client-2" }],
	["widened to another scope", { ...CONNECTION, scopes: [...CONNECTION.scopes, "contacts.read"] }],
	[
		"given another callback",
		{ ...CONNECTION, callbackUri: `${ISSUER}/v2/session/federation-grants/callback/calendar` },
	],
];

const changeConnection = (
	w: World,
	changed: FederationGrantAcquisitionConnection | undefined,
): void => {
	if (changed === undefined) w.state.connections.delete(CONNECTION.name);
	else w.state.connections.set(CONNECTION.name, changed);
};

describe("what the flow re-checks at each step, and the dates it records", () => {
	it.each(CONNECTION_CHANGES)(
		"stops at connect when the connection was %s since the intent was lodged",
		async (_, changed) => {
			const w = world();
			const { handle, grantId } = await w.lodge();
			w.signIn("b-1");
			changeConnection(w, changed);
			const response = await w.connect(handle, "b-1");
			expect(response.status).toBe(400);
			isPlain(response);
			expect(response.text).toBe(
				"The connection has changed since this request was made. Start again.",
			);
			await w.background.drain();
			expect(
				w.events.find((e) => e.type === "federation.grant.authorization_failed"),
			).toMatchObject({ details: { grantId, outcome: "connection_changed" } });
		},
	);

	it.each(CONNECTION_CHANGES)(
		"exchanges no code at the callback when the connection was %s since the flow was approved",
		async (_, changed) => {
			const w = world();
			const a = await approved(w, "b-1");
			changeConnection(w, changed);
			expect(returned(await callback(w, { state: a.state, code: "c" }, "b-1")).get("error")).toBe(
				"grant_not_authorizable",
			);
			expect(w.state.exchanged).toHaveLength(0);
		},
	);

	it("stops at connect when the client may no longer use the connection, or its callback moved", async () => {
		const w = world();
		const { handle } = await w.lodge();
		w.signIn("b-1");
		w.state.client = { ...CLIENT, allowedFederationGrantConnections: [] };
		const refused = await w.connect(handle, "b-1");
		expect(refused.status).toBe(403);
		isPlain(refused);
		w.state.client = { ...CLIENT };
		w.state.connections.set(CONNECTION.name, {
			...CONNECTION,
			callbackUri: `${ISSUER}/v2/session/federation-grants/callback/calendar`,
		});
		expect((await w.connect(handle, "b-1")).status).toBe(400);
	});

	it("will not show or take an answer through a new login in the same browser", async () => {
		// express-session may keep its record across a logout and a login; the
		// durable session is new. A consent parked under the old one is not the
		// new login's to answer.
		const w = world();
		const { handle } = await w.lodge();
		w.signIn("b-1");
		const challenge = await w.challengeFor(handle, "b-1");
		w.browsers.set("b-1", { isAuthenticated: true, user: { id: "alice" }, sid: "sid-relogin" });
		w.durable.set("sid-relogin", {
			sid: "sid-relogin",
			sub: "alice",
			authTime: w.state.now,
			createdAt: w.state.now,
			expiresAt: new Date(w.state.now.getTime() + DAY),
			claims: {},
			// A password login's record (the MFA ADR's D9).
			...passwordSessionAuthentication(),
		});
		expect((await w.page(challenge, "b-1")).status).toBe(400);
		expect((await w.answer({ challenge, decision: "accept" }, "b-1")).status).toBe(400);
	});

	it("does not exchange a code for a flow the grant no longer names, or whose connection changed", async () => {
		const w = world();
		const a = await approved(w, "b-1");
		await w.grants.revoke(a.grantId, "operator", w.state.now);
		expect(returned(await callback(w, { state: a.state, code: "c" }, "b-1")).get("error")).toBe(
			"grant_not_authorizable",
		);
		const b = await approved(w, "b-2");
		w.state.connections.set(CONNECTION.name, {
			...CONNECTION,
			scopes: [...CONNECTION.scopes, "contacts.read"],
		});
		expect(returned(await callback(w, { state: b.state, code: "c" }, "b-2")).get("error")).toBe(
			"grant_not_authorizable",
		);
		// Neither reached the upstream: a code exchanged for a grant that cannot
		// be activated leaves a refresh token there that nothing will ever use.
		expect(w.state.exchanged).toHaveLength(0);
	});

	it("holds the upstream account to what the client said it expected", async () => {
		const w = world();
		const lodged = await lodgeFederationGrantIntent(w.deps, {
			client: CLIENT,
			connection: CONNECTION.name,
			subject: "alice",
			redirectUri: REDIRECT,
			clientState: "client-state-1",
			upstreamSubject: "00u-expected",
			correlationId: "corr-1",
		});
		if (!lodged.ok) throw new Error("fixture");
		w.signIn("b-1");
		const challenge = await w.challengeFor(lodged.handle, "b-1");
		const answered = await w.answer({ challenge, decision: "accept" }, "b-1");
		const state = new URL(answered.headers.location as string).searchParams.get("state") ?? "";
		expect(returned(await callback(w, { state, code: "c" }, "b-1")).get("error")).toBe(
			"account_mismatch",
		);
	});

	it("dates the grant from the consent, not from the callback, and the token no later than it arrived", async () => {
		const w = world();
		const a = await approved(w, "b-1");
		const consentedAt = w.state.now;
		// The user spent a minute at the upstream, whose answer names an expiry
		// far in the future.
		w.state.now = new Date(consentedAt.getTime() + 60_000);
		w.state.exchange = {
			...w.state.exchange,
			tokens: { ...w.state.exchange.tokens, expiresAt: new Date(w.state.now.getTime() + 10 * DAY) },
		};
		returned(await callback(w, { state: a.state, code: "c" }, "b-1"));
		const opened = await w.grants.open(a.grantId, w.state.now);
		const grant = opened?.grant as { consent: { at: Date }; expiresAt: Date };
		expect(grant.consent.at).toEqual(consentedAt);
		expect(grant.expiresAt).toEqual(new Date(consentedAt.getTime() + 30 * DAY));
		const credentials = opened?.credentials as { value: { accessToken: { obtainedAt: Date } } };
		expect(credentials.value.accessToken.obtainedAt.getTime()).toBeLessThanOrEqual(
			w.state.now.getTime(),
		);
	});
});

describe("the browser: what the login trip carries back, and a session that is not the flow's", () => {
	it("sends the browser back from the login page with the handle and nothing else it came with", async () => {
		const w = world();
		const { handle } = await w.lodge();
		const response = await request(w.app)
			.get(`${FEDERATION_GRANTS_BROWSER_MOUNT_PATH}/connect`)
			.query({ request: handle, next: "https://evil.test/", prompt: "none" });
		const back = new URL(
			new URL(response.headers.location as string, ISSUER).searchParams.get("redirect_to") ?? "",
		);
		expect([...back.searchParams.keys()]).toEqual(["request"]);
	});

	it("refuses a browser whose durable session belongs to someone else", async () => {
		// An inconsistent session — the cookie's user is alice, the durable record
		// it points at is bob's — is not a session this flow can trust either way.
		const w = world();
		const { handle, grantId } = await w.lodge();
		w.browsers.set("b-1", { isAuthenticated: true, user: { id: "alice" }, sid: "sid-bob" });
		w.durable.set("sid-bob", {
			sid: "sid-bob",
			sub: "bob",
			authTime: w.state.now,
			createdAt: w.state.now,
			expiresAt: new Date(w.state.now.getTime() + DAY),
			claims: {},
			// A password login's record (the MFA ADR's D9).
			...passwordSessionAuthentication(),
		});
		const response = await w.connect(handle, "b-1");
		expect(response.status).toBe(403);
		expect(response.text).toBe("Sign in again to continue.");
		// Admission's reading of it (the session-admission ADR's D10): one warn
		// naming the action — the flow's grant and the request's id bound to it,
		// no subject or sid — and the audit event naming both subjects.
		expect(written(await settledLines(w))).toEqual(["warn session_admission_subject_mismatch"]);
		expect(payloadOf(w.lines, "session_admission_subject_mismatch")).toEqual({
			grantId,
			correlationId: response.headers["x-request-id"],
			action: "federation_grants.connect",
		});
		expect(w.events.find((e) => e.type === "session.admission.subject_mismatch")).toMatchObject({
			subject: "bob",
			details: { sid: "sid-bob", carrier: "cookie", claimedSubject: "alice", recordSubject: "bob" },
		});
	});

	it("will not show a question to another express session carrying the same durable session", async () => {
		// Both halves of the binding count: the durable session alone is not the
		// browser the challenge was issued to.
		const w = world();
		const { handle } = await w.lodge();
		w.signIn("b-1");
		const challenge = await w.challengeFor(handle, "b-1");
		w.browsers.set("b-copy", { isAuthenticated: true, user: { id: "alice" }, sid: "sid-b-1" });
		expect((await w.page(challenge, "b-copy")).status).toBe(400);
		expect((await w.answer({ challenge, decision: "accept" }, "b-copy")).status).toBe(400);
	});
});

describe("shutting down", () => {
	it("refuses new browser work once the drain has begun, and spends nothing doing so", async () => {
		// A callback admitted into the drain is waited for; one that is not could
		// consume its transaction and then have the grant store closed under it
		// before the credential is written.
		const w = world();
		const a = await approved(w);
		const draining = w.background.drain();
		const refused = await callback(w, { state: a.state, code: "c" }, "b-1");
		expect(refused.status).toBe(503);
		isPlain(refused);
		// The transaction was not consumed: the flow was never started.
		expect(
			await w.intents.consumeTransaction({
				state: a.state,
				connection: CONNECTION.name,
				now: w.state.now,
			}),
		).not.toBeNull();
		const { handle } = await w.lodge();
		expect((await w.connect(handle, "b-1")).status).toBe(503);
		await draining;
	});

	it("refuses to show the question once the drain has begun, as it refuses the answer", async () => {
		// Reading the question touches the durable session, the intent store and
		// the client registry — each of which the drain is about to close.
		const w = world();
		const { handle } = await w.lodge();
		w.signIn("b-1");
		const challenge = await w.challengeFor(handle, "b-1");
		const draining = w.background.drain();
		for (const response of [
			await w.page(challenge, "b-1"),
			await w.answer({ challenge, decision: "accept" }, "b-1"),
		]) {
			expect(response.status).toBe(503);
			expect(response.body).toEqual({
				error: "service_unavailable",
				error_description: "shutting_down",
			});
		}
		// Nothing was answered: the question is still parked.
		expect(await w.intents.getConsent(challenge, w.state.now)).not.toBeNull();
		await draining;
	});
});

describe("across the flow: correlation, redirects, the identity lookup, sessions, outages and a declined consent", () => {
	it("correlates every event of one flow by the id its lodging carried", async () => {
		const w = world();
		const a = await approved(w, "b-1");
		returned(await callback(w, { state: a.state, code: "c" }, "b-1"));
		const b = await approved(w, "b-2");
		// Declined at the upstream: a failure, after the intent is known.
		returned(await callback(w, { state: b.state, error: "access_denied" }, "b-2"));
		await w.background.drain();
		const authorized = w.events.find((e) => e.type === "federation.grant.authorized");
		const failed = w.events.find(
			(e) => e.type === "federation.grant.authorization_failed" && e.details?.grantId === b.grantId,
		);
		expect(authorized?.details?.correlationId).toBe("corr-1");
		expect(failed?.details?.correlationId).toBe("corr-1");
	});

	it("sends the browser to the consent page by an absolute URL on the issuer, never a relative one", async () => {
		const w = world();
		const { handle } = await w.lodge();
		w.signIn("b-1");
		const location = (await w.connect(handle, "b-1")).headers.location as string;
		expect(location.startsWith(`${ISSUER}/consent/grants?`)).toBe(true);
	});

	it("hands the identity lookup the registration the identity was issued under, and the verified subject", async () => {
		// The registration — name, issuer, client — is what a Store needs to
		// place a pairwise `sub`. All three are the connection's
		// configuration; nothing the upstream said stands in for them.
		const w = world();
		const a = await approved(w, "b-1");
		returned(await callback(w, { state: a.state, code: "c" }, "b-1"));
		expect(w.state.lookups).toEqual([
			{
				provider: "upstream",
				issuer: CONNECTION.upstreamIssuer,
				clientId: "provider-client",
				sub: "00u-alice",
				claims: {},
			},
		]);
	});

	it("does not finish a flow whose connection was re-pointed onto another federation since it was lodged", async () => {
		// The revisions pin the issuer and the client, not the federation's
		// name, so a connection could move onto another entry for the same
		// registration mid-flow. Boot probed the Store's coverage under the NEW
		// name; the flow would have asked it about the old one. The name is
		// pinned with the rest: nothing is exchanged and nothing is asked.
		const w = world();
		const a = await approved(w, "b-1");
		w.state.connections.set(CONNECTION.name, { ...CONNECTION, federation: "upstream-renamed" });
		expect(returned(await callback(w, { state: a.state, code: "c" }, "b-1")).get("error")).toBe(
			"grant_not_authorizable",
		);
		expect(w.state.exchanged).toHaveLength(0);
		expect(w.state.lookups).toHaveLength(0);

		// And the consent refuses to show a question about the old one.
		const { handle } = await w.lodge();
		w.signIn("b-2");
		const challenge = await w.challengeFor(handle, "b-2");
		w.state.connections.set(CONNECTION.name, { ...CONNECTION, federation: "upstream-other" });
		const shown = await w.page(challenge, "b-2");
		expect(shown.status).toBe(400);
		expect(shown.body.error_description ?? shown.body.error).toBeDefined();
	});

	it("does not exchange a code for a flow whose callback moved since it was approved", async () => {
		const w = world();
		const a = await approved(w, "b-1");
		w.state.connections.set(CONNECTION.name, {
			...CONNECTION,
			callbackUri: `${ISSUER}/v2/session/federation-grants/callback/calendar`,
		});
		expect(returned(await callback(w, { state: a.state, code: "c" }, "b-1")).get("error")).toBe(
			"grant_not_authorizable",
		);
		expect(w.state.exchanged).toHaveLength(0);
	});

	it("holds the callback to both halves of the browser's session, and to a live one", async () => {
		const w = world();
		// Another express session carrying the same durable session.
		const a = await approved(w, "b-1");
		w.browsers.set("b-copy", { isAuthenticated: true, user: { id: "alice" }, sid: "sid-b-1" });
		expect(returned(await callback(w, { state: a.state, code: "c" }, "b-copy")).get("error")).toBe(
			"reauthentication_required",
		);
		// Signed out since.
		const b = await approved(w, "b-2");
		w.browsers.set("b-2", { isAuthenticated: false, user: { id: "alice" }, sid: "sid-b-2" });
		expect(returned(await callback(w, { state: b.state, code: "c" }, "b-2")).get("error")).toBe(
			"reauthentication_required",
		);
		// A durable session that has expired.
		const c = await approved(w, "b-3");
		const durable = w.durable.get("sid-b-3") as UserSession;
		w.durable.set("sid-b-3", { ...durable, expiresAt: new Date(w.state.now.getTime() - 1) });
		expect(returned(await callback(w, { state: c.state, code: "c" }, "b-3")).get("error")).toBe(
			"reauthentication_required",
		);
	});

	it("asks a browser whose durable session expired to sign in again at connect", async () => {
		const w = world();
		const { handle } = await w.lodge();
		const sid = w.signIn("b-1");
		const durable = w.durable.get(sid) as UserSession;
		w.durable.set(sid, { ...durable, expiresAt: new Date(w.state.now.getTime() - 1) });
		const response = await w.connect(handle, "b-1");
		expect(response.status).toBe(403);
		expect(response.text).toMatch(/sign in again/i);
	});

	it("reads a connection that could not be made as an outage, not the upstream's fault", async () => {
		const w = world();
		const a = await approved(w, "b-1");
		// As undici raises it: `fetch`'s TypeError, the socket's coded error as its
		// cause. Read by the code, never by the text.
		w.state.exchangeThrows = new TypeError("fetch failed", {
			cause: Object.assign(new Error("connect ECONNREFUSED 192.0.2.1:443"), {
				code: "ECONNREFUSED",
			}),
		});
		expect(returned(await callback(w, { state: a.state, code: "c" }, "b-1")).get("error")).toBe(
			"temporarily_unavailable",
		);
	});

	it("audits a declined consent, and parks nothing for a prerender", async () => {
		const w = world();
		const { handle, grantId } = await w.lodge();
		w.signIn("b-1");
		expect((await w.connect(handle, "b-1").set("Sec-Purpose", "prefetch;prerender")).status).toBe(
			204,
		);
		const challenge = await w.challengeFor(handle, "b-1");
		await w.answer({ challenge, decision: "deny" }, "b-1");
		await w.background.drain();
		expect(
			w.events.find(
				(e) => e.type === "federation.grant.authorization_failed" && e.details?.grantId === grantId,
			)?.details,
		).toMatchObject({ outcome: "access_denied" });
	});
});

// ---------------------------------------------------------------------------
// The outage branches, each of which promises to fail closed, and the races a
// real store can lose: every one a promise, each held to it here.
// ---------------------------------------------------------------------------

const noPending = {
	error: "invalid_request",
	error_description: expect.stringContaining("no pending consent"),
};

describe("connect, when the world fails or moves", () => {
	it("fails closed when the intent store cannot read the flow or park the question, and parks nothing", async () => {
		const w = world();
		const { handle } = await w.lodge();
		w.signIn("b-1");
		w.state.faults.set("getIntent", 0);
		const unread = await w.connect(handle, "b-1");
		expect(unread.status).toBe(503);
		isPlain(unread);

		w.state.faults.clear();
		w.state.faults.set("parkConsent", 0);
		w.state.ids.push("challenge-1");
		const unparked = await w.connect(handle, "b-1");
		expect(unparked.status).toBe(503);
		isPlain(unparked);
		expect(await w.intents.getConsent("challenge-1", w.state.now)).toBeNull();
	});

	it("parks nothing for a flow that finished while this browser was being judged", async () => {
		const w = world();
		const { handle } = await w.lodge();
		w.signIn("b-1");
		w.state.before.set("userSessionStore.get", () => w.intents.finishIntent(handle, w.state.now));
		const response = await w.connect(handle, "b-1");
		expect(response.status).toBe(400);
		isPlain(response);
		expect(response.text).toMatch(/expired or has already been used/);
	});

	it("audits a connect whose question cannot be parked for this browser as a stale link, with the flow's grant", async () => {
		// The question already parked for another browser of the same user, and a
		// flow that finished while this browser was being judged.
		const arrangements: readonly ((w: World, handle: string) => Promise<void>)[] = [
			async (w, handle) => {
				w.signIn("b-2");
				await w.challengeFor(handle, "b-2");
			},
			async (w, handle) => {
				w.state.before.set("userSessionStore.get", () =>
					w.intents.finishIntent(handle, w.state.now),
				);
			},
		];
		for (const arrange of arrangements) {
			const w = world();
			const { handle, grantId } = await w.lodge();
			w.signIn("b-1");
			await arrange(w, handle);
			const response = await w.connect(handle, "b-1");
			expect(response.status).toBe(400);
			isPlain(response);
			expect(response.text).toBe("This link has expired or has already been used. Start again.");
			await w.background.drain();
			expect(
				w.events
					.filter((e) => e.type === "federation.grant.authorization_failed")
					.map((e) => e.details),
			).toEqual([expect.objectContaining({ grantId, outcome: "stale", correlationId: "corr-1" })]);
		}
	});

	it("asks a browser with no durable session behind its cookie to sign in again", async () => {
		const w = world();
		const { handle } = await w.lodge();
		w.browsers.set("b-bare", { isAuthenticated: true, user: { id: "alice" } });
		const response = await w.connect(handle, "b-bare");
		expect(response.status).toBe(403);
		expect(response.text).toMatch(/sign in again/i);
	});

	it("reads a sessions boundary that is neither a date nor null as an outage", async () => {
		const w = world();
		const { handle } = await w.lodge();
		w.signIn("b-1");
		w.state.sessionsBoundary = "yesterday" as never;
		expect((await w.connect(handle, "b-1")).status).toBe(503);
	});

	it("refuses a client whose registration no longer lists any connection", async () => {
		const w = world();
		const { handle } = await w.lodge();
		w.signIn("b-1");
		w.state.client = {
			clientId: CLIENT.clientId,
			tokenEndpointAuthMethod: CLIENT.tokenEndpointAuthMethod,
		} as never;
		const response = await w.connect(handle, "b-1");
		expect(response.status).toBe(403);
		expect(response.text).toMatch(/may no longer use this connection/);
	});

	it("answers a failure nothing expected with a plain 500", async () => {
		const w = world();
		const { handle } = await w.lodge();
		w.signIn("b-1");
		w.state.configurationThrows = true;
		const response = await w.connect(handle, "b-1");
		expect(response.status).toBe(500);
		isPlain(response);
	});
});

describe("the browser throttle, when the limiter is down", () => {
	it("refuses every route in its own representation when the limiter's policy fails closed", async () => {
		const w = world({ rateLimiter: { ...brokenLimiter, failMode: "closed" } });
		const connect = await w.connect("any");
		expect(connect.status).toBe(503);
		isPlain(connect);
		const page = await w.page("any");
		expect(page.status).toBe(503);
		expect(page.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "rate_limiter",
		});
		const back = await callback(w, { state: "any", code: "c" });
		expect(back.status).toBe(503);
		isPlain(back);
	});

	it("lets the request through when the limiter's policy fails open", async () => {
		const w = world({ rateLimiter: { ...brokenLimiter, failMode: "open" } });
		// Past the throttle, to the handler's own refusal of a link without a handle.
		const response = await request(w.app).get(`${FEDERATION_GRANTS_BROWSER_MOUNT_PATH}/connect`);
		expect(response.status).toBe(400);
		isPlain(response);
	});

	it("answers the consent page's budget as /oauth/consent does", async () => {
		const w = world({ rateLimiter: refusingLimiter });
		const response = await w.page("any");
		expect(response.status).toBe(429);
		expect(response.body).toEqual({ error: "rate_limited", error_description: "provider" });
	});
});

describe("the consent, when the world fails or moves", () => {
	/** A question parked for alice's browser `b-1`. */
	async function parked(w: World) {
		const lodged = await w.lodge();
		w.signIn("b-1");
		return { ...lodged, challenge: await w.challengeFor(lodged.handle, "b-1") };
	}

	it("fails closed when the question cannot be read", async () => {
		const w = world();
		const { challenge } = await parked(w);
		w.state.faults.set("getConsent", 0);
		const response = await w.page(challenge, "b-1");
		expect(response.status).toBe(503);
		expect(response.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "storage",
		});
	});

	it("stops a parked question the world has moved past, each with its own answer", async () => {
		const w = world();
		const { challenge, grantId } = await parked(w);

		w.state.sessionsBoundary = new Error("down");
		const unreadable = await w.page(challenge, "b-1");
		expect(unreadable.status).toBe(503);
		// Described by what could not answer, as every consumer of admission
		// describes it (core's describeAdmissionOutage).
		expect(unreadable.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "revocation store unavailable",
		});
		w.state.sessionsBoundary = null;

		w.state.client = { ...CLIENT, allowedFederationGrantConnections: [] };
		const withdrawn = await w.page(challenge, "b-1");
		expect(withdrawn.status).toBe(403);
		expect(withdrawn.body).toEqual({
			error: "access_denied",
			error_description: "connection_not_permitted",
		});
		// A deployment's own repository that answers a string instead of a list
		// would turn the check into a substring match; the boundary refuses the
		// record, and a client that cannot be read is not a yes.
		w.state.client = {
			...CLIENT,
			allowedFederationGrantConnections: "calendar-prod" as unknown as string[],
		};
		const misread = await w.page(challenge, "b-1");
		expect(misread.status).toBe(503);
		expect(misread.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "client registry unavailable",
		});
		w.state.client = { ...CLIENT };

		// The grant ended between the park and the read: nothing left to answer.
		await w.grants.revoke(grantId, "operator", w.state.now);
		const stale = await w.page(challenge, "b-1");
		expect(stale.status).toBe(400);
		expect(stale.body).toEqual(noPending);
	});

	it("fails closed when the client registry cannot describe the client", async () => {
		const w = world();
		const { challenge } = await parked(w);
		// The judgement's own read succeeds; the description's fails.
		w.state.faults.set("findById", 1);
		const response = await w.page(challenge, "b-1");
		expect(response.status).toBe(503);
		expect(response.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "client registry unavailable",
		});
	});

	it("answers a failure nothing expected with a JSON 500, on both methods", async () => {
		const w = world();
		const { challenge } = await parked(w);
		w.state.configurationThrows = true;
		for (const response of [
			await w.page(challenge, "b-1"),
			await w.answer({ challenge, decision: "accept" }, "b-1"),
		]) {
			expect(response.status).toBe(500);
			expect(response.body).toEqual({
				error: "server_error",
				error_description: "unexpected_error",
			});
		}
	});

	it("tells the page that an answer another tab sent first leaves nothing to answer", async () => {
		const w = world();
		const binding = { sessionId: "b-1", sid: "sid-b-1", subject: "alice" };
		const first = await parked(w);
		// Approved in another tab while this one was refusing.
		w.state.before.set("answerConsent", () =>
			w.intents.answerConsent({
				challenge: first.challenge,
				binding,
				answer: { decision: "accept", state: "s-other", codeVerifier: "v", nonce: "n" },
				now: w.state.now,
			}),
		);
		const refused = await w.answer({ challenge: first.challenge, decision: "deny" }, "b-1");
		expect(refused.status).toBe(400);
		expect(refused.body).toEqual(noPending);

		// Refused in another tab while this one was approving.
		const second = await parked(w);
		w.state.before.set("answerConsent", () =>
			w.intents.answerConsent({
				challenge: second.challenge,
				binding,
				answer: { decision: "deny" },
				now: w.state.now,
			}),
		);
		const approved = await w.answer({ challenge: second.challenge, decision: "accept" }, "b-1");
		expect(approved.status).toBe(400);
		expect(approved.body).toEqual(noPending);
	});

	it("does not spend the user's answer on an upstream state another flow already holds", async () => {
		const w = world();
		const first = await parked(w);
		w.state.ids.push("same-state", "nonce-1", "verifier-1");
		expect((await w.answer({ challenge: first.challenge, decision: "accept" }, "b-1")).status).toBe(
			303,
		);
		const second = await parked(w);
		w.state.ids.push("same-state", "nonce-2", "verifier-2");
		const collided = await w.answer({ challenge: second.challenge, decision: "accept" }, "b-1");
		expect(collided.status).toBe(503);
		expect(collided.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "storage",
		});
		// Still parked: the user can answer again.
		expect((await w.page(second.challenge, "b-1")).status).toBe(200);
	});

	it("returns a declined renewal to the client even when its pointer cannot be retired", async () => {
		const w = world();
		const { challenge } = await renewalChallenge(w);
		w.state.faults.set("retireIntent", 0);
		const response = await w.answer({ challenge, decision: "deny" }, "b-2");
		expect(response.status).toBe(303);
		const back = new URL(response.headers.location as string);
		expect(back.searchParams.get("error")).toBe("access_denied");
		expect(back.searchParams.get("state")).toBe("client-state-2");
	});

	it("keeps the answer when the federation's capability has gone", async () => {
		const w = world();
		const { challenge } = await parked(w);
		w.state.authorizerMissing = true;
		const response = await w.answer({ challenge, decision: "accept" }, "b-1");
		expect(response.status).toBe(503);
		expect(response.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "upstream_unavailable",
		});
		w.state.authorizerMissing = false;
		expect((await w.page(challenge, "b-1")).status).toBe(200);
	});

	it("answers a callback path Express cannot decode as JSON 400 malformed_path", async () => {
		// Decoding fails before the callback's own checks run, so the answer is
		// the routers' last handler's — JSON, not the callback's plain pages.
		const w = world();
		const response = await request(w.app).get(
			`${FEDERATION_GRANTS_BROWSER_MOUNT_PATH}/callback/%zz`,
		);
		expect(response.status).toBe(400);
		expect(response.headers["content-type"]).toMatch(/^application\/json/);
		expect(response.body).toEqual({
			error: "invalid_request",
			error_description: "malformed_path",
		});
	});

	it("answers a body it cannot parse, and one too large, as the JSON routes do", async () => {
		const w = world();
		const path = `${FEDERATION_GRANTS_BROWSER_MOUNT_PATH}/consent`;
		const malformed = await request(w.app)
			.post(path)
			.set("Content-Type", "application/json")
			.send("{");
		expect(malformed.status).toBe(400);
		expect(malformed.body).toEqual({
			error: "invalid_request",
			error_description: "malformed_body",
		});
		const large = await request(w.app)
			.post(path)
			.send({ challenge: "x".repeat(16 * 1024), decision: "accept" });
		expect(large.status).toBe(413);
		expect(large.body).toEqual({ error: "invalid_request", error_description: "body_too_large" });
	});

	it.each([
		// [label, headers, body, status, description]
		[
			"a charset the parser cannot decode",
			{ "Content-Type": "application/json; charset=latin1" },
			'{"decision":"accept"}',
			415,
			"unsupported_encoding",
		],
		[
			"a compressed body that does not decompress",
			{ "Content-Type": "application/json", "Content-Encoding": "gzip" },
			"not gzip at all",
			400,
			"malformed_body",
		],
		[
			"more form parameters than the parser takes",
			{ "Content-Type": "application/x-www-form-urlencoded" },
			Array.from({ length: 1001 }, (_, i) => `p${i}=1`).join("&"),
			413,
			"body_too_large",
		],
	] as const)(
		"answers %s as the caller's mistake, not a 500",
		async (_label, headers, body, status, description) => {
			const w = world();
			const response = await request(w.app)
				.post(`${FEDERATION_GRANTS_BROWSER_MOUNT_PATH}/consent`)
				.set(headers)
				.send(body);
			expect(response.status).toBe(status);
			expect(response.body).toEqual({ error: "invalid_request", error_description: description });
		},
	);
});

describe("the callback, when the world fails or moves", () => {
	it("fails closed when the transaction cannot be read, and sends the browser nowhere", async () => {
		const w = world();
		const a = await approved(w);
		w.state.faults.set("consumeTransaction", 0);
		const response = await callback(w, { state: a.state, code: "c" }, "b-1");
		expect(response.status).toBe(503);
		isPlain(response);
		expect(response.headers.location).toBeUndefined();
	});

	it("activates the grant and returns the browser even when the flow cannot be closed", async () => {
		const w = world();
		const a = await approved(w);
		w.state.faults.set("finishIntent", 0);
		expect(returned(await callback(w, { state: a.state, code: "c" }, "b-1")).has("error")).toBe(
			false,
		);
		expect((await w.grants.find(a.grantId, w.state.now))?.status).toBe("active");
	});

	it("fails closed on a grants boundary it cannot read before the exchange, or that is not a date", async () => {
		const w = world();
		const a = await approved(w, "b-1");
		w.state.grantsBoundary = new Error("down");
		expect(returned(await callback(w, { state: a.state, code: "c" }, "b-1")).get("error")).toBe(
			"temporarily_unavailable",
		);
		const b = await approved(w, "b-2");
		w.state.grantsBoundary = "yesterday" as never;
		expect(returned(await callback(w, { state: b.state, code: "c" }, "b-2")).get("error")).toBe(
			"temporarily_unavailable",
		);
		expect(w.state.exchanged).toHaveLength(0);
	});

	it("reads a return carrying neither a code nor an error as the upstream's fault", async () => {
		const w = world();
		const a = await approved(w);
		expect(returned(await callback(w, { state: a.state }, "b-1")).get("error")).toBe(
			"upstream_error",
		);
		expect(w.state.exchanged).toHaveLength(0);
	});

	it("fails closed when the session cannot be read", async () => {
		const w = world();
		const a = await approved(w);
		w.state.faults.set("userSessionStore.get", 0);
		expect(returned(await callback(w, { state: a.state, code: "c" }, "b-1")).get("error")).toBe(
			"temporarily_unavailable",
		);
	});

	it("fails closed on the re-read and on the activation, and names a lost guard as such", async () => {
		const w = world();
		// Check 2's read succeeds; the re-read after the exchange does not.
		const a = await approved(w, "b-1");
		w.state.faults.set("isCurrentIntent", 1);
		expect(returned(await callback(w, { state: a.state, code: "c" }, "b-1")).get("error")).toBe(
			"temporarily_unavailable",
		);
		w.state.faults.clear();

		const b = await approved(w, "b-2");
		w.state.faults.set("activate", 0);
		expect(returned(await callback(w, { state: b.state, code: "c" }, "b-2")).get("error")).toBe(
			"temporarily_unavailable",
		);
		w.state.faults.clear();

		// Revoked after the re-read, before the write: the store's guard is what
		// stops it, and the answer says no more than the store did.
		const c = await approved(w, "b-3");
		w.state.before.set("activate", () => w.grants.revoke(c.grantId, "operator", w.state.now));
		expect(returned(await callback(w, { state: c.state, code: "c" }, "b-3")).get("error")).toBe(
			"grant_not_authorizable",
		);
		for (const { grantId } of [a, b, c]) {
			expect((await w.grants.find(grantId, w.state.now))?.status).not.toBe("active");
		}
	});

	it("returns the browser with an outage when something nothing expected fails after check 1", async () => {
		const w = world();
		const a = await approved(w);
		w.state.configurationThrows = true;
		expect(returned(await callback(w, { state: a.state, code: "c" }, "b-1")).get("error")).toBe(
			"temporarily_unavailable",
		);
	});

	it("fails closed when a renewal's grant cannot be read, at the backstop or at the account check", async () => {
		const atBackstop = world();
		const first = await renewal(atBackstop);
		atBackstop.state.faults.set("find", 0);
		expect(
			returned(await callback(atBackstop, { state: first.state, code: "c2" }, "b-2")).get("error"),
		).toBe("temporarily_unavailable");
		expect(atBackstop.state.exchanged).toHaveLength(1);

		const atAccount = world();
		const second = await renewal(atAccount);
		atAccount.state.faults.set("find", 1);
		expect(
			returned(await callback(atAccount, { state: second.state, code: "c2" }, "b-2")).get("error"),
		).toBe("temporarily_unavailable");
		expect(await atAccount.grants.find(second.grantId, atAccount.state.now)).toStrictEqual(
			second.before,
		);
	});
});

describe("the identity lookup, when it cannot answer", () => {
	it("fails closed when the lookup is required and throws, or has gone from the repository", async () => {
		const throwing = world();
		const a = await approved(throwing);
		throwing.state.faults.set("findSubjectByFederatedIdentity", 0);
		expect(
			returned(await callback(throwing, { state: a.state, code: "c" }, "b-1")).get("error"),
		).toBe("temporarily_unavailable");

		const missing = world({ userRepository: {} });
		const b = await approved(missing);
		expect(
			returned(await callback(missing, { state: b.state, code: "c" }, "b-1")).get("error"),
		).toBe("temporarily_unavailable");
		expect(payloadOf(missing.lines, "federation_grant_callback_unavailable")).toMatchObject({
			store: "user_directory",
			step: "find_subject_by_federated_identity",
		});
	});

	it("asks nothing when the deployment recorded it cannot, and says so in the audit", async () => {
		const w = world({ identityLookup: "unsupported", userRepository: {} });
		const a = await approved(w);
		expect(returned(await callback(w, { state: a.state, code: "c" }, "b-1")).has("error")).toBe(
			false,
		);
		await w.background.drain();
		expect(w.events.find((e) => e.type === "federation.grant.authorized")?.details).toMatchObject({
			outcome: "unsupported",
		});
	});
});

describe('identityLookup = "unsupported" skips the lookup and nothing else', () => {
	// The opt-out is a recorded decision about ONE test. The issuer and the
	// renewal's account binding are not the Store's to answer, and an early
	// return placed above them would let a renewal swap the upstream account
	// on an existing grant.
	it("still refuses another issuer's identity", async () => {
		const w = world({ identityLookup: "unsupported", userRepository: {} });
		const a = await approved(w);
		w.state.exchange = {
			...w.state.exchange,
			upstream: { issuer: "https://attacker.test", subject: "00u-alice" },
		};
		expect(returned(await callback(w, { state: a.state, code: "c" }, "b-1")).get("error")).toBe(
			"upstream_error",
		);
	});

	it("still holds a renewal to the upstream account already on the grant", async () => {
		const w = world({ identityLookup: "unsupported", userRepository: {} });
		const { grantId, state, before } = await renewal(w);
		w.state.exchange = {
			...w.state.exchange,
			upstream: { issuer: CONNECTION.upstreamIssuer, subject: "00u-someone-else" },
		};
		expect(returned(await callback(w, { state, code: "c2" }, "b-2")).get("error")).toBe(
			"account_mismatch",
		);
		expect(await w.grants.find(grantId, w.state.now)).toStrictEqual(before);
	});
});

/**
 * A Store with its own directory, keyed by what does not change across
 * registrations: Entra's tenant and object id, provisioned from the IdP. The
 * only kind of Store that can cover a registration whose `sub` is pairwise —
 * a login told it `<provider>:<sub>`, and that is a different `sub`.
 */
class TenantDirectory {
	readonly asked: FederatedIdentityLookup[] = [];
	constructor(private readonly people: ReadonlyMap<string, string>) {}

	supportsFederatedIdentityLookup(_registration: unknown, identityClaims: readonly string[]) {
		return identityClaims.includes("tid") && identityClaims.includes("oid");
	}

	async findSubjectByFederatedIdentity(
		identity: FederatedIdentityLookup,
	): Promise<FederatedIdentityLookupResult> {
		this.asked.push({ ...identity, claims: { ...identity.claims } });
		const owner = this.people.get(`${identity.claims.tid}|${identity.claims.oid}`);
		return owner === undefined ? { kind: "unlinked" } : { kind: "linked", subject: owner };
	}
}

describe("verified identity claims let a Store place a pairwise sub", () => {
	const ENTRA = { ...CONNECTION, identityClaims: ["oid", "tid"] };
	const entraWorld = (people: ReadonlyMap<string, string>) => {
		const directory = new TenantDirectory(people);
		const w = world({ userRepository: directory });
		w.state.connections.set(CONNECTION.name, ENTRA);
		return { w, directory };
	};
	const asUpstream = (w: World, subject: string, claims: unknown) => {
		w.state.exchange = {
			...w.state.exchange,
			upstream: { issuer: CONNECTION.upstreamIssuer, subject, claims } as never,
		};
	};

	it("refuses Bob's upstream account to Alice, found by tenant and object id although its sub is one no login saw", async () => {
		// Bob signed in through the login registration, whose pairwise sub for
		// him is `login-B`. The grants registration calls him `grant-B`. Only
		// `(tid, oid)` is the same person in both.
		const { w, directory } = entraWorld(
			new Map([
				["T-1|O-BOB", "bob"],
				["T-1|O-ALICE", "alice"],
			]),
		);
		const a = await approved(w);
		asUpstream(w, "grant-B", { oid: "O-BOB", tid: "T-1" });
		expect(returned(await callback(w, { state: a.state, code: "c" }, "b-1")).get("error")).toBe(
			"identity_conflict",
		);
		expect(directory.asked).toEqual([
			{
				provider: "upstream",
				issuer: CONNECTION.upstreamIssuer,
				clientId: "provider-client",
				sub: "grant-B",
				claims: { oid: "O-BOB", tid: "T-1" },
			},
		]);
		// Alice's own account, under the same registration, passes.
		const b = await approved(w, "b-2");
		asUpstream(w, "grant-A", { oid: "O-ALICE", tid: "T-1" });
		expect(returned(await callback(w, { state: b.state, code: "c" }, "b-2")).has("error")).toBe(
			false,
		);
	});

	it("asks the adapter for the connection's claims, and for none when the deployment does not ask the Store", async () => {
		const { w } = entraWorld(new Map());
		const a = await approved(w);
		asUpstream(w, "grant-A", { oid: "O", tid: "T" });
		returned(await callback(w, { state: a.state, code: "c" }, "b-1"));
		expect(w.state.exchanged.at(-1)?.identityClaims).toEqual(["oid", "tid"]);

		// Asked for none, the adapter answers none — and the flow still succeeds:
		// under "unsupported" the connection's claims are not evidence anyone
		// needs, so their absence refuses nothing.
		const off = world({ identityLookup: "unsupported", userRepository: {} });
		off.state.connections.set(CONNECTION.name, ENTRA);
		const b = await approved(off);
		asUpstream(off, "grant-A", {});
		expect(returned(await callback(off, { state: b.state, code: "c" }, "b-1")).has("error")).toBe(
			false,
		);
		expect(off.state.exchanged.at(-1)?.identityClaims).toEqual([]);
	});

	it("hands the Store exactly the connection's claims, never what else the adapter answered", async () => {
		const { w, directory } = entraWorld(new Map());
		const a = await approved(w);
		asUpstream(w, "grant-A", { oid: "O", tid: "T", unrequested: "sentinel-extra" });
		returned(await callback(w, { state: a.state, code: "c" }, "b-1"));
		expect(directory.asked[0]?.claims).toStrictEqual({ oid: "O", tid: "T" });
	});

	it("refuses without asking the Store when any claim the connection needs is missing or not a string", async () => {
		const inherited = Object.assign(Object.create({ tid: "T" }), { oid: "O" });
		const cases: unknown[] = [
			{},
			{ oid: "O" },
			{ oid: "O", tid: 42 },
			{ oid: "O", tid: "" },
			{ oid: "O", tid: ["T"] },
			inherited,
			null,
			undefined,
			"oid=O;tid=T",
		];
		for (const claims of cases) {
			const { w, directory } = entraWorld(new Map());
			const a = await approved(w);
			asUpstream(w, "grant-A", claims);
			const label = JSON.stringify(claims) ?? String(claims);
			expect(
				returned(await callback(w, { state: a.state, code: "c" }, "b-1")).get("error"),
				label,
			).toBe("identity_unverifiable");
			expect(directory.asked, label).toHaveLength(0);
			expect((await w.grants.find(a.grantId, w.state.now))?.status, label).toBe("pending");
			expect(w.intents.reservations("worker", "alice"), label).toBe(0);
			await w.background.drain();
			expect(
				w.events.find((e) => e.type === "federation.grant.authorization_failed")?.details,
				label,
			).toMatchObject({ outcome: "identity_unverifiable/identity_claims_unavailable" });
		}
	});

	it("leaves a grant a renewal without the claims would have replaced exactly as it was", async () => {
		const { w, directory } = entraWorld(new Map());
		asUpstream(w, "00u-alice", { oid: "O", tid: "T" });
		const { grantId, state, before } = await renewal(w);
		asUpstream(w, "00u-alice", { oid: "O" });
		expect(returned(await callback(w, { state, code: "c2" }, "b-2")).get("error")).toBe(
			"identity_unverifiable",
		);
		expect(await w.grants.find(grantId, w.state.now)).toStrictEqual(before);
		expect(directory.asked).toHaveLength(1);
	});

	it("refuses an array answered as the claims, even under a claim name an array has", async () => {
		// `"0"` is a legal claim name, and `typeof [] === "object"`: an adapter
		// answering `["owner-id"]` would otherwise pass for `{ "0": "owner-id" }`.
		const directory = new TenantDirectory(new Map());
		const w = world({ userRepository: directory });
		w.state.connections.set(CONNECTION.name, { ...CONNECTION, identityClaims: ["0"] });
		const a = await approved(w);
		asUpstream(w, "grant-A", ["owner-id"]);
		expect(returned(await callback(w, { state: a.state, code: "c" }, "b-1")).get("error")).toBe(
			"identity_unverifiable",
		);
		expect(directory.asked).toHaveLength(0);
	});

	it("keeps the claims out of the grant, the audit, the logs and the redirect", async () => {
		const { w } = entraWorld(new Map());
		// What the router hands `activate`, not what the memory store keeps: both
		// bundled stores re-project the upstream, and a custom one that stored
		// the authorization whole would keep whatever it was handed.
		const activations: unknown[] = [];
		const activate = w.grants.activate.bind(w.grants);
		(w.grants as { activate: typeof activate }).activate = async (input) => {
			activations.push(input);
			return await activate(input);
		};
		const a = await approved(w);
		asUpstream(w, "grant-A", { oid: "SENTINEL-OID", tid: "SENTINEL-TID" });
		const response = await callback(w, { state: a.state, code: "c" }, "b-1");
		expect(response.headers.location).not.toContain("SENTINEL");
		expect(activations).toHaveLength(1);
		expect(
			(activations[0] as { authorization: { upstream: unknown } }).authorization.upstream,
		).toStrictEqual({ issuer: CONNECTION.upstreamIssuer, subject: "grant-A" });
		const grant = await w.grants.find(a.grantId, w.state.now);
		expect(grant?.status).toBe("active");
		expect(JSON.stringify(grant)).not.toContain("SENTINEL");
		await w.background.drain();
		expect(JSON.stringify(w.events)).not.toContain("SENTINEL");
		expect(JSON.stringify(w.lines)).not.toContain("SENTINEL");
	});
});

describe("an answer that establishes no ownership refuses the delegation", () => {
	for (const reason of ["registration_not_covered", "identity_not_resolvable"] as const) {
		it(`refuses on indeterminate/${reason}: no activation, no grant event, the flow spent`, async () => {
			const w = world();
			const a = await approved(w);
			w.state.owners.set("00u-alice", { kind: "indeterminate", reason });
			const back = returned(await callback(w, { state: a.state, code: "c" }, "b-1"));
			expect(back.get("error")).toBe("identity_unverifiable");
			expect(back.get("grant_id")).toBe(a.grantId);
			expect(back.get("state")).toBe("client-state-1");
			// It was the lookup that refused: it was reached, once, and asked.
			expect(w.state.lookups).toHaveLength(1);
			expect((await w.grants.find(a.grantId, w.state.now))?.status).toBe("pending");
			expect(w.intents.reservations("worker", "alice")).toBe(0);
			// The transaction is spent: the same answer cannot be replayed into a grant.
			expect((await callback(w, { state: a.state, code: "c" }, "b-1")).status).toBe(400);
			await w.background.drain();
			expect(w.events.some((e) => e.type === "federation.grant.authorized")).toBe(false);
			expect(
				w.events.find((e) => e.type === "federation.grant.authorization_failed")?.details,
			).toMatchObject({ grantId: a.grantId, outcome: `identity_unverifiable/${reason}` });
		});
	}

	it("refuses, with the bundled repository, a dedicated registration whose pairwise sub it cannot place", async () => {
		// The federation-grants ADR's D19 recommended setup: Bob signed in
		// through the LOGIN registration, whose pairwise `sub` for him is
		// `login-pairwise-B`; the grant's own registration gives the same person
		// `grant-pairwise-B`. A lookup that found no link under the grant's name
		// would let Alice take Bob's upstream account. The bundled repository cannot see across the two, so
		// it says so, and that refuses.
		const w = world({
			userRepository: new InMemoryUserRepository(
				new Map([
					["alice", { password: "x", id: "alice" }],
					["bob", { password: "y", id: "bob", token: "entra-login:login-pairwise-B" }],
				]),
			),
		});
		const a = await approved(w);
		w.state.exchange = {
			...w.state.exchange,
			upstream: { issuer: CONNECTION.upstreamIssuer, subject: "grant-pairwise-B" },
		};
		expect(returned(await callback(w, { state: a.state, code: "c" }, "b-1")).get("error")).toBe(
			"identity_unverifiable",
		);
		expect((await w.grants.find(a.grantId, w.state.now))?.status).toBe("pending");
	});

	it("leaves a grant a refused renewal would have replaced exactly as it was", async () => {
		const w = world();
		const { grantId, state, before } = await renewal(w);
		w.state.owners.set("00u-alice", { kind: "indeterminate", reason: "identity_not_resolvable" });
		expect(returned(await callback(w, { state, code: "c2" }, "b-2")).get("error")).toBe(
			"identity_unverifiable",
		);
		expect(await w.grants.find(grantId, w.state.now)).toStrictEqual(before);
		await w.background.drain();
		expect(w.events.some((e) => e.type === "federation.grant.reauthorized")).toBe(false);
	});

	it("reads an answer that is not one of the port's as an outage, and reports it", async () => {
		// Positively recognised or refused: neither a string nor null may fall
		// through to success.
		const malformed: unknown[] = [
			null,
			"bob",
			{},
			{ kind: "linked" },
			{ kind: "linked", subject: "" },
			{ kind: "linked", subject: 7 },
			{ kind: "indeterminate" },
			{ kind: "indeterminate", reason: "unknown_reason" },
			{ kind: "unlinked-ish" },
		];
		for (const answer of malformed) {
			const w = world();
			const a = await approved(w);
			w.state.owners.set("00u-alice", answer);
			expect(
				returned(await callback(w, { state: a.state, code: "c" }, "b-1")).get("error"),
				JSON.stringify(answer),
			).toBe("temporarily_unavailable");
			expect((await w.grants.find(a.grantId, w.state.now))?.status).toBe("pending");
			expect(payloadOf(w.lines, "federation_grant_callback_unavailable")).toMatchObject({
				store: "user_directory",
				step: "find_subject_by_federated_identity",
				err: { name: "TypeError" },
			});
		}
	});

	it("records, on the grant it lets through, which answer did: linked to this user, or to nobody", async () => {
		const linked = world();
		const a = await approved(linked);
		linked.state.owners.set("00u-alice", { kind: "linked", subject: "alice" });
		expect(
			returned(await callback(linked, { state: a.state, code: "c" }, "b-1")).has("error"),
		).toBe(false);
		await linked.background.drain();
		expect(
			linked.events.find((e) => e.type === "federation.grant.authorized")?.details,
		).toMatchObject({ outcome: "required/linked" });

		const renewed = world();
		const r = await renewal(renewed);
		returned(await callback(renewed, { state: r.state, code: "c2" }, "b-2"));
		await renewed.background.drain();
		expect(
			renewed.events.find((e) => e.type === "federation.grant.reauthorized")?.details,
		).toMatchObject({ outcome: "required/unlinked" });
	});

	it("audits a conflict as a conflict, and never names the other owner", async () => {
		const w = world();
		const a = await approved(w);
		w.state.owners.set("00u-alice", { kind: "linked", subject: "bob-the-other-owner" });
		expect(returned(await callback(w, { state: a.state, code: "c" }, "b-1")).get("error")).toBe(
			"identity_conflict",
		);
		await w.background.drain();
		expect(
			w.events.find((e) => e.type === "federation.grant.authorization_failed")?.details,
		).toMatchObject({ outcome: "identity_conflict" });
		expect(JSON.stringify(w.events)).not.toContain("bob-the-other-owner");
	});
});

describe("an audit sink that drops everything", () => {
	it("changes no answer the browser half gives, and fails no drain", async () => {
		const w = world();
		w.state.auditFails = true;
		// A refusal audited as authorization_failed.
		w.signIn("b-0");
		expect((await w.connect("no-such-handle", "b-0")).status).toBe(400);
		// A first grant, authorized.
		const a = await approved(w, "b-1");
		expect(returned(await callback(w, { state: a.state, code: "c" }, "b-1")).has("error")).toBe(
			false,
		);
		await w.background.drain();
		expect(w.events).toEqual([]);
	});

	it("changes nothing a renewal writes, whether it is authorized or revoked by the backstop", async () => {
		const renewed = world();
		const first = await renewal(renewed);
		renewed.state.auditFails = true;
		expect(
			returned(await callback(renewed, { state: first.state, code: "c2" }, "b-2")).has("error"),
		).toBe(false);

		const backstopped = world();
		const second = await renewal(backstopped);
		backstopped.state.auditFails = true;
		backstopped.state.grantsBoundary = new Date(backstopped.state.now.getTime());
		expect(
			returned(await callback(backstopped, { state: second.state, code: "c2" }, "b-2")).get(
				"error",
			),
		).toBe("grant_not_authorizable");
		expect((await backstopped.grants.find(second.grantId, backstopped.state.now))?.status).toBe(
			"revoked",
		);
		await Promise.all([renewed.background.drain(), backstopped.background.drain()]);
	});
});

describe("a callback that carries a parameter twice", () => {
	it("refuses it as a malformed response rather than dropping the copies, and exchanges nothing", async () => {
		// Dropping a repeated `iss` from what the adapter is handed would make
		// whether RFC 9207's check runs depend on the issuer's metadata, not on
		// what the response said. RFC 6749 §3.1: a response parameter MUST
		// NOT be included more than once.
		const w = world();
		const a = await approved(w, "b-1");
		const response = await request(w.app)
			.get(
				`${FEDERATION_GRANTS_BROWSER_MOUNT_PATH}/callback/${CONNECTION.name}?state=${encodeURIComponent(a.state)}&code=c&iss=${encodeURIComponent(CONNECTION.upstreamIssuer)}&iss=https%3A%2F%2Fevil.example`,
			)
			.set("x-browser", "b-1");
		expect(returned(response).get("error")).toBe("upstream_error");
		expect(w.state.exchanged).toHaveLength(0);
		expect((await w.grants.find(a.grantId, w.state.now))?.status).toBe("pending");

		// Any parameter, not only `iss`: the response is malformed either way.
		const b = await approved(w, "b-2");
		const other = await request(w.app)
			.get(
				`${FEDERATION_GRANTS_BROWSER_MOUNT_PATH}/callback/${CONNECTION.name}?state=${encodeURIComponent(b.state)}&code=c&session_state=x&session_state=y`,
			)
			.set("x-browser", "b-2");
		expect(returned(other).get("error")).toBe("upstream_error");
		expect(w.state.exchanged).toHaveLength(0);
	});
});

// ---------------------------------------------------------------------------
// What each outage logs. One line, at error, object-first, naming what could
// not answer (`store` / `step`, or the `reason`) with the error's projection —
// for every 503 and every `temporarily_unavailable` redirect. A failure that
// changed no answer is one warn.
// ---------------------------------------------------------------------------

/** Every line, once the work the answers handed over has finished. */
const settledLines = async (w: World) => {
	await w.background.drain();
	return w.lines;
};

const injected = (name: string) =>
	expect.objectContaining({ name: "Error", detail: `injected outage: ${name}` });

describe("connect — what an outage logs", () => {
	const connectWith = async (arrange: (w: World) => void) => {
		const w = world();
		const { handle, grantId } = await w.lodge();
		w.signIn("b-1");
		arrange(w);
		const response = await w.connect(handle, "b-1");
		return { w, response, grantId };
	};

	it.each([
		["getIntent", "federation_grant_intent", "get_intent", false],
		["parkConsent", "federation_grant_intent", "park_consent", true],
		["isCurrentIntent", "federation_grant", "is_current_intent", true],
	] as const)(
		"logs %s failing as one error line naming %s / %s",
		async (method, store, step, named) => {
			const { w, response, grantId } = await connectWith((w) => w.state.faults.set(method, 0));
			expect(response.status).toBe(503);
			expect(written(await settledLines(w))).toEqual([
				"error federation_grant_connect_unavailable",
			]);
			expect(payloadOf(w.lines, "federation_grant_connect_unavailable")).toEqual({
				...(named ? { grantId } : {}),
				correlationId: expect.any(String),
				reason: "storage",
				store,
				step,
				err: injected(method),
			});
		},
	);

	it("logs the session store that could not answer once, as admission's line, with the grant and the request's id", async () => {
		const { w, response, grantId } = await connectWith((w) =>
			w.state.faults.set("userSessionStore.get", 0),
		);
		expect(response.status).toBe(503);
		isPlain(response);
		expect(written(await settledLines(w))).toEqual(["error session_admission_unavailable"]);
		expect(payloadOf(w.lines, "session_admission_unavailable")).toEqual({
			grantId,
			correlationId: response.headers["x-request-id"],
			store: "user_session",
			action: "federation_grants.connect",
			err: injected("userSessionStore.get"),
		});
	});

	it("names the sessions boundary, and a value from it that is not one, in admission's line", async () => {
		for (const boundary of [new Error("boundary down"), "yesterday"]) {
			const { w, response, grantId } = await connectWith((w) => {
				w.state.sessionsBoundary = boundary as never;
			});
			expect(response.status).toBe(503);
			expect(written(await settledLines(w))).toEqual(["error session_admission_unavailable"]);
			expect(payloadOf(w.lines, "session_admission_unavailable")).toMatchObject({
				grantId,
				correlationId: response.headers["x-request-id"],
				store: "revocation_boundary",
				action: "federation_grants.connect",
				err: { name: boundary instanceof Error ? "Error" : "TypeError" },
			});
		}
	});

	it("logs the client registry through core's one line, with this route as its site", async () => {
		const { w, response } = await connectWith((w) => w.state.faults.set("findById", 0));
		expect(response.status).toBe(503);
		expect(written(await settledLines(w))).toEqual(["error client_repository_unavailable"]);
		expect(payloadOf(w.lines, "client_repository_unavailable")).toEqual({
			site: "federation_grant_connect",
			step: "find",
			clientId: CLIENT.clientId,
			err: injected("findById"),
		});
	});

	it("logs a failure nothing expected as an unexpected error", async () => {
		const { w, response } = await connectWith((w) => {
			w.state.configurationThrows = true;
		});
		expect(response.status).toBe(500);
		expect(written(await settledLines(w))).toEqual(["error federation_grants_unexpected_error"]);
		expect(payloadOf(w.lines, "federation_grants_unexpected_error")).toMatchObject({
			site: "connect",
			err: { name: "Error", detail: "injected: configuration unreadable" },
		});
	});
});

describe("connect — what an outage audits", () => {
	/** Every event written, without its timestamp and request metadata. */
	const audited = (w: World) =>
		w.events.map(({ type, clientId, subject, details }) => ({ type, clientId, subject, details }));

	it("audits a handle the intent store cannot read as unavailable, naming no flow, beside its one line", async () => {
		const w = world();
		const { handle } = await w.lodge();
		w.signIn("b-1");
		w.state.faults.set("getIntent", 0);
		const response = await w.connect(handle, "b-1");
		expect(response.status).toBe(503);
		isPlain(response);
		expect(response.text).toBe("Temporarily unavailable.");
		expect(written(await settledLines(w))).toEqual(["error federation_grant_connect_unavailable"]);
		expect(payloadOf(w.lines, "federation_grant_connect_unavailable")).toEqual({
			correlationId: response.headers["x-request-id"],
			reason: "storage",
			store: "federation_grant_intent",
			step: "get_intent",
			err: injected("getIntent"),
		});
		expect(audited(w)).toEqual([
			{
				type: "federation.grant.authorization_failed",
				clientId: "",
				subject: "",
				details: {
					correlationId: response.headers["x-request-id"],
					grantId: "",
					outcome: "unavailable",
					operation: "connect",
				},
			},
		]);
	});

	it.each([
		["parkConsent", "federation_grant_intent", "park_consent"],
		["isCurrentIntent", "federation_grant", "is_current_intent"],
	] as const)(
		"audits %s failing as unavailable with the flow's grant, client, subject and connection, beside its one line",
		async (method, store, step) => {
			const w = world();
			const { handle, grantId } = await w.lodge();
			w.signIn("b-1");
			w.state.faults.set(method, 0);
			const response = await w.connect(handle, "b-1");
			expect(response.status).toBe(503);
			isPlain(response);
			expect(response.text).toBe("Temporarily unavailable.");
			expect(written(await settledLines(w))).toEqual([
				"error federation_grant_connect_unavailable",
			]);
			expect(payloadOf(w.lines, "federation_grant_connect_unavailable")).toEqual({
				grantId,
				correlationId: response.headers["x-request-id"],
				reason: "storage",
				store,
				step,
				err: injected(method),
			});
			expect(audited(w)).toEqual([
				{
					type: "federation.grant.authorization_failed",
					clientId: CLIENT.clientId,
					subject: "alice",
					details: {
						correlationId: "corr-1",
						grantId,
						connection: CONNECTION.name,
						outcome: "unavailable",
						operation: "connect",
					},
				},
			]);
		},
	);
});

describe("consent — what an outage logs", () => {
	/** A question parked for alice's browser `b-1`. */
	async function asked(w: World) {
		const lodged = await w.lodge();
		w.signIn("b-1");
		return { ...lodged, challenge: await w.challengeFor(lodged.handle, "b-1") };
	}

	it("logs the question that could not be read", async () => {
		const w = world();
		const { challenge } = await asked(w);
		w.state.faults.set("getConsent", 0);
		expect((await w.page(challenge, "b-1")).status).toBe(503);
		expect(written(await settledLines(w))).toEqual(["error federation_grant_consent_unavailable"]);
		expect(payloadOf(w.lines, "federation_grant_consent_unavailable")).toEqual({
			method: "GET",
			correlationId: expect.any(String),
			reason: "storage",
			store: "federation_grant_intent",
			step: "get_consent",
			err: injected("getConsent"),
		});
	});

	it.each(["GET", "POST"] as const)(
		"logs the judgement that could not be made on %s — the session's part as admission's line, with the method",
		async (method) => {
			const w = world();
			const { challenge, grantId } = await asked(w);
			w.state.sessionsBoundary = new Error("boundary down");
			const response =
				method === "GET"
					? await w.page(challenge, "b-1")
					: await w.answer({ challenge, decision: "accept" }, "b-1");
			expect(response.status).toBe(503);
			expect(response.body).toEqual({
				error: "temporarily_unavailable",
				error_description: "revocation store unavailable",
			});
			expect(written(await settledLines(w))).toEqual(["error session_admission_unavailable"]);
			expect(payloadOf(w.lines, "session_admission_unavailable")).toEqual({
				method,
				grantId,
				correlationId: response.headers["x-request-id"],
				store: "revocation_boundary",
				action: "federation_grants.consent",
				err: expect.objectContaining({ name: "Error", detail: "boundary down" }),
			});
		},
	);

	it.each(["GET", "POST"] as const)(
		"describes an admission outage on %s by the store that could not answer, as every consumer of admission does — core's describeAdmissionOutage, in this route's envelope",
		async (method) => {
			const w = world();
			const { challenge } = await asked(w);
			w.state.faults.set("userSessionStore.get", 0);
			const response =
				method === "GET"
					? await w.page(challenge, "b-1")
					: await w.answer({ challenge, decision: "accept" }, "b-1");
			expect(response.status).toBe(503);
			expect(response.body).toEqual({
				error: "temporarily_unavailable",
				error_description: "session store unavailable",
			});
			expect(written(await settledLines(w))).toEqual(["error session_admission_unavailable"]);
			expect(payloadOf(w.lines, "session_admission_unavailable")).toMatchObject({
				method,
				store: "user_session",
				action: "federation_grants.consent",
			});
		},
	);

	it.each(["GET", "POST"] as const)(
		"answers a grant store that cannot say whether the question is current on %s as this package's own outage — storage, never admission's wording — and logs it once as the consent's line",
		async (method) => {
			const w = world();
			const { challenge, grantId } = await asked(w);
			// The session's part is admitted; the judgement's first read of the
			// flow's own state — is this intent still the grant's? — fails.
			w.state.faults.set("isCurrentIntent", 0);
			const response =
				method === "GET"
					? await w.page(challenge, "b-1")
					: await w.answer({ challenge, decision: "accept" }, "b-1");
			expect(response.status).toBe(503);
			expect(response.body).toEqual({
				error: "temporarily_unavailable",
				error_description: "storage",
			});
			expect(written(await settledLines(w))).toEqual([
				"error federation_grant_consent_unavailable",
			]);
			expect(payloadOf(w.lines, "federation_grant_consent_unavailable")).toMatchObject({
				method,
				grantId,
				correlationId: response.headers["x-request-id"],
				reason: "storage",
				store: "federation_grant",
				step: "is_current_intent",
				err: injected("isCurrentIntent"),
			});
		},
	);

	it("answers a client registry that cannot judge the question as the page's own lookup does, and logs it once", async () => {
		// The judgement's read fails, on both methods: one answer for one
		// outage, `/oauth/consent`'s — never `storage`, which names another store.
		for (const method of ["GET", "POST"] as const) {
			const w = world();
			const { challenge } = await asked(w);
			w.state.faults.set("findById", 0);
			const response =
				method === "GET"
					? await w.page(challenge, "b-1")
					: await w.answer({ challenge, decision: "accept" }, "b-1");
			expect(response.status).toBe(503);
			expect(response.body).toEqual({
				error: "temporarily_unavailable",
				error_description: "client registry unavailable",
			});
			expect(written(await settledLines(w))).toEqual(["error client_repository_unavailable"]);
			expect(payloadOf(w.lines, "client_repository_unavailable")).toMatchObject({
				site: "federation_grant_consent",
				step: "find",
			});
		}
	});

	it("logs the client registry that could not describe the client through core's one line", async () => {
		const w = world();
		const { challenge } = await asked(w);
		// The judgement's own read succeeds; the description's fails.
		w.state.faults.set("findById", 1);
		expect((await w.page(challenge, "b-1")).status).toBe(503);
		expect(written(await settledLines(w))).toEqual(["error client_repository_unavailable"]);
		expect(payloadOf(w.lines, "client_repository_unavailable")).toEqual({
			site: "federation_grant_consent",
			step: "find",
			clientId: CLIENT.clientId,
			err: injected("findById"),
		});
	});

	it("answers an intent store that cannot record the answer 503, not 500, and logs it", async () => {
		for (const decision of ["accept", "deny"]) {
			const w = world();
			const { challenge } = await asked(w);
			w.state.faults.set("answerConsent", 0);
			const response = await w.answer({ challenge, decision }, "b-1");
			expect(response.status).toBe(503);
			expect(response.body).toEqual({
				error: "temporarily_unavailable",
				error_description: "storage",
			});
			expect(written(await settledLines(w))).toEqual([
				"error federation_grant_consent_unavailable",
			]);
			expect(payloadOf(w.lines, "federation_grant_consent_unavailable")).toMatchObject({
				method: "POST",
				reason: "storage",
				store: "federation_grant_intent",
				step: "answer_consent",
				err: injected("answerConsent"),
			});
		}
	});

	it("logs an upstream state another flow already holds: a fault on this side", async () => {
		const w = world();
		const first = await asked(w);
		w.state.ids.push("same-state", "nonce-1", "verifier-1");
		expect((await w.answer({ challenge: first.challenge, decision: "accept" }, "b-1")).status).toBe(
			303,
		);
		const second = await asked(w);
		w.state.ids.push("same-state", "nonce-2", "verifier-2");
		expect(
			(await w.answer({ challenge: second.challenge, decision: "accept" }, "b-1")).status,
		).toBe(503);
		expect(written(await settledLines(w))).toEqual(["error federation_grant_consent_unavailable"]);
		expect(payloadOf(w.lines, "federation_grant_consent_unavailable")).toMatchObject({
			method: "POST",
			reason: "storage",
			store: "federation_grant_intent",
			step: "answer_consent",
			refusal: "state_collision",
		});
	});

	it("logs an upstream URL that could not be built, and a capability that has gone", async () => {
		for (const [arrange, step, err] of [
			[(w: World) => (w.state.authorizerThrows = true), "authorization_url", true],
			[(w: World) => (w.state.authorizerMissing = true), "authorizer", false],
		] as const) {
			const w = world();
			const { challenge } = await asked(w);
			arrange(w);
			expect((await w.answer({ challenge, decision: "accept" }, "b-1")).status).toBe(503);
			expect(written(await settledLines(w))).toEqual([
				"error federation_grant_consent_unavailable",
			]);
			const payload = payloadOf(w.lines, "federation_grant_consent_unavailable");
			expect(payload).toMatchObject({ method: "POST", reason: "upstream_unavailable", step });
			if (err) expect(payload.err).toMatchObject({ name: "Error", detail: "reserved parameter" });
			else expect(payload).not.toHaveProperty("err");
		}
	});

	it("logs a renewal's pointer it could not retire after a refusal as one warn", async () => {
		const w = world();
		const { challenge } = await renewalChallenge(w);
		w.state.faults.set("retireIntent", 0);
		expect((await w.answer({ challenge, decision: "deny" }, "b-2")).status).toBe(303);
		expect(written(await settledLines(w))).toEqual(["warn federation_grant_consent_step_failed"]);
		expect(payloadOf(w.lines, "federation_grant_consent_step_failed")).toMatchObject({
			store: "federation_grant",
			step: "retire_intent",
			err: injected("retireIntent"),
		});
	});
});

describe("consent — what an outage audits", () => {
	/** A question parked for alice's browser `b-1`. */
	async function asked(w: World) {
		const lodged = await w.lodge();
		w.signIn("b-1");
		return { ...lodged, challenge: await w.challengeFor(lodged.handle, "b-1") };
	}

	/** Every authorization_failed written, without its timestamp and request metadata. */
	const failures = async (w: World) => {
		await w.background.drain();
		return w.events
			.filter((e) => e.type === "federation.grant.authorization_failed")
			.map(({ clientId, subject, details }) => ({ clientId, subject, details }));
	};

	it.each(["getConsent", "getIntent"] as const)(
		"audits %s failing at the read as unavailable, naming no flow",
		async (method) => {
			const w = world();
			const { challenge } = await asked(w);
			w.state.faults.set(method, 0);
			const response = await w.page(challenge, "b-1");
			expect(response.status).toBe(503);
			expect(await failures(w)).toEqual([
				{
					clientId: "",
					subject: "",
					details: {
						correlationId: response.headers["x-request-id"],
						grantId: "",
						outcome: "unavailable",
						operation: "connect",
					},
				},
			]);
		},
	);

	it("audits a client registry that could not describe the client as unavailable with the flow's grant, client, subject and connection", async () => {
		const w = world();
		const { challenge, grantId } = await asked(w);
		// The judgement's own read succeeds; the description's fails.
		w.state.faults.set("findById", 1);
		const response = await w.page(challenge, "b-1");
		expect(response.status).toBe(503);
		expect(response.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "client registry unavailable",
		});
		expect(await failures(w)).toEqual([
			{
				clientId: CLIENT.clientId,
				subject: "alice",
				details: {
					correlationId: "corr-1",
					grantId,
					connection: CONNECTION.name,
					outcome: "unavailable",
					operation: "connect",
				},
			},
		]);
	});

	/** Another flow, already upstream, holding the state the next answer is given. */
	const collidingState = async (w: World) => {
		const first = await asked(w);
		w.state.ids.push("same-state", "nonce-1", "verifier-1");
		expect((await w.answer({ challenge: first.challenge, decision: "accept" }, "b-1")).status).toBe(
			303,
		);
		return () => w.state.ids.push("same-state", "nonce-2", "verifier-2");
	};

	it.each([
		{
			path: "an accept the intent store cannot record",
			decision: "accept",
			description: "storage",
			arrange: async (w: World) => () => w.state.faults.set("answerConsent", 0),
		},
		{
			path: "a deny the intent store cannot record",
			decision: "deny",
			description: "storage",
			arrange: async (w: World) => () => w.state.faults.set("answerConsent", 0),
		},
		{
			path: "an upstream state another flow already holds",
			decision: "accept",
			description: "storage",
			arrange: collidingState,
		},
		{
			path: "an upstream URL that could not be built",
			decision: "accept",
			description: "upstream_unavailable",
			arrange: async (w: World) => () => {
				w.state.authorizerThrows = true;
			},
		},
		{
			path: "a federation that lost the capability",
			decision: "accept",
			description: "upstream_unavailable",
			arrange: async (w: World) => () => {
				w.state.authorizerMissing = true;
			},
		},
	] as const)(
		"audits $path as unavailable with the flow's grant, client, subject and connection",
		async ({ decision, description, arrange }) => {
			const w = world();
			const fail = await arrange(w);
			const { challenge, grantId } = await asked(w);
			fail();
			const response = await w.answer({ challenge, decision }, "b-1");
			expect(response.status).toBe(503);
			expect(response.body).toEqual({
				error: "temporarily_unavailable",
				error_description: description,
			});
			expect(await failures(w)).toEqual([
				{
					clientId: CLIENT.clientId,
					subject: "alice",
					details: {
						correlationId: "corr-1",
						grantId,
						connection: CONNECTION.name,
						outcome: "unavailable",
						operation: "connect",
					},
				},
			]);
		},
	);
});

describe("the callback — what an outage logs", () => {
	const unavailable = async (w: World, arrange: () => void, browser = "b-1", state?: string) => {
		const a = state === undefined ? await approved(w, browser) : { state, grantId: "" };
		arrange();
		const response = await callback(w, { state: a.state, code: "c" }, browser);
		return { response, grantId: a.grantId };
	};

	it("logs a transaction that could not be spent as one error line", async () => {
		const w = world();
		const { response } = await unavailable(w, () => w.state.faults.set("consumeTransaction", 0));
		expect(response.status).toBe(503);
		expect(written(await settledLines(w))).toEqual(["error federation_grant_callback_unavailable"]);
		expect(payloadOf(w.lines, "federation_grant_callback_unavailable")).toEqual({
			correlationId: expect.any(String),
			reason: "storage",
			store: "federation_grant_intent",
			step: "consume_transaction",
			err: injected("consumeTransaction"),
		});
	});

	it.each([
		["the grant store, at check 2", "isCurrentIntent", 0, "federation_grant", "is_current_intent"],
		[
			"the grant store, at the re-read",
			"isCurrentIntent",
			1,
			"federation_grant",
			"is_current_intent",
		],
		["the activation", "activate", 0, "federation_grant", "activate"],
		[
			"the identity lookup",
			"findSubjectByFederatedIdentity",
			0,
			"user_directory",
			"find_subject_by_federated_identity",
		],
	] as const)(
		"logs %s behind the temporarily_unavailable redirect",
		async (_label, method, passes, store, step) => {
			const w = world();
			const { response, grantId } = await unavailable(w, () => w.state.faults.set(method, passes));
			expect(returned(response).get("error")).toBe("temporarily_unavailable");
			expect(written(await settledLines(w))).toEqual([
				"error federation_grant_callback_unavailable",
			]);
			expect(payloadOf(w.lines, "federation_grant_callback_unavailable")).toEqual({
				grantId,
				correlationId: expect.any(String),
				reason: "storage",
				store,
				step,
				err: injected(method),
			});
		},
	);

	it.each([
		["at check 3", 0],
		["at the re-read", 1],
	] as const)(
		"logs the session store that could not answer %s once, as admission's line",
		async (_label, passes) => {
			const w = world();
			const { response, grantId } = await unavailable(w, () =>
				w.state.faults.set("userSessionStore.get", passes),
			);
			expect(returned(response).get("error")).toBe("temporarily_unavailable");
			expect(written(await settledLines(w))).toEqual(["error session_admission_unavailable"]);
			expect(payloadOf(w.lines, "session_admission_unavailable")).toEqual({
				grantId,
				correlationId: response.headers["x-request-id"],
				store: "user_session",
				action: "federation_grants.callback",
				err: injected("userSessionStore.get"),
			});
		},
	);

	it("logs the grants boundary that could not be read", async () => {
		const w = world();
		const { response } = await unavailable(w, () => {
			w.state.grantsBoundary = new Error("boundary down");
		});
		expect(returned(response).get("error")).toBe("temporarily_unavailable");
		expect(written(await settledLines(w))).toEqual(["error federation_grant_callback_unavailable"]);
		expect(payloadOf(w.lines, "federation_grant_callback_unavailable")).toMatchObject({
			store: "revocation_boundary",
			step: "read",
			err: { name: "Error", detail: "boundary down" },
		});
	});

	it("logs a renewal's grant that could not be read, at the backstop or at the account check", async () => {
		for (const passes of [0, 1]) {
			const w = world();
			const { state } = await renewal(w);
			const { response } = await unavailable(
				w,
				() => w.state.faults.set("find", passes),
				"b-2",
				state,
			);
			expect(returned(response).get("error")).toBe("temporarily_unavailable");
			expect(written(await settledLines(w))).toEqual([
				"error federation_grant_callback_unavailable",
			]);
			expect(payloadOf(w.lines, "federation_grant_callback_unavailable")).toMatchObject({
				store: "federation_grant",
				step: "find",
				err: injected("find"),
			});
		}
	});

	it("logs a repository that lost the identity lookup: a composition fault", async () => {
		const w = world({ userRepository: {} });
		const { response } = await unavailable(w, () => undefined);
		expect(returned(response).get("error")).toBe("temporarily_unavailable");
		expect(written(await settledLines(w))).toEqual(["error federation_grant_callback_unavailable"]);
		expect(payloadOf(w.lines, "federation_grant_callback_unavailable")).toMatchObject({
			store: "user_directory",
			step: "find_subject_by_federated_identity",
			err: { name: "TypeError" },
		});
	});

	it("logs an upstream it could not reach as the outage, classified by the error's name or code", async () => {
		for (const thrown of [
			Object.assign(new Error("timed out"), { name: "TimeoutError" }),
			Object.assign(new TypeError("fetch failed"), {
				cause: Object.assign(new Error("socket hang up"), { code: "ECONNRESET" }),
			}),
		]) {
			const w = world();
			const { response } = await unavailable(w, () => {
				w.state.exchangeThrows = thrown;
			});
			expect(returned(response).get("error")).toBe("temporarily_unavailable");
			expect(written(await settledLines(w))).toEqual([
				"error federation_grant_callback_unavailable",
			]);
			expect(payloadOf(w.lines, "federation_grant_callback_unavailable")).toMatchObject({
				reason: "upstream",
				step: "exchange",
				err: { name: thrown.name },
			});
		}
	});

	it("logs an upstream answering 5xx as the outage — as openid-client raises it — the reading the token route's refresh makes too", async () => {
		// The shapes the real library throws (federation-oidc's
		// delegated-outage.test.mts): a 503 or 502 that oauth4webapi will not
		// read is a ClientError over the Response; an OAuth error body under a
		// 5xx carries the status on the error.
		for (const thrown of [
			Object.assign(
				new Error("unexpected HTTP response status code", {
					cause: new Response("<html>down</html>", { status: 503 }),
				}),
				{ name: "ClientError", code: "OAUTH_RESPONSE_IS_NOT_CONFORM" },
			),
			Object.assign(new Error("server responded with an error in the response body"), {
				name: "ResponseBodyError",
				status: 503,
				error: "temporarily_unavailable",
			}),
		]) {
			const w = world();
			const { response } = await unavailable(w, () => {
				w.state.exchangeThrows = thrown;
			});
			expect(returned(response).get("error")).toBe("temporarily_unavailable");
			expect(written(await settledLines(w))).toEqual([
				"error federation_grant_callback_unavailable",
			]);
			expect(payloadOf(w.lines, "federation_grant_callback_unavailable")).toMatchObject({
				reason: "upstream",
				step: "exchange",
				err: { name: thrown.name },
			});
		}
	});

	it("reads what an error's text says as no outage: only its name and code classify it", async () => {
		const w = world();
		const { response } = await unavailable(w, () => {
			w.state.exchangeThrows = new Error("connect ECONNREFUSED 192.0.2.1:443 (fetch failed)");
		});
		expect(returned(response).get("error")).toBe("upstream_error");
		expect(written(await settledLines(w))).toEqual([
			"warn federation_grant_callback_exchange_refused",
		]);
	});

	it("logs the upstream refusing the code as one warn: it answered", async () => {
		const w = world();
		const { response, grantId } = await unavailable(w, () => {
			w.state.exchangeThrows = Object.assign(new Error("bad code"), { error: "invalid_grant" });
		});
		expect(returned(response).get("error")).toBe("upstream_error");
		expect(written(await settledLines(w))).toEqual([
			"warn federation_grant_callback_exchange_refused",
		]);
		expect(payloadOf(w.lines, "federation_grant_callback_exchange_refused")).toMatchObject({
			grantId,
			step: "exchange",
			err: { name: "Error", error: "invalid_grant" },
		});
	});

	it("logs a flow it could not finish after activating as one warn", async () => {
		const w = world();
		const { response } = await unavailable(w, () => w.state.faults.set("finishIntent", 0));
		expect(returned(response).has("error")).toBe(false);
		expect(written(await settledLines(w))).toEqual(["warn federation_grant_callback_step_failed"]);
		expect(payloadOf(w.lines, "federation_grant_callback_step_failed")).toMatchObject({
			store: "federation_grant_intent",
			step: "finish_intent",
			err: injected("finishIntent"),
		});
	});

	it("logs a failure nothing expected behind the redirect as an unexpected error", async () => {
		const w = world();
		const { response } = await unavailable(w, () => {
			w.state.configurationThrows = true;
		});
		expect(returned(response).get("error")).toBe("temporarily_unavailable");
		expect(written(await settledLines(w))).toEqual(["error federation_grants_unexpected_error"]);
		expect(payloadOf(w.lines, "federation_grants_unexpected_error")).toMatchObject({
			site: "callback",
			err: { name: "Error", detail: "injected: configuration unreadable" },
		});
	});
});

describe("the callback — what an outage audits", () => {
	it("audits a transaction that could not be spent as temporarily_unavailable, naming no flow", async () => {
		const w = world();
		const { state } = await approved(w);
		w.state.faults.set("consumeTransaction", 0);
		const response = await callback(w, { state, code: "c" }, "b-1");
		expect(response.status).toBe(503);
		await w.background.drain();
		expect(
			w.events
				.filter((e) => e.type === "federation.grant.authorization_failed")
				.map(({ clientId, subject, details }) => ({ clientId, subject, details })),
		).toEqual([
			{
				clientId: "",
				subject: "",
				details: {
					correlationId: response.headers["x-request-id"],
					grantId: "",
					outcome: "temporarily_unavailable",
					operation: "connect",
				},
			},
		]);
	});
});

describe("the callback, when the composition fails where nothing expected it", () => {
	it("answers a registry that throws on the unknown-transaction exit a plain 500, logged as unexpected", async () => {
		// The drain registry is the composition's component: one that throws
		// when the refusal's audit is handed to it escapes the check-1 exits.
		const real = createFederationGrantBackground();
		const w = world({
			background: {
				...real,
				register: () => {
					throw new Error("registry closed");
				},
			},
		});
		const response = await callback(w, { state: "never-issued", code: "c" }, "b-1");
		expect(response.status).toBe(500);
		isPlain(response);
		expect(written(await settledLines(w))).toEqual(["error federation_grants_unexpected_error"]);
		expect(payloadOf(w.lines, "federation_grants_unexpected_error")).toMatchObject({
			site: "callback",
			err: { name: "Error", detail: "registry closed" },
		});
	});
});

describe("the browser throttle, when the limiter is down — what it logs and audits", () => {
	it("logs through the deployment's own logger and records the audit event", async () => {
		const w = world({
			rateLimiter: {
				kind: "down",
				failMode: "closed",
				check: async () => {
					throw new Error("limiter down");
				},
			},
		});
		expect((await w.connect("any")).status).toBe(503);
		expect(written(await settledLines(w))).toEqual(["error rate_limiter_failed_closed"]);
		expect(payloadOf(w.lines, "rate_limiter_failed_closed")).toMatchObject({
			tag: "federation_grants_browser",
			error: "limiter down",
		});
		expect(w.events.find((event) => event.type === "rate_limit.unavailable")?.details).toEqual({
			tag: "federation_grants_browser",
			cause: { name: "Error" },
		});
	});
});

/**
 * A requirement that answers `answer` and records what it was asked. Its page
 * is set, so a `step_up` is one admission can answer; its reach is empty, as
 * any requirement's but the second-factor authority's must be in this
 * release.
 */
const fixture = (
	answer: (input: RequirementInput) => RequirementVerdict,
	asked: RequirementInput[] = [],
): SessionRequirement => ({
	name: "fixture",
	reach: new Set<string>(),
	stepUpPage: { url: "/step-up", params: {} },
	remediations: [],
	hintKeys: [],
	admit: async (input) => {
		asked.push(input);
		return answer(input);
	},
});

/** `answer` for `action`, `met` for every other. */
const on =
	(action: string, answer: RequirementVerdict) =>
	(input: RequirementInput): RequirementVerdict =>
		input.action.name === action ? answer : { outcome: "met" };

const STEP_UP: RequirementVerdict = { outcome: "step_up", whenStillUnmet: "reauthenticate" };

describe("the browser half on session admission", () => {
	it("admits connect, the consent read and answered, and the callback twice — each its own action, graded use — on the cookie's claim", async () => {
		const asked: RequirementInput[] = [];
		const w = world({ requirements: [fixture(() => ({ outcome: "met" }), asked)] });
		const { handle } = await w.lodge();
		w.signIn("b-1");
		const challenge = await w.challengeFor(handle, "b-1");
		expect((await w.page(challenge, "b-1")).status).toBe(200);
		const answered = await w.answer({ challenge, decision: "accept" }, "b-1");
		const state = new URL(answered.headers.location as string).searchParams.get("state") ?? "";
		expect(returned(await callback(w, { state, code: "c" }, "b-1")).has("error")).toBe(false);
		expect(asked.map((input) => input.action)).toEqual([
			{ name: "federation_grants.connect", grade: "use" },
			{ name: "federation_grants.consent", grade: "use" },
			{ name: "federation_grants.consent", grade: "use" },
			{ name: "federation_grants.callback", grade: "use" },
			{ name: "federation_grants.callback", grade: "use" },
		]);
		for (const input of asked) {
			expect(input).toMatchObject({
				carrier: "cookie",
				subject: "alice",
				session: { sid: "sid-b-1", sub: "alice" },
			});
		}
	});

	it("answers a step-up at connect, on the return from its trip, with the plain 403 a dead session gets, and parks nothing", async () => {
		// The trip itself: browserConnect.stepUp.test.mts.
		const w = world({ requirements: [fixture(on("federation_grants.connect", STEP_UP))] });
		const { handle, grantId } = await w.lodge();
		w.signIn("b-1");
		const response = await w.connect(handle, "b-1").query({ stepped_up: "1" });
		expect(response.status).toBe(403);
		isPlain(response);
		expect(response.text).toBe("Sign in again to continue.");
		expect(response.headers.location).toBeUndefined();
		expect(w.intents.size).toBe(1);
		await w.background.drain();
		expect(w.events.find((e) => e.type === "federation.grant.authorization_failed")).toMatchObject({
			details: { grantId, outcome: "reauthentication_required" },
		});
	});

	it("answers a step-up at the consent 403 reauthentication_required, read or answered, and spends nothing", async () => {
		const w = world({ requirements: [fixture(on("federation_grants.consent", STEP_UP))] });
		const { handle } = await w.lodge();
		w.signIn("b-1");
		const challenge = await w.challengeFor(handle, "b-1");
		const refused = {
			error: "reauthentication_required",
			error_description: "sign in again to continue",
		};
		const read = await w.page(challenge, "b-1");
		expect(read.status).toBe(403);
		expect(read.body).toEqual(refused);
		const answered = await w.answer({ challenge, decision: "accept" }, "b-1");
		expect(answered.status).toBe(403);
		expect(answered.body).toEqual(refused);
		expect(w.authorized).toEqual([]);
	});

	it("answers a step-up at the callback — before the exchange or at the re-read — with error=reauthentication_required, and activates nothing", async () => {
		let callbacks = 0;
		let steppedUpAt = 1;
		const w = world({
			requirements: [
				fixture((input) => {
					if (input.action.name !== "federation_grants.callback") return { outcome: "met" };
					callbacks += 1;
					return callbacks === steppedUpAt ? STEP_UP : { outcome: "met" };
				}),
			],
		});
		const a = await approved(w, "b-1");
		expect(returned(await callback(w, { state: a.state, code: "c" }, "b-1")).get("error")).toBe(
			"reauthentication_required",
		);
		expect(w.state.exchanged).toEqual([]);

		callbacks = 0;
		steppedUpAt = 2;
		const b = await approved(w, "b-2");
		expect(returned(await callback(w, { state: b.state, code: "c" }, "b-2")).get("error")).toBe(
			"reauthentication_required",
		);
		expect(w.state.exchanged).toHaveLength(1);
		for (const { grantId } of [a, b]) {
			expect((await w.grants.find(grantId, w.state.now))?.status).toBe("pending");
		}
	});

	it.each(["reauthenticate", "unmet"] as const)(
		"answers a requirement's %s as a session that must sign in again, at every step",
		async (outcome) => {
			const at = (action: string) => world({ requirements: [fixture(on(action, { outcome }))] });

			const connecting = at("federation_grants.connect");
			const lodged = await connecting.lodge();
			connecting.signIn("b-1");
			const connected = await connecting.connect(lodged.handle, "b-1");
			expect(connected.status).toBe(403);
			expect(connected.text).toBe("Sign in again to continue.");

			const consenting = at("federation_grants.consent");
			const parked = await consenting.lodge();
			consenting.signIn("b-1");
			const challenge = await consenting.challengeFor(parked.handle, "b-1");
			expect((await consenting.page(challenge, "b-1")).body.error).toBe(
				"reauthentication_required",
			);

			const returning = at("federation_grants.callback");
			const a = await approved(returning, "b-1");
			expect(
				returned(await callback(returning, { state: a.state, code: "c" }, "b-1")).get("error"),
			).toBe("reauthentication_required");
		},
	);

	it("answers a requirement that throws as the outage it is, logged once — by admission, with the requirement's name", async () => {
		const down = (action: string) =>
			world({
				requirements: [
					fixture((input) => {
						if (input.action.name === action) throw new Error("risk engine down");
						return { outcome: "met" };
					}),
				],
			});

		const connecting = down("federation_grants.connect");
		const lodged = await connecting.lodge();
		connecting.signIn("b-1");
		const connected = await connecting.connect(lodged.handle, "b-1");
		expect(connected.status).toBe(503);
		expect(connected.text).toBe("Temporarily unavailable.");
		expect(written(await settledLines(connecting))).toEqual([
			"error session_admission_unavailable",
		]);
		expect(payloadOf(connecting.lines, "session_admission_unavailable")).toMatchObject({
			grantId: lodged.grantId,
			correlationId: connected.headers["x-request-id"],
			store: "fixture",
			action: "federation_grants.connect",
			err: { name: "Error", detail: "risk engine down" },
		});

		const consenting = down("federation_grants.consent");
		const parked = await consenting.lodge();
		consenting.signIn("b-1");
		const challenge = await consenting.challengeFor(parked.handle, "b-1");
		const read = await consenting.page(challenge, "b-1");
		expect(read.status).toBe(503);
		// A requirement's outage is described as one — never as the session
		// store's, nor by the requirement's name, which is the operator's.
		expect(read.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "session requirement unavailable",
		});

		const returning = down("federation_grants.callback");
		const a = await approved(returning, "b-1");
		expect(
			returned(await callback(returning, { state: a.state, code: "c" }, "b-1")).get("error"),
		).toBe("temporarily_unavailable");
		expect(written(await settledLines(returning))).toEqual(["error session_admission_unavailable"]);
	});

	it("refuses a durable session whose expiresAt is not later than now — admission's reading, the one the routes made", async () => {
		const w = world();
		const { handle } = await w.lodge();
		for (const [browser, offset, status] of [
			["b-now", 0, 403],
			["b-later", 1, 303],
		] as const) {
			const sid = w.signIn(browser);
			const durable = w.durable.get(sid) as UserSession;
			w.durable.set(sid, { ...durable, expiresAt: new Date(w.state.now.getTime() + offset) });
			expect((await w.connect(handle, browser)).status, browser).toBe(status);
		}
	});

	it("tells a browser signed out since — its user gone with it — to sign in again at the callback, not that it is another account", async () => {
		const w = world();
		const a = await approved(w, "b-1");
		w.browsers.set("b-1", { isAuthenticated: false });
		expect(returned(await callback(w, { state: a.state, code: "c" }, "b-1")).get("error")).toBe(
			"reauthentication_required",
		);
	});

	it("binds the browser by both halves around admission: the express session's id at connect, the durable sid at the callback", async () => {
		// Admission reads the session the cookie names; which browser the flow
		// is bound to stays the routes' own question.
		const w = world();
		const { handle } = await w.lodge();
		w.signIn("b-1");
		w.state.withoutSessionId.add("b-1");
		const unbound = await w.connect(handle, "b-1");
		expect(unbound.status).toBe(403);
		expect(unbound.text).toBe("Sign in again to continue.");
		w.state.withoutSessionId.clear();

		// A new login in the same browser since the consent: a live session
		// of the same subject, and not the one the flow was bound to.
		const a = await approved(w, "b-2");
		w.signIn("b-2-relogin");
		w.browsers.set("b-2", w.browsers.get("b-2-relogin") as Browser);
		expect(returned(await callback(w, { state: a.state, code: "c" }, "b-2")).get("error")).toBe(
			"reauthentication_required",
		);
		expect(w.state.exchanged).toEqual([]);
	});

	it("reads another user's cookie on the bound browser as no challenge at all: 400, and nothing audited", async () => {
		const w = world();
		const { handle } = await w.lodge();
		w.signIn("b-1");
		const challenge = await w.challengeFor(handle, "b-1");
		w.browsers.set("b-1", { isAuthenticated: true, user: { id: "mallory" }, sid: "sid-b-1" });
		const read = await w.page(challenge, "b-1");
		expect(read.status).toBe(400);
		expect(read.body).toEqual(noPending);
		await w.background.drain();
		expect(w.events.filter((e) => e.type === "federation.grant.authorization_failed")).toEqual([]);
	});

	it("writes admission's outage line to core's console logger when no logger is wired, the grant bound to it", async () => {
		// Core's console logger writes through `console`; a child of it too.
		const spy = vi.spyOn(console, "error").mockImplementation(() => {});
		try {
			const w = world({ withoutLogger: true });
			const { handle, grantId } = await w.lodge();
			w.signIn("b-1");
			w.state.faults.set("userSessionStore.get", 0);
			expect((await w.connect(handle, "b-1")).status).toBe(503);
			expect(spy).toHaveBeenCalledTimes(1);
			expect(spy.mock.calls[0]?.[1]).toBe("session_admission_unavailable");
			expect(spy.mock.calls[0]?.[0]).toMatchObject({ grantId, store: "user_session" });
		} finally {
			spy.mockRestore();
		}
	});

	it("binds the flow to the admitted record's sid: a store answering a record whose sid is not its key fails closed at the consent", async () => {
		// The binding's sid is the record admission read, not the cookie's: a
		// store that answers a record under another sid — a deployment's own
		// store gone wrong — leaves a challenge no browser can read or answer.
		const w = world();
		const { handle } = await w.lodge();
		const sid = w.signIn("b-1");
		const durable = w.durable.get(sid) as UserSession;
		w.durable.set(sid, { ...durable, sid: "sid-somebody-else" });
		const connected = await w.connect(handle, "b-1");
		expect(connected.status).toBe(303);
		const challenge =
			new URL(connected.headers.location as string, ISSUER).searchParams.get("challenge") ?? "";
		const read = await w.page(challenge, "b-1");
		expect(read.status).toBe(400);
		expect(read.body).toEqual(noPending);
		expect((await w.answer({ challenge, decision: "accept" }, "b-1")).status).toBe(400);
		expect(w.authorized).toEqual([]);
	});

	it("registers admission's audit write with the drain, as every audit write of this router is", async () => {
		// A shutdown that has begun waits for the subject-mismatch event
		// admission writes, as it waits for the route's own.
		const w = world();
		const { handle } = await w.lodge();
		w.browsers.set("b-1", { isAuthenticated: true, user: { id: "alice" }, sid: "sid-bob" });
		w.durable.set("sid-bob", {
			sid: "sid-bob",
			sub: "bob",
			authTime: w.state.now,
			createdAt: w.state.now,
			expiresAt: new Date(w.state.now.getTime() + DAY),
			claims: {},
			...passwordSessionAuthentication(),
		});
		let release = (): void => undefined;
		w.state.auditGates.set(
			"session.admission.subject_mismatch",
			new Promise<void>((resolve) => {
				release = resolve;
			}),
		);
		expect((await w.connect(handle, "b-1")).status).toBe(403);
		let drained = false;
		const draining = w.background.drain().then(() => {
			drained = true;
		});
		await new Promise((resolve) => setImmediate(resolve));
		expect(drained).toBe(false);
		release();
		await draining;
		expect(w.events.map((event) => event.type)).toContain("session.admission.subject_mismatch");
	});

	it("refuses to be built without the subject revocation it reads the sessions boundary through: no boundary is no backstop", () => {
		expect(() =>
			createFederationGrantBrowserRouter({
				requirements: resolverForTests([], { actions: FEDERATION_GRANTS_ADMISSION_ACTIONS }),
			} as never),
		).toThrow(
			new TypeError(
				"createFederationGrantBrowserRouter: subjectRevocation is required — the sessions " +
					"boundary a session must have authenticated after is read through it",
			),
		);
	});

	it("refuses to be built on an issuer that is not an absolute http(s) URL: the consent location and the connect URI are built on it, and on mailto:, urn: or data: each would throw, a 500 on every request", () => {
		for (const issuer of [
			"mailto:admin@example.com",
			"urn:example:issuer",
			"data:text/plain,issuer",
			"auth.test/relative",
			"/relative",
		]) {
			expect(() => world({ issuer }), issuer).toThrow(/issuer/);
		}
	});

	it("refuses to be built without requirements, or with a resolver the planner did not build, naming the factory", () => {
		expect(() => createFederationGrantBrowserRouter({} as never)).toThrow(
			/^createFederationGrantBrowserRouter: requirements is required/,
		);
		const forged = { get: () => undefined, entries: () => [][Symbol.iterator]() };
		expect(() => createFederationGrantBrowserRouter({ requirements: forged } as never)).toThrow(
			/^createFederationGrantBrowserRouter: requirements must be the sessionRequirementResolver the boot planner built/,
		);
	});

	it("refuses to be built on a resolver on which a step's action is not registered, naming the factory and the action", () => {
		expect(() =>
			createFederationGrantBrowserRouter({
				requirements: resolverForTests([], {
					actions: {
						"federation_grants.connect": { grade: "use" },
						"federation_grants.consent": { grade: "use" },
					},
				}),
			} as never),
		).toThrow(
			/^createFederationGrantBrowserRouter: admits "federation_grants\.callback", which no module registers/,
		);
	});
});
