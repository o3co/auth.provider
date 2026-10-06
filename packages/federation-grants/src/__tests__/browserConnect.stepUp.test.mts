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
 * `GET /connect` when session admission asks the session to step up: one trip
 * to the requirement's page, returning to this link with a one-trip marker,
 * and a plain `403` for a marked return that is still asked to step up. The
 * marker carries no authority: it only narrows what connect does.
 *
 * Mounted for real over the in-memory intent and grant stores, behind a
 * stand-in for express-session; the durable sessions, the requirement and the
 * upstream are doubles. A renewal is modelled as the step-up's finish is: a
 * new express session id holding the same durable `sid`.
 */

import { randomUUID } from "node:crypto";
import {
	type AuditEvent,
	createInMemorySessionLifecycleStore,
	createMemoryFederationGrantIntentStore,
	createMemoryFederationGrantStore,
	createMemoryRateLimiter,
	type FederationGrantAcquisitionConnection,
	lodgeFederationGrantIntent,
	passwordSessionAuthentication,
	type RequirementInput,
	type RequirementVerdict,
	type SessionLifecycleStore,
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
import { describe, expect, it } from "vitest";
import { FEDERATION_GRANTS_ADMISSION_ACTIONS } from "#/admissionActions.mjs";
import { createFederationGrantBackground } from "#/background.mjs";
import {
	createFederationGrantBrowserRouter,
	FEDERATION_GRANTS_BROWSER_MOUNT_PATH,
} from "#/browserRoutes.mjs";
import { createLogSpy, payloadOf, written } from "./logSpy.mjs";

const ISSUER = "https://auth.test";
const REDIRECT = "https://client.test/connected";
const DAY = 86_400_000;
const CONNECT_PATH = `${FEDERATION_GRANTS_BROWSER_MOUNT_PATH}/connect`;
const STEP_UP_PAGE = `${ISSUER}/step-up`;

const CONNECTION: FederationGrantAcquisitionConnection = {
	name: "calendar",
	federation: "upstream",
	upstreamIssuer: "https://issuer.example",
	upstreamClientId: "provider-client",
	scopes: ["openid", "offline_access", "calendar.read"],
	boundary: "production",
	maxAccessTokenLifetime: 3600,
	callbackUri: `${ISSUER}/session/federation-grants/callback/calendar`,
};

const CLIENT = {
	clientId: "worker",
	tokenEndpointAuthMethod: "client_secret_basic" as const,
	clientName: "Calendar Agent",
	allowedFederationGrantConnections: ["calendar"],
	federationGrantRedirectUris: [REDIRECT],
};

const STEP_UP: RequirementVerdict = { outcome: "step_up", whenStillUnmet: "reauthenticate" };
const MET: RequirementVerdict = { outcome: "met" };

interface Browser {
	readonly isAuthenticated: boolean;
	readonly user?: { readonly id: string };
	readonly sid?: string;
}

interface WorldOptions {
	/** The origin the requirement's page is registered on; the issuer's by default. */
	readonly pageIssuer?: string;
	/** Wires no durable session store: admission then admits with no record to bind to. */
	readonly withoutUserSessionStore?: boolean;
}

function world(options: WorldOptions = {}) {
	const grants = createMemoryFederationGrantStore();
	const intents = createMemoryFederationGrantIntentStore();
	const background = createFederationGrantBackground();
	const events: AuditEvent[] = [];
	const browsers = new Map<string, Browser>();
	// Core's lifecycle store: every durable session written opens its record,
	// active, as the login that wrote it does (a session with no record reads
	// as closed).
	const records = createInMemorySessionLifecycleStore();
	const opening: Promise<unknown>[] = [];
	const durable = new (class extends Map<string, UserSession> {
		override set(sid: string, session: UserSession): this {
			opening.push(records.open(sid, session.sub, new Date(Date.now() + 86_400_000)));
			return super.set(sid, session);
		}
	})();
	const openedRecords: SessionLifecycleStore = {
		...records,
		read: async (sid) => {
			await Promise.all(opening);
			return records.read(sid);
		},
	};
	const spy = createLogSpy();
	const state = {
		now: new Date(Date.now() + 3 * DAY),
		/** What the fixture requirement answers, per question. */
		verdict: (_input: RequirementInput): RequirementVerdict => MET,
		/** Every action the requirement was asked, in order. */
		asked: [] as string[],
		/** Every consent parked, by the browser it was parked for. */
		parked: [] as string[],
		/** Every upstream authorization URL built: none is, before a consent answer. */
		authorized: 0,
	};
	const now = () => state.now;

	const requirement: SessionRequirement = {
		name: "fixture",
		reach: new Set<string>(),
		stepUpPage: { url: "/step-up", params: {} },
		remediations: [],
		hintKeys: [],
		admit: async (input) => {
			state.asked.push(input.action.name);
			return state.verdict(input);
		},
	};

	const recordingIntents = new Proxy(intents, {
		get(target, key) {
			const value = Reflect.get(target, key);
			if (key === "parkConsent" && typeof value === "function") {
				return async (input: { binding: { sessionId: string } }) => {
					state.parked.push(input.binding.sessionId);
					return await value.call(target, input);
				};
			}
			return typeof value === "function" ? value.bind(target) : value;
		},
	});

	const app = express();
	app.set("trust proxy", "loopback");
	app.use((req, _res, next) => {
		const id = req.get("x-browser");
		if (id !== undefined && browsers.has(id)) {
			(req as unknown as { sessionID: string }).sessionID = id;
			(req as unknown as { session: Browser }).session = browsers.get(id) as Browser;
		}
		next();
	});
	app.use(
		FEDERATION_GRANTS_BROWSER_MOUNT_PATH,
		createFederationGrantBrowserRouter({
			intentStore: recordingIntents,
			grantStore: grants,
			// Behind core's client-record boundary, as boot installs it in the
			// `clientRepository` slot the module hands the router.
			clientRepository: validatedClientRepository(
				{
					findById: async (id: string) => (id === CLIENT.clientId ? (CLIENT as never) : null),
					authenticate: async () => null,
				},
				{ logger: spy.logger },
			),
			userSessionStore:
				options.withoutUserSessionStore === true
					? (undefined as never)
					: ({ get: async (sid: string) => durable.get(sid) ?? null } as never),
			sessionLifecycleStore: openedRecords,
			subjectRevocation: {
				kind: "test",
				revokeBefore: async () => undefined,
				revokedBefore: async () => null,
			},
			requirements: resolverForTests([requirement], {
				issuer: options.pageIssuer ?? ISSUER,
				actions: FEDERATION_GRANTS_ADMISSION_ACTIONS,
			}),
			revocationSkewMs: 1000,
			connections: new Map([[CONNECTION.name, CONNECTION]]),
			authorizerFor: () => ({
				buildDelegatedAuthorizationUrl: () => {
					state.authorized += 1;
					return new URL("https://issuer.example/authorize");
				},
				exchangeDelegatedCode: async () => {
					throw new Error("not reached");
				},
			}),
			consentUrl: "/consent/grants",
			login: createTestLoginEntry("/login"),
			csrfGuard: createTestCsrfGuard(),
			issuer: ISSUER,
			grantsBoundary: async () => null,
			identityLookup: "unsupported",
			logger: spy.logger,
			upstreamTimeoutMs: 5_000,
			rateLimiter: createMemoryRateLimiter({
				limits: {},
				defaultLimit: { limit: 1000, windowSeconds: 60 },
			}),
			background,
			now,
			randomId: () => randomUUID(),
			auditSink: {
				kind: "test",
				record: async (event) => {
					events.push(event);
				},
			},
		}),
	);

	const lodge = async (subject = "alice") => {
		const lodged = await lodgeFederationGrantIntent(
			{
				grantStore: grants,
				intentStore: intents,
				connections: new Map([[CONNECTION.name, CONNECTION]]),
				limits: { defaultLifetimeMs: 30 * DAY, maxLifetimeMs: 30 * DAY },
				now,
				grantsRevokedBefore: async () => null,
				revocationSkewMs: 1000,
				maxExpiresInMs: 30 * DAY,
			},
			{
				client: CLIENT,
				connection: CONNECTION.name,
				subject,
				redirectUri: REDIRECT,
				clientState: "client-state-1",
				correlationId: "corr-1",
			},
		);
		if (!lodged.ok) throw new Error(`fixture: ${lodged.reason}`);
		return lodged;
	};

	/** A signed-in browser for `subject`, over a live durable session of its own. */
	const signIn = (browser: string, subject = "alice") => {
		const sid = `sid-${browser}`;
		browsers.set(browser, { isAuthenticated: true, user: { id: subject }, sid });
		durable.set(sid, {
			sid,
			sub: subject,
			authTime: state.now,
			createdAt: state.now,
			expiresAt: new Date(state.now.getTime() + DAY),
			claims: {},
			...passwordSessionAuthentication(),
		});
		return sid;
	};

	/** The step-up's finish: the express session renewed, the durable session kept. */
	const renew = (from: string, to: string) => {
		browsers.set(to, browsers.get(from) as Browser);
		browsers.delete(from);
	};

	/** `GET` a path-and-query on this app, as `browser` when one is named. */
	const get = (pathAndQuery: string, browser?: string) => {
		const call = request(app).get(pathAndQuery);
		return browser === undefined ? call : call.set("x-browser", browser);
	};

	const connect = (handle: string, browser?: string, extra: Record<string, string> = {}) =>
		get(`${CONNECT_PATH}?${new URLSearchParams({ request: handle, ...extra })}`, browser);

	/** Follows an absolute URL on the issuer, as the browser does. */
	const follow = (location: string, browser?: string) => {
		const url = new URL(location);
		expect(url.origin).toBe(ISSUER);
		return get(`${url.pathname}${url.search}`, browser);
	};

	const audited = async (): Promise<AuditEvent[]> => {
		await background.drain();
		return events.filter((event) => event.type === "federation.grant.authorization_failed");
	};

	return {
		app,
		intents,
		state,
		lines: spy.lines,
		lodge,
		signIn,
		renew,
		connect,
		follow,
		audited,
		durable,
		browsers,
	};
}

/** Answers `verdict` at connect for any session whose `sid` has not stepped up; met otherwise. */
const stepUpAtConnect =
	(steppedUp: ReadonlySet<string>, verdict: RequirementVerdict = STEP_UP) =>
	(input: RequirementInput): RequirementVerdict =>
		input.action.name === "federation_grants.connect" && !steppedUp.has(input.session?.sid ?? "")
			? verdict
			: MET;

/** The connect URI this test expects a trip to return to: the handle and the marker, nothing else. */
const markedReturn = (handle: string): string => {
	const url = new URL(`${ISSUER}${CONNECT_PATH}`);
	url.searchParams.set("request", handle);
	url.searchParams.set("stepped_up", "1");
	return url.href;
};

/** The `redirect_to` a step-up trip's `Location` carries, after checking the page. */
const tripReturnOf = (location: string): string => {
	const target = new URL(location);
	expect(`${target.origin}${target.pathname}`).toBe(STEP_UP_PAGE);
	expect([...target.searchParams.keys()]).toEqual(["redirect_to"]);
	return target.searchParams.get("redirect_to") ?? "";
};

const consentChallengeOf = (location: string): string | null => {
	const url = new URL(location);
	expect(url.pathname).toBe("/consent/grants");
	return url.searchParams.get("challenge");
};

describe("GET /connect — a session a requirement steps up", () => {
	it("sends the browser to the requirement's page, returning to this link with the one-trip marker; nothing is parked or audited", async () => {
		const w = world();
		w.state.verdict = stepUpAtConnect(new Set());
		const { handle } = await w.lodge();
		w.signIn("b-1");

		const response = await w.connect(handle, "b-1");

		expect(response.status).toBe(303);
		expect(tripReturnOf(response.headers.location as string)).toBe(markedReturn(handle));
		expect(w.state.parked).toEqual([]);
		expect(await w.audited()).toEqual([]);
	});

	it("answers a marked return that is still asked to step up with the plain 403 a dead session gets, audited, and never sends it again", async () => {
		const w = world();
		w.state.verdict = stepUpAtConnect(new Set());
		const { handle, grantId } = await w.lodge();
		w.signIn("b-1");
		const trip = await w.connect(handle, "b-1");

		const back = await w.follow(tripReturnOf(trip.headers.location as string), "b-1");

		expect(back.status).toBe(403);
		expect(back.headers["content-type"]).toMatch(/^text\/plain/);
		expect(back.text).toBe("Sign in again to continue.");
		expect(back.headers.location).toBeUndefined();
		expect(w.state.parked).toEqual([]);
		expect(await w.audited()).toEqual([
			expect.objectContaining({
				details: expect.objectContaining({ grantId, outcome: "reauthentication_required" }),
			}),
		]);
	});

	it.each([
		["marked", true],
		["unmarked", false],
	])("parks the consent for a session that stepped up, %s", async (_name, marked) => {
		const w = world();
		const steppedUp = new Set<string>();
		w.state.verdict = stepUpAtConnect(steppedUp);
		const { handle } = await w.lodge();
		const sid = w.signIn("b-1");
		const trip = await w.connect(handle, "b-1");
		const markedLink = tripReturnOf(trip.headers.location as string);

		// The step-up page's finish: the factor recorded, the express session renewed.
		steppedUp.add(sid);
		w.renew("b-1", "b-1r");
		const back = marked ? await w.follow(markedLink, "b-1r") : await w.connect(handle, "b-1r");

		expect(back.status).toBe(303);
		expect(consentChallengeOf(back.headers.location as string)).toEqual(expect.any(String));
		expect(w.state.parked).toEqual(["b-1r"]);
		expect(await w.audited()).toEqual([]);
	});

	it("answers 'start again' to a session that stepped up after its consent was parked under the binding before the renewal, and keeps that binding", async () => {
		const w = world();
		const steppedUp = new Set<string>();
		const { handle } = await w.lodge();
		const sid = w.signIn("b-1");
		// Parked before any requirement asked for a step-up.
		const first = await w.connect(handle, "b-1");
		const challenge = consentChallengeOf(first.headers.location as string) ?? "";

		w.state.verdict = stepUpAtConnect(steppedUp);
		const trip = await w.connect(handle, "b-1");
		expect(trip.status).toBe(303);
		steppedUp.add(sid);
		w.renew("b-1", "b-1r");
		const back = await w.follow(tripReturnOf(trip.headers.location as string), "b-1r");

		expect(back.status).toBe(400);
		expect(back.text).toBe("This link has expired or has already been used. Start again.");
		expect((await w.intents.getConsent(challenge, w.state.now))?.binding).toEqual({
			sessionId: "b-1",
			sid,
			subject: "alice",
		});
		expect((await w.audited()).map((event) => event.details?.outcome)).toEqual(["stale"]);
	});

	it("allows one more trip after a new login: a marked return on a cookie session that ended is sent to log in without the marker", async () => {
		const w = world();
		w.state.verdict = stepUpAtConnect(new Set());
		const { handle } = await w.lodge();
		w.signIn("b-1");
		const first = await w.connect(handle, "b-1");
		const markedLink = tripReturnOf(first.headers.location as string);

		// The cookie session ended before the browser came back.
		w.browsers.delete("b-1");
		const login = await w.follow(markedLink);
		expect(login.status).toBe(303);
		const loginPage = new URL(login.headers.location as string, ISSUER);
		expect(loginPage.pathname).toBe("/login");
		const loginReturn = loginPage.searchParams.get("redirect_to") ?? "";
		expect([...new URL(loginReturn).searchParams.keys()]).toEqual(["request"]);

		// The new login: one more trip, then a refusal.
		w.signIn("b-2");
		const second = await w.follow(loginReturn, "b-2");
		expect(second.status).toBe(303);
		const back = await w.follow(tripReturnOf(second.headers.location as string), "b-2");
		expect(back.status).toBe(403);
		expect(w.state.parked).toEqual([]);
	});

	it("keeps the consent's dead-session answer to a step-up: connect has gated, and only connect takes a trip", async () => {
		const w = world();
		const { handle } = await w.lodge();
		w.signIn("b-1");
		const connected = await w.connect(handle, "b-1");
		const challenge = consentChallengeOf(connected.headers.location as string) ?? "";
		w.state.verdict = (input) =>
			input.action.name === "federation_grants.consent" ? STEP_UP : MET;

		const read = await request(w.app)
			.get(`${FEDERATION_GRANTS_BROWSER_MOUNT_PATH}/consent`)
			.query({ challenge })
			.set("x-browser", "b-1");

		expect(read.status).toBe(403);
		expect(read.body).toEqual({
			error: "reauthentication_required",
			error_description: "sign in again to continue",
		});
		expect(read.headers.location).toBeUndefined();
	});

	it("refuses a session admission admits with no record to bind to, as a dead session, and parks nothing", async () => {
		const w = world({ withoutUserSessionStore: true });
		const { handle, grantId } = await w.lodge();
		w.signIn("b-1");

		const response = await w.connect(handle, "b-1");

		expect(response.status).toBe(403);
		expect(response.text).toBe("Sign in again to continue.");
		expect(response.headers.location).toBeUndefined();
		expect(w.state.parked).toEqual([]);
		expect(await w.audited()).toEqual([
			expect.objectContaining({
				details: expect.objectContaining({ grantId, outcome: "reauthentication_required" }),
			}),
		]);
	});

	it("never follows a page off the issuer's origin: a plain 500 and one error line naming the requirement", async () => {
		const w = world({ pageIssuer: "https://elsewhere.test" });
		w.state.verdict = stepUpAtConnect(new Set());
		const { handle, grantId } = await w.lodge();
		w.signIn("b-1");

		const response = await w.connect(handle, "b-1");

		expect(response.status).toBe(500);
		expect(response.headers["content-type"]).toMatch(/^text\/plain/);
		expect(response.headers.location).toBeUndefined();
		expect(response.text).not.toContain("elsewhere");
		expect(written(w.lines)).toContain("error federation_grant_step_up_page_off_origin");
		expect(payloadOf(w.lines, "federation_grant_step_up_page_off_origin")).toMatchObject({
			requirement: "fixture",
			grantId,
		});
		expect(w.state.parked).toEqual([]);
	});
});

describe("GET /connect — the one-trip marker carries no authority", () => {
	it("builds the return from the issuer and the handle alone: no parameter, Host or forwarded origin a request carries reaches it", async () => {
		const w = world();
		w.state.verdict = stepUpAtConnect(new Set());
		const { handle } = await w.lodge();
		w.signIn("b-1");

		const response = await w
			.connect(handle, "b-1", {
				redirect_to: "https://evil.example/",
				return_to: "https://evil.example/",
				next: "//evil.example/",
			})
			.set("Host", "evil.example")
			.set("X-Forwarded-Host", "evil.example")
			.set("X-Forwarded-Proto", "http");

		expect(response.status).toBe(303);
		expect(new URL(response.headers.location as string).origin).toBe(ISSUER);
		expect(tripReturnOf(response.headers.location as string)).toBe(markedReturn(handle));
		expect(response.headers.location).not.toContain("evil");
	});

	it("refuses a forged marker on a first visit with the plain 403, never a pass", async () => {
		const w = world();
		w.state.verdict = stepUpAtConnect(new Set());
		const { handle } = await w.lodge();
		w.signIn("b-1");

		const response = await w.connect(handle, "b-1", { stepped_up: "1" });

		expect(response.status).toBe(403);
		expect(response.text).toBe("Sign in again to continue.");
		expect(w.state.parked).toEqual([]);
		expect(w.state.asked).toEqual(["federation_grants.connect"]);
	});

	it("skips no admission: a marked connect is still judged, and refused, when the session is gone, the cookie unauthenticated, or the subject another", async () => {
		const w = world();
		const { handle } = await w.lodge();

		// The durable session is gone.
		const sid = w.signIn("b-1");
		w.durable.delete(sid);
		const gone = await w.connect(handle, "b-1", { stepped_up: "1" });
		expect(gone.status).toBe(403);
		expect(gone.text).toBe("Sign in again to continue.");

		// Not signed in: the login trip, which does not carry the marker.
		const anonymous = await w.connect(handle, undefined, { stepped_up: "1" });
		expect(anonymous.status).toBe(303);
		const back = new URL(
			new URL(anonymous.headers.location as string, ISSUER).searchParams.get("redirect_to") ?? "",
		);
		expect(back.searchParams.has("stepped_up")).toBe(false);

		// Another subject's session.
		w.signIn("b-2", "mallory");
		const other = await w.connect(handle, "b-2", { stepped_up: "1" });
		expect(other.status).toBe(403);
		expect(other.text).toBe("This request was made for another account.");

		expect(w.state.parked).toEqual([]);
	});

	it("bypasses no consent: a marked connect an admitted session makes only parks the question and sends the browser to the consent page", async () => {
		const w = world();
		const { handle } = await w.lodge();
		w.signIn("b-1");

		const response = await w.connect(handle, "b-1", { stepped_up: "1" });

		expect(response.status).toBe(303);
		expect(consentChallengeOf(response.headers.location as string)).toEqual(expect.any(String));
		expect(w.state.authorized).toBe(0);
		expect(w.state.parked).toEqual(["b-1"]);
	});

	it.each([
		["a value other than 1", { stepped_up: "0" }],
		["an empty value", { stepped_up: "" }],
	])("reads %s as no marker: the trip is offered, never skipped", async (_name, extra) => {
		const w = world();
		w.state.verdict = stepUpAtConnect(new Set());
		const { handle } = await w.lodge();
		w.signIn("b-1");

		const response = await w.connect(handle, "b-1", extra);

		expect(response.status).toBe(303);
		expect(tripReturnOf(response.headers.location as string)).toBe(markedReturn(handle));
	});
});
