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
 * The browser half of acquisition (#593, D7, D8, slice 6): `GET /connect` and
 * the consent the deployment's page reads and answers.
 *
 * Mounted for real, behind a stand-in for express-session, over the real
 * lodging function and the real in-memory stores. What is faked is the world
 * outside the provider: which browser is asking, the durable sessions, the
 * subject's boundary, and the upstream's authorization endpoint.
 */

import {
	type AuditEvent,
	createMemoryFederationGrantIntentStore,
	createMemoryFederationGrantStore,
	createMemoryRateLimiter,
	type FederationGrantAcquisitionConnection,
	lodgeFederationGrantIntent,
	lodgeFederationGrantReauthorization,
	type RateLimiter,
	type UserSession,
} from "@o3co/auth-provider-core";
import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createFederationGrantBackground } from "#/background.mjs";
import {
	createFederationGrantBrowserRouter,
	FEDERATION_GRANTS_BROWSER_MOUNT_PATH,
	type FederationGrantDelegatedAuthorizer,
} from "#/browserRoutes.mjs";

const ISSUER = "https://auth.test";
const REDIRECT = "https://client.test/connected";
const DAY = 86_400_000;

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
	clientName: "Calendar Agent",
	allowedFederationGrantConnections: ["calendar"],
	federationGrantRedirectUris: [REDIRECT],
};

interface Browser {
	readonly isAuthenticated: boolean;
	readonly user?: { readonly id: string };
	readonly sid?: string;
}

function world(options: { rateLimiter?: RateLimiter } = {}) {
	const grants = createMemoryFederationGrantStore();
	const intents = createMemoryFederationGrantIntentStore();
	const background = createFederationGrantBackground();
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
		/** Which local user an upstream subject is already linked to. */
		linked: new Map<string, string>(),
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
		exchangeThrows: undefined as Error | undefined,
		exchanged: [] as Record<string, unknown>[],
	};
	const now = () => state.now;

	const app = express();
	// A stand-in for express-session: which browser this is comes from a header.
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
			intentStore: intents,
			grantStore: grants,
			clientRepository: {
				findById: async (id: string) => (id === CLIENT.clientId ? (state.client as never) : null),
				authenticate: async () => null,
			} as never,
			userSessionStore: {
				get: async (sid: string) => durable.get(sid) ?? null,
			} as never,
			sessionsBoundary: async () => {
				if (state.sessionsBoundary instanceof Error) throw state.sessionsBoundary;
				return state.sessionsBoundary;
			},
			revocationSkewMs: 1000,
			connections: {
				get: (name: string) => state.connections.get(name),
			} as ReadonlyMap<string, FederationGrantAcquisitionConnection>,
			authorizerFor: (federation) =>
				federation === "upstream"
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
								if (typeof tokens.expiresIn === "number" && !("expiresAt" in tokens)) {
									tokens.expiresAt = new Date(state.now.getTime() + tokens.expiresIn * 1000);
								}
								return { upstream: { ...state.exchange.upstream }, tokens } as never;
							},
						}
					: undefined,
			consentUrl: "/consent/grants",
			loginUrl: () => "/login",
			issuer: ISSUER,
			grantsBoundary: async () => {
				if (state.grantsBoundary instanceof Error) throw state.grantsBoundary;
				return state.grantsBoundary;
			},
			identityLookup: "required",
			userRepository: {
				findSubjectByFederatedIdentity: async ({ sub }) => state.linked.get(sub) ?? null,
			},
			upstreamTimeoutMs: 5_000,
			rateLimiter:
				options.rateLimiter ??
				createMemoryRateLimiter({ limits: {}, defaultLimit: { limit: 1000, windowSeconds: 60 } }),
			failMode: "closed",
			background,
			now,
			auditSink: { kind: "test", record: async (event) => void events.push(event) },
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
		} as UserSession);
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

	const answer = (
		body: Record<string, unknown>,
		browser: string,
		headers: Record<string, string> = {},
	) =>
		request(app)
			.post(`${FEDERATION_GRANTS_BROWSER_MOUNT_PATH}/consent`)
			.set("x-browser", browser)
			.set(headers)
			.send(body);

	return {
		app,
		grants,
		intents,
		background,
		events,
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
		expect(foreign.body.error_description).toMatch(/no pending consent/);
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
			},
			credentials: {
				refreshToken: "rt",
				accessToken: {
					value: "at",
					tokenType: "Bearer",
					obtainedAt: w.state.now,
					issuedLifetime: 3600,
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
		expect((await w.answer({ challenge, decision: "maybe" }, "b-1")).status).toBe(400);
		const crossSite = await w.answer({ challenge, decision: "accept" }, "b-1", {
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

// ---------------------------------------------------------------------------
// The callback (D7): eight checks, then the activation.
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
			details: { grantId, connection: CONNECTION.name, outcome: "required" },
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
		w.state.linked.set("00u-alice", "bob");
		expect(returned(await callback(w, { state: a.state, code: "c" }, "b-1")).get("error")).toBe(
			"identity_conflict",
		);
		// Linked to this very user is fine.
		const b = await approved(w, "b-2");
		w.state.linked.set("00u-alice", "alice");
		expect(returned(await callback(w, { state: b.state, code: "c" }, "b-2")).has("error")).toBe(
			false,
		);
		w.state.linked.clear();
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
			[{ scope: "openid offline_access calendar.read admin" }, "scope_exceeded"],
			[{ scope: "" }, "upstream_token_ineligible"],
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

	it("keeps what the upstream narrowed to, and reads an omitted scope as the one requested", async () => {
		const w = world();
		const a = await approved(w, "b-1");
		w.state.exchange = {
			...w.state.exchange,
			tokens: { ...w.state.exchange.tokens, scope: "openid offline_access" },
		};
		returned(await callback(w, { state: a.state, code: "c" }, "b-1"));
		expect((await w.grants.find(a.grantId, w.state.now)) as { scopes: string[] }).toMatchObject({
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

describe("the callback for a renewal", () => {
	/** An active grant, then a renewal lodged, connected and approved in a second browser. */
	async function renewal(w: World) {
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
		const challenge = await w.challengeFor(lodged.handle, "b-2");
		const answered = await w.answer({ challenge, decision: "accept" }, "b-2");
		const state = new URL(answered.headers.location as string).searchParams.get("state") ?? "";
		const before = await w.grants.find(first.grantId, w.state.now);
		return { grantId: first.grantId, state, before };
	}

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
		expect(await w.grants.find(grantId, w.state.now)).toEqual(before);
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

describe("rules the first draft of these tests did not reach", () => {
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
		} as UserSession);
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

describe("what the browser-half mutation pass found", () => {
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
		const { handle } = await w.lodge();
		w.browsers.set("b-1", { isAuthenticated: true, user: { id: "alice" }, sid: "sid-bob" });
		w.durable.set("sid-bob", {
			sid: "sid-bob",
			sub: "bob",
			authTime: w.state.now,
			createdAt: w.state.now,
			expiresAt: new Date(w.state.now.getTime() + DAY),
			claims: {},
		} as UserSession);
		expect((await w.connect(handle, "b-1")).status).toBe(403);
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

describe("shutting down (Codex on slice 6)", () => {
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
});
