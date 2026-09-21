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
						}
					: undefined,
			consentUrl: "/consent/grants",
			loginUrl: () => "/login",
			issuer: ISSUER,
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
