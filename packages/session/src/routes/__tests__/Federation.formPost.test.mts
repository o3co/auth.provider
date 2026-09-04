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
 * `response_mode=form_post` federations (#479).
 *
 * Three properties are under test here, and the third is the reason the other
 * two exist:
 *
 * 1. a provider that declares `responseMode: "form_post"` gets the parameter
 *    on its authorization URL, a POST callback, and a `SameSite=None; Secure`
 *    federation *transaction* cookie of its own — and a provider that declares
 *    nothing gets none of it, nor does the application session cookie change
 *    for either (#494);
 * 2. the POST callback's state / CSRF / PKCE / nonce binding is the GET
 *    callback's, not a second implementation that drifts from it;
 * 3. a fake Apple — form_post, `user` body on first authorization, string
 *    `email_verified`, nonce echoed — logs in end to end and lands its
 *    `email` / `name` in the session's claims envelope under the existing
 *    promotion rules.
 */

import type { UserRepository } from "@o3co/auth-provider-core";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { codeChallenge } from "#/federations/pkce.mjs";
import { FEDERATION_TRANSACTION_KEY_PREFIX } from "#/federations/transaction.mjs";
import type { FederationProfile, FederationProvider } from "#/federations/types.mjs";
import {
	buildFederationApp,
	HARNESS_TRANSACTION_COOKIE_NAME,
	makeUserRepository,
} from "./federation-harness.mjs";

const APPLE_CALLBACK_URL = "https://app.example.com/session/oauth/federation/apple/callback";
const QUERY_CALLBACK_URL = "https://app.example.com/session/oauth/federation/query-idp/callback";

// ---------------------------------------------------------------------------
// Fake Apple
// ---------------------------------------------------------------------------

type ExchangeCall = Parameters<FederationProvider["exchangeCode"]>[0];

/**
 * A provider shaped like Sign in with Apple: form_post response mode, an
 * id_token whose `email_verified` is the *string* `"true"`, an
 * `is_private_email` relay marker, and a display name that exists only in the
 * `user` field of the first authorization's POST body.
 */
function makeFakeApple(): FederationProvider & {
	calls: ExchangeCall[];
	mapClaims: (p: FederationProfile) => Record<string, unknown>;
} {
	const calls: ExchangeCall[] = [];
	return {
		name: "apple",
		scope: ["name", "email"],
		responseMode: "form_post",
		calls,
		buildAuthorizationUrl: ({ redirectUri, state, codeVerifier, nonce }) => {
			const url = new URL("https://appleid.apple.com/auth/authorize");
			url.searchParams.set("redirect_uri", redirectUri);
			url.searchParams.set("state", state);
			url.searchParams.set("code_challenge", codeChallenge(codeVerifier));
			url.searchParams.set("code_challenge_method", "S256");
			if (nonce) url.searchParams.set("nonce", nonce);
			return url;
		},
		exchangeCode: async (params) => {
			calls.push(params);
			if (!params.nonce) throw new Error("fake Apple requires a nonce");

			// Apple's id_token: `email_verified` arrives as a string on some
			// responses, and the name is never in it.
			const idTokenClaims: Record<string, unknown> = {
				sub: "000123.abcdef.0456",
				email: "sxyz@privaterelay.appleid.com",
				email_verified: "true",
				is_private_email: "true",
				nonce: params.nonce,
			};

			// The name comes from the POST body, once, on first authorization.
			let name: string | undefined;
			const rawUser = params.callbackParams?.user;
			if (typeof rawUser === "string" && rawUser.length > 0) {
				const parsed = JSON.parse(rawUser) as { name?: { firstName?: string; lastName?: string } };
				const parts = [parsed.name?.firstName, parsed.name?.lastName].filter(
					(p): p is string => typeof p === "string" && p.length > 0,
				);
				if (parts.length > 0) name = parts.join(" ");
			}

			return {
				issuer: "https://appleid.apple.com",
				sub: String(idTokenClaims.sub),
				email: String(idTokenClaims.email),
				emailVerified: idTokenClaims.email_verified === "true",
				isPrivateEmail: idTokenClaims.is_private_email === "true",
				...(name ? { name } : {}),
				accessToken: "apple-at",
				refreshToken: "apple-rt",
				idToken: "apple-id-token",
				expiresAt: new Date(Date.now() + 3_600_000),
			} satisfies FederationProfile;
		},
		mapClaims: (profile: FederationProfile) => {
			const claims: Record<string, unknown> = {};
			if (typeof profile.email === "string") claims.email = profile.email;
			if (typeof profile.emailVerified === "boolean") claims.emailVerified = profile.emailVerified;
			if (typeof profile.name === "string") claims.name = profile.name;
			if (typeof profile.isPrivateEmail === "boolean")
				claims.isPrivateEmail = profile.isPrivateEmail;
			return claims;
		},
	};
}

/** A plain query-mode provider — the shape every pre-#479 federation has. */
function makeQueryProvider(): FederationProvider {
	return {
		name: "query-idp",
		scope: ["openid"],
		buildAuthorizationUrl: ({ state, codeVerifier }) => {
			const url = new URL("https://idp.example.com/authorize");
			url.searchParams.set("state", state);
			url.searchParams.set("code_challenge", codeChallenge(codeVerifier));
			return url;
		},
		exchangeCode: vi.fn(async () => ({
			issuer: "https://idp.example.com",
			sub: "query-sub",
			expiresAt: null,
		})),
	};
}

function buildApp(opts: { userRepository?: UserRepository } = {}) {
	const apple = makeFakeApple();
	const queryProvider = makeQueryProvider();
	const harness = buildFederationApp({
		providers: new Map<string, FederationProvider>([
			["apple", apple],
			["query-idp", queryProvider],
		]),
		providerCallbackUrls: new Map([
			["apple", APPLE_CALLBACK_URL],
			["query-idp", QUERY_CALLBACK_URL],
		]),
		...opts,
	});
	return { ...harness, apple, queryProvider };
}

type StartedFlow = {
	sid: string;
	/** The opaque transaction id, for a form_post federation. */
	transactionId?: string;
	state: string;
	nonce: string;
	codeVerifier: string;
	startResponse: request.Response;
	/** POST the callback carrying this flow's cookies. */
	post: (body: Record<string, string>) => request.Test;
	/** GET the callback carrying this flow's cookies. */
	get: (query: Record<string, string>) => request.Test;
};

/** Every `Set-Cookie` the start leg emitted, as one blob. */
function setCookieHeader(res: request.Response): string {
	return ((res.headers["set-cookie"] as unknown as string[]) ?? []).join("\n");
}

/** The transaction id the start leg put in its cookie, if it issued one. */
function readTransactionCookie(res: request.Response): string | undefined {
	const match = setCookieHeader(res).match(
		new RegExp(`${HARNESS_TRANSACTION_COOKIE_NAME}=([^;\n]*)`),
	);
	if (!match?.[1]) return undefined;
	return decodeURIComponent(match[1]);
}

/**
 * Drive the start leg and read back the ephemeral state the route persisted.
 *
 * Where that state lives is the whole of #494: a `"query"` federation still
 * keeps it in the session, while a `"form_post"` federation keeps it in a
 * transaction record addressed by a cookie of its own. This helper reads
 * whichever applies and replays whichever cookies the flow actually needs.
 *
 * The cookies are replayed by hand rather than through a supertest agent: the
 * transaction cookie is `Secure`, and superagent's cookie jar correctly refuses
 * to send a `Secure` cookie back over the plain HTTP the test server speaks.
 * That refusal is the harness being right about the attribute, so the test
 * carries the cookie itself instead of weakening it.
 */
async function startFlow(
	harness: ReturnType<typeof buildApp>,
	name = "apple",
): Promise<StartedFlow> {
	const startResponse = await request(harness.app).get(`/oauth/federation/${name}`);
	const sidMatch = setCookieHeader(startResponse).match(/sid=([^;\n]+)/);
	if (!sidMatch) throw new Error("start leg issued no session cookie");
	const sid = decodeURIComponent(sidMatch[1]);
	const cookies = [`sid=${encodeURIComponent(sid)}`];

	const transactionId = readTransactionCookie(startResponse);
	let federation: { state: string; nonce: string; codeVerifier: string } | undefined;

	if (transactionId !== undefined) {
		const record = harness.records.get(`${FEDERATION_TRANSACTION_KEY_PREFIX}${transactionId}`) as
			| { federation?: { state: string; nonce: string; codeVerifier: string } }
			| undefined;
		federation = record?.federation;
		if (!federation) throw new Error("start leg issued a transaction cookie but stored no record");
		cookies.push(`${HARNESS_TRANSACTION_COOKIE_NAME}=${encodeURIComponent(transactionId)}`);
	} else {
		federation = harness.store.get(sid)?.data.federation as typeof federation;
		if (!federation) throw new Error("start leg persisted no federation state");
	}

	const cookie = cookies.join("; ");
	return {
		sid,
		...(transactionId === undefined ? {} : { transactionId }),
		state: federation.state,
		nonce: federation.nonce,
		codeVerifier: federation.codeVerifier,
		startResponse,
		post: (body) =>
			request(harness.app)
				.post(`/oauth/federation/${name}/callback`)
				.set("Cookie", cookie)
				.type("form")
				.send(body),
		get: (query) =>
			request(harness.app)
				.get(`/oauth/federation/${name}/callback`)
				.set("Cookie", cookie)
				.query(query),
	};
}

// ---------------------------------------------------------------------------
// Start leg
// ---------------------------------------------------------------------------

describe("GET /oauth/federation/:name (start) — response mode", () => {
	it("appends response_mode=form_post to the authorization URL of a form_post federation", async () => {
		const { app } = buildApp();
		const res = await request(app).get("/oauth/federation/apple");
		expect(res.status).toBe(302);
		const location = new URL(res.headers.location as string);
		expect(location.searchParams.get("response_mode")).toBe("form_post");
	});

	it("adds no response_mode for a federation that declares none", async () => {
		const { app } = buildApp();
		const res = await request(app).get("/oauth/federation/query-idp");
		const location = new URL(res.headers.location as string);
		expect(location.searchParams.has("response_mode")).toBe(false);
	});

	it("issues a HttpOnly; Secure; SameSite=None transaction cookie for a form_post federation", async () => {
		const { app } = buildApp();
		const res = await request(app).get("/oauth/federation/apple");
		const transactionCookie = ((res.headers["set-cookie"] as unknown as string[]) ?? []).find((c) =>
			c.startsWith(`${HARNESS_TRANSACTION_COOKIE_NAME}=`),
		);
		expect(transactionCookie).toBeDefined();
		expect(transactionCookie).toMatch(/SameSite=None/i);
		expect(transactionCookie).toMatch(/Secure/);
		expect(transactionCookie).toMatch(/HttpOnly/i);
		// Scoped to the callback route the IdP was told to POST to, and to
		// nothing else — a SameSite=None cookie is offered on every cross-site
		// request to a matching path.
		expect(transactionCookie).toMatch(/Path=\/session\/oauth\/federation\/apple\/callback/);
		// And bounded, so an abandoned flow expires on its own.
		expect(transactionCookie).toMatch(/Max-Age=\d+/);
	});

	it("leaves the application session cookie exactly as configured for a form_post federation", async () => {
		// #494: the start route is unauthenticated, so anything it changed about
		// the session cookie would be changeable by any third party who could get
		// a browser to follow a link here.
		const { app } = buildApp();
		const res = await request(app).get("/oauth/federation/apple");
		const sessionCookie = ((res.headers["set-cookie"] as unknown as string[]) ?? []).find((c) =>
			c.startsWith("sid="),
		);
		expect(sessionCookie).toBeDefined();
		expect(sessionCookie).toMatch(/SameSite=Lax/i);
		expect(sessionCookie).not.toMatch(/Secure/);
	});

	it("keeps the session cookie SameSite=Lax for a query federation, and issues no transaction cookie", async () => {
		// A deployment that adds Apple must not find its Google logins changed in
		// any way at all.
		const { app } = buildApp();
		const res = await request(app).get("/oauth/federation/query-idp");
		const setCookie = ((res.headers["set-cookie"] as unknown as string[]) ?? []).join("\n");
		expect(setCookie).toMatch(/SameSite=Lax/i);
		expect(setCookie).not.toMatch(/Secure/);
		expect(setCookie).not.toContain(HARNESS_TRANSACTION_COOKIE_NAME);
	});

	it("keeps a query federation's envelope in the session and writes no transaction record", async () => {
		const harness = buildApp();
		const flow = await startFlow(harness, "query-idp");
		expect(flow.transactionId).toBeUndefined();
		expect(harness.records.size).toBe(0);
		expect(harness.store.get(flow.sid)?.data.federation).toBeDefined();
	});

	it("keeps a form_post federation's envelope out of the session entirely", async () => {
		const harness = buildApp();
		const flow = await startFlow(harness);
		expect(flow.transactionId).toBeDefined();
		expect(harness.store.get(flow.sid)?.data.federation).toBeUndefined();
		expect(harness.records.size).toBe(1);
	});
});

// ---------------------------------------------------------------------------
// The transaction cookie is what binds the callback to the browser (#494)
// ---------------------------------------------------------------------------

describe("the federation transaction cookie binds the callback to its browser", () => {
	it("completes the callback when the transaction cookie is presented", async () => {
		const flow = await startFlow(buildApp());
		const res = await flow.post({ state: flow.state, code: "apple-code" });
		expect(res.status).toBe(302);
	});

	it("refuses the callback when the transaction cookie is absent", async () => {
		const harness = buildApp();
		const flow = await startFlow(harness);
		// Same session, same valid `state` — only the transaction cookie withheld.
		const res = await request(harness.app)
			.post("/oauth/federation/apple/callback")
			.set("Cookie", `sid=${encodeURIComponent(flow.sid)}`)
			.type("form")
			.send({ state: flow.state, code: "apple-code" });
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_session");
		expect(harness.apple.calls).toHaveLength(0);
	});

	it("refuses a stolen state replayed from a different browser", async () => {
		// The login-CSRF property, stated directly: knowing `state` is not enough,
		// because `state` was never the thing bound to the browser.
		const harness = buildApp();
		const victim = await startFlow(harness);

		const attacker = await request(harness.app)
			.post("/oauth/federation/apple/callback")
			.set("Cookie", "sid=attacker-session")
			.type("form")
			.send({ state: victim.state, code: "apple-code" });

		expect(attacker.status).toBe(400);
		expect(attacker.body.error).toBe("invalid_session");
		expect(harness.apple.calls).toHaveLength(0);
		// And the victim's own transaction is untouched, so their flow still works.
		expect(await victim.post({ state: victim.state, code: "apple-code" })).toHaveProperty(
			"status",
			302,
		);
	});

	it("refuses a transaction cookie that names no record", async () => {
		const harness = buildApp();
		const res = await request(harness.app)
			.post("/oauth/federation/apple/callback")
			.set("Cookie", `${HARNESS_TRANSACTION_COOKIE_NAME}=not-a-real-transaction`)
			.type("form")
			.send({ state: "whatever", code: "apple-code" });
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_session");
	});

	it("deletes the transaction record and clears its cookie after a successful callback", async () => {
		const harness = buildApp();
		const flow = await startFlow(harness);
		const res = await flow.post({ state: flow.state, code: "apple-code" });

		expect(res.status).toBe(302);
		expect(harness.records.size).toBe(0);
		expect(setCookieHeader(res)).toMatch(new RegExp(`${HARNESS_TRANSACTION_COOKIE_NAME}=;`));
	});

	it("deletes the transaction record and clears its cookie after a failed callback", async () => {
		const harness = buildApp();
		const flow = await startFlow(harness);
		// A state mismatch: the transaction is spent either way, so a wrong guess
		// cannot be retried against the same record.
		const res = await flow.post({ state: `${flow.state}-tampered`, code: "apple-code" });

		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_state");
		expect(harness.records.size).toBe(0);
		expect(setCookieHeader(res)).toMatch(new RegExp(`${HARNESS_TRANSACTION_COOKIE_NAME}=;`));

		// And the spent transaction cannot then be completed with the right state.
		const retry = await flow.post({ state: flow.state, code: "apple-code" });
		expect(retry.status).toBe(400);
		expect(retry.body.error).toBe("invalid_session");
	});

	it("deletes the transaction record even when the exchange fails downstream", async () => {
		const harness = buildApp();
		const flow = await startFlow(harness);
		harness.apple.exchangeCode = async () => {
			throw new Error("upstream down");
		};
		const res = await flow.post({ state: flow.state, code: "apple-code" });
		expect(res.status).toBe(502);
		expect(harness.records.size).toBe(0);
	});
});

// ---------------------------------------------------------------------------
// POST callback — surface
// ---------------------------------------------------------------------------

describe("POST /oauth/federation/:name/callback — surface", () => {
	it("returns 404 for an unregistered provider", async () => {
		const { app } = buildApp();
		const res = await request(app).post("/oauth/federation/unknown/callback").type("form").send({});
		expect(res.status).toBe(404);
		expect(res.body.error).toBe("not_found");
	});

	it("refuses a POST callback for a federation that did not declare form_post", async () => {
		// Google and GitHub gain no POST surface from #479: an IdP that returns
		// its response in the query string has no reason to POST, so a POST here
		// is either a misconfiguration or someone probing.
		const { app } = buildApp();
		const res = await request(app)
			.post("/oauth/federation/query-idp/callback")
			.type("form")
			.send({ state: "x", code: "y" });
		expect(res.status).toBe(405);
		expect(res.body.error).toBe("method_not_allowed");
		expect(res.headers.allow).toBe("GET");
	});

	it("accepts an application/x-www-form-urlencoded body", async () => {
		const flow = await startFlow(buildApp());
		const res = await flow.post({ state: flow.state, code: "apple-code" });
		expect(res.status).toBe(302);
	});
});

// ---------------------------------------------------------------------------
// POST callback — binding parity with GET
// ---------------------------------------------------------------------------

describe("POST callback binds state / CSRF / PKCE / nonce exactly as GET does", () => {
	it("400 invalid_session when no federation is in flight", async () => {
		const { app } = buildApp();
		const res = await request(app)
			.post("/oauth/federation/apple/callback")
			.type("form")
			.send({ state: "whatever", code: "c" });
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_session");
	});

	it("400 invalid_session when the in-flight federation is a different provider", async () => {
		const harness = buildApp();
		const flow = await startFlow(harness, "query-idp");
		const res = await request(harness.app)
			.post("/oauth/federation/apple/callback")
			.set("Cookie", `sid=${encodeURIComponent(flow.sid)}`)
			.type("form")
			.send({ state: flow.state, code: "c" });
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_session");
	});

	it("400 invalid_state when the body state does not match the session state", async () => {
		const harness = buildApp();
		const flow = await startFlow(harness);
		const res = await flow.post({ state: `${flow.state}-tampered`, code: "c" });
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_state");
		expect(harness.apple.calls).toHaveLength(0);
	});

	it("400 invalid_state when the body carries no state at all", async () => {
		const flow = await startFlow(buildApp());
		const res = await flow.post({ code: "c" });
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_state");
	});

	it("400 invalid_request when the body carries no code", async () => {
		const flow = await startFlow(buildApp());
		const res = await flow.post({ state: flow.state });
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_request");
	});

	it("hands exchangeCode the session's PKCE verifier and nonce, never the body's", async () => {
		const harness = buildApp();
		const flow = await startFlow(harness);
		await flow.post({
			state: flow.state,
			code: "apple-code",
			code_verifier: "attacker-supplied",
			nonce: "attacker-supplied",
		});
		expect(harness.apple.calls).toHaveLength(1);
		expect(harness.apple.calls[0].codeVerifier).toBe(flow.codeVerifier);
		expect(harness.apple.calls[0].nonce).toBe(flow.nonce);
		expect(harness.apple.calls[0].redirectUri).toBe(APPLE_CALLBACK_URL);
	});

	it("consumes the federation state so a replayed POST cannot reuse it", async () => {
		const flow = await startFlow(buildApp());
		const first = await flow.post({ state: flow.state, code: "apple-code" });
		expect(first.status).toBe(302);

		const replay = await flow.post({ state: flow.state, code: "apple-code" });
		expect(replay.status).toBe(400);
		expect(replay.body.error).toBe("invalid_session");
	});

	it("502 exchange_failed when the token exchange throws, same as the GET callback", async () => {
		const harness = buildApp();
		const flow = await startFlow(harness);
		harness.apple.exchangeCode = async () => {
			throw new Error("upstream down");
		};
		const res = await flow.post({ state: flow.state, code: "apple-code" });
		expect(res.status).toBe(502);
		expect(res.body.error).toBe("exchange_failed");
	});

	it("401 unknown_user when no local account is linked, same as the GET callback", async () => {
		const flow = await startFlow(buildApp({ userRepository: makeUserRepository(null) }));
		const res = await flow.post({ state: flow.state, code: "apple-code" });
		expect(res.status).toBe(401);
		expect(res.body.error).toBe("unknown_user");
	});

	it("produces the same rejection on GET as on POST for every binding failure", async () => {
		// The two callbacks are one handler over two parameter sources; this is
		// the assertion that keeps them from becoming two handlers.
		const cases: ReadonlyArray<{ params: Record<string, string>; error: string }> = [
			{ params: { code: "c" }, error: "invalid_state" },
			{ params: { state: "wrong", code: "c" }, error: "invalid_state" },
			{ params: {}, error: "invalid_state" },
		];
		for (const { params, error } of cases) {
			const viaPost = await startFlow(buildApp());
			const postRes = await viaPost.post(params);

			const viaGet = await startFlow(buildApp());
			const getRes = await viaGet.get(params);

			expect(postRes.status).toBe(getRes.status);
			expect(postRes.body).toEqual(getRes.body);
			expect(postRes.body.error).toBe(error);
		}
	});

	it("rejects a missing code identically on GET and POST once state matches", async () => {
		const viaPost = await startFlow(buildApp());
		const postRes = await viaPost.post({ state: viaPost.state });

		const viaGet = await startFlow(buildApp());
		const getRes = await viaGet.get({ state: viaGet.state });

		expect(postRes.status).toBe(400);
		expect(postRes.status).toBe(getRes.status);
		expect(postRes.body).toEqual(getRes.body);
		expect(postRes.body.error).toBe("invalid_request");
	});
});

// ---------------------------------------------------------------------------
// callbackParams — what the adapter is and is not handed
// ---------------------------------------------------------------------------

describe("callbackParams excludes the parameters the framework binds", () => {
	it("keeps code and state out of it on the POST callback", async () => {
		const harness = buildApp();
		const flow = await startFlow(harness);
		const userField = JSON.stringify({ name: { firstName: "Ada" } });
		await flow.post({ state: flow.state, code: "apple-code", user: userField });

		const call = harness.apple.calls[0];
		// The two values the route already checked and already passes in named
		// fields do not appear a second time under a generic bag: an adapter that
		// could read `callbackParams.code` could read the one the route never
		// validated against the session.
		expect(call.callbackParams).not.toHaveProperty("code");
		expect(call.callbackParams).not.toHaveProperty("state");
		// Everything else survives, and the dedicated fields still carry the two.
		expect(call.callbackParams?.user).toBe(userField);
		expect(call.code).toBe("apple-code");
	});

	it("keeps code and state out of it on the GET callback too", async () => {
		const harness = buildApp();
		const flow = await startFlow(harness);
		await flow.get({ state: flow.state, code: "apple-code", extra: "kept" });

		const call = harness.apple.calls[0];
		expect(call.callbackParams).not.toHaveProperty("code");
		expect(call.callbackParams).not.toHaveProperty("state");
		expect(call.callbackParams?.extra).toBe("kept");
		expect(call.code).toBe("apple-code");
	});

	it("hands the adapter an empty bag rather than nothing when there is nothing else", async () => {
		const harness = buildApp();
		const flow = await startFlow(harness);
		await flow.post({ state: flow.state, code: "apple-code" });
		expect(harness.apple.calls[0].callbackParams).toEqual({});
	});
});

// ---------------------------------------------------------------------------
// End-to-end: fake Apple
// ---------------------------------------------------------------------------

describe("fake Apple end-to-end through the federation routes", () => {
	it("logs in from a form_post callback carrying the first-authorization user body", async () => {
		const harness = buildApp();

		// 1. Start leg — response_mode goes upstream, state cookie is relaxed.
		const flow = await startFlow(harness);
		const authorizeUrl = new URL(flow.startResponse.headers.location as string);
		expect(authorizeUrl.origin).toBe("https://appleid.apple.com");
		expect(authorizeUrl.searchParams.get("response_mode")).toBe("form_post");
		expect(authorizeUrl.searchParams.get("nonce")).toBe(flow.nonce);
		expect(authorizeUrl.searchParams.get("code_challenge")).toBe(codeChallenge(flow.codeVerifier));

		// 2. Apple POSTs the callback with `user` — only ever on first authorization.
		const userField = JSON.stringify({
			name: { firstName: "Ada", lastName: "Lovelace" },
			email: "sxyz@privaterelay.appleid.com",
		});
		const res = await flow.post({
			state: flow.state,
			code: "apple-authorization-code",
			user: userField,
		});

		expect(res.status).toBe(302);
		expect(harness.apple.calls).toHaveLength(1);
		expect(harness.apple.calls[0].callbackParams?.user).toBe(userField);
		expect(harness.apple.calls[0].nonce).toBe(flow.nonce);

		// 3. A session exists, with the claims the precedence rules allow.
		expect(harness.userSessionStore.create).toHaveBeenCalledTimes(1);
		const created = harness.userSessionStore.create.mock.calls[0][0] as {
			sub: string;
			claims: Record<string, unknown>;
		};
		expect(created.sub).toBe("user-1");
		// `email` and `name` are promoted: the local record left both absent.
		expect(created.claims.email).toBe("sxyz@privaterelay.appleid.com");
		expect(created.claims.name).toBe("Ada Lovelace");
		// `emailVerified` normalised from the string "true" — and namespaced, not
		// promoted, because it is Store-owned state (#297).
		expect(created.claims.emailVerified).toBeUndefined();
		const federated = created.claims.federated as Record<string, Record<string, unknown>>;
		expect(federated.apple.emailVerified).toBe(true);
		// The relay marker is surfaced so a deployment can decide about it.
		expect(federated.apple.isPrivateEmail).toBe(true);

		// 4. Upstream tokens attached under the provider name.
		expect(harness.federationTokenStore.attach).toHaveBeenCalledTimes(1);
		expect(harness.federationTokenStore.attach.mock.calls[0][1]).toBe("apple");
	});

	it("logs in on a later authorization, where Apple sends no user body and no name", async () => {
		const harness = buildApp();
		const flow = await startFlow(harness);
		const res = await flow.post({ state: flow.state, code: "apple-authorization-code" });

		expect(res.status).toBe(302);
		const created = harness.userSessionStore.create.mock.calls[0][0] as {
			claims: Record<string, unknown>;
		};
		expect(created.claims.email).toBe("sxyz@privaterelay.appleid.com");
		// No name anywhere in the response: absent, not an empty string.
		expect(created.claims.name).toBeUndefined();
		const federated = created.claims.federated as Record<string, Record<string, unknown>>;
		expect("name" in federated.apple).toBe(false);
	});

	it("does not let the user body reach a claim the local record already answers", async () => {
		const harness = buildApp({
			userRepository: makeUserRepository({
				id: "user-1",
				username: "alice",
				email: "alice@corp.example",
				name: "Alice Corp",
			}),
		});
		const flow = await startFlow(harness);
		await flow.post({
			state: flow.state,
			code: "c",
			user: JSON.stringify({ name: { firstName: "Not", lastName: "Alice" } }),
		});

		const created = harness.userSessionStore.create.mock.calls[0][0] as {
			claims: Record<string, unknown>;
		};
		expect(created.claims.email).toBe("alice@corp.example");
		expect(created.claims.name).toBe("Alice Corp");
		const federated = created.claims.federated as Record<string, Record<string, unknown>>;
		expect(federated.apple.name).toBe("Not Alice");
	});
});
