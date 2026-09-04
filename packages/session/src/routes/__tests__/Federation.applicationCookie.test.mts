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
 * The application session cookie's attributes, across a **real**
 * `express-session` store round trip (#494).
 *
 * Every other federation test in this package runs on a hand-written session
 * shim. A shim can model whatever it likes about `req.session.cookie`, and the
 * one in `federation-harness.mts` modelled it wrongly — which is precisely why
 * no test caught a start leg that permanently relaxed the session cookie of
 * any browser a third party could point at `GET /oauth/federation/:name`.
 *
 * So this file uses the real middleware and the real `MemoryStore`, and asks
 * the only question that matters: after a `form_post` federation starts, is
 * the session that comes **back out of the store** still the deployment's
 * `SameSite=Strict; secure=false` session?
 *
 * `Store.prototype.createSession` rebuilds the cookie on every load with
 * `new Cookie(sess.cookie)`, and that constructor copies every own key of what
 * it is handed. So anything a route writes onto `req.session.cookie` is
 * serialised into the store and restored on every later request — for the life
 * of the session, in MemoryStore and in Redis alike. Nothing in the start leg
 * may write there.
 */

import express from "express";
import session from "express-session";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { codeChallenge } from "#/federations/pkce.mjs";
import { FEDERATION_TRANSACTION_KEY_PREFIX } from "#/federations/transaction.mjs";
import type { FederationProvider } from "#/federations/types.mjs";
import { createRouter } from "#/routes/Federation.mjs";
import {
	makeFederationTokenStore,
	makePermissivePolicy,
	makeSessionFederationIndex,
	makeUserRepository,
	makeUserSessionStore,
} from "./federation-harness.mjs";

const APPLE_CALLBACK_URL = "https://app.example.com/oauth/federation/apple/callback";
const QUERY_CALLBACK_URL = "https://app.example.com/oauth/federation/query-idp/callback";

/** The deployment's own cookie policy — the thing that must survive. */
const SESSION_COOKIE = {
	path: "/",
	httpOnly: true,
	secure: false,
	sameSite: "strict",
	maxAge: 3_600_000,
} as const;

const SESSION_COOKIE_NAME = "app.session";

function makeFormPostProvider(): FederationProvider {
	return {
		name: "apple",
		scope: ["name", "email"],
		responseMode: "form_post",
		buildAuthorizationUrl: ({ redirectUri, state, codeVerifier, nonce }) => {
			const url = new URL("https://appleid.apple.com/auth/authorize");
			url.searchParams.set("redirect_uri", redirectUri);
			url.searchParams.set("state", state);
			url.searchParams.set("code_challenge", codeChallenge(codeVerifier));
			if (nonce) url.searchParams.set("nonce", nonce);
			return url;
		},
		exchangeCode: async () => ({
			issuer: "https://appleid.apple.com",
			sub: "000123.abcdef.0456",
			accessToken: "apple-at",
			expiresAt: new Date(Date.now() + 3_600_000),
		}),
	};
}

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
		exchangeCode: async () => ({
			issuer: "https://idp.example.com",
			sub: "query-sub",
			expiresAt: null,
		}),
	};
}

type RealApp = {
	app: express.Express;
	store: session.MemoryStore;
};

/**
 * An app wired the way `sessionStoreModule` wires a deployment: real
 * `express-session`, real store, the federation router mounted behind it.
 *
 * `/prime` exists so a test can establish a session the ordinary way and hold
 * its signed cookie, and `/peek` reports what the session looks like once the
 * middleware has loaded it back out of the store on a later request.
 */
function buildRealApp({ rolling = false }: { rolling?: boolean } = {}): RealApp {
	const store = new session.MemoryStore();
	const app = express();

	app.use(
		session({
			name: SESSION_COOKIE_NAME,
			secret: "test-secret-of-at-least-32-bytes-length!",
			resave: false,
			saveUninitialized: false,
			// `rolling` is what makes the re-issue test below able to assert
			// anything at all: without it express-session emits no `Set-Cookie`
			// on an unmodified session, so a test looking for one finds nothing
			// under the fix *and* nothing under the bug (#502).
			rolling,
			store,
			cookie: { ...SESSION_COOKIE },
		}),
	);

	app.get("/prime", (req, res) => {
		(req.session as unknown as Record<string, unknown>).primed = true;
		req.session.save(() => res.status(204).end());
	});

	const providers = new Map<string, FederationProvider>([
		["apple", makeFormPostProvider()],
		["query-idp", makeQueryProvider()],
	]);

	app.use(
		createRouter(express, {
			config: {} as never,
			federationProviders: providers,
			federationRedirectPolicyResolver: new Map(
				[...providers.keys()].map((name) => [name, makePermissivePolicy()]),
			) as never,
			providerCallbackUrls: new Map([
				["apple", APPLE_CALLBACK_URL],
				["query-idp", QUERY_CALLBACK_URL],
			]),
			userRepository: makeUserRepository(),
			userSessionStore: makeUserSessionStore(),
			sessionFederationIndex: makeSessionFederationIndex(),
			federationTokenStore: makeFederationTokenStore(),
		}),
	);

	app.get("/peek", (req, res) => {
		res.json({
			sameSite: req.session.cookie.sameSite ?? null,
			secure: req.session.cookie.secure ?? null,
		});
	});

	return { app, store };
}

/**
 * The whole `Set-Cookie` header for the application session, attributes and
 * all. Throws when the response emitted none — which is an assertion in its own
 * right, since express-session suppresses the header entirely for a `Secure`
 * session cookie over a plain-HTTP hop.
 */
function sessionSetCookie(res: request.Response): string {
	const setCookie = (res.headers["set-cookie"] as unknown as string[]) ?? [];
	const header = setCookie.find((c) => c.startsWith(`${SESSION_COOKIE_NAME}=`));
	if (!header) throw new Error("no application session cookie was issued");
	return header;
}

/** The `Set-Cookie` value for the application session, replayed verbatim. */
function readSessionCookie(res: request.Response): string {
	return sessionSetCookie(res).split(";")[0] as string;
}

/** Every key the store is holding, sessions and transaction records alike. */
async function storeKeys(store: session.MemoryStore): Promise<string[]> {
	return await new Promise<string[]>((resolve, reject) => {
		store.all((err, sessions) => {
			if (err) return reject(err as Error);
			resolve(Object.keys((sessions ?? {}) as Record<string, unknown>));
		});
	});
}

/**
 * The single session id the store is holding.
 *
 * Transaction records live in this same store — that is the design, and it is
 * why they carry a key prefix of their own: the two key spaces have to stay
 * disjoint, so that nothing can be read as the other.
 */
async function onlySessionId(store: session.MemoryStore): Promise<string> {
	const ids = (await storeKeys(store)).filter(
		(key) => !key.startsWith(FEDERATION_TRANSACTION_KEY_PREFIX),
	);
	if (ids.length !== 1) throw new Error(`expected exactly one stored session, found ${ids.length}`);
	return ids[0] as string;
}

/**
 * The session as the store hands it back — i.e. through
 * `Store.prototype.createSession`, the rebuild that makes a mutated cookie
 * permanent.
 */
async function loadFromStore(
	store: session.MemoryStore,
	sid: string,
): Promise<session.SessionData> {
	return await new Promise<session.SessionData>((resolve, reject) => {
		store.get(sid, (err, sess) => {
			if (err) return reject(err as Error);
			if (!sess) return reject(new Error(`session ${sid} is not in the store`));
			resolve(sess);
		});
	});
}

describe("the application session cookie survives a form_post federation start (#494)", () => {
	it("leaves the stored session's cookie attributes exactly as the deployment configured them", async () => {
		const { app, store } = buildRealApp();

		const primed = await request(app).get("/prime");
		expect(primed.status).toBe(204);
		const cookie = readSessionCookie(primed);

		const start = await request(app).get("/oauth/federation/apple").set("Cookie", cookie);
		expect(start.status).toBe(302);

		// The round trip: what express-session actually wrote to the store.
		const sid = await onlySessionId(store);
		const stored = await loadFromStore(store, sid);
		expect(stored.cookie.sameSite).toBe("strict");
		expect(stored.cookie.secure).toBe(false);
	});

	it("still presents a SameSite=Strict session to a request made after the federation started", async () => {
		const { app } = buildRealApp();

		const primed = await request(app).get("/prime");
		const cookie = readSessionCookie(primed);

		await request(app).get("/oauth/federation/apple").set("Cookie", cookie);

		// A later, entirely unrelated request. `Store.prototype.createSession`
		// has rebuilt the cookie from the stored record by now.
		const peek = await request(app).get("/peek").set("Cookie", cookie);
		expect(peek.status).toBe(200);
		expect(peek.body.sameSite).toBe("strict");
		expect(peek.body.secure).toBe(false);
	});

	it("keeps re-issuing the session cookie over a plain-HTTP hop", async () => {
		// A forced `secure: true` does not merely mislabel the cookie: express-session
		// stops emitting `Set-Cookie` at all when the session's cookie is Secure and
		// the hop is not TLS, so the session silently stops being delivered.
		//
		// #502: this test used to guard its assertion with `if (sessionHeader)`,
		// and on an unmodified session express-session emits no `Set-Cookie` at
		// all — so the guard was false in the fixed tree and in the buggy one
		// alike, and the assertion never ran. `rolling: true` forces the re-issue,
		// and the header is now required rather than inspected if present:
		// `sessionSetCookie` throws when it is missing, which is exactly the
		// symptom the bug produces.
		const { app } = buildRealApp({ rolling: true });

		const primed = await request(app).get("/prime");
		const cookie = readSessionCookie(primed);

		const start = await request(app).get("/oauth/federation/apple").set("Cookie", cookie);
		expect(start.status).toBe(302);
		expect(sessionSetCookie(start)).not.toMatch(/Secure/i);
		// And the session is still delivered on the request after that one, which
		// is the property an operator would actually notice losing.
		const peek = await request(app).get("/peek").set("Cookie", cookie);
		expect(peek.status).toBe(200);
		expect(sessionSetCookie(peek)).not.toMatch(/Secure/i);
		expect(peek.body.secure).toBe(false);
	});

	it("is unaffected by a third party who only causes the start navigation", async () => {
		// `GET /oauth/federation/:name` requires no authentication and a
		// SameSite=Lax/Strict cookie IS sent on a top-level GET, so this is the
		// whole attack: one navigation, no login, no callback, no completed flow.
		const { app } = buildRealApp();

		const primed = await request(app).get("/prime");
		const cookie = readSessionCookie(primed);
		const before = await request(app).get("/peek").set("Cookie", cookie);

		await request(app).get("/oauth/federation/apple").set("Cookie", cookie);

		const after = await request(app).get("/peek").set("Cookie", cookie);
		expect(after.body).toEqual(before.body);
	});

	it("holds the transaction record in the very store the session uses, under a prefix of its own", async () => {
		const { app, store } = buildRealApp();

		const primed = await request(app).get("/prime");
		const cookie = readSessionCookie(primed);
		await request(app).get("/oauth/federation/apple").set("Cookie", cookie);

		const keys = await storeKeys(store);
		const transactionKeys = keys.filter((k) => k.startsWith(FEDERATION_TRANSACTION_KEY_PREFIX));
		expect(transactionKeys).toHaveLength(1);
		// No new component slot was invented for this: the record shares the
		// store the deployment already points at Redis, and the prefix is what
		// keeps a transaction from ever being loadable as a session.
		expect(keys).toHaveLength(2);
	});

	it("leaves a query-mode federation's session untouched, as it always did", async () => {
		const { app, store } = buildRealApp();

		const primed = await request(app).get("/prime");
		const cookie = readSessionCookie(primed);

		await request(app).get("/oauth/federation/query-idp").set("Cookie", cookie);

		const sid = await onlySessionId(store);
		const stored = await loadFromStore(store, sid);
		expect(stored.cookie.sameSite).toBe("strict");
		expect(stored.cookie.secure).toBe(false);
	});
});
