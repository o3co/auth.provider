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
 * What the federation transaction's single use does — and does not —
 * guarantee (#502).
 *
 * The transaction is consumed by a read followed by a delete, over the
 * express-session `Store` API. That API is `get` / `set` / `destroy`: there is
 * no compare-and-delete on it, and no atomic read-and-consume can be built out
 * of the three. So the sequential property holds and the concurrent one does
 * not, and this file pins both rather than letting a README claim stand in for
 * either.
 *
 * `MemoryStore` answers synchronously, which serialises the callbacks and
 * hides the difference. A store with latency — any network store, Redis
 * included — does not, so these tests run against one that defers every answer
 * by a fixed delay. That is the entire reason the rest of the suite never saw
 * this.
 *
 * What actually bounds a concurrent replay is the IdP: an authorization code
 * is single-use at the IdP, every racing callback necessarily carries the same
 * one, and so at most one `exchangeCode` can succeed. The fake IdP here
 * enforces exactly that, because it is the real guarantee.
 */

import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { codeChallenge } from "#/federations/pkce.mjs";
import { FEDERATION_TRANSACTION_KEY_PREFIX } from "#/federations/transaction.mjs";
import type { FederationProvider } from "#/federations/types.mjs";
import { createRouter } from "#/routes/Federation.mjs";
import {
	HARNESS_TRANSACTION_COOKIE_NAME,
	makeFederationTokenStore,
	makePermissivePolicy,
	makeRecordStore,
	makeSessionFederationIndex,
	makeUserRepository,
	makeUserSessionStore,
} from "./federation-harness.mjs";

const CALLBACK_URL = "https://app.example.com/oauth/federation/apple/callback";

/**
 * Round-trip latency to give every store answer.
 *
 * Long enough that all of the racing callbacks have issued their `get` before
 * the first one returns, which is the condition a network store meets by
 * default and the in-process `MemoryStore` never meets.
 */
const STORE_LATENCY_MS = 25;

/** How many callbacks race. Five is what the #502 reviewer ran. */
const RACERS = 5;

/**
 * A form_post provider whose IdP enforces what a real IdP enforces: an
 * authorization code may be exchanged once.
 */
function makeApple(): FederationProvider & { calls: string[] } {
	const calls: string[] = [];
	const spent = new Set<string>();
	return {
		name: "apple",
		scope: ["name", "email"],
		responseMode: "form_post",
		calls,
		buildAuthorizationUrl: ({ state, codeVerifier }) => {
			const url = new URL("https://appleid.apple.com/auth/authorize");
			url.searchParams.set("state", state);
			url.searchParams.set("code_challenge", codeChallenge(codeVerifier));
			return url;
		},
		exchangeCode: async ({ code }) => {
			calls.push(code);
			// The IdP's own single-use rule, which is the property that actually
			// stops a concurrent replay from becoming a second session.
			if (spent.has(code)) throw new Error("authorization code already redeemed");
			spent.add(code);
			return {
				issuer: "https://appleid.apple.com",
				sub: "apple-sub",
				accessToken: "apple-at",
				expiresAt: null,
			};
		},
	};
}

/** Defer a store answer the way a network hop does. */
const later = (fn: () => void): void => {
	setTimeout(fn, STORE_LATENCY_MS);
};

function buildApp() {
	const records = new Map<string, unknown>();
	const backing = makeRecordStore(records);

	/**
	 * The deployment's express-session store, with a network hop in front of
	 * every method. Nothing else about it differs from the synchronous harness
	 * store the other federation tests use.
	 */
	const sessionStore = {
		get(sid: string, cb: (err: unknown, record?: unknown) => void) {
			later(() => backing.get(sid, cb));
		},
		set(sid: string, record: unknown, cb?: (err?: unknown) => void) {
			later(() => backing.set(sid, record, cb));
		},
		destroy(sid: string, cb?: (err?: unknown) => void) {
			later(() => backing.destroy(sid, cb));
		},
	};

	const app = express();
	app.use((req, _res, next) => {
		(req as unknown as { session: Record<string, unknown> }).session = {
			cookie: { sameSite: "lax", secure: false, httpOnly: true },
			save(cb?: (err: unknown) => void) {
				cb?.(null);
			},
			regenerate(cb?: (err: unknown) => void) {
				cb?.(null);
			},
			destroy(cb?: (err: unknown) => void) {
				cb?.(null);
			},
		};
		(req as unknown as { sessionStore: unknown }).sessionStore = sessionStore;
		next();
	});

	const apple = makeApple();
	const userSessionStore = makeUserSessionStore();

	app.use(
		createRouter(express, {
			config: { session: { name: "harness.session" } } as never,
			federationProviders: new Map<string, FederationProvider>([["apple", apple]]),
			federationRedirectPolicyResolver: new Map([["apple", makePermissivePolicy()]]) as never,
			providerCallbackUrls: new Map([["apple", CALLBACK_URL]]),
			userRepository: makeUserRepository(),
			userSessionStore,
			sessionFederationIndex: makeSessionFederationIndex(),
			federationTokenStore: makeFederationTokenStore(),
			federationTransactionCookieName: HARNESS_TRANSACTION_COOKIE_NAME,
		}),
	);

	return { app, records, apple, userSessionStore };
}

type Flow = {
	cookie: string;
	state: string;
	post: (body: Record<string, string>) => request.Test;
};

/** Start a flow and hand back what a callback needs to present. */
async function startFlow(harness: ReturnType<typeof buildApp>): Promise<Flow> {
	const res = await request(harness.app).get("/oauth/federation/apple");
	const header = ((res.headers["set-cookie"] as unknown as string[]) ?? []).find((c) =>
		c.startsWith(`${HARNESS_TRANSACTION_COOKIE_NAME}=`),
	);
	if (!header) throw new Error("start leg issued no transaction cookie");
	const id = decodeURIComponent(header.split(";")[0]?.split("=").slice(1).join("=") ?? "");
	const record = harness.records.get(`${FEDERATION_TRANSACTION_KEY_PREFIX}${id}`) as {
		federation: { state: string };
	};
	const cookie = `${HARNESS_TRANSACTION_COOKIE_NAME}=${encodeURIComponent(id)}`;
	return {
		cookie,
		state: record.federation.state,
		post: (body) =>
			request(harness.app)
				.post("/oauth/federation/apple/callback")
				.set("Cookie", cookie)
				.type("form")
				.send(body),
	};
}

describe("the federation transaction is single-use in sequence", () => {
	it("refuses a callback replayed after the first one finished", async () => {
		// The guarantee that does hold, and the one that matters for a replay
		// hours later from a proxy log: once a callback has completed, the record
		// is gone and its cookie cleared.
		const harness = buildApp();
		const flow = await startFlow(harness);

		const first = await flow.post({ state: flow.state, code: "apple-code" });
		expect(first.status).toBe(302);
		expect(harness.records.size).toBe(0);

		const replay = await flow.post({ state: flow.state, code: "apple-code" });
		expect(replay.status).toBe(400);
		expect(replay.body.error).toBe("invalid_session");
		expect(harness.apple.calls).toHaveLength(1);
	});
});

describe("the federation transaction is NOT single-use under concurrency", () => {
	it("lets every racing callback past the transaction, and leaves the IdP to stop them", async () => {
		// Read this as the specification it is, not as a bug left in place.
		//
		// `Federation.mts` reads the record and then deletes it, and there is no
		// compare-and-delete on the express-session `Store` API to do it in one
		// step. Racing callbacks therefore all read the record before any of them
		// deletes it, and all pass the `state` comparison. The consequence is
		// bounded by the IdP: they all carry the same authorization code, the IdP
		// spends it once, and the rest get `502 exchange_failed`.
		//
		// If this ever becomes atomic, this test fails — deliberately, so the
		// README's account of the guarantee is revisited in the same change.
		const harness = buildApp();
		const flow = await startFlow(harness);

		const responses = await Promise.all(
			Array.from({ length: RACERS }, () => flow.post({ state: flow.state, code: "apple-code" })),
		);

		// The transaction did not serialise them…
		expect(harness.apple.calls.length).toBeGreaterThan(1);
		// …and the IdP's single-use code did: exactly one session is created.
		expect(responses.filter((res) => res.status === 302)).toHaveLength(1);
		expect(harness.userSessionStore.create).toHaveBeenCalledTimes(1);
		for (const res of responses.filter((r) => r.status !== 302)) {
			expect(res.status).toBe(502);
			expect(res.body.error).toBe("exchange_failed");
		}
		// Whatever the ordering, the record is gone once the dust settles.
		expect(harness.records.size).toBe(0);
	});
});
