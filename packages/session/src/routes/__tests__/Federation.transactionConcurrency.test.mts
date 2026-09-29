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
 * guarantee (README, What "single use" guarantees). It is consumed by a read
 * followed by a delete over the express-session `Store` API, which has no
 * compare-and-delete, so the sequential property holds and the concurrent one
 * does not. This file pins both.
 *
 * `MemoryStore` answers synchronously, which serialises the callbacks and
 * hides the difference, so these tests run against a store that answers out
 * of band, as any network store does. What bounds a concurrent replay is the
 * IdP's single-use authorization code, which the fake IdP here enforces.
 */

import type { FederationProvider } from "@o3co/auth-provider-core";
import { codeChallenge } from "@o3co/auth-provider-core";
import { resolverForTests } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { FEDERATION_TRANSACTION_KEY_PREFIX } from "#/federations/transaction.mjs";
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
 * Round-trip latency for every store answer: enough for a real async
 * boundary, which `MemoryStore`, answering synchronously, never is.
 */
const STORE_LATENCY_MS = 25;

/**
 * How long a held read waits before answering anyway. Only reached if fewer
 * reads arrive than the test asked to hold; releasing turns that into a
 * failed assertion instead of a suite-level timeout.
 */
const BARRIER_ESCAPE_MS = 2_000;

/** How many callbacks race. */
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
	 * Reads currently being held, and how many must arrive before they run.
	 * A fixed delay would leave the overlap to the scheduler, which a loaded CI
	 * runner need not honour; holding the reads until all have arrived
	 * constructs the overlap a network store produces, with no timing
	 * assumption.
	 */
	let barrier: { needed: number; held: Array<() => void>; giveUp: NodeJS.Timeout } | null = null;

	const releaseBarrier = (): void => {
		if (!barrier) return;
		const { held, giveUp } = barrier;
		barrier = null;
		clearTimeout(giveUp);
		for (const resume of held) resume();
	};

	/**
	 * The deployment's express-session store, with a network hop in front of
	 * every method. Nothing else about it differs from the synchronous harness
	 * store the other federation tests use.
	 */
	const sessionStore = {
		get(sid: string, cb: (err: unknown, record?: unknown) => void) {
			const run = () => backing.get(sid, cb);
			if (!barrier) return later(run);
			barrier.held.push(run);
			if (barrier.held.length >= barrier.needed) releaseBarrier();
		},
		set(sid: string, record: unknown, cb?: (err?: unknown) => void) {
			later(() => backing.set(sid, record, cb));
		},
		destroy(sid: string, cb?: (err?: unknown) => void) {
			later(() => backing.destroy(sid, cb));
		},
	};

	/** Hold every read until `count` of them are outstanding, then run them all. */
	const holdReads = (count: number): void => {
		barrier = { needed: count, held: [], giveUp: setTimeout(releaseBarrier, BARRIER_ESCAPE_MS) };
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
			requirements: resolverForTests([]),
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

	return { app, records, apple, userSessionStore, holdReads };
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
		// The specification, not a bug left in place. Racing callbacks all read
		// the record before any of them deletes it, and all pass the `state`
		// comparison; they carry the same authorization code, the IdP spends it
		// once, and the rest get `502 exchange_failed`. `holdReads` constructs
		// the overlap, so the counts are exact. If this ever becomes atomic, this
		// test fails, so the README's account is revisited in the same change.
		const harness = buildApp();
		const flow = await startFlow(harness);
		harness.holdReads(RACERS);

		const responses = await Promise.all(
			Array.from({ length: RACERS }, () => flow.post({ state: flow.state, code: "apple-code" })),
		);

		// The transaction did not serialise them: every one of them got through.
		expect(harness.apple.calls).toHaveLength(RACERS);
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
