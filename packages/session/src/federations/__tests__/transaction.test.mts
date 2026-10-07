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
 * The federation transaction: the record and the cookie name that carry a
 * `form_post` federation's state, so the application session cookie is never
 * relaxed.
 */

import { describe, expect, it } from "vitest";
import {
	createFederationTransactionStore,
	DEFAULT_FEDERATION_TRANSACTION_TTL_MS,
	deriveFederationTransactionCookieName,
	FEDERATION_TRANSACTION_KEY_PREFIX,
	type FederationTransactionSessionStore,
	mintFederationTransactionId,
} from "#/federations/transaction.mjs";

/** A store shaped like express-session's, with its writes visible to the test. */
function fakeStore(): FederationTransactionSessionStore & {
	records: Map<string, unknown>;
	failOn?: "get" | "set" | "destroy";
} {
	const records = new Map<string, unknown>();
	const store = {
		records,
		failOn: undefined as "get" | "set" | "destroy" | undefined,
		get(sid: string, cb: (err: unknown, record?: unknown) => void) {
			if (store.failOn === "get") return cb(new Error("store down"));
			// Round-tripped through JSON, as every real store does.
			const raw = records.get(sid);
			cb(null, raw === undefined ? undefined : (JSON.parse(JSON.stringify(raw)) as unknown));
		},
		set(sid: string, record: unknown, cb?: (err?: unknown) => void) {
			if (store.failOn === "set") return cb?.(new Error("store down"));
			records.set(sid, record);
			cb?.();
		},
		destroy(sid: string, cb?: (err?: unknown) => void) {
			if (store.failOn === "destroy") return cb?.(new Error("store down"));
			records.delete(sid);
			cb?.();
		},
	};
	return store;
}

const envelope = {
	name: "apple",
	state: "state-value",
	codeVerifier: "verifier-value",
	nonce: "nonce-value",
	redirectTo: "/after-login",
};

describe("deriveFederationTransactionCookieName", () => {
	it("names the cookie after the deployment's session cookie and the federation", () => {
		expect(deriveFederationTransactionCookieName("auth.session", "apple")).toBe(
			"__Host-auth.session.federation.apple",
		);
	});

	it("applies __Host- unconditionally, even to a session name that carries no prefix", () => {
		// Not merely a swap: unlike the session cookie, whose `Secure` flag is the
		// operator's to set, this cookie is SameSite=None and so is always issued
		// with `Secure`. `__Host-` states that where the browser enforces it, and
		// also that no other host — a sibling subdomain included — can set it.
		for (const name of ["auth.session", "sid", "my_app-cookie"]) {
			expect(deriveFederationTransactionCookieName(name, "apple")).toBe(
				`__Host-${name}.federation.apple`,
			);
		}
	});

	it("swaps a __Secure- prefix for __Host-, so a sibling host cannot set the cookie", () => {
		// A `__Secure-` cookie may carry `Domain=<parent>`: a sibling host
		// could set it for this one. `__Host-` may not.
		expect(deriveFederationTransactionCookieName("__Secure-app.sid", "apple")).toBe(
			"__Host-app.sid.federation.apple",
		);
	});

	it("does not double up an existing __Host- prefix", () => {
		expect(deriveFederationTransactionCookieName("__Host-auth.session", "apple")).toBe(
			"__Host-auth.session.federation.apple",
		);
	});

	it("strips a prefix in any case, as browsers match it", () => {
		for (const name of [
			"__host-app.sid",
			"__HOST-app.sid",
			"__secure-app.sid",
			"__SECURE-app.sid",
		]) {
			expect(deriveFederationTransactionCookieName(name, "apple")).toBe(
				"__Host-app.sid.federation.apple",
			);
		}
	});

	it("gives each federation a name of its own", () => {
		// The cookie is `Path=/`, so the name — not the path — is what keeps
		// two federations' transactions apart.
		const apple = deriveFederationTransactionCookieName("auth.session", "apple");
		const other = deriveFederationTransactionCookieName("auth.session", "apple-staging");
		expect(apple).not.toBe(other);
	});

	it("keeps the federation's name as written, so names differing only in case stay distinct", () => {
		expect(deriveFederationTransactionCookieName("auth.session", "Apple")).toBe(
			"__Host-auth.session.federation.Apple",
		);
		expect(deriveFederationTransactionCookieName("auth.session", "Apple")).not.toBe(
			deriveFederationTransactionCookieName("auth.session", "apple"),
		);
	});
});

describe("mintFederationTransactionId", () => {
	it("mints distinct, URL-safe, bearer-sized ids", () => {
		const a = mintFederationTransactionId();
		const b = mintFederationTransactionId();
		expect(a).not.toBe(b);
		expect(a).toMatch(/^[A-Za-z0-9_-]+$/);
		// 32 bytes of CSPRNG output, base64url — the id is what proves the
		// callback reached the browser that started the flow.
		expect(Buffer.from(a, "base64url")).toHaveLength(32);
	});
});

describe("the federation transaction store, over an express-session store", () => {
	it("round-trips an envelope", async () => {
		const store = fakeStore();
		const transactions = createFederationTransactionStore(store);

		await transactions.set("tx-1", envelope, DEFAULT_FEDERATION_TRANSACTION_TTL_MS);
		expect(await transactions.get("tx-1")).toEqual(envelope);
	});

	it("keys records under a prefix, so they share the store without sharing a key space", () => {
		const store = fakeStore();
		const transactions = createFederationTransactionStore(store);

		return transactions.set("tx-1", envelope, 1000).then(() => {
			expect([...store.records.keys()]).toEqual([`${FEDERATION_TRANSACTION_KEY_PREFIX}tx-1`]);
		});
	});

	it("writes an expiry the store implementations already know how to reap", async () => {
		// `MemoryStore` drops a record whose `cookie.expires` has passed;
		// `connect-redis` turns the same field into the key's `EX`. Writing the
		// expiry there is what makes an abandoned transaction expire on its own
		// in both deployments, with no sweeper of ours.
		const store = fakeStore();
		const transactions = createFederationTransactionStore(store);
		const before = Date.now();

		await transactions.set("tx-1", envelope, 60_000);

		const record = store.records.get(`${FEDERATION_TRANSACTION_KEY_PREFIX}tx-1`) as {
			cookie: { expires: Date; maxAge: number };
		};
		expect(record.cookie.maxAge).toBe(60_000);
		expect(record.cookie.expires.getTime()).toBeGreaterThanOrEqual(before + 60_000);
		expect(record.cookie.expires.getTime()).toBeLessThanOrEqual(Date.now() + 60_000);
	});

	it("reads back nothing for an id that was never written", async () => {
		const transactions = createFederationTransactionStore(fakeStore());
		expect(await transactions.get("never-written")).toBeNull();
	});

	it("refuses to read a record that is not a transaction envelope", async () => {
		// Defence in depth for sharing a store with sessions: a record without a
		// well-shaped `federation` envelope is not one this module wrote.
		const store = fakeStore();
		store.records.set(`${FEDERATION_TRANSACTION_KEY_PREFIX}tx-1`, {
			cookie: {},
			sid: "a-session",
			isAuthenticated: true,
		});
		const transactions = createFederationTransactionStore(store);
		expect(await transactions.get("tx-1")).toBeNull();
	});

	it("refuses an envelope missing any of the fields the callback binds on", async () => {
		const store = fakeStore();
		const transactions = createFederationTransactionStore(store);
		store.records.set(`${FEDERATION_TRANSACTION_KEY_PREFIX}tx-1`, {
			cookie: {},
			federation: { name: "apple", state: "s" },
		});
		expect(await transactions.get("tx-1")).toBeNull();
	});

	it("omits an absent nonce and redirectTo rather than reading them as undefined keys", async () => {
		const store = fakeStore();
		const transactions = createFederationTransactionStore(store);
		await transactions.set(
			"tx-1",
			{ name: "github", state: "s", codeVerifier: "v" },
			DEFAULT_FEDERATION_TRANSACTION_TTL_MS,
		);
		expect(await transactions.get("tx-1")).toEqual({
			name: "github",
			state: "s",
			codeVerifier: "v",
		});
	});

	it("round-trips a link intent with its sid and its subject", async () => {
		const store = fakeStore();
		const transactions = createFederationTransactionStore(store);
		await transactions.set(
			"tx-1",
			{ ...envelope, link: { sid: "s-1", subject: "user-1" } },
			DEFAULT_FEDERATION_TRANSACTION_TTL_MS,
		);
		expect((await transactions.get("tx-1"))?.link).toEqual({ sid: "s-1", subject: "user-1" });
	});

	it("reads a link intent written before the subject was recorded as the sid alone, and drops a subject that is not a non-empty string", async () => {
		const store = fakeStore();
		const transactions = createFederationTransactionStore(store);
		for (const [written, read] of [
			[{ sid: "s-1" }, { sid: "s-1" }],
			[{ sid: "s-1", subject: "" }, { sid: "s-1" }],
			[{ sid: "s-1", subject: 7 }, { sid: "s-1" }],
		] as const) {
			await transactions.set(
				"tx-1",
				{ ...envelope, link: written as never },
				DEFAULT_FEDERATION_TRANSACTION_TTL_MS,
			);
			const link = (await transactions.get("tx-1"))?.link;
			expect(link).toEqual(read);
			expect(link !== undefined && "subject" in link).toBe(false);
		}
	});

	it("deletes a record", async () => {
		const store = fakeStore();
		const transactions = createFederationTransactionStore(store);

		await transactions.set("tx-1", envelope, DEFAULT_FEDERATION_TRANSACTION_TTL_MS);
		await transactions.delete("tx-1");

		expect(store.records.size).toBe(0);
		expect(await transactions.get("tx-1")).toBeNull();
	});

	it("propagates a store failure rather than swallowing it", async () => {
		// The route decides what an un-writable or un-deletable transaction
		// means; this layer only reports it. A delete that quietly failed would
		// leave a replayable transaction behind.
		const store = fakeStore();
		const transactions = createFederationTransactionStore(store);

		store.failOn = "set";
		await expect(transactions.set("tx-1", envelope, 1000)).rejects.toThrow("store down");

		store.failOn = "get";
		await expect(transactions.get("tx-1")).rejects.toThrow("store down");

		store.failOn = "destroy";
		await expect(transactions.delete("tx-1")).rejects.toThrow("store down");
	});
});
