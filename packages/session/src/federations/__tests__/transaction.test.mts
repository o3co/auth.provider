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
 * The federation transaction: the record and the cookie name that replaced
 * relaxing the application session cookie (#494).
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
	it("names the cookie after the deployment's session cookie", () => {
		expect(deriveFederationTransactionCookieName("auth.session")).toBe(
			"__Secure-auth.session.federation",
		);
	});

	it("applies __Secure- unconditionally, even to a session name that carries no prefix", () => {
		// Not merely a swap: unlike the session cookie, whose `Secure` flag is the
		// operator's to set, this cookie is SameSite=None and so is always issued
		// with `Secure`. The prefix states that invariant where the browser
		// enforces it.
		for (const name of ["auth.session", "sid", "my_app-cookie"]) {
			expect(deriveFederationTransactionCookieName(name)).toBe(`__Secure-${name}.federation`);
		}
	});

	it("swaps a __Host- prefix for __Secure-, because this cookie is path-scoped", () => {
		// `__Host-` requires `Path=/`. This cookie is deliberately scoped to the
		// callback route, so a `__Host-` name would be dropped by every browser
		// and the callback would fail with nothing visibly wrong.
		expect(deriveFederationTransactionCookieName("__Host-auth.session")).toBe(
			"__Secure-auth.session.federation",
		);
	});

	it("does not double up an existing __Secure- prefix", () => {
		expect(deriveFederationTransactionCookieName("__Secure-app.sid")).toBe(
			"__Secure-app.sid.federation",
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
