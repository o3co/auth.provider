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
 * The re-authentication ask record (#481), on its own.
 *
 * `/authorize`'s suite drives the round trip; this one drives the store the
 * round trip rests on — the rejections that keep a forged or foreign ask from
 * being honoured, and the error paths a real session store takes when it is
 * unavailable.
 */

import { describe, expect, it, vi } from "vitest";
import {
	createReauthAskStore,
	REAUTH_ASK_KEY_PREFIX,
	REAUTH_ASK_TTL_MS,
	type ReauthAskSessionStore,
	reauthAskStoreFor,
} from "#/routes/reauthAsk.mjs";

const REQUEST = "https://issuer.example/oauth/authorize?client_id=app&state=xyz";

/** An express-session store, with the three callbacks the module uses. */
const memoryStore = (): ReauthAskSessionStore & { records: Map<string, unknown> } => {
	const records = new Map<string, unknown>();
	return {
		records,
		get: (sid, cb) => cb(null, records.get(sid)),
		set: (sid, record, cb) => {
			records.set(sid, record);
			cb?.();
		},
		destroy: (sid, cb) => {
			records.delete(sid);
			cb?.();
		},
	};
};

describe("createReauthAskStore — minting and spending an ask (#481)", () => {
	it("records the ask under a prefix of its own, with the expiry the store reaps on", async () => {
		const backing = memoryStore();
		const store = createReauthAskStore(backing);
		const askedAt = Math.floor(Date.now() / 1000);
		const id = await store.ask({ askedAt, request: REQUEST });

		// 32 bytes of base64url: unguessable, so naming an ask that exists is
		// itself the proof this server issued it.
		expect(id).toMatch(/^[A-Za-z0-9_-]{43}$/);
		const key = `${REAUTH_ASK_KEY_PREFIX}${id}`;
		expect([...backing.records.keys()]).toEqual([key]);
		// Shaped like a session so `MemoryStore` and `connect-redis` both reap it
		// without a sweeper of ours — the federation transaction's envelope.
		const record = backing.records.get(key) as { cookie: { expires: Date }; reauth: unknown };
		expect(record.cookie.expires.getTime()).toBeGreaterThan(Date.now());
		expect(record.reauth).toEqual({ askedAt, request: REQUEST });
	});

	it("hands the record back once and removes it in the same step", async () => {
		const backing = memoryStore();
		const store = createReauthAskStore(backing);
		const askedAt = Math.floor(Date.now() / 1000);
		const id = await store.ask({ askedAt, request: REQUEST });

		expect(await store.consume(id, REQUEST)).toEqual({ askedAt, request: REQUEST });
		expect(backing.records.size).toBe(0);
		expect(await store.consume(id, REQUEST)).toBeNull();
	});

	it("has nothing for an id it never minted", async () => {
		const store = createReauthAskStore(memoryStore());
		expect(await store.consume("an-id-this-server-never-minted", REQUEST)).toBeNull();
	});

	it("refuses an ask minted for another request, and spends it anyway", async () => {
		// Spent on the mismatch too: an ask presented once must not be retriable
		// against a third request until one of them happens to match.
		const backing = memoryStore();
		const store = createReauthAskStore(backing);
		const id = await store.ask({ askedAt: Math.floor(Date.now() / 1000), request: REQUEST });

		expect(await store.consume(id, `${REQUEST}&state=another`)).toBeNull();
		expect(backing.records.size).toBe(0);
	});

	it("refuses one that has aged past its window", async () => {
		const backing = memoryStore();
		const store = createReauthAskStore(backing);
		const askedAt = Math.floor((Date.now() - REAUTH_ASK_TTL_MS - 1000) / 1000);
		const id = await store.ask({ askedAt, request: REQUEST });

		expect(await store.consume(id, REQUEST)).toBeNull();
	});

	it("refuses anything under its key that is not the record it wrote", async () => {
		// A store shared with sessions: whatever else is found under the prefix
		// is not an ask, however session-shaped it looks.
		const backing = memoryStore();
		const store = createReauthAskStore(backing);
		const key = `${REAUTH_ASK_KEY_PREFIX}planted`;
		for (const planted of [
			undefined,
			null,
			"a string",
			{},
			{ reauth: null },
			{ reauth: "not an object" },
			{ reauth: { request: REQUEST } },
			{ reauth: { askedAt: "not a number", request: REQUEST } },
			{ reauth: { askedAt: Number.NaN, request: REQUEST } },
			{ reauth: { askedAt: 1, request: 42 } },
		]) {
			backing.records.set(key, planted);
			expect(await store.consume("planted", REQUEST), JSON.stringify(planted ?? null)).toBeNull();
		}
	});

	it("propagates a store that cannot answer, rather than reading an outage as no ask", async () => {
		// `/authorize` turns these into `temporarily_unavailable`: an outage is
		// not a decision either way, and "no ask" would silently re-ask.
		const boom = new Error("session store unavailable");
		const failing = (over: Partial<ReauthAskSessionStore>): ReauthAskSessionStore => ({
			...memoryStore(),
			...over,
		});

		await expect(
			createReauthAskStore(failing({ set: (_sid, _rec, cb) => cb?.(boom) })).ask({
				askedAt: 1,
				request: REQUEST,
			}),
		).rejects.toThrow(/unavailable/);

		await expect(
			createReauthAskStore(failing({ get: (_sid, cb) => cb(boom) })).consume("id", REQUEST),
		).rejects.toThrow(/unavailable/);

		const backing = memoryStore();
		const destroying = createReauthAskStore({
			...backing,
			destroy: (_sid, cb) => cb?.(boom),
		});
		const id = await destroying.ask({ askedAt: Math.floor(Date.now() / 1000), request: REQUEST });
		await expect(destroying.consume(id, REQUEST)).rejects.toThrow(/unavailable/);
	});
});

describe("reauthAskStoreFor — the store the session middleware mounted (#481)", () => {
	it("takes it off the request when it is store-shaped", () => {
		expect(reauthAskStoreFor({ sessionStore: memoryStore() })).toBeDefined();
	});

	it("finds none when there is none, or when what is there is not a store", () => {
		// A composition with no session middleware in front of `/authorize`, or
		// one whose store does not implement what an ask record needs. Either is
		// a composition error, which the endpoint refuses rather than working
		// around.
		expect(reauthAskStoreFor({})).toBeUndefined();
		expect(reauthAskStoreFor({ sessionStore: undefined })).toBeUndefined();
		expect(reauthAskStoreFor({ sessionStore: null })).toBeUndefined();
		expect(reauthAskStoreFor({ sessionStore: "not an object" })).toBeUndefined();
		expect(reauthAskStoreFor({ sessionStore: { get: vi.fn() } })).toBeUndefined();
		expect(reauthAskStoreFor({ sessionStore: { get: vi.fn(), set: vi.fn() } })).toBeUndefined();
		expect(
			reauthAskStoreFor({ sessionStore: { get: vi.fn(), set: vi.fn(), destroy: "no" } }),
		).toBeUndefined();
	});
});
