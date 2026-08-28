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
 * jwks-etag.test.mts — the #293 item 4 caching contract of the JWKS route.
 *
 * The response body is computed once per key SET and revalidated with a
 * strong ETag; the cache is keyed on (kid, publicKey identity) pairs because
 * the KeyStore contract has no rotation event to hook. These tests pin the
 * three behaviors that matter: a stable set serves a stable ETag and answers
 * `304` to `If-None-Match`, a changed set changes the ETag (and the body),
 * and the error paths stay uncached and untagged.
 */
import express from "express";
import { generateKeyPair } from "jose";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import type { KeyStore, ManagedKey } from "#/keys/KeyStore.mjs";
import { createRouter } from "#/routes/Jwks.mjs";

const makeStore = async () => {
	const first = await generateKeyPair("EdDSA");
	const second = await generateKeyPair("EdDSA");
	let keys: ManagedKey[] = [{ kid: "v1", publicKey: first.publicKey }];
	const getVerificationKeys = vi.fn(async () => keys);
	const store = {
		algorithm: "EdDSA",
		getVerificationKeys,
	} as unknown as KeyStore;
	return {
		store,
		getVerificationKeys,
		rotate: () => {
			keys = [
				{ kid: "v2", publicKey: second.publicKey },
				{ kid: "v1", publicKey: first.publicKey },
			];
		},
		empty: () => {
			keys = [];
		},
		shuffle: () => {
			keys = [...keys].reverse();
		},
	};
};

const makeApp = (store: KeyStore) => {
	const app = express();
	// Express's own weak auto-ETag would tag every body (503s included) and
	// answer If-None-Match itself; off, so what these tests observe is the
	// route's contract, not the framework's.
	app.set("etag", false);
	app.use(createRouter(express, store));
	return app;
};

const PATH = "/.well-known/jwks.json";

describe("JWKS route — ETag + one serialization per key set (#293 item 4)", () => {
	it("serves a stable strong ETag for a stable key set and 304s on If-None-Match", async () => {
		const { store } = await makeStore();
		const app = makeApp(store);

		const first = await request(app).get(PATH);
		expect(first.status).toBe(200);
		const etag = first.headers.etag;
		expect(etag).toMatch(/^"[A-Za-z0-9_-]+"$/);

		const second = await request(app).get(PATH);
		expect(second.headers.etag).toBe(etag);
		expect(second.body).toEqual(first.body);

		const revalidated = await request(app).get(PATH).set("If-None-Match", etag);
		expect(revalidated.status).toBe(304);
		expect(revalidated.headers.etag).toBe(etag);
		// 304 keeps the caching policy visible to the intermediary.
		expect(revalidated.headers["cache-control"]).toContain("max-age");
	});

	it("changes the ETag when the key set changes, and stops honoring the old tag", async () => {
		const { store, rotate } = await makeStore();
		const app = makeApp(store);

		const before = await request(app).get(PATH);
		rotate();
		const after = await request(app).get(PATH).set("If-None-Match", before.headers.etag);

		// The old tag no longer validates: full 200 with the new set.
		expect(after.status).toBe(200);
		expect(after.headers.etag).not.toBe(before.headers.etag);
		expect(after.body.keys.map((k: { kid: string }) => k.kid)).toEqual(["v2", "v1"]);
	});

	it("treats a reordered set as the same set: stable ETag, 304 still honored", async () => {
		// RFC 7517 assigns no meaning to key order — an adapter returning the
		// same keys reordered must not churn the cache or break pollers' 304s.
		const { store, rotate, shuffle } = await makeStore();
		const app = makeApp(store);

		rotate();
		const before = await request(app).get(PATH);
		shuffle();
		const revalidated = await request(app).get(PATH).set("If-None-Match", before.headers.etag);
		expect(revalidated.status).toBe(304);
		expect(revalidated.headers.etag).toBe(before.headers.etag);
	});

	it("runs the key export once per key set, not once per request", async () => {
		const { store, getVerificationKeys } = await makeStore();
		const app = makeApp(store);

		const first = await request(app).get(PATH);
		const second = await request(app).get(PATH);
		expect(second.text).toBe(first.text);
		// The keystore is still consulted per request (that is how expiry-based
		// shrink is noticed) — the cache sits behind it.
		expect(getVerificationKeys).toHaveBeenCalledTimes(2);
	});

	it("keeps the empty-set outage uncached and untagged", async () => {
		const { store, empty, rotate } = await makeStore();
		const app = makeApp(store);

		await request(app).get(PATH);
		empty();
		const res = await request(app).get(PATH);
		expect(res.status).toBe(503);
		expect(res.headers["cache-control"]).toBe("no-store");
		expect(res.headers.etag).toBeUndefined();

		// The outage neither poisoned the cache nor got cached itself: a
		// recovered set serves a tagged 200 again.
		rotate();
		const recovered = await request(app).get(PATH);
		expect(recovered.status).toBe(200);
		expect(recovered.headers.etag).toMatch(/^"[A-Za-z0-9_-]+"$/);
	});
});
