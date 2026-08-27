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

// #291 — the redis FederationTokenStore against a real Redis, end to end.
//
// The unit tests pin the store's logic against a fake; this file pins that the
// chain actually works over the wire: the index write, the SSCAN-paged read,
// the batched UNLINK, and the migration fallback that reaches records written
// before the index existed.

import type { FederationTokens } from "@o3co/auth-provider-core";
import Redis from "ioredis";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createRedisFederationTokenStore } from "../src/federation-tokens.mjs";
import { makeIoredisClients } from "../src/ioredis.mjs";

let container: StartedTestContainer;
let raw: Redis;

beforeAll(async () => {
	container = await new GenericContainer("redis:7.2-alpine")
		.withExposedPorts(6379)
		.withStartupTimeout(60_000)
		.start();
	raw = new Redis({ host: container.getHost(), port: container.getMappedPort(6379) });
}, 90_000);

afterAll(async () => {
	raw?.disconnect();
	await container?.stop();
});

const tokens: FederationTokens = {
	accessToken: "at",
	refreshToken: "rt-secret",
	expiresAt: new Date(Date.now() + 3600_000),
};

let suiteCounter = 0;
const makeStore = (scanFallback: boolean) => {
	suiteCounter += 1;
	const keyPrefix = `t291ft:${suiteCounter}:`;
	const { federationTokenStoreClient } = makeIoredisClients(raw);
	return {
		keyPrefix,
		store: createRedisFederationTokenStore({
			client: federationTokenStoreClient,
			encryption: { mode: "allow-plaintext" },
			keyPrefix,
			scanFallback,
		}),
	};
};

describe("redis FederationTokenStore.removeBySid over a real Redis", () => {
	it("removes the session's federations without a keyspace scan", async () => {
		const { keyPrefix, store } = makeStore(false);
		await store.attach("sid-1", "google", tokens);
		await store.attach("sid-1", "github", tokens);
		await store.attach("sid-2", "google", tokens);

		await store.removeBySid("sid-1");

		expect(await store.get("sid-1", "google")).toBeNull();
		expect(await store.get("sid-1", "github")).toBeNull();
		expect(await store.get("sid-2", "google")).toEqual(tokens);
		// The index key is gone too, not left to age out.
		expect(await raw.exists(`${keyPrefix}idx:sid-1`)).toBe(0);
		expect(await raw.exists(`${keyPrefix}idx:sid-2`)).toBe(1);
	});

	it("handles a session linked to more federations than fit in one batch", async () => {
		const { keyPrefix, store } = makeStore(false);
		const names = Array.from({ length: 250 }, (_, i) => `idp-${String(i).padStart(3, "0")}`);
		for (const name of names) await store.attach("sid-many", name, tokens);

		await store.removeBySid("sid-many");

		expect(await raw.keys(`${keyPrefix}sid-many:*`)).toEqual([]);
		expect(await raw.exists(`${keyPrefix}idx:sid-many`)).toBe(0);
	});

	it("the index key never collides with the envelope keyspace", async () => {
		const { keyPrefix, store } = makeStore(false);
		await store.attach("sid-1", "google", tokens);
		// The migration fallback matches `${keyPrefix}${sid}:*`; the index must
		// sit outside it, or one session's sweep would reach another's index.
		expect(await raw.keys(`${keyPrefix}sid-1:*`)).toEqual([`${keyPrefix}sid-1:google`]);
		expect(await raw.type(`${keyPrefix}idx:sid-1`)).toBe("set");
	});

	it("delete(sid, name) leaves the remaining federation removable", async () => {
		const { store } = makeStore(false);
		await store.attach("sid-1", "google", tokens);
		await store.attach("sid-1", "github", tokens);
		await store.delete("sid-1", "google");
		await store.removeBySid("sid-1");
		expect(await store.get("sid-1", "github")).toBeNull();
	});

	it("scanFallback reaches envelopes written before the index existed", async () => {
		const { keyPrefix, store } = makeStore(true);
		// Exactly what the previous release wrote: an envelope, no index member.
		await raw.set(
			`${keyPrefix}legacy:google`,
			JSON.stringify({ accessToken: "at", expiresAtMs: null }),
			"PX",
			3600_000,
		);

		await store.removeBySid("legacy");

		expect(await raw.exists(`${keyPrefix}legacy:google`)).toBe(0);
	});

	it("with the fallback off, a pre-index envelope survives — the flag is the migration", async () => {
		const { keyPrefix, store } = makeStore(false);
		await raw.set(
			`${keyPrefix}legacy:google`,
			JSON.stringify({ accessToken: "at", expiresAtMs: null }),
			"PX",
			3600_000,
		);

		await store.removeBySid("legacy");

		expect(await raw.exists(`${keyPrefix}legacy:google`)).toBe(1);
	});
});
