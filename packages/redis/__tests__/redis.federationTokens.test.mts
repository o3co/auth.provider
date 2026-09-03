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
import { encryptTokenField } from "#/internal/crypto.mjs";
import {
	createRedisFederationTokenStore,
	type EncryptionConfig,
} from "../src/federation-tokens.mjs";
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
const makeStore = (
	scanFallback: boolean,
	encryption: EncryptionConfig = { mode: "allow-plaintext" },
) => {
	suiteCounter += 1;
	const keyPrefix = `t291ft:${suiteCounter}:`;
	const { federationTokenStoreClient } = makeIoredisClients(raw);
	return {
		keyPrefix,
		store: createRedisFederationTokenStore({
			client: federationTokenStoreClient,
			encryption,
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

// #293 — the whole envelope is one AES-256-GCM ciphertext bound to its key.
// The unit tests pin this against a fake; this block pins that the bytes
// which actually land in Redis carry no plaintext, that a legacy per-field
// record is dropped on first read, and that a ciphertext moved to another
// key is refused — all over the wire.
describe("#293 — mode=required over a real Redis", () => {
	const encryptionKey = Buffer.alloc(32, 7);
	const fullTokens: FederationTokens = {
		accessToken: "at-secret",
		refreshToken: "rt-secret",
		idToken: "it-secret",
		expiresAt: new Date(1_900_000_000_000),
		tokenType: "Bearer",
		scope: "openid email",
		rawParams: {
			access_token: "at-secret",
			refresh_token: "rt-secret",
			expires_in: 3599,
			account_hint: "user@example.com",
		},
	};
	const makeEncrypted = () => makeStore(false, { mode: "required", key: encryptionKey });

	it("stores one ciphertext — no token, no rawParams, no field name in clear", async () => {
		const { keyPrefix, store } = makeEncrypted();
		await store.attach("sid-1", "google", fullTokens);

		const value = (await raw.get(`${keyPrefix}sid-1:google`)) as string;
		for (const marker of [
			"at-secret",
			"rt-secret",
			"it-secret",
			"openid email",
			"user@example.com",
		]) {
			expect(value).not.toContain(marker);
		}
		const record = JSON.parse(value) as Record<string, unknown>;
		expect(Object.keys(record).sort()).toEqual(["c", "v"]);
		expect(record.v).toBe(2);
	});

	it("round-trips every field, rawParams and a null expiry included", async () => {
		const { store } = makeEncrypted();
		await store.attach("sid-1", "google", fullTokens);
		await store.attach("sid-1", "github", { ...fullTokens, expiresAt: null });
		expect(await store.get("sid-1", "google")).toEqual(fullTokens);
		expect(await store.get("sid-1", "github")).toEqual({ ...fullTokens, expiresAt: null });
	});

	it("drops a legacy per-field record on read — key and index member gone, null returned", async () => {
		const { keyPrefix, store } = makeEncrypted();
		// What v0.11 and earlier wrote, under the same key this store holds.
		await raw.set(
			`${keyPrefix}sid-1:google`,
			JSON.stringify({
				accessToken: encryptTokenField("at-secret", encryptionKey),
				refreshToken: encryptTokenField("rt-secret", encryptionKey),
				expiresAtMs: null,
				scope: "openid email",
				rawParams: { account_hint: "user@example.com" },
			}),
			"PX",
			3600_000,
		);
		await raw.sadd(`${keyPrefix}idx:sid-1`, "google", "github");

		expect(await store.get("sid-1", "google")).toBeNull();
		expect(await raw.exists(`${keyPrefix}sid-1:google`)).toBe(0);
		expect(await raw.sismember(`${keyPrefix}idx:sid-1`, "google")).toBe(0);
		expect(await raw.sismember(`${keyPrefix}idx:sid-1`, "github")).toBe(1);
	});

	it("a ciphertext copied to another session's key is refused and removed (AAD)", async () => {
		const { keyPrefix, store } = makeEncrypted();
		await store.attach("sid-1", "google", fullTokens);
		const bytes = (await raw.get(`${keyPrefix}sid-1:google`)) as string;
		await raw.set(`${keyPrefix}sid-2:google`, bytes, "PX", 3600_000);
		await raw.sadd(`${keyPrefix}idx:sid-2`, "google");

		expect(await store.get("sid-2", "google")).toBeNull();
		expect(await raw.exists(`${keyPrefix}sid-2:google`)).toBe(0);
		expect(await raw.exists(`${keyPrefix}idx:sid-2`)).toBe(0);
		// The original is still readable under the key it was sealed for.
		expect(await store.get("sid-1", "google")).toEqual(fullTokens);
	});
});
