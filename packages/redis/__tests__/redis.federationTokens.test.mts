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

// The Redis FederationTokenStore against a real Redis. The unit tests pin its
// logic against a fake; this file pins the chain over the wire: the index
// write, the SSCAN-paged read, the batched UNLINK, and the migration fallback
// that reaches records written before the index existed.

import { type FederationTokens, isStoreGeneration } from "@o3co/auth-provider-core";
import { Redis } from "ioredis";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createRedisFederationTokenStore, type EncryptionConfig } from "#/federation-tokens.mjs";
import { encryptTokenField } from "#/internal/crypto.mjs";
import { makeIoredisClients } from "#/ioredis.mjs";
import { serverClock, testRedis, until } from "./support/redis.mjs";

let raw: Redis;

beforeAll(async () => {
	const at = await testRedis();
	raw = new Redis(at);
});

afterAll(async () => {
	raw?.disconnect();
});

const tokens: FederationTokens = {
	accessToken: "at",
	refreshToken: "rt-secret",
	expiresAt: new Date(Date.now() + 3600_000),
	idToken: undefined,
	tokenType: undefined,
	scope: undefined,
	grantedScope: undefined,
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
			deploymentMode: "unset",
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
		// An envelope with no index member, as written before the index existed.
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

// The whole envelope is one AES-256-GCM ciphertext bound to its key.
// The unit tests pin this against a fake; this block pins that the bytes
// which actually land in Redis carry no plaintext, that a legacy per-field
// record is dropped on first read, and that a ciphertext moved to another
// key is refused — all over the wire.
describe("mode=required over a real Redis", () => {
	const encryptionKey = Buffer.alloc(32, 7);
	const fullTokens: FederationTokens = {
		accessToken: "at-secret",
		refreshToken: "rt-secret",
		idToken: "it-secret",
		expiresAt: new Date(1_900_000_000_000),
		tokenType: "Bearer",
		scope: "openid email",
		// Included, so the round-trip pins this field too.
		grantedScope: "openid email profile",
	};
	const makeEncrypted = () => makeStore(false, { mode: "required", key: encryptionKey });

	it("stores one ciphertext — no token, no field name in clear", async () => {
		const { keyPrefix, store } = makeEncrypted();
		await store.attach("sid-1", "google", fullTokens);

		const value = (await raw.get(`${keyPrefix}sid-1:google`)) as string;
		for (const marker of ["at-secret", "rt-secret", "it-secret", "openid email"]) {
			expect(value).not.toContain(marker);
		}
		const record = JSON.parse(value) as Record<string, unknown>;
		expect(Object.keys(record).sort()).toEqual(["c", "g", "v"]);
		expect(record.v).toBe(2);
	});

	it("round-trips every field, a null expiry included", async () => {
		const { store } = makeEncrypted();
		await store.attach("sid-1", "google", fullTokens);
		await store.attach("sid-1", "github", { ...fullTokens, expiresAt: null });
		expect(await store.get("sid-1", "google")).toEqual(fullTokens);
		expect(await store.get("sid-1", "github")).toEqual({ ...fullTokens, expiresAt: null });
	});

	it("drops a legacy per-field record on read — key gone, index member kept, null returned", async () => {
		const { keyPrefix, store } = makeEncrypted();
		// A legacy per-field record, under the same key this store holds.
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
		expect(await raw.sismember(`${keyPrefix}idx:sid-1`, "google")).toBe(1);
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
		expect(await raw.sismember(`${keyPrefix}idx:sid-2`, "google")).toBe(1);
		// The original is still readable under the key it was sealed for.
		expect(await store.get("sid-1", "google")).toEqual(fullTokens);
	});
});

// `obtainedAt` is one optional field inside the sealed envelope: written only
// when the record has one, read back as a fresh Date, absent as no key, and a
// value this store would never write takes the same self-heal as any
// unreadable record. The wrapper stays `v: 2`.
describe("obtainedAt over a real Redis", () => {
	const encryptionKey = Buffer.alloc(32, 7);
	const obtainedAt = new Date(1_899_999_000_000);
	const encryptions: ReadonlyArray<EncryptionConfig> = [
		{ mode: "required", key: encryptionKey },
		{ mode: "allow-plaintext" },
	];

	for (const encryption of encryptions) {
		describe(`mode=${encryption.mode}`, () => {
			// A v2 wrapper around `innerJson`, sealed for `key` under `required`.
			// Spliced in verbatim, so `1e999` reaches the reader as written.
			const wrap = (key: string, innerJson: string) =>
				encryption.mode === "required"
					? JSON.stringify({ v: 2, c: encryptTokenField(innerJson, encryptionKey, key) })
					: `{"v":2,"p":${innerJson}}`;

			it("round-trips obtainedAt through attach, update and get", async () => {
				const { store } = makeStore(false, encryption);
				await store.attach("sid-1", "google", { ...tokens, obtainedAt });
				expect(await store.get("sid-1", "google")).toStrictEqual({ ...tokens, obtainedAt });

				const later = new Date(obtainedAt.getTime() + 60_000);
				await store.update("sid-1", "google", { ...tokens, obtainedAt: later });
				expect((await store.get("sid-1", "google"))?.obtainedAt).toStrictEqual(later);
			});

			it("a record without obtainedAt reads back with the key absent, not undefined", async () => {
				const { store } = makeStore(false, encryption);
				await store.attach("sid-1", "google", tokens);
				const read = await store.get("sid-1", "google");
				expect(read).toStrictEqual(tokens);
				expect(Object.hasOwn(read ?? {}, "obtainedAt")).toBe(false);

				// An update without it removes a value an earlier write held.
				await store.attach("sid-2", "google", { ...tokens, obtainedAt });
				await store.update("sid-2", "google", tokens);
				expect(Object.hasOwn((await store.get("sid-2", "google")) ?? {}, "obtainedAt")).toBe(false);
			});

			it("hands out a copy: mutating either Date leaves the stored value", async () => {
				const { store } = makeStore(false, encryption);
				const callers = new Date(obtainedAt.getTime());
				await store.attach("sid-1", "google", { ...tokens, obtainedAt: callers });
				callers.setTime(0);
				(await store.get("sid-1", "google"))?.obtainedAt?.setTime(0);
				expect((await store.get("sid-1", "google"))?.obtainedAt).toStrictEqual(obtainedAt);
			});

			it("keeps the v2 wrapper", async () => {
				const { keyPrefix, store } = makeStore(false, encryption);
				await store.attach("sid-1", "google", { ...tokens, obtainedAt });
				const record = JSON.parse((await raw.get(`${keyPrefix}sid-1:google`)) as string) as Record<
					string,
					unknown
				>;
				expect(record.v).toBe(2);
				expect(Object.keys(record).sort()).toEqual(
					encryption.mode === "required" ? ["c", "g", "v"] : ["g", "p", "v"],
				);
			});

			it("writes an Invalid Date obtainedAt as absent: the tokens stay readable", async () => {
				const { store } = makeStore(false, encryption);
				await store.attach("sid-1", "google", { ...tokens, obtainedAt: new Date(Number.NaN) });
				const read = await store.get("sid-1", "google");
				expect(read).toStrictEqual(tokens);
			});

			it.each([
				["a string", '"soon"'],
				// JSON.stringify writes NaN as null.
				["null, as NaN is written", "null"],
				["not finite", "1e999"],
				["past the Date range", "8640000000000001"],
				["before the Date range", "-8640000000000001"],
			])(
				"a corrupt obtainedAtMs (%s) self-heals: key gone, index member kept, null returned",
				async (_label, value) => {
					const { keyPrefix, store } = makeStore(false, encryption);
					await store.attach("sid-1", "github", tokens);
					const key = `${keyPrefix}sid-1:google`;
					await raw.set(
						key,
						wrap(key, `{"accessToken":"at","expiresAtMs":null,"obtainedAtMs":${value}}`),
						"PX",
						3600_000,
					);
					await raw.sadd(`${keyPrefix}idx:sid-1`, "google");

					expect(await store.get("sid-1", "google")).toBeNull();
					expect(await raw.exists(key)).toBe(0);
					expect(await raw.sismember(`${keyPrefix}idx:sid-1`, "google")).toBe(1);
					expect(await raw.sismember(`${keyPrefix}idx:sid-1`, "github")).toBe(1);
				},
			);
		});
	}
});

// The conditional members over the wire: the generation in the wrapper, minted
// into a record written without one, the deadline each conditional script
// keeps, the index they never shrink, and the index the record never outlives.
describe("conditional writes over a real Redis", () => {
	const encryptionKey = Buffer.alloc(32, 7);
	const makeEncrypted = () => makeStore(false, { mode: "required", key: encryptionKey });

	/** The record at `key` rewritten as a replica without generations writes it: no `g`, `PX` `ttlMs`. */
	const rewriteWithoutGeneration = async (key: string, ttlMs: number): Promise<string> => {
		const { g: _g, ...rest } = JSON.parse((await raw.get(key)) as string) as Record<
			string,
			unknown
		>;
		const bytes = JSON.stringify(rest);
		await raw.set(key, bytes, "PX", ttlMs);
		return bytes;
	};

	const live = async (
		store: ReturnType<typeof makeEncrypted>["store"],
		sid: string,
		name: string,
	) => {
		const read = await store.getVersioned(sid, name);
		if (read === null) throw new Error(`${sid}/${name} is not live`);
		return read;
	};

	it("keeps the generation in the wrapper, outside the ciphertext, and moves it on every write", async () => {
		const { keyPrefix, store } = makeEncrypted();
		const key = `${keyPrefix}sid-1:google`;
		await store.attach("sid-1", "google", tokens);
		const record = JSON.parse((await raw.get(key)) as string) as Record<string, unknown>;
		expect(Object.keys(record).sort()).toEqual(["c", "g", "v"]);
		expect(record.v).toBe(2);
		const read = await live(store, "sid-1", "google");
		expect(read.generation).toBe(record.g);
		expect(isStoreGeneration(read.generation)).toBe(true);
		await store.update("sid-1", "google", tokens);
		const after = JSON.parse((await raw.get(key)) as string) as Record<string, unknown>;
		expect(after.g).not.toBe(record.g);
		expect(await store.get("sid-1", "google")).toEqual(tokens);
	});

	it("mints a generation into a record written without one, at its first versioned read, keeping its TTL", async () => {
		const { keyPrefix, store } = makeEncrypted();
		const key = `${keyPrefix}sid-1:google`;
		await store.attach("sid-1", "google", tokens);
		await rewriteWithoutGeneration(key, 600_000);
		// A replica without generations still reads it.
		expect(await store.get("sid-1", "google")).toEqual(tokens);
		expect(JSON.parse((await raw.get(key)) as string)).not.toHaveProperty("g");

		const read = await live(store, "sid-1", "google");
		expect(isStoreGeneration(read.generation)).toBe(true);
		expect(read.value).toEqual(tokens);
		const stored = JSON.parse((await raw.get(key)) as string) as Record<string, unknown>;
		expect(stored.g).toBe(read.generation);
		const pttl = await raw.pttl(key);
		expect(pttl).toBeGreaterThan(0);
		expect(pttl).toBeLessThanOrEqual(600_000);
		// The minted generation is the record's now: read again, and written at.
		expect((await live(store, "sid-1", "google")).generation).toBe(read.generation);
		const replaced = await store.replaceIf("sid-1", "google", read.generation, tokens);
		expect(replaced.outcome).toBe("updated");
	});

	it("answers conflict to a conditional write against a record rewritten without a generation, and mints nothing", async () => {
		const { keyPrefix, store } = makeEncrypted();
		const key = `${keyPrefix}sid-1:google`;
		await store.attach("sid-1", "google", tokens);
		const read = await live(store, "sid-1", "google");
		// A replica without generations rewrites the record after that read.
		const bytes = await rewriteWithoutGeneration(key, 600_000);

		expect(await store.replaceIf("sid-1", "google", read.generation, tokens)).toEqual({
			outcome: "conflict",
		});
		expect(await store.removeIf("sid-1", "google", read.generation)).toEqual({
			outcome: "conflict",
		});
		expect(await raw.get(key)).toBe(bytes);

		const again = await live(store, "sid-1", "google");
		expect(again.generation).not.toBe(read.generation);
	});

	it("answers null to a versioned read of an unreadable record, removes it, and keeps its index member", async () => {
		const { keyPrefix, store } = makeEncrypted();
		const key = `${keyPrefix}sid-1:google`;
		await raw.set(key, "{not-json", "PX", 600_000);
		await raw.sadd(`${keyPrefix}idx:sid-1`, "google");

		expect(await store.getVersioned("sid-1", "google")).toBeNull();
		expect(await raw.exists(key)).toBe(0);
		expect(await raw.sismember(`${keyPrefix}idx:sid-1`, "google")).toBe(1);
	});

	it("never shrinks the index, and never adds to it but on updated", async () => {
		const { keyPrefix, store } = makeEncrypted();
		const index = `${keyPrefix}idx:sid-1`;
		await store.attach("sid-1", "google", tokens);
		const read = await live(store, "sid-1", "google");
		// A removal leaves the member: a concurrent attach may have just added it.
		expect(await store.removeIf("sid-1", "google", read.generation)).toEqual({
			outcome: "removed",
		});
		expect(await raw.sismember(index, "google")).toBe(1);

		// missing never re-adds an entry.
		await raw.srem(index, "google");
		expect(await store.replaceIf("sid-1", "google", read.generation, tokens)).toEqual({
			outcome: "missing",
		});
		expect(await raw.sismember(index, "google")).toBe(0);

		// Nor does conflict.
		await store.attach("sid-1", "github", tokens);
		const stale = await live(store, "sid-1", "github");
		await store.update("sid-1", "github", tokens);
		await raw.srem(index, "github");
		expect(await store.replaceIf("sid-1", "github", stale.generation, tokens)).toEqual({
			outcome: "conflict",
		});
		expect(await raw.sismember(index, "github")).toBe(0);
	});

	it("after updated, the index outlives the record, and an index that had expired is made again", async () => {
		const { keyPrefix, store } = makeEncrypted();
		const index = `${keyPrefix}idx:sid-1`;
		const key = `${keyPrefix}sid-1:google`;
		await store.attach("sid-1", "google", tokens);
		await raw.pexpire(index, 60_000);
		const read = await live(store, "sid-1", "google");
		const replaced = await store.replaceIf("sid-1", "google", read.generation, tokens);
		expect(replaced.outcome).toBe("updated");
		expect(await raw.pttl(index)).toBeGreaterThanOrEqual(await raw.pttl(key));

		await raw.del(index);
		if (replaced.outcome !== "updated") throw new Error("not updated");
		expect((await store.replaceIf("sid-1", "google", replaced.generation, tokens)).outcome).toBe(
			"updated",
		);
		expect(await raw.sismember(index, "google")).toBe(1);
		expect(await raw.pttl(index)).toBeGreaterThanOrEqual(await raw.pttl(key));
	});

	it("a logout after a replace finds the record by the index, however long the replace took to reach the record", async () => {
		suiteCounter += 1;
		const keyPrefix = `t291ft:${suiteCounter}:`;
		const { federationTokenStoreClient } = makeIoredisClients(raw);
		// The index's TTL is raised, then the replace is held back past that TTL's end.
		const heldMs = 1_500;
		const store = createRedisFederationTokenStore({
			deploymentMode: "unset",
			client: {
				...federationTokenStoreClient,
				pExpireGT: async (k, ttlMs) => {
					await federationTokenStoreClient.pExpireGT(k, ttlMs);
					await new Promise((resolve) => setTimeout(resolve, heldMs));
				},
			},
			encryption: { mode: "required", key: encryptionKey },
			keyPrefix,
			scanFallback: false,
			ttl: 2,
		});
		await store.attach("sid-1", "google", tokens);
		const read = await live(store, "sid-1", "google");
		const raisedAt = Date.now();
		expect((await store.replaceIf("sid-1", "google", read.generation, tokens)).outcome).toBe(
			"updated",
		);
		// Past the deadline the raise set (2 s from it), short of the record's.
		await until(
			async () => Date.now() > raisedAt + 2_200,
			"the raised TTL to pass",
			raisedAt + 10_000,
		);
		expect(await raw.exists(`${keyPrefix}sid-1:google`)).toBe(1);
		await store.removeBySid("sid-1");
		expect(await raw.exists(`${keyPrefix}sid-1:google`)).toBe(0);
	});

	it("a conditional write that reaches the server past its deadline writes nothing", async () => {
		const { keyPrefix, store } = makeEncrypted();
		const key = `${keyPrefix}sid-1:google`;
		await store.attach("sid-1", "google", tokens);
		const read = await live(store, "sid-1", "google");
		const before = await raw.get(key);
		const { federationTokenStoreClient: client } = makeIoredisClients(raw);
		const past = (await serverClock(() => raw)()) - 1;
		expect(
			await client.replaceIfGeneration(key, {
				expected: read.generation,
				value: "replaced",
				ttlMs: 60_000,
				deadlineMs: past,
			}),
		).toBe("late");
		expect(
			await client.removeIfGeneration(key, { expected: read.generation, deadlineMs: past }),
		).toBe("late");
		expect(await raw.get(key)).toBe(before);
		// Within its deadline, the same write commits.
		expect(
			await client.removeIfGeneration(key, {
				expected: read.generation,
				deadlineMs: Date.now() + 60_000,
			}),
		).toBe("removed");
		expect(await raw.exists(key)).toBe(0);
	});
});
