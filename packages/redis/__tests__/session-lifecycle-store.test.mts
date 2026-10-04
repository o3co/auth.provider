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

// What the Redis SessionLifecycleStore adds to the port's contract, on a real
// Redis: one key per session that lapses whole at the port's retention; the
// closing index, written before the closing commit and pruned only of entries
// no close can still commit; a write's replay key answering a copy the driver
// sends again; a key of another type refused as an outage; and the boot check
// of the server's eviction policy.

import {
	DEFAULT_CLOCK_SKEW_MS,
	type Logger,
	readVersionedSessionLifecycle,
	type SessionCloseRequest,
	type SessionLifecycleStore,
	type StoreGeneration,
} from "@o3co/auth-provider-core";
import { Redis } from "ioredis";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { RedisDurability, SessionLifecycleStoreClient } from "#/clients.mjs";
import { RedisStoreEvictableError } from "#/internal/eviction-policy.mjs";
import { checkSessionLifecycleEviction } from "#/internal/session-lifecycle-eviction.mjs";
import { makeIoredisClients } from "#/ioredis.mjs";
import { createRedisSessionLifecycleStore } from "#/session-lifecycle-store.mjs";
import { EXPIRY_GRACE_MS, serverClock, testRedis, until } from "./support/redis.mjs";

const HOUR = 60 * 60 * 1000;

let io: Redis;

beforeAll(async () => {
	io = new Redis(await testRedis());
});

afterAll(() => {
	io?.disconnect();
});

let prefixes = 0;

/** A store on a key prefix of its own, its client, and its keys. */
const fresh = (options: { maxParticipants?: number } = {}) => {
	prefixes += 1;
	const keyPrefix = `lct:${prefixes}:`;
	const client = makeIoredisClients(io).sessionLifecycleStoreClient;
	const store = createRedisSessionLifecycleStore({ client, keyPrefix, ...options });
	const tag = (sid: string) => Buffer.from(JSON.stringify(sid), "utf8").toString("base64url");
	return {
		keyPrefix,
		client,
		store,
		record: (sid: string) => `${keyPrefix}s:{${tag(sid)}}`,
		index: {
			sids: `${keyPrefix}c:{closing}:sids`,
			deadlines: `${keyPrefix}c:{closing}:deadlines`,
		},
	};
};

const CLOSE: SessionCloseRequest = {
	cause: "rp_logout",
	steps: ["user_session"],
	perParticipant: ["rp"],
	retainMs: 0,
};

const nowOnServer = serverClock(() => io);

const later = async (): Promise<Date> => new Date((await nowOnServer()) + HOUR);

const read = async (store: SessionLifecycleStore, sid: string) =>
	readVersionedSessionLifecycle(await store.read(sid));

/** The part of `key` Redis Cluster hashes: its first non-empty `{…}`, else the whole key. */
const hashedPartOf = (key: string): string => {
	const open = key.indexOf("{");
	if (open !== -1) {
		const close = key.indexOf("}", open + 1);
		if (close > open + 1) return key.slice(open + 1, close);
	}
	return key;
};

describe("createRedisSessionLifecycleStore: one key per session", () => {
	it("keeps a session's whole record in one hash, on a hash tag its every key shares, expiring at expiresAt plus the clock skew", async () => {
		const { store, record, keyPrefix } = fresh();
		for (const sid of ["sid-1", "{brace}d}", "a}b{c", "セッション"]) {
			const expiresAt = await later();
			expect((await store.open(sid, "user-1", expiresAt)).outcome).toBe("opened");
			expect((await store.join(sid, { kind: "rp", id: "client-1", data: "d" })).outcome).toBe(
				"joined",
			);
			expect((await store.join(sid, { kind: "family", id: "fam-1", data: "" })).outcome).toBe(
				"joined",
			);
			const key = record(sid);
			expect(await io.type(key)).toBe("hash");
			expect(await io.pexpiretime(key)).toBe(expiresAt.getTime() + DEFAULT_CLOCK_SKEW_MS);
			const keys = (await io.keys(`${keyPrefix}*`)).filter(
				(k) => hashedPartOf(k) === hashedPartOf(key),
			);
			const replays = keys.filter((k) => k !== key);
			expect(replays.length).toBeGreaterThan(0);
			for (const replay of replays) {
				expect(replay.startsWith(`${keyPrefix}w:{`)).toBe(true);
				expect(await io.pexpiretime(replay)).toBeLessThan((await nowOnServer()) + 5_000);
			}
		}
	});

	it("a close raises that one expiry to the later of it and the closing commit plus retainMs, and keeps it through closed", async () => {
		const { store, record } = fresh();
		const sid = "retain-long";
		const expiresAt = await later();
		await store.open(sid, "user-1", expiresAt);
		await store.join(sid, { kind: "rp", id: "client-1", data: "" });
		const closing = await store.beginClose(sid, { ...CLOSE, retainMs: 10 * HOUR });
		if (closing.outcome !== "closing") throw new Error(closing.outcome);
		const until = (closing.record.close?.closingAt.getTime() ?? Number.NaN) + 10 * HOUR;
		expect(await io.pexpiretime(record(sid))).toBe(until);
		let generation = closing.generation;
		for (const item of closing.record.close?.pending ?? []) {
			const done = await store.completeIf(sid, generation, item);
			if (done.outcome !== "updated") throw new Error(done.outcome);
			generation = done.generation;
		}
		expect((await read(store, sid))?.value.state).toBe("closed");
		expect(await io.pexpiretime(record(sid))).toBe(until);

		const short = "retain-short";
		const shortEnd = await later();
		await store.open(short, "user-1", shortEnd);
		await store.beginClose(short, CLOSE);
		expect(await io.pexpiretime(record(short))).toBe(shortEnd.getTime() + DEFAULT_CLOCK_SKEW_MS);
	});

	it("past that expiry the whole record is gone at once: read, join, close, completion and listing all find nothing", async () => {
		const { store, record } = fresh();
		const sid = "lapse";
		await store.open(sid, "user-1", await later());
		await store.join(sid, { kind: "rp", id: "client-1", data: "" });
		const closing = await store.beginClose(sid, CLOSE);
		if (closing.outcome !== "closing") throw new Error(closing.outcome);
		expect(await store.listClosing(10)).toEqual([sid]);
		await io.pexpire(record(sid), 1);
		await until(
			async () => (await io.exists(record(sid))) === 0,
			"the record to lapse",
			Date.now() + EXPIRY_GRACE_MS,
		);
		expect(await store.read(sid)).toBeNull();
		expect((await store.join(sid, { kind: "rp", id: "client-2", data: "" })).outcome).toBe(
			"missing",
		);
		expect((await store.beginClose(sid, CLOSE)).outcome).toBe("missing");
		expect((await store.completeIf(sid, closing.generation, "user_session")).outcome).toBe(
			"missing",
		);
		expect(await store.listClosing(10)).toEqual([]);
	});

	it("a join past maxParticipants rejects and writes nothing; a participant joined again is not counted twice", async () => {
		const { store } = fresh({ maxParticipants: 2 });
		const sid = "full";
		await store.open(sid, "user-1", await later());
		await store.join(sid, { kind: "rp", id: "a", data: "" });
		await store.join(sid, { kind: "rp", id: "b", data: "" });
		expect((await store.join(sid, { kind: "rp", id: "a", data: "again" })).outcome).toBe("joined");
		const before = await read(store, sid);
		await expect(store.join(sid, { kind: "rp", id: "c", data: "" })).rejects.toThrow(
			/at most 2 participants/,
		);
		expect(await read(store, sid)).toEqual(before);
	});

	it("refuses a key prefix holding a brace, and a maxParticipants that is no whole number from 1", () => {
		const client = makeIoredisClients(io).sessionLifecycleStoreClient;
		for (const keyPrefix of ["a{b:", "a}b:"]) {
			expect(() => createRedisSessionLifecycleStore({ client, keyPrefix })).toThrow(RangeError);
		}
		for (const maxParticipants of [0, 1.5, -1, Number.NaN]) {
			expect(() => createRedisSessionLifecycleStore({ client, maxParticipants })).toThrow(
				RangeError,
			);
		}
	});

	it("refuses a caller's input outside the port's rules as a RangeError, writing nothing", async () => {
		const { store, keyPrefix } = fresh();
		const expiresAt = await later();
		await expect(store.open("", "user-1", expiresAt)).rejects.toThrow(RangeError);
		await expect(store.open("s", "", expiresAt)).rejects.toThrow(RangeError);
		await expect(store.open("\ud800", "user-1", expiresAt)).rejects.toThrow(RangeError);
		await expect(store.open("s", "user-1", new Date(Number.NaN))).rejects.toThrow(RangeError);
		await expect(store.join("s", { kind: "nope", id: "x", data: "" } as never)).rejects.toThrow(
			RangeError,
		);
		await expect(store.beginClose("s", { ...CLOSE, steps: ["Bad"] })).rejects.toThrow(RangeError);
		await expect(
			store.completeIf("s", "00000000-0000-4000-8000-000000000000" as StoreGeneration, "no:x"),
		).rejects.toThrow(RangeError);
		await expect(store.listClosing(0)).rejects.toThrow(RangeError);
		await expect(store.listClosing(1001)).rejects.toThrow(RangeError);
		await expect(store.listClosing(1, "\udc00")).rejects.toThrow(RangeError);
		expect(await io.keys(`${keyPrefix}*`)).toEqual([]);
	});
});

describe("createRedisSessionLifecycleStore: the closing index", () => {
	it("is written before the closing commit: when it cannot be written, the close rejects and the record stays active", async () => {
		const { store, index } = fresh();
		const sid = "unindexed";
		await store.open(sid, "user-1", await later());
		await store.join(sid, { kind: "rp", id: "client-1", data: "" });
		await io.set(index.sids, "not a sorted set");
		await expect(store.beginClose(sid, CLOSE)).rejects.toThrow();
		const after = await read(store, sid);
		expect(after?.value.state).toBe("active");
		expect(after?.value.close).toBeUndefined();
	});

	it("listClosing names only records still closing: an entry whose record is active, closed or gone is skipped, and removed once the deadline of the close that added it has passed", async () => {
		const { store, index } = fresh();
		await store.open("active", "user-1", await later());
		await store.open("closed", "user-1", await later());
		await store.beginClose("closed", { ...CLOSE, steps: [], perParticipant: [] });
		await store.open("closing", "user-1", await later());
		await store.beginClose("closing", CLOSE);
		await store.open("in-flight", "user-1", await later());
		for (const sid of ["active", "closed", "gone"]) {
			await io.zadd(index.sids, "0", sid);
			await io.hset(index.deadlines, sid, "0");
		}
		await io.zadd(index.sids, "0", "in-flight");
		await io.hset(index.deadlines, "in-flight", String((await nowOnServer()) + HOUR));

		expect(await store.listClosing(1000)).toEqual(["closing"]);
		expect(await io.zrange(index.sids, "0", "-1")).toEqual(["closing", "in-flight"]);
		expect(await io.hkeys(index.deadlines)).toEqual(
			expect.arrayContaining(["closing", "in-flight"]),
		);
		expect(await io.hlen(index.deadlines)).toBe(2);
	});

	it("reaches a closing record past any number of stale entries ahead of it, a page at a time", async () => {
		const { store, index } = fresh();
		const stale = Array.from({ length: 250 }, (_, i) => `a-${String(i).padStart(3, "0")}`);
		for (const sid of stale) {
			await io.zadd(index.sids, "0", sid);
			await io.hset(index.deadlines, sid, "0");
		}
		await store.open("b-closing", "user-1", await later());
		await store.beginClose("b-closing", CLOSE);
		expect(await store.listClosing(1)).toEqual(["b-closing"]);
		expect(await store.listClosing(1, "b-closing")).toEqual([]);
		expect(await io.zrange(index.sids, "0", "-1")).toEqual(["b-closing"]);
	});

	it("the completion that closes a record removes its entry; a close answered closed at once removes its own", async () => {
		const { store, index } = fresh();
		await store.open("done", "user-1", await later());
		const closing = await store.beginClose("done", CLOSE);
		if (closing.outcome !== "closing") throw new Error(closing.outcome);
		expect(await io.zscore(index.sids, "done")).toBe("0");
		const done = await store.completeIf("done", closing.generation, "user_session");
		expect(done.outcome).toBe("updated");
		expect(await io.zscore(index.sids, "done")).toBeNull();
		expect(await io.hexists(index.deadlines, "done")).toBe(0);

		await store.open("empty", "user-1", await later());
		expect((await store.beginClose("empty", { ...CLOSE, steps: [] })).outcome).toBe("closed");
		expect(await io.zscore(index.sids, "empty")).toBeNull();
	});

	it("an entry a later close raised past the closed record's retention is kept, for the listing to judge", async () => {
		const { store, index } = fresh();
		const expiresAt = await later();
		await store.open("raised", "user-1", expiresAt);
		const closing = await store.beginClose("raised", CLOSE);
		if (closing.outcome !== "closing") throw new Error(closing.outcome);
		await io.hset(index.deadlines, "raised", String(expiresAt.getTime() + 10 * HOUR));
		expect((await store.completeIf("raised", closing.generation, "user_session")).outcome).toBe(
			"updated",
		);
		expect(await io.zscore(index.sids, "raised")).toBe("0");
		expect(await store.listClosing(10)).toEqual([]);
		expect(await io.zscore(index.sids, "raised")).toBe("0");
	});
});

describe("createRedisSessionLifecycleStore: a write sent again", () => {
	const deadlineOf = async (
		client: SessionLifecycleStoreClient,
		keyPrefix: string,
		key: string,
	) => {
		const deadlineMs = (await nowOnServer()) + 1_000;
		const tagged = key.slice(key.indexOf("{"));
		return {
			deadlineMs,
			replayKey: `${keyPrefix}w:${tagged.slice(0, tagged.indexOf("}") + 1)}:resend-${Math.random()}`,
			clockSkewMs: 1_000,
			client,
		};
	};

	it("a completion sent again answers what the first copy did and writes nothing, even after a later write", async () => {
		const { store, client, record, keyPrefix } = fresh();
		const sid = "complete-resend";
		await store.open(sid, "user-1", await later());
		const closing = await store.beginClose(sid, {
			...CLOSE,
			steps: ["user_session", "subject_index"],
		});
		if (closing.outcome !== "closing") throw new Error(closing.outcome);
		const { deadlineMs, replayKey, clockSkewMs } = await deadlineOf(client, keyPrefix, record(sid));
		const input = {
			deadlineMs,
			replayKey,
			clockSkewMs,
			expected: closing.generation,
			item: "user_session",
			generation: "11111111-1111-4111-8111-111111111111",
		};
		expect(await client.completeRecordItem(record(sid), input)).toEqual({ outcome: "updated" });
		const once = await read(store, sid);
		expect(once?.generation).toBe(input.generation);
		expect(await client.completeRecordItem(record(sid), input)).toEqual({ outcome: "updated" });
		expect(await read(store, sid)).toEqual(once);
		const next = await store.completeIf(sid, input.generation as StoreGeneration, "subject_index");
		expect(next.outcome).toBe("updated");
		const closed = await read(store, sid);
		expect(closed?.value.state).toBe("closed");
		expect(await client.completeRecordItem(record(sid), input)).toEqual({ outcome: "updated" });
		expect(await read(store, sid)).toEqual(closed);
	});

	it("a join whose reply was lost, sent again after the close committed, answers joined, and its participant is in the snapshot", async () => {
		const { store, client, record, keyPrefix } = fresh();
		const sid = "join-resend";
		await store.open(sid, "user-1", await later());
		const { deadlineMs, replayKey, clockSkewMs } = await deadlineOf(client, keyPrefix, record(sid));
		const input = {
			deadlineMs,
			replayKey,
			clockSkewMs,
			item: "rp:client-1",
			data: "d",
			generation: "22222222-2222-4222-8222-222222222222",
			maxParticipants: 10,
		};
		expect(await client.joinRecord(record(sid), input)).toBe("joined");
		const closing = await store.beginClose(sid, CLOSE);
		if (closing.outcome !== "closing") throw new Error(closing.outcome);
		expect(await client.joinRecord(record(sid), input)).toBe("joined");
		expect(closing.record.participants).toEqual([{ kind: "rp", id: "client-1", data: "d" }]);
		expect(closing.record.close?.pending).toContain("rp:client-1");
		expect((await read(store, sid))?.generation).toBe(closing.generation);
	});

	it("a write that reaches the server at or after its deadline writes nothing, and the store rejects it as an unknown outcome", async () => {
		const { store, client, record, keyPrefix } = fresh();
		const sid = "late";
		await store.open(sid, "user-1", await later());
		const before = await read(store, sid);
		const { replayKey, clockSkewMs } = await deadlineOf(client, keyPrefix, record(sid));
		const deadlineMs = (await nowOnServer()) - 1;
		expect(
			await client.joinRecord(record(sid), {
				deadlineMs,
				replayKey,
				clockSkewMs,
				item: "rp:x",
				data: "",
				generation: "33333333-3333-4333-8333-333333333333",
				maxParticipants: 10,
			}),
		).toBe("late");
		expect(await read(store, sid)).toEqual(before);

		const lateClient: SessionLifecycleStoreClient = {
			...client,
			openRecord: async () => "late",
			joinRecord: async () => "late",
			beginCloseRecord: async () => "late",
			completeRecordItem: async () => ({ outcome: "late" }),
		};
		const lateStore = createRedisSessionLifecycleStore({ client: lateClient, keyPrefix });
		await expect(lateStore.open("x", "user-1", await later())).rejects.toThrow(
			/outcome is unknown/,
		);
		await expect(lateStore.join(sid, { kind: "rp", id: "y", data: "" })).rejects.toThrow(
			/outcome is unknown/,
		);
		await expect(lateStore.beginClose(sid, CLOSE)).rejects.toThrow(/outcome is unknown/);
		await expect(
			lateStore.completeIf(sid, before?.generation as StoreGeneration, "user_session"),
		).rejects.toThrow(/outcome is unknown/);
	});
});

describe("createRedisSessionLifecycleStore: what it cannot read is an outage", () => {
	it("a session key of another type rejects every member, never answering an outcome, and is left as it was", async () => {
		const { store, record } = fresh();
		const sid = "wrong-type";
		await io.set(record(sid), "a string");
		const generation = "44444444-4444-4444-8444-444444444444" as StoreGeneration;
		const calls: Array<[string, () => Promise<unknown>]> = [
			["open", async () => store.open(sid, "user-1", await later())],
			["join", () => store.join(sid, { kind: "rp", id: "c", data: "" })],
			["beginClose", () => store.beginClose(sid, CLOSE)],
			["completeIf", () => store.completeIf(sid, generation, "user_session")],
			["read", () => store.read(sid)],
		];
		for (const [name, call] of calls) {
			const outcome = await call().then(
				() => "answered",
				(err: unknown) => err,
			);
			expect(outcome, name).toBeInstanceOf(Error);
			expect(outcome, name).not.toBeInstanceOf(RangeError);
		}
		expect(await io.get(record(sid))).toBe("a string");
	});

	it("a closing index of another type rejects listClosing", async () => {
		const { store, index } = fresh();
		await io.set(index.sids, "not a sorted set");
		await expect(store.listClosing(10)).rejects.toThrow();
	});

	it("a record this store did not write is refused, never read as absent", async () => {
		const { store, record } = fresh();
		await io.hset(record("bad-state"), {
			sub: "u",
			state: "open",
			exp: "1",
			gen: "x",
			until: "1",
			np: "0",
		});
		await io.hset(record("no-state"), { sub: "u" });
		await io.hset(record("stray"), {
			sub: "u",
			state: "active",
			exp: String(Date.now() + HOUR),
			gen: "55555555-5555-4555-8555-555555555555",
			until: String(Date.now() + 2 * HOUR),
			np: "0",
			other: "x",
		});
		for (const sid of ["bad-state", "no-state", "stray"]) {
			await expect(store.read(sid), sid).rejects.toThrow();
		}
		await expect(store.join("bad-state", { kind: "rp", id: "c", data: "" })).rejects.toThrow();
		await expect(store.join("no-state", { kind: "rp", id: "c", data: "" })).rejects.toThrow();
		await expect(store.listClosing(10)).resolves.toEqual([]);
	});
});

describe("checkSessionLifecycleEviction", () => {
	const report = (maxmemoryPolicy: string | undefined, refusal?: unknown): RedisDurability => ({
		maxmemoryPolicy,
		appendOnly: undefined,
		snapshots: undefined,
		refusal,
	});
	const logger = () =>
		({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }) as unknown as Logger & {
			warn: ReturnType<typeof vi.fn>;
		};

	it("passes noeviction silently", async () => {
		const log = logger();
		await checkSessionLifecycleEviction(async () => report("noeviction"), log);
		expect(log.warn).not.toHaveBeenCalled();
	});

	it.each([
		"volatile-lru",
		"volatile-lfu",
		"volatile-random",
		"volatile-ttl",
		"allkeys-lru",
		"allkeys-lfu",
		"allkeys-random",
	])("refuses %s, naming it", async (policy) => {
		const err = await checkSessionLifecycleEviction(async () => report(policy), logger()).then(
			() => undefined,
			(e: unknown) => e,
		);
		expect(err).toBeInstanceOf(RedisStoreEvictableError);
		expect(err).toMatchObject({
			reason: "session-lifecycle-store-evictable",
			maxmemoryPolicy: policy,
		});
	});

	it("warns once and boots when the policy cannot be read, is unknown, or the server cannot answer", async () => {
		for (const durability of [
			async () => report(undefined, new Error("NOPERM")),
			async () => report("some-future-policy"),
			async () => {
				throw new Error("down");
			},
		]) {
			const log = logger();
			await checkSessionLifecycleEviction(durability, log);
			expect(log.warn).toHaveBeenCalledTimes(1);
			expect(log.warn.mock.calls[0]?.[1]).toBe("session_lifecycle_store_eviction_unchecked");
		}
	});
});
