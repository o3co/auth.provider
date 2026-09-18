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

// The indivisible steps the Redis federation grant store is built from
// (#593, D16), against a real Redis: what one script does, what it refuses,
// what a key's own deadline becomes, and what the subject index holds.
//
// These are the rules the shared contract suite cannot reach. It holds both
// adapters to the same answers; it cannot see a key TTL, a member's score, or
// what happens when two writers interleave inside one millisecond.

import Redis from "ioredis";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { FederationGrantStoreClient } from "../src/clients.mjs";
import { makeIoredisFederationGrantStoreClient } from "../src/ioredis.mjs";

let container: StartedTestContainer;
let redis: Redis;
let client: FederationGrantStoreClient;
let run = 0;

beforeAll(async () => {
	container = await new GenericContainer("redis:7.2-alpine")
		.withExposedPorts(6379)
		.withStartupTimeout(60_000)
		.start();
	redis = new Redis({ host: container.getHost(), port: container.getMappedPort(6379) });
	client = makeIoredisFederationGrantStoreClient(redis);
}, 90_000);

afterAll(async () => {
	await redis?.quit();
	await container?.stop();
});

const MIN = 60_000;
const DAY = 86_400_000;
const RETENTION = 30 * DAY;
/** Every case in its own keyspace: the suite's files run in parallel inside one package. */
let prefix = "";
let now = 0;
const at = (ms: number): number => now + ms;

beforeEach(() => {
	run += 1;
	prefix = `t${run}:`;
	now = Math.floor(Date.now() / 1000) * 1000 + 137;
});

const grantKey = (id: string): string => `${prefix}{${id}}:grant`;
const credKey = (id: string): string => `${prefix}{${id}}:cred`;
const indexKey = (subject: string): string => `${prefix}sub:${subject}`;

const base = (id: string): string =>
	JSON.stringify([id, "u-1", "agent", "okta-calendar", String(now)]);

const pending = (
	id = "g-1",
	over: Partial<Parameters<FederationGrantStoreClient["createPending"]>[2]> = {},
) =>
	client.createPending(grantKey(id), credKey(id), {
		nowMs: now,
		base: base(id),
		handle: JSON.stringify(`h-${id}`),
		intentExpiresAtMs: at(10 * MIN),
		retentionMs: RETENTION,
		...over,
	});

/**
 * An `active` record, written field by field. The transitions that produce one
 * land in the next commit; what `touch` does to one is a rule of its own.
 */
const active = async (id = "g-1"): Promise<void> => {
	await redis.hset(grantKey(id), {
		format: "1",
		base: base(id),
		status: "active",
		version: "2",
		retentionMs: String(RETENTION),
		expiresAtMs: String(at(30 * DAY)),
	});
};

/** What a key's own deadline is, in epoch milliseconds; -1 when it has none. */
const deadline = async (key: string): Promise<number> =>
	Number(await redis.call("PEXPIRETIME", key));

describe("createPending (#593, D16)", () => {
	it("writes the record, at version 1, and hangs the key's deadline on the intent's expiry", async () => {
		const fields = await pending();
		expect(fields).toMatchObject({
			format: "1",
			base: base("g-1"),
			status: "pending",
			version: "1",
			retentionMs: String(RETENTION),
			intentHandle: JSON.stringify("h-g-1"),
			intentExpiresAt: String(at(10 * MIN)),
		});
		// A `pending` record keeps no retention: it is gone when its intent is.
		expect(await deadline(grantKey("g-1"))).toBe(at(10 * MIN));
		expect(await redis.exists(credKey("g-1"))).toBe(0);
	});

	it("creates nothing over a record that is still there, whatever this caller's clock says", async () => {
		await pending();
		// A second lodging under the same ID, from a caller whose clock is ahead
		// of the record's horizon: an ID is taken for as long as its record is
		// resident, not for as long as this caller can see it.
		expect(
			await pending("g-1", { nowMs: at(5_000 * DAY), intentExpiresAtMs: at(5_001 * DAY) }),
		).toBeNull();
		const fields = await client.snapshot(grantKey("g-1"), credKey("g-1"));
		expect(fields?.fields.intentExpiresAt).toBe(String(at(10 * MIN)));
	});

	it("creates nothing for an intent that has already lapsed, and nothing for one dated at this instant", async () => {
		for (const intentExpiresAtMs of [now, now - 1, Number.NaN]) {
			expect(await pending("g-1", { intentExpiresAtMs }), String(intentExpiresAtMs)).toBeNull();
		}
		expect(await redis.exists(grantKey("g-1"))).toBe(0);
	});

	it("takes an orphaned credential with it: a fresh record holds no secret from whatever was there before", async () => {
		// A mismatched restore, or a reused ID, can leave a ciphertext behind. It
		// would never authenticate under the new authorization, but a secret at
		// rest that nothing can use is still a secret at rest.
		await redis.set(credKey("g-1"), "v2.stale");
		expect(await pending()).not.toBeNull();
		expect(await redis.exists(credKey("g-1"))).toBe(0);
	});

	it("leaves an existing record's credential alone when it refuses", async () => {
		await pending();
		await redis.set(credKey("g-1"), "v2.live");
		expect(await pending("g-1", { handle: JSON.stringify("h-other") })).toBeNull();
		expect(await redis.get(credKey("g-1"))).toBe("v2.live");
	});
});

describe("snapshot (#593, D16)", () => {
	it("reads the record and its credential in one step", async () => {
		await pending();
		await redis.set(credKey("g-1"), "v2.sealed");
		const snapshot = await client.snapshot(grantKey("g-1"), credKey("g-1"));
		expect(snapshot?.fields.status).toBe("pending");
		expect(snapshot?.credential).toBe("v2.sealed");
	});

	it("says there is no record rather than an empty one, and tells a missing credential from an empty one", async () => {
		expect(await client.snapshot(grantKey("nothing"), credKey("nothing"))).toBeNull();
		await pending();
		expect((await client.snapshot(grantKey("g-1"), credKey("g-1")))?.credential).toBeNull();
		await redis.set(credKey("g-1"), "");
		expect((await client.snapshot(grantKey("g-1"), credKey("g-1")))?.credential).toBe("");
	});

	it("reads nothing at all when the key holds something that is not a record", async () => {
		await redis.set(grantKey("wrong"), "not a hash");
		await expect(client.snapshot(grantKey("wrong"), credKey("wrong"))).rejects.toThrow();
	});
});

describe("the intent pointer (#593, D16)", () => {
	it("is replaced on an authorized record and on nothing else, and moves no deadline", async () => {
		await pending();
		// A `pending` grant's intent is named at creation and never renamed: the
		// port refuses a renewal for one that was never authorized.
		expect(
			await client.nameIntent(grantKey("g-1"), {
				nowMs: at(MIN),
				handle: JSON.stringify("h-re"),
				intentExpiresAtMs: at(20 * MIN),
			}),
		).toBeNull();
		expect(await deadline(grantKey("g-1"))).toBe(at(10 * MIN));
	});

	it("is removed by retiring it, and only when the handle given is the one there", async () => {
		await pending();
		expect(
			await client.retireIntent(grantKey("g-1"), {
				nowMs: at(MIN),
				handle: JSON.stringify("h-other"),
			}),
		).toBeNull();
		expect((await client.snapshot(grantKey("g-1"), credKey("g-1")))?.fields.intentHandle).toBe(
			JSON.stringify("h-g-1"),
		);
	});
});

describe("touch (#593, D16)", () => {
	it("moves the last use forward and never back", async () => {
		await active();
		await client.touch(grantKey("g-1"), at(MIN));
		await client.touch(grantKey("g-1"), at(MIN - 1));
		expect((await client.snapshot(grantKey("g-1"), credKey("g-1")))?.fields.lastUsedAt).toBe(
			String(at(MIN)),
		);
	});

	it("records nothing on a grant that is not active: a use is a fact about a grant in use", async () => {
		await pending();
		await client.touch(grantKey("g-1"), at(MIN));
		expect(
			(await client.snapshot(grantKey("g-1"), credKey("g-1")))?.fields.lastUsedAt,
		).toBeUndefined();
	});

	it("writes nothing when there is no record: an ID that has lapsed is not brought back by a use", async () => {
		await client.touch(grantKey("gone"), at(MIN));
		expect(await redis.exists(grantKey("gone"))).toBe(0);
	});
});

describe("the subject index (#593, D16)", () => {
	const member = (id: string): string => JSON.stringify(id);

	it("holds each grant at its horizon, and the key's own deadline runs past the last of them", async () => {
		await client.reserve(indexKey("u-1"), member("g-1"), at(30 * DAY), MIN);
		await client.reserve(indexKey("u-1"), member("g-2"), at(60 * DAY), MIN);
		expect(await client.members(indexKey("u-1"))).toStrictEqual([member("g-1"), member("g-2")]);
		expect(await deadline(indexKey("u-1"))).toBe(at(60 * DAY) + MIN);
	});

	it("moves a horizon forward and never back: the record that wins a race is the one still listed", async () => {
		// Two writers lodge the same ID. The one whose record is created is not
		// necessarily the one that reserved last, so a reservation that loses must
		// not pull the horizon back under the winner.
		await client.reserve(indexKey("u-1"), member("g-1"), at(60 * DAY), MIN);
		await client.reserve(indexKey("u-1"), member("g-1"), at(10 * MIN), MIN);
		expect(await redis.zscore(indexKey("u-1"), member("g-1"))).toBe(String(at(60 * DAY)));
		expect(await deadline(indexKey("u-1"))).toBe(at(60 * DAY) + MIN);
	});

	it("drops a member only once its horizon is past by the allowance, and never one still to come", async () => {
		await client.reserve(indexKey("u-1"), member("due"), at(MIN), MIN);
		await client.reserve(indexKey("u-1"), member("just-due"), at(2 * MIN), MIN);
		await client.reserve(indexKey("u-1"), member("to-come"), at(10 * MIN), MIN);
		await client.prune(indexKey("u-1"), at(3 * MIN), MIN);
		// `just-due` sits exactly at the allowance and stays: the boundary belongs
		// to the record, because a member dropped while a replica whose clock is
		// behind can still read its record is a record `find` answers for and a
		// listing has lost.
		expect(await client.members(indexKey("u-1"))).toStrictEqual([
			member("just-due"),
			member("to-come"),
		]);
	});

	it("is gone as a whole once every horizon it holds is past: an index of dead members is not kept alive", async () => {
		// The deadline is the last horizon plus the allowance, so an index with
		// nothing live in it has a deadline behind Redis's own clock, and Redis
		// takes it from there. Nothing had to decide to delete it.
		await client.reserve(indexKey("u-1"), member("long-gone"), at(-DAY), MIN);
		expect(await redis.exists(indexKey("u-1"))).toBe(0);
	});

	it("never drops a member reserved for a record still being written: its horizon is in the future", async () => {
		// The window the layout is built around. The member goes in first, at the
		// horizon the record will have, so a pruning listing in between sees a
		// score that is not due and leaves it alone.
		await client.reserve(indexKey("u-1"), member("g-1"), at(10 * MIN), MIN);
		await client.prune(indexKey("u-1"), now, MIN);
		expect(await client.members(indexKey("u-1"))).toStrictEqual([member("g-1")]);
		expect(await pending()).not.toBeNull();
		expect(await client.members(indexKey("u-1"))).toStrictEqual([member("g-1")]);
	});

	it("is gone when the last of its members is, and not before", async () => {
		await client.reserve(indexKey("u-1"), member("g-1"), at(MIN), MIN);
		expect(await redis.exists(indexKey("u-1"))).toBe(1);
		await client.prune(indexKey("u-1"), at(30 * MIN), MIN);
		expect(await client.members(indexKey("u-1"))).toStrictEqual([]);
		expect(await redis.exists(indexKey("u-1"))).toBe(0);
	});

	it("says nothing is there for a subject that never had a grant", async () => {
		expect(await client.members(indexKey("u-nobody"))).toStrictEqual([]);
		await client.prune(indexKey("u-nobody"), now, MIN);
		expect(await redis.exists(indexKey("u-nobody"))).toBe(0);
	});
});
