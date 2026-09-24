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
 * Redis {@link SubjectSessionIndex} (#321) — the adapter that makes
 * `revokeAllForSubject` work on a multi-replica deployment. Without it
 * `redisSessionStoresModule` fills neither subject slot and a password reset
 * revokes nothing.
 */

import Redis from "ioredis";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { makeIoredisClients } from "../src/ioredis.mjs";
import { createRedisSubjectSessionIndex } from "../src/subjectSessionIndex.mjs";
import { runSubjectSessionIndexContract } from "./subjectSessionIndex.contract.mjs";
import { serverClock, testRedis } from "./support/redis.mjs";

let raw: Redis;

beforeAll(async () => {
	const at = await testRedis();
	raw = new Redis(at);
});

afterAll(async () => {
	raw?.disconnect();
});

let suiteCounter = 0;
runSubjectSessionIndexContract(async () => {
	suiteCounter += 1;
	const { subjectSessionIndexClient } = makeIoredisClients(raw);
	return createRedisSubjectSessionIndex({
		client: subjectSessionIndexClient,
		keyPrefix: `t321i:${suiteCounter}:`,
	});
});

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** The server's clock: what the prune in `listSids` compares scores against. */
const serverNow = serverClock(() => raw);

/**
 * An expiry a second ahead of whichever clock is later: the host's, which
 * `addSid` checks it against, and the server's, which ages it out. The read
 * that follows the write lands well inside it however loaded the run is.
 */
const aheadOfBoth = async (): Promise<Date> =>
	new Date(Math.max(Date.now(), await serverNow()) + 1_000);

/** Resolves once the server's clock has passed `at` — waited out there, not slept on the host. */
const serverPasses = async (at: Date): Promise<void> => {
	while ((await serverNow()) <= at.getTime()) await sleep(20);
};

describe("SubjectSessionIndex — Redis-specific behaviour (#321)", () => {
	const index = (prefix: string) =>
		createRedisSubjectSessionIndex({
			client: makeIoredisClients(raw).subjectSessionIndexClient,
			keyPrefix: prefix,
		});

	it("ages a member out on the server's clock, not the caller's", async () => {
		// The property fake timers cannot test: the score is compared against
		// Redis time, and a member whose expiry passes while the index holds it
		// stops being listed. Dated from, and waited out on, that clock: a
		// 60 ms expiry and a 150 ms sleep on the host had the server prune the
		// member before the first read on a loaded run, or keep it past the
		// second when its clock lagged the host's.
		const idx = index("t321i:age:");
		const expiresAt = await aheadOfBoth();
		await idx.addSid("u1", "short", expiresAt);
		await idx.addSid("u1", "long", new Date(expiresAt.getTime() + 600_000));
		expect([...(await idx.listSids("u1"))].sort()).toEqual(["long", "short"]);
		await serverPasses(expiresAt);
		expect(await idx.listSids("u1")).toEqual(["long"]);
	});

	it("reclaims the key once every member has aged out", async () => {
		// Lazy GC on read is the only sweep, so an emptied set must not survive
		// as a key for everyone who ever logged in.
		const idx = index("t321i:reclaim:");
		const expiresAt = await aheadOfBoth();
		await idx.addSid("u2", "s1", expiresAt);
		await serverPasses(expiresAt);
		expect(await idx.listSids("u2")).toEqual([]);
		expect(await raw.exists("t321i:reclaim:u2")).toBe(0);
	});

	it("bounds an abandoned subject key with a TTL", async () => {
		// Nothing revisits a subject that never logs in again, so the key needs
		// its own expiry as a backstop — the shape #269 paid for. Read back as
		// the absolute deadline (`PEXPIRETIME`), which no clock moves: the key
		// expires exactly when its only member does.
		const idx = index("t321i:ttl:");
		const expiresAt = new Date(Date.now() + 600_000);
		await idx.addSid("u3", "s1", expiresAt);
		expect(await raw.pexpiretime("t321i:ttl:u3")).toBe(expiresAt.getTime());
	});

	it("extends the key TTL for a longer-lived session but never truncates it", async () => {
		// On the absolute deadline rather than two `PTTL` readings taken a
		// round-trip apart, so the claim is exact: the key keeps the furthest
		// member's expiry.
		const idx = index("t321i:ttlgt:");
		const long = new Date(Date.now() + 600_000);
		await idx.addSid("u4", "long", long);
		expect(await raw.pexpiretime("t321i:ttlgt:u4")).toBe(long.getTime());
		await idx.addSid("u4", "short", new Date(Date.now() + 5_000));
		// A shorter-lived member must not pull the whole subject's key in with it.
		expect(await raw.pexpiretime("t321i:ttlgt:u4")).toBe(long.getTime());
		const longer = new Date(Date.now() + 900_000);
		await idx.addSid("u4", "longer", longer);
		expect(await raw.pexpiretime("t321i:ttlgt:u4")).toBe(longer.getTime());
	});

	it("keeps two subjects in separate keys", async () => {
		// A shared prefix would let a sid collide with a subject.
		const idx = index("t321i:sep:");
		await idx.addSid("alice", "s1", new Date(Date.now() + 600_000));
		await idx.addSid("bob", "s2", new Date(Date.now() + 600_000));
		expect(await raw.exists("t321i:sep:alice")).toBe(1);
		expect(await raw.exists("t321i:sep:bob")).toBe(1);
	});

	it("survives 100 parallel adds for one subject", async () => {
		const idx = index("t321i:conc:");
		await Promise.all(
			Array.from({ length: 100 }, (_, i) =>
				idx.addSid("u5", `s${i}`, new Date(Date.now() + 600_000)),
			),
		);
		expect((await idx.listSids("u5")).length).toBe(100);
	});
});

describe("SubjectSessionIndex — the read boundary is the store's clock (#321)", () => {
	it("hands the read no timestamp of its own", async () => {
		// Structural, not incidental: `pruneExpiredAndList` takes a key and
		// nothing else, so the adapter *cannot* pass a caller-side `Date.now()`
		// as the boundary. Scores are written by whichever replica handled the
		// login and read by whichever replica handles the next request; a host
		// clock on either side of that comparison is the skew that drops live
		// sessions early or keeps expired ones listed.
		const calls: unknown[][] = [];
		const idx = createRedisSubjectSessionIndex({
			client: {
				multi: () => {
					throw new Error("not used by listSids");
				},
				zAdd: async () => 1,
				pruneExpiredAndList: async (...args: unknown[]) => {
					calls.push(args);
					return ["s1"];
				},
				zRem: async () => 1,
				unlink: async () => 1,
			} as never,
			keyPrefix: "t321i:clock:",
		});

		expect(await idx.listSids("u9")).toEqual(["s1"]);
		expect(calls).toEqual([["t321i:clock:u9"]]);
	});
});
