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
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { makeIoredisClients } from "../src/ioredis.mjs";
import { createRedisSubjectSessionIndex } from "../src/subjectSessionIndex.mjs";
import { runSubjectSessionIndexContract } from "./subjectSessionIndex.contract.mjs";

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

describe("SubjectSessionIndex — Redis-specific behaviour (#321)", () => {
	const index = (prefix: string) =>
		createRedisSubjectSessionIndex({
			client: makeIoredisClients(raw).subjectSessionIndexClient,
			keyPrefix: prefix,
		});

	it("ages a member out on the server's clock, not the caller's", async () => {
		// The property fake timers cannot test: the score is compared against
		// Redis time, and a member whose expiry passes while the index holds it
		// stops being listed.
		const idx = index("t321i:age:");
		await idx.addSid("u1", "short", new Date(Date.now() + 60));
		await idx.addSid("u1", "long", new Date(Date.now() + 600_000));
		expect([...(await idx.listSids("u1"))].sort()).toEqual(["long", "short"]);
		await sleep(150);
		expect(await idx.listSids("u1")).toEqual(["long"]);
	});

	it("reclaims the key once every member has aged out", async () => {
		// Lazy GC on read is the only sweep, so an emptied set must not survive
		// as a key for everyone who ever logged in.
		const idx = index("t321i:reclaim:");
		await idx.addSid("u2", "s1", new Date(Date.now() + 60));
		await sleep(150);
		expect(await idx.listSids("u2")).toEqual([]);
		expect(await raw.exists("t321i:reclaim:u2")).toBe(0);
	});

	it("bounds an abandoned subject key with a TTL", async () => {
		// Nothing revisits a subject that never logs in again, so the key needs
		// its own expiry as a backstop — the shape #269 paid for.
		const idx = index("t321i:ttl:");
		await idx.addSid("u3", "s1", new Date(Date.now() + 600_000));
		const ttl = await raw.pttl("t321i:ttl:u3");
		expect(ttl).toBeGreaterThan(0);
		// The expiry is an absolute timestamp taken from the *host* clock and
		// read back against the *container's*, so a few milliseconds of skew
		// between them is expected and is not what this asserts. The claim is
		// that the key is bounded by roughly the member's own lifetime, not that
		// the two clocks agree.
		expect(ttl).toBeLessThanOrEqual(605_000);
	});

	it("extends the key TTL for a longer-lived session but never truncates it", async () => {
		const idx = index("t321i:ttlgt:");
		await idx.addSid("u4", "long", new Date(Date.now() + 600_000));
		const afterLong = await raw.pttl("t321i:ttlgt:u4");
		await idx.addSid("u4", "short", new Date(Date.now() + 5_000));
		const afterShort = await raw.pttl("t321i:ttlgt:u4");
		// A shorter-lived member must not pull the whole subject's key in with it.
		expect(afterShort).toBeGreaterThan(5_000);
		expect(Math.abs(afterShort - afterLong)).toBeLessThan(2_000);
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
