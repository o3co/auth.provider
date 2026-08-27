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

// #291 — the sid-keyed SET backing the federation token store's per-session
// key index, against a real Redis. Sibling of `internalSidHash.test.mts` and
// `internalSidSortedSet.test.mts`.
//
// The expiry semantics (`PEXPIRE … NX` + `PEXPIRE … GT` inside one MULTI) and
// the `SSCAN` paging live in the ioredis wrapper, so a fake cannot vouch for
// them: these run through `makeIoredisClients`.

import Redis from "ioredis";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { RedisSidSetClient } from "../src/internal/redisSidSet.mjs";
import { createRedisSidSet } from "../src/internal/redisSidSet.mjs";
import { makeIoredisClients } from "../src/ioredis.mjs";

let container: StartedTestContainer;
let raw: Redis;
let client: RedisSidSetClient;

beforeAll(async () => {
	container = await new GenericContainer("redis:7.2-alpine")
		.withExposedPorts(6379)
		.withStartupTimeout(60_000)
		.start();
	raw = new Redis({ host: container.getHost(), port: container.getMappedPort(6379) });
	client = makeIoredisClients(raw).federationTokenStoreClient;
}, 90_000);

afterAll(async () => {
	raw?.disconnect();
	await container?.stop();
});

const prefix = (s: string) => `t291:${s}:`;
const HOUR_MS = 3600_000;

const collect = async (it: AsyncIterable<string>): Promise<string[]> => {
	const out = new Set<string>();
	for await (const m of it) out.add(m);
	return [...out].sort();
};

describe("createRedisSidSet", () => {
	it("add then members returns the inserted member", async () => {
		const s = createRedisSidSet({ client, keyPrefix: prefix("basic") });
		await s.add("sid-1", "google", HOUR_MS);
		expect(await collect(s.members("sid-1"))).toEqual(["google"]);
	});

	it("distinct members accumulate; re-adding one is a no-op", async () => {
		const s = createRedisSidSet({ client, keyPrefix: prefix("accum") });
		await s.add("sid-1", "google", HOUR_MS);
		await s.add("sid-1", "github", HOUR_MS);
		await s.add("sid-1", "google", HOUR_MS);
		expect(await collect(s.members("sid-1"))).toEqual(["github", "google"]);
	});

	it("members of an absent sid is an empty iteration, not an error", async () => {
		const s = createRedisSidSet({ client, keyPrefix: prefix("ghost") });
		expect(await collect(s.members("nobody"))).toEqual([]);
	});

	// The bootstrap half of the D-10 pair: a bare `PEXPIRE … GT` would silently
	// no-op on a key with no TTL, leaving the index persistent — a key that
	// outlives every session it ever described.
	it("first write sets a TTL (no infinite-TTL bootstrap leak)", async () => {
		const s = createRedisSidSet({ client, keyPrefix: prefix("ttl-boot") });
		await s.add("sid-fresh", "google", HOUR_MS);
		const pttl = await raw.pttl(`${prefix("ttl-boot")}sid-fresh`);
		expect(pttl).toBeGreaterThan(0);
	});

	it("a later write with a shorter TTL does not truncate the existing one (GT)", async () => {
		const key = `${prefix("ttl-trunc")}sid-1`;
		const s = createRedisSidSet({ client, keyPrefix: prefix("ttl-trunc") });
		await s.add("sid-1", "google", HOUR_MS);
		await s.add("sid-1", "github", 500);
		expect(await raw.pttl(key)).toBeGreaterThan(HOUR_MS - 60_000);
	});

	it("a later write with a longer TTL raises it (the index must outlive its envelopes)", async () => {
		const key = `${prefix("ttl-raise")}sid-1`;
		const s = createRedisSidSet({ client, keyPrefix: prefix("ttl-raise") });
		await s.add("sid-1", "google", 5_000);
		await s.add("sid-1", "github", HOUR_MS);
		expect(await raw.pttl(key)).toBeGreaterThan(HOUR_MS - 60_000);
	});

	it("the key expires on its own once the TTL elapses", async () => {
		const s = createRedisSidSet({ client, keyPrefix: prefix("ttl-expire") });
		await s.add("sid-1", "google", 200);
		expect(await collect(s.members("sid-1"))).toEqual(["google"]);
		await new Promise((r) => setTimeout(r, 300));
		expect(await collect(s.members("sid-1"))).toEqual([]);
	});

	it("remove drops only the named member", async () => {
		const s = createRedisSidSet({ client, keyPrefix: prefix("rem-one") });
		await s.add("sid-1", "google", HOUR_MS);
		await s.add("sid-1", "github", HOUR_MS);
		await s.remove("sid-1", "google");
		expect(await collect(s.members("sid-1"))).toEqual(["github"]);
	});

	it("removeBySid clears the key", async () => {
		const s = createRedisSidSet({ client, keyPrefix: prefix("rem-all") });
		await s.add("sid-1", "google", HOUR_MS);
		await s.add("sid-1", "github", HOUR_MS);
		await s.removeBySid("sid-1");
		expect(await raw.exists(`${prefix("rem-all")}sid-1`)).toBe(0);
	});

	it("removeBySid is idempotent on an absent sid", async () => {
		const s = createRedisSidSet({ client, keyPrefix: prefix("rem-ghost") });
		await expect(s.removeBySid("nobody")).resolves.toBeUndefined();
	});

	// 500 members is well past `set-max-listpack-entries` (128 by default), so
	// Redis stores this as a real hashtable and SSCAN genuinely spans several
	// cursors rather than answering in one.
	it("members pages through a set far larger than one cursor", async () => {
		const s = createRedisSidSet({ client, keyPrefix: prefix("paged"), scanCount: 25 });
		const expected = Array.from({ length: 500 }, (_, i) => `idp-${String(i).padStart(3, "0")}`);
		for (const m of expected) await s.add("sid-paged", m, HOUR_MS);
		expect(await collect(s.members("sid-paged"))).toEqual([...expected].sort());
	});

	// Copilot review on PR #352. The unit tests assert this against a fake, so
	// they only prove we handle the reply shape we assumed. This proves the
	// assumption: a real Redis answers EXEC successfully while reporting
	// WRONGTYPE for the queued SADD, and ioredis resolves rather than rejects.
	// Without the reply check the caller would be told the index write landed.
	it("add surfaces a queued command's failure instead of reporting success", async () => {
		const s = createRedisSidSet({ client, keyPrefix: prefix("wrongtype") });
		await raw.set(`${prefix("wrongtype")}sid-1`, "not-a-set");
		await expect(s.add("sid-1", "google", HOUR_MS)).rejects.toThrow(/WRONGTYPE/);
	});

	it("100 parallel adds of the same member converge to one entry", async () => {
		const s = createRedisSidSet({ client, keyPrefix: prefix("conc-same") });
		await Promise.all(Array.from({ length: 100 }, () => s.add("sid-c", "google", HOUR_MS)));
		expect(await collect(s.members("sid-c"))).toEqual(["google"]);
	});
});
