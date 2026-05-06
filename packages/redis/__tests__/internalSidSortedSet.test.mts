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

import Redis from "ioredis";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { SessionSidSortedSetClient, SessionSidSortedSetMultiClient } from "../src/clients.mjs";
import { createRedisSidSortedSet } from "../src/internal/redisSidSortedSet.mjs";

let container: StartedTestContainer;
let raw: Redis;
let client: SessionSidSortedSetClient;

beforeAll(async () => {
	container = await new GenericContainer("redis:7.2-alpine").withExposedPorts(6379).start();
	raw = new Redis({ host: container.getHost(), port: container.getMappedPort(6379) });
	client = makeWrapper(raw);
}, 60_000);

afterAll(async () => {
	raw?.disconnect();
	await container?.stop();
});

const FUTURE = () => new Date(Date.now() + 60_000);
const PAST = () => new Date(Date.now() - 1);
const prefix = (s: string) => `t13:${s}:`;

describe("createRedisSidSortedSet", () => {
	it("add then list returns inserted member", async () => {
		const z = createRedisSidSortedSet({ client, keyPrefix: prefix("basic") });
		await z.add("sid-1", "alpha", FUTURE());
		expect(await z.list("sid-1")).toEqual(["alpha"]);
	});

	it("add preserves insertion order across distinct members", async () => {
		const z = createRedisSidSortedSet({ client, keyPrefix: prefix("order") });
		// Insertion order is guaranteed by the module-level monotonic counter
		// in createRedisSidSortedSet (per A4 §5.4 — see internal/redisSidSortedSet.mts);
		// no inter-add sleep is needed.
		await z.add("sid-1", "google", FUTURE());
		await z.add("sid-1", "github", FUTURE());
		await z.add("sid-1", "gitlab", FUTURE());
		expect(await z.list("sid-1")).toEqual(["google", "github", "gitlab"]);
	});

	it("re-add of existing member does NOT promote position (ZADD NX)", async () => {
		const z = createRedisSidSortedSet({ client, keyPrefix: prefix("nx") });
		// Insertion order is guaranteed by the module-level monotonic counter
		// in createRedisSidSortedSet (per A4 §5.4 — see internal/redisSidSortedSet.mts);
		// no inter-add sleep is needed.
		await z.add("sid-1", "google", FUTURE());
		await z.add("sid-1", "github", FUTURE());
		await z.add("sid-1", "google", FUTURE()); // re-add: must NOT move to end
		expect(await z.list("sid-1")).toEqual(["google", "github"]);
	});

	it("add after expiry no-ops (no zombie key)", async () => {
		const z = createRedisSidSortedSet({ client, keyPrefix: prefix("zombie") });
		await z.add("sid-1", "google", PAST());
		expect(await z.list("sid-1")).toEqual([]);
		const exists = await raw.exists(`${prefix("zombie")}sid-1`);
		expect(exists).toBe(0);
	});

	it("PEXPIREAT applied: key disappears after expiresAt", async () => {
		const z = createRedisSidSortedSet({ client, keyPrefix: prefix("ttl") });
		const soon = new Date(Date.now() + 200);
		await z.add("sid-1", "google", soon);
		expect(await z.list("sid-1")).toHaveLength(1);
		await new Promise((r) => setTimeout(r, 250));
		expect(await z.list("sid-1")).toEqual([]);
	});

	// D-10 / CR-3: a stale-`expiresAt` race with a shorter TTL must NOT
	// truncate the key's existing TTL. The `pExpireGT` (NX + GT pair) prevents
	// the write from clobbering a longer existing TTL with a shorter one.
	it("does NOT truncate the key TTL on a stale-shorter-expiresAt write (CR-3)", async () => {
		const z = createRedisSidSortedSet({ client, keyPrefix: prefix("ttl-trunc") });
		const longExpiry = new Date(Date.now() + 5000); // 5s — first writer
		const stale = new Date(longExpiry.getTime() - 4500); // 0.5s — stale view
		await z.add("sid-1", "google", longExpiry);
		expect(await z.list("sid-1")).toEqual(["google"]);
		// Stale write — must NOT truncate the existing 5s TTL.
		await z.add("sid-1", "github", stale);
		expect(await z.list("sid-1")).toEqual(["google", "github"]);
		// Wait past the stale TTL window. With bare-PEXPIREAT (no GT) the key
		// would have been truncated to 0.5s and expired by now.
		await new Promise((r) => setTimeout(r, 700));
		expect(await z.list("sid-1")).toEqual(["google", "github"]);
	});

	// D-10 bootstrap test: the very first write must set the TTL even though
	// the key has no prior TTL. A bare `PEXPIREAT … GT` would silently no-op
	// here (Redis treats no-TTL as infinite TTL for the GT flag), leaving the
	// key persistent. The NX clause in `pExpireGT` covers this bootstrap gap.
	it("first write to a fresh sid sets a TTL (no infinite-TTL bootstrap leak)", async () => {
		const z = createRedisSidSortedSet({ client, keyPrefix: prefix("ttl-boot") });
		await z.add("sid-fresh", "google", FUTURE());
		const pttl = await raw.pttl(`${prefix("ttl-boot")}sid-fresh`);
		// PTTL returns -1 for a key with no TTL (the bug case) and -2 if the
		// key is missing. A positive value means the TTL is set as expected.
		expect(pttl).toBeGreaterThan(0);
	});

	it("remove(sid, member) removes only the named member", async () => {
		const z = createRedisSidSortedSet({ client, keyPrefix: prefix("rem-one") });
		await z.add("sid-1", "google", FUTURE());
		await z.add("sid-1", "github", FUTURE());
		await z.remove("sid-1", "google");
		expect(await z.list("sid-1")).toEqual(["github"]);
	});

	it("removeBySid clears all", async () => {
		const z = createRedisSidSortedSet({ client, keyPrefix: prefix("rem-all") });
		await z.add("sid-1", "google", FUTURE());
		await z.add("sid-1", "github", FUTURE());
		await z.removeBySid("sid-1");
		expect(await z.list("sid-1")).toEqual([]);
	});

	it("100 parallel distinct-member add calls all land", async () => {
		const z = createRedisSidSortedSet({ client, keyPrefix: prefix("conc-distinct") });
		const expiresAt = FUTURE();
		await Promise.all(
			Array.from({ length: 100 }, (_, i) => z.add("sid-conc", `m-${i}`, expiresAt)),
		);
		expect(await z.list("sid-conc")).toHaveLength(100);
	});

	it("100 parallel same-member add calls converge to ONE entry (ZADD NX)", async () => {
		const z = createRedisSidSortedSet({ client, keyPrefix: prefix("conc-same") });
		const expiresAt = FUTURE();
		await Promise.all(
			Array.from({ length: 100 }, () => z.add("sid-conc-same", "m-shared", expiresAt)),
		);
		expect(await z.list("sid-conc-same")).toEqual(["m-shared"]);
	});
});

function makeWrapper(io: Redis): SessionSidSortedSetClient {
	const buildMulti = (): SessionSidSortedSetMultiClient => {
		const p = io.multi();
		const m: SessionSidSortedSetMultiClient = {
			pExpireAt: (k, ms) => {
				p.pexpireat(k, ms);
				return m;
			},
			pExpireGT: (k, ms) => {
				p.pexpireat(k, ms, "NX");
				p.pexpireat(k, ms, "GT");
				return m;
			},
			zAdd: (k, e, opts) => {
				if (opts?.NX) p.zadd(k, "NX", e.score, e.value);
				else p.zadd(k, e.score, e.value);
				return m;
			},
			exec: async () => p.exec(),
		};
		return m;
	};

	return {
		del: (k) => io.del(k),
		multi: () => buildMulti(),
		pExpireAt: (k, ms) => io.pexpireat(k, ms),
		pExpireGT: async (k, ms) => {
			const nx = await io.pexpireat(k, ms, "NX");
			if (nx === 1) return nx;
			return io.pexpireat(k, ms, "GT");
		},
		zAdd: (k, e, opts) =>
			opts?.NX
				? (io.zadd(k, "NX", e.score, e.value) as Promise<unknown> as Promise<number>)
				: (io.zadd(k, e.score, e.value) as Promise<unknown> as Promise<number>),
		zRange: (k, s, e) => io.zrange(k, s, e),
		zRem: (k, m) => io.zrem(k, m) as Promise<number>,
	};
}
