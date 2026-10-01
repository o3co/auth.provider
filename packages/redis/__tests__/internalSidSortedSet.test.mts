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

import { Redis } from "ioredis";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { SessionSidSortedSetClient } from "#/clients.mjs";
import { createRedisSidSortedSet } from "#/internal/redisSidSortedSet.mjs";
import { makeIoredisClients } from "#/ioredis.mjs";
import { aheadOfServer, serverPasses, testRedis } from "./support/redis.mjs";

let raw: Redis;
let client: SessionSidSortedSetClient;

beforeAll(async () => {
	const at = await testRedis();
	raw = new Redis(at);
	// The shipped wrapper — see the note in `internalSidHash.test.mts`.
	client = makeIoredisClients(raw).sessionFamilyIndexClient;
});

afterAll(async () => {
	raw?.disconnect();
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
		// in createRedisSidSortedSet (see internal/redisSidSortedSet.mts); no
		// inter-add sleep is needed.
		await z.add("sid-1", "google", FUTURE());
		await z.add("sid-1", "github", FUTURE());
		await z.add("sid-1", "gitlab", FUTURE());
		expect(await z.list("sid-1")).toEqual(["google", "github", "gitlab"]);
	});

	it("re-add of existing member does NOT promote position (ZADD NX)", async () => {
		const z = createRedisSidSortedSet({ client, keyPrefix: prefix("nx") });
		// Insertion order is guaranteed by the module-level monotonic counter
		// in createRedisSidSortedSet (see internal/redisSidSortedSet.mts); no
		// inter-add sleep is needed.
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
		// Dated from, and waited out on, the server's clock — the one a
		// PEXPIREAT deadline is judged by — not the host's.
		const z = createRedisSidSortedSet({ client, keyPrefix: prefix("ttl") });
		const soon = await aheadOfServer(() => raw)();
		await z.add("sid-1", "google", soon);
		expect(await z.list("sid-1")).toHaveLength(1);
		await serverPasses(() => raw)(soon.getTime());
		expect(await z.list("sid-1")).toEqual([]);
	});

	// A stale-`expiresAt` race with a shorter TTL must NOT truncate the key's
	// existing TTL. The `pExpireGT` (NX + GT pair) prevents the write from
	// clobbering a longer existing TTL with a shorter one.
	it("does NOT truncate the key TTL on a stale-shorter-expiresAt write", async () => {
		const z = createRedisSidSortedSet({ client, keyPrefix: prefix("ttl-trunc") });
		const longExpiry = FUTURE(); // first writer
		const stale = await aheadOfServer(() => raw)(); // a second out — stale view
		await z.add("sid-1", "google", longExpiry);
		expect(await z.list("sid-1")).toEqual(["google"]);
		// Stale write — must NOT truncate the existing TTL. The deadline is read
		// back exactly: it is still the first writer's.
		await z.add("sid-1", "github", stale);
		expect(await z.list("sid-1")).toEqual(["google", "github"]);
		expect(await raw.pexpiretime(`${prefix("ttl-trunc")}sid-1`)).toBe(longExpiry.getTime());
		// Wait past the stale deadline on the server's clock. With bare-PEXPIREAT
		// (no GT) the key would have been truncated to it and expired by now.
		await serverPasses(() => raw)(stale.getTime());
		expect(await z.list("sid-1")).toEqual(["google", "github"]);
	});

	// The very first write must set the TTL even though the key has no prior
	// TTL. A bare `PEXPIREAT … GT` would silently no-op here (Redis treats
	// no-TTL as infinite TTL for the GT flag), leaving the key persistent. The
	// NX clause in `pExpireGT` covers this bootstrap gap.
	it("first write to a fresh sid sets a TTL (no infinite-TTL bootstrap leak)", async () => {
		const z = createRedisSidSortedSet({ client, keyPrefix: prefix("ttl-boot") });
		await z.add("sid-fresh", "google", FUTURE());
		const pttl = await raw.pttl(`${prefix("ttl-boot")}sid-fresh`);
		// PTTL returns -1 for a key with no TTL and -2 if the key is missing.
		// A positive value means the TTL is set.
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

	// `list` pages by rank instead of `ZRANGE key 0 -1`. Insertion order is
	// the load-bearing part and must survive the page boundaries.
	it("list returns every member, in insertion order, across several rank pages", async () => {
		const z = createRedisSidSortedSet({ client, keyPrefix: prefix("paged"), pageSize: 25 });
		const expiresAt = FUTURE();
		const members = Array.from({ length: 260 }, (_, i) => `m-${String(i).padStart(3, "0")}`);
		for (const m of members) await z.add("sid-paged", m, expiresAt);
		expect(await z.list("sid-paged")).toEqual(members);
	});

	// `_insertionCounter` is monotonic across restart.
	describe("_insertionCounter restart-monotonicity", () => {
		it("two add() calls with same expiresAt — second member sorts after first in list()", async () => {
			const z = createRedisSidSortedSet({ client, keyPrefix: prefix("or8-same-exp") });
			const sharedExp = FUTURE();
			await z.add("sid-or8-1", "first", sharedExp);
			await z.add("sid-or8-1", "second", sharedExp);
			// Insertion order holds even when expiresAt is identical.
			expect(await z.list("sid-or8-1")).toEqual(["first", "second"]);
		});

		it("post-restart simulation via fresh module load — first score from a freshly-imported module exceeds an injected high pre-crash baseline", async () => {
			// Earlier tests in this file advance the module-scoped
			// `_insertionCounter`, so a low injected score would lose to the
			// counter whatever it started at. `vi.resetModules()` + a dynamic
			// re-import re-initialise the counter (to `Date.now()`), and the
			// injected pre-crash score is HIGH enough that only the Date.now()
			// baseline beats it: `100_000` is well above any counter this file
			// could advance from `0`, and well below `Date.now()`.
			//
			// The pre-crash member has a DIFFERENT name from the post-restart
			// one: ZADD NX would otherwise keep the pre-existing low score.
			const sid = "sid-or8-restart-v2";
			const key = `${prefix("or8-restart-v2")}${sid}`;
			const PRE_CRASH_HIGH = 100_000;
			await raw.zadd(key, "NX", PRE_CRASH_HIGH, "pre-crash-high");

			vi.resetModules();
			const fresh = (await import(
				// @ts-expect-error tsc resolves no query string; the cast below types the module.
				"#/internal/redisSidSortedSet.mjs?freshOR8RED2"
			)) as typeof import("#/internal/redisSidSortedSet.mjs");
			const z = fresh.createRedisSidSortedSet({ client, keyPrefix: prefix("or8-restart-v2") });
			await z.add(sid, "post-restart-fresh", FUTURE());

			const score = await raw.zscore(key, "post-restart-fresh");
			expect(score).not.toBeNull();
			expect(Number(score)).toBeGreaterThan(PRE_CRASH_HIGH);
			// The injected score is > 0 yet < Date.now(), so the new member
			// sorts AFTER the pre-crash member.
			expect(await z.list(sid)).toEqual(["pre-crash-high", "post-restart-fresh"]);
		});

		it("module counter is shared across multiple createRedisSidSortedSet instances — interleaved adds get strictly increasing scores globally", async () => {
			const za = createRedisSidSortedSet({ client, keyPrefix: prefix("or8-shared-A") });
			const zb = createRedisSidSortedSet({ client, keyPrefix: prefix("or8-shared-B") });
			await za.add("sid-X", "a-1", FUTURE());
			await zb.add("sid-X", "b-1", FUTURE());
			await za.add("sid-X", "a-2", FUTURE());
			await zb.add("sid-X", "b-2", FUTURE());

			const scoreA1 = await raw.zscore(`${prefix("or8-shared-A")}sid-X`, "a-1");
			const scoreB1 = await raw.zscore(`${prefix("or8-shared-B")}sid-X`, "b-1");
			const scoreA2 = await raw.zscore(`${prefix("or8-shared-A")}sid-X`, "a-2");
			const scoreB2 = await raw.zscore(`${prefix("or8-shared-B")}sid-X`, "b-2");

			expect(scoreA1).not.toBeNull();
			expect(scoreB1).not.toBeNull();
			expect(scoreA2).not.toBeNull();
			expect(scoreB2).not.toBeNull();
			// Strict global monotonicity: a-1 < b-1 < a-2 < b-2.
			expect(Number(scoreA1)).toBeLessThan(Number(scoreB1));
			expect(Number(scoreB1)).toBeLessThan(Number(scoreA2));
			expect(Number(scoreA2)).toBeLessThan(Number(scoreB2));
		});

		it("a freshly-loaded module emits a first score that exceeds 10^12 (structural assertion of the Date.now() baseline, not a tautology)", async () => {
			// Exercises the module's actual init rather than `Date.now()`
			// itself (`expect(Date.now() > 1e12)` would pass whatever the
			// module does): `vi.resetModules()` re-evaluates the
			// `let _insertionCounter = ...` line, then a single add() through
			// the fresh instance must produce a score above 10^12. A counter
			// starting at 0 would score `1` and fail; `Date.now()` scores
			// `~1.75×10^12`.
			const sid = "sid-or8-fresh-baseline";
			const key = `${prefix("or8-fresh-baseline")}${sid}`;

			vi.resetModules();
			const fresh = (await import(
				// @ts-expect-error tsc resolves no query string; the cast below types the module.
				"#/internal/redisSidSortedSet.mjs?freshOR8RED4"
			)) as typeof import("#/internal/redisSidSortedSet.mjs");
			const z = fresh.createRedisSidSortedSet({
				client,
				keyPrefix: prefix("or8-fresh-baseline"),
			});
			await z.add(sid, "first-after-reload", FUTURE());

			const score = await raw.zscore(key, "first-after-reload");
			expect(score).not.toBeNull();
			expect(Number(score)).toBeGreaterThan(1_000_000_000_000);
		});
	});
});
