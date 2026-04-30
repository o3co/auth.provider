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
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import Redis from "ioredis";
import { createRedisSidSortedSet } from "../src/internal/redisSidSortedSet.mjs";
import type { RedisClient } from "../src/types.mjs";

let container: StartedTestContainer;
let raw: Redis;
let client: RedisClient;

beforeAll(async () => {
	container = await new GenericContainer("redis:7-alpine").withExposedPorts(6379).start();
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
		await z.add("sid-1", "google", FUTURE());
		// guarantee distinct millisecond scores so ordering is deterministic
		await new Promise((r) => setTimeout(r, 5));
		await z.add("sid-1", "github", FUTURE());
		await new Promise((r) => setTimeout(r, 5));
		await z.add("sid-1", "gitlab", FUTURE());
		expect(await z.list("sid-1")).toEqual(["google", "github", "gitlab"]);
	});

	it("re-add of existing member does NOT promote position (ZADD NX)", async () => {
		const z = createRedisSidSortedSet({ client, keyPrefix: prefix("nx") });
		await z.add("sid-1", "google", FUTURE());
		await new Promise((r) => setTimeout(r, 5));
		await z.add("sid-1", "github", FUTURE());
		await new Promise((r) => setTimeout(r, 5));
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

function makeWrapper(io: Redis): RedisClient {
	return {
		set: (k, v, _mode, ttl, _cond) => io.set(k, v, "PX", ttl, "NX") as Promise<"OK" | null>,
		del: (k) => io.del(k),
		pttl: (k) => io.pttl(k),
		exists: (k) => io.exists(k),
		get: (k) => io.get(k),
		watch: (...keys) => io.watch(...keys) as Promise<"OK">,
		unwatch: () => io.unwatch() as Promise<"OK">,
		multi: () => {
			const p = io.multi();
			const m = {
				set: (k: string, v: string, _mode: "PX", ttl: number) => {
					p.set(k, v, "PX", ttl);
					return m;
				},
				hSet: (k: string, f: string, v: string) => {
					p.hset(k, f, v);
					return m;
				},
				pExpireAt: (k: string, ms: number) => {
					p.pexpireat(k, ms);
					return m;
				},
				zAdd: (k: string, e: { score: number; value: string }, opts?: { NX: true }) => {
					if (opts?.NX) p.zadd(k, "NX", e.score, e.value);
					else p.zadd(k, e.score, e.value);
					return m;
				},
				exec: async () => p.exec(),
			};
			return m as unknown as ReturnType<RedisClient["multi"]>;
		},
		duplicate: () => {
			throw new Error("duplicate() not used in this test");
		},
		hSet: (k, f, v) => io.hset(k, f, v) as Promise<number>,
		hVals: (k) => io.hvals(k),
		pExpireAt: (k, ms) => io.pexpireat(k, ms),
		zAdd: (k, e, opts) =>
			opts?.NX
				? (io.zadd(k, "NX", e.score, e.value) as Promise<unknown> as Promise<number>)
				: (io.zadd(k, e.score, e.value) as Promise<unknown> as Promise<number>),
		zRange: (k, s, e) => io.zrange(k, s, e),
		zRem: (k, m) => io.zrem(k, m) as Promise<number>,
	};
}
