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
import { createRedisSidHash } from "../src/internal/redisSidHash.mjs";
import type { RedisClient } from "../src/types.mjs";

let container: StartedTestContainer;
let raw: Redis;
let client: RedisClient;

beforeAll(async () => {
	container = await new GenericContainer("redis:7-alpine").withExposedPorts(6379).start();
	raw = new Redis({ host: container.getHost(), port: container.getMappedPort(6379) });
	// In production the wrapper adapter normalises ioredis to RedisClient. For
	// these tests we use a hand-rolled minimal wrapper.
	client = makeWrapper(raw);
}, 60_000);

afterAll(async () => {
	raw?.disconnect();
	await container?.stop();
});

const FUTURE = () => new Date(Date.now() + 60_000);
const PAST = () => new Date(Date.now() - 1);

const prefix = (suffix: string) => `t12:${suffix}:`;

describe("createRedisSidHash", () => {
	it("setField then listValues returns inserted JSON value", async () => {
		const h = createRedisSidHash({ client, keyPrefix: prefix("setget") });
		await h.setField("sid-1", "id-a", JSON.stringify({ x: 1 }), FUTURE());
		const out = await h.listValues("sid-1");
		expect(out).toHaveLength(1);
		expect(JSON.parse(out[0]!)).toEqual({ x: 1 });
	});

	it("setField with same id replaces value", async () => {
		const h = createRedisSidHash({ client, keyPrefix: prefix("upsert") });
		await h.setField("sid-1", "id-a", JSON.stringify({ x: 1 }), FUTURE());
		await h.setField("sid-1", "id-a", JSON.stringify({ x: 2 }), FUTURE());
		const out = await h.listValues("sid-1");
		expect(out).toHaveLength(1);
		expect(JSON.parse(out[0]!)).toEqual({ x: 2 });
	});

	it("setField after expiry no-ops (no zombie key)", async () => {
		const h = createRedisSidHash({ client, keyPrefix: prefix("zombie") });
		await h.setField("sid-1", "id-a", JSON.stringify({ x: 1 }), PAST());
		expect(await h.listValues("sid-1")).toEqual([]);
		// Verify no key was created at the underlying level.
		const exists = await raw.exists(`${prefix("zombie")}sid-1`);
		expect(exists).toBe(0);
	});

	it("PEXPIREAT applied: key disappears after expiresAt", async () => {
		const h = createRedisSidHash({ client, keyPrefix: prefix("ttl") });
		const soon = new Date(Date.now() + 200);
		await h.setField("sid-1", "id-a", JSON.stringify({ x: 1 }), soon);
		expect(await h.listValues("sid-1")).toHaveLength(1);
		await new Promise((r) => setTimeout(r, 250));
		expect(await h.listValues("sid-1")).toEqual([]);
	});

	it("removeBySid clears the key", async () => {
		const h = createRedisSidHash({ client, keyPrefix: prefix("rem") });
		await h.setField("sid-1", "id-a", JSON.stringify({ x: 1 }), FUTURE());
		await h.removeBySid("sid-1");
		expect(await h.listValues("sid-1")).toEqual([]);
	});

	it("100 parallel distinct-id setField calls all land", async () => {
		const h = createRedisSidHash({ client, keyPrefix: prefix("conc-distinct") });
		const sid = "sid-conc-1";
		const expiresAt = FUTURE();
		await Promise.all(
			Array.from({ length: 100 }, (_, i) =>
				h.setField(sid, `id-${i}`, JSON.stringify({ i }), expiresAt),
			),
		);
		const out = await h.listValues(sid);
		expect(out).toHaveLength(100);
	});

	it("100 parallel same-id setField calls converge to ONE entry (HSET dedup)", async () => {
		const h = createRedisSidHash({ client, keyPrefix: prefix("conc-same") });
		const sid = "sid-conc-2";
		const expiresAt = FUTURE();
		await Promise.all(
			Array.from({ length: 100 }, (_, i) =>
				h.setField(sid, "id-shared", JSON.stringify({ writer: i }), expiresAt),
			),
		);
		const out = await h.listValues(sid);
		expect(out).toHaveLength(1);
	});
});

function makeWrapper(io: Redis): RedisClient {
	const wrapper: RedisClient = {
		set: (k, v, _mode, ttl, _cond) => io.set(k, v, "PX", ttl, "NX") as Promise<"OK" | null>,
		del: (k) => io.del(k),
		pttl: (k) => io.pttl(k),
		exists: (k) => io.exists(k),
		get: (k) => io.get(k),
		watch: (...keys) => io.watch(...keys) as Promise<"OK">,
		unwatch: () => io.unwatch() as Promise<"OK">,
		multi: () => makeMultiWrapper(io),
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
	return wrapper;
}

function makeMultiWrapper(io: Redis) {
	const pipeline = io.multi();
	const m = {
		set: (k: string, v: string, _mode: "PX", ttl: number) => {
			pipeline.set(k, v, "PX", ttl);
			return m;
		},
		hSet: (k: string, f: string, v: string) => {
			pipeline.hset(k, f, v);
			return m;
		},
		pExpireAt: (k: string, ms: number) => {
			pipeline.pexpireat(k, ms);
			return m;
		},
		zAdd: (k: string, e: { score: number; value: string }, opts?: { NX: true }) => {
			if (opts?.NX) pipeline.zadd(k, "NX", e.score, e.value);
			else pipeline.zadd(k, e.score, e.value);
			return m;
		},
		exec: async () => pipeline.exec(),
	};
	return m as unknown as ReturnType<RedisClient["multi"]>;
}
