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
import type { SessionRPRegistryClient, SessionRPRegistryMultiClient } from "../src/clients.mjs";
import { createRedisSidHash } from "../src/internal/redisSidHash.mjs";

let container: StartedTestContainer;
let raw: Redis;
let client: SessionRPRegistryClient;

beforeAll(async () => {
	container = await new GenericContainer("redis:7.2-alpine")
		.withExposedPorts(6379)
		.withStartupTimeout(60_000)
		.start();
	raw = new Redis({ host: container.getHost(), port: container.getMappedPort(6379) });
	// In production the wrapper adapter normalises ioredis to SessionRPRegistryClient.
	// For these tests we use a hand-rolled minimal wrapper.
	client = makeWrapper(raw);
}, 90_000);

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
		expect(JSON.parse(out[0] as string)).toEqual({ x: 1 });
	});

	it("setField with same id replaces value", async () => {
		const h = createRedisSidHash({ client, keyPrefix: prefix("upsert") });
		await h.setField("sid-1", "id-a", JSON.stringify({ x: 1 }), FUTURE());
		await h.setField("sid-1", "id-a", JSON.stringify({ x: 2 }), FUTURE());
		const out = await h.listValues("sid-1");
		expect(out).toHaveLength(1);
		expect(JSON.parse(out[0] as string)).toEqual({ x: 2 });
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

	// D-10 / CR-3: a stale-`expiresAt` race with a shorter TTL must NOT truncate
	// the key's existing TTL. The `pExpireGT` (NX + GT pair) prevents the
	// write from clobbering a longer existing TTL with a shorter incoming one.
	it("does NOT truncate the key TTL on a stale-shorter-expiresAt write (CR-3)", async () => {
		const h = createRedisSidHash({ client, keyPrefix: prefix("ttl-trunc") });
		const longExpiry = new Date(Date.now() + 5000); // 5s — first writer
		const stale = new Date(longExpiry.getTime() - 4500); // 0.5s — stale view
		await h.setField("sid-1", "id-a", JSON.stringify({ x: 1 }), longExpiry);
		expect(await h.listValues("sid-1")).toHaveLength(1);
		// Stale write — must NOT truncate the existing 5s TTL.
		await h.setField("sid-1", "id-b", JSON.stringify({ y: 2 }), stale);
		expect(await h.listValues("sid-1")).toHaveLength(2);
		// Wait past the stale TTL window. With bare-PEXPIREAT (no GT) the key
		// would have been truncated to 0.5s and expired by now; with the GT
		// guard the key still has ~4s of TTL remaining.
		await new Promise((r) => setTimeout(r, 700));
		expect(await h.listValues("sid-1")).toHaveLength(2);
	});

	// D-10 bootstrap test: the very first write must set the TTL even though
	// the key has no prior TTL. A bare `PEXPIREAT … GT` would silently no-op
	// here (Redis treats no-TTL as infinite TTL for the GT flag), leaving the
	// key persistent. The NX clause in `pExpireGT` covers this bootstrap gap.
	it("first write to a fresh sid sets a TTL (no infinite-TTL bootstrap leak)", async () => {
		const h = createRedisSidHash({ client, keyPrefix: prefix("ttl-boot") });
		await h.setField("sid-fresh", "id-a", JSON.stringify({ x: 1 }), FUTURE());
		const pttl = await raw.pttl(`${prefix("ttl-boot")}sid-fresh`);
		// PTTL returns -1 for a key with no TTL (the bug case) and -2 if the
		// key is missing. A positive value means the TTL is set as expected.
		expect(pttl).toBeGreaterThan(0);
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

	// #291: `listValues` walks HSCAN cursors instead of issuing one HVALS.
	// 500 fields is well past `hash-max-listpack-entries` (128 by default), so
	// Redis stores this as a real hashtable and the read genuinely spans
	// several cursors — including, potentially, one that repeats a field.
	it("listValues returns every field of a hash far larger than one cursor page", async () => {
		const h = createRedisSidHash({ client, keyPrefix: prefix("paged"), scanCount: 25 });
		const sid = "sid-paged";
		const expiresAt = FUTURE();
		for (let i = 0; i < 500; i++) {
			await h.setField(sid, `id-${i}`, JSON.stringify({ i }), expiresAt);
		}
		const out = await h.listValues(sid);
		expect(out).toHaveLength(500);
		const seen = new Set(out.map((v) => (JSON.parse(v) as { i: number }).i));
		expect(seen.size).toBe(500);
	});
});

function makeWrapper(io: Redis): SessionRPRegistryClient {
	const buildMulti = (): SessionRPRegistryMultiClient => {
		const p = io.multi();
		const m: SessionRPRegistryMultiClient = {
			hSet: (k, f, v) => {
				p.hset(k, f, v);
				return m;
			},
			pExpireAt: (k, ms) => {
				p.pexpireat(k, ms);
				return m;
			},
			pExpireGT: (k, ms) => {
				p.pexpireat(k, ms, "NX");
				p.pexpireat(k, ms, "GT");
				return m;
			},
			exec: async () => p.exec(),
		};
		return m;
	};

	return {
		unlink: (k) => io.unlink(k),
		hSet: (k, f, v) => io.hset(k, f, v) as Promise<number>,
		hScanIterator: (key, opts) =>
			(async function* () {
				const stream = io.hscanStream(key, { count: opts?.COUNT });
				for await (const flat of stream) {
					const pairs = flat as string[];
					for (let i = 0; i + 1 < pairs.length; i += 2) {
						yield [pairs[i] as string, pairs[i + 1] as string] as const;
					}
				}
			})(),
		multi: () => buildMulti(),
		pExpireAt: (k, ms) => io.pexpireat(k, ms),
		pExpireGT: async (k, ms) => {
			const nx = await io.pexpireat(k, ms, "NX");
			if (nx === 1) return nx;
			return io.pexpireat(k, ms, "GT");
		},
	};
}
