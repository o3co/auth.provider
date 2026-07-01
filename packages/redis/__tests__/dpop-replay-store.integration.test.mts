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

// Integration test for createRedisDPoPReplayStore.
// Uses testcontainers to spin up a real Redis 7.2 instance — same pattern as
// challenges.test.mts, replay-seen-set.test.mts, etc.

import Redis from "ioredis";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import {
	createRedisDPoPReplayStore,
	type DPoPReplayStoreClient,
} from "../src/dpop-replay-store.mjs";

let container: StartedTestContainer;
let redis: Redis;
let keyCounter = 0;

beforeAll(async () => {
	container = await new GenericContainer("redis:7.2-alpine")
		.withExposedPorts(6379)
		.withStartupTimeout(120_000)
		.start();
	redis = new Redis({
		host: container.getHost(),
		port: container.getMappedPort(6379),
	});
}, 60_000);

afterAll(async () => {
	await redis?.quit();
	await container?.stop();
});

function makeStore() {
	keyCounter += 1;
	const prefix = `dpop:replay:test-${keyCounter}:`;
	const client: DPoPReplayStoreClient = {
		set: (k, v, _mode, ttlMs, _cond) => redis.set(k, v, "PX", ttlMs, "NX") as Promise<"OK" | null>,
	};
	return createRedisDPoPReplayStore({ client, keyPrefix: prefix });
}

afterEach(async () => {
	// Clean up test keys for this counter value
	const pattern = `dpop:replay:test-${keyCounter}:*`;
	const keys = await redis.keys(pattern);
	if (keys.length > 0) {
		await redis.del(...keys);
	}
});

describe("createRedisDPoPReplayStore — integration (Redis 7.2)", () => {
	it("returns false on the first seen() and true on the second within TTL", async () => {
		const store = makeStore();
		const seen1 = await store.seen("jti-1", "jkt-A", 60);
		const seen2 = await store.seen("jti-1", "jkt-A", 60);
		expect(seen1).toBe(false);
		expect(seen2).toBe(true);
	});

	it("isolates by jkt (same jti from different keys are NOT replays)", async () => {
		const store = makeStore();
		const seenA = await store.seen("jti-1", "jkt-A", 60);
		const seenB = await store.seen("jti-1", "jkt-B", 60);
		expect(seenA).toBe(false);
		expect(seenB).toBe(false);
	});

	it("isolates by jti (different jtis from same key are NOT replays)", async () => {
		const store = makeStore();
		const seen1 = await store.seen("jti-1", "jkt-A", 60);
		const seen2 = await store.seen("jti-2", "jkt-A", 60);
		expect(seen1).toBe(false);
		expect(seen2).toBe(false);
	});

	it("expires entries after TTL", async () => {
		const store = makeStore();
		// Use 1-second TTL and wait for expiry
		await store.seen("jti-exp", "jkt-E", 1);
		// Wait 1.2 seconds for key to expire
		await new Promise((r) => setTimeout(r, 1200));
		const seen = await store.seen("jti-exp", "jkt-E", 60);
		expect(seen).toBe(false); // entry expired; treated as fresh
	}, 10_000);

	it("is atomic under concurrent same-key calls (Promise.all)", async () => {
		const store = makeStore();
		const results = await Promise.all([
			store.seen("jti-c", "jkt-C", 60),
			store.seen("jti-c", "jkt-C", 60),
			store.seen("jti-c", "jkt-C", 60),
		]);
		// Exactly one of the three sees false (was the first); the others see true.
		const fresh = results.filter((r) => r === false).length;
		expect(fresh).toBe(1);
	});
});
