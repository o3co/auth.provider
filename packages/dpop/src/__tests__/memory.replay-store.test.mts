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
import { describe, expect, it } from "vitest";
import { createMemoryDPoPReplayStore } from "#/memory/replay-store.mjs";

describe("createMemoryDPoPReplayStore", () => {
	it("returns false on the first seen() and true on the second within TTL", async () => {
		const store = createMemoryDPoPReplayStore();
		const seen1 = await store.seen("jti-1", "jkt-A", 60);
		const seen2 = await store.seen("jti-1", "jkt-A", 60);
		expect(seen1).toBe(false);
		expect(seen2).toBe(true);
	});

	it("isolates by jkt (same jti from different keys are NOT replays)", async () => {
		const store = createMemoryDPoPReplayStore();
		const seenA = await store.seen("jti-1", "jkt-A", 60);
		const seenB = await store.seen("jti-1", "jkt-B", 60);
		expect(seenA).toBe(false);
		expect(seenB).toBe(false);
	});

	it("isolates by jti (different jtis from same key are NOT replays)", async () => {
		const store = createMemoryDPoPReplayStore();
		const seen1 = await store.seen("jti-1", "jkt-A", 60);
		const seen2 = await store.seen("jti-2", "jkt-A", 60);
		expect(seen1).toBe(false);
		expect(seen2).toBe(false);
	});

	it("expires entries after TTL (uses injected clock)", async () => {
		const clock = { now: 1_000_000 };
		const store = createMemoryDPoPReplayStore({ now: () => clock.now });
		await store.seen("jti-x", "jkt-X", 10);
		clock.now += 11_000; // advance 11s — past 10s TTL
		const seen = await store.seen("jti-x", "jkt-X", 10);
		expect(seen).toBe(false); // entry expired; treated as fresh
	});

	it("is atomic under concurrent same-key calls (Promise.all)", async () => {
		const store = createMemoryDPoPReplayStore();
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
