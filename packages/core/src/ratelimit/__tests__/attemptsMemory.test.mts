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
 * What the in-process `AttemptCounter` adds to the port's contract (which
 * `@o3co/auth-provider-test-kit`'s `attemptCounterContract` holds it to): its
 * bound, refused at rather than evicted past, its clock, and its options.
 */

import { describe, expect, it } from "vitest";
import type { AttemptSpec } from "#/ratelimit/attempts.mjs";
import {
	createMemoryAttemptCounter,
	DEFAULT_MEMORY_ATTEMPT_COUNTER_MAX_ENTRIES,
	MemoryAttemptCounterFullError,
} from "#/ratelimit/attemptsMemory.mjs";
import { MAX_MEMORY_STORE_ENTRIES } from "#/single-use/max-entries.mjs";

const SPEC: AttemptSpec = { limit: 2, windowSeconds: 60 };

const clock = (start = Date.parse("2026-10-03T00:00:00.000Z")) => {
	let now = start;
	return {
		now: () => now,
		advance(ms: number) {
			now += ms;
		},
	};
};

describe("createMemoryAttemptCounter", () => {
	it("counts on the clock it is given: the window starts at the first attempt and ends windowSeconds later", async () => {
		const time = clock();
		const counter = createMemoryAttemptCounter({ now: time.now });
		const first = await counter.consume("k", SPEC);
		expect(first).toEqual({
			allowed: true,
			remaining: 1,
			resetAt: new Date(time.now() + 60_000),
		});
		time.advance(59_999);
		await counter.consume("k", SPEC);
		expect((await counter.consume("k", SPEC)).allowed).toBe(false);
		time.advance(1);
		expect(await counter.consume("k", SPEC)).toEqual({
			allowed: true,
			remaining: 1,
			resetAt: new Date(time.now() + 60_000),
		});
	});

	it("refuses a new key at its cap, as a store fault, and counts nothing for it", async () => {
		const time = clock();
		const counter = createMemoryAttemptCounter({ now: time.now, maxEntries: 2 });
		await counter.consume("a", SPEC);
		await counter.consume("b", SPEC);
		await expect(counter.consume("c", SPEC)).rejects.toBeInstanceOf(MemoryAttemptCounterFullError);
		// The keys it holds are still counted: nothing was evicted to make room.
		await counter.consume("a", SPEC);
		expect((await counter.consume("a", SPEC)).allowed).toBe(false);
	});

	it("makes room from windows that have ended", async () => {
		const time = clock();
		const counter = createMemoryAttemptCounter({ now: time.now, maxEntries: 2 });
		await counter.consume("short", { limit: 1, windowSeconds: 1 });
		await counter.consume("long", SPEC);
		await expect(counter.consume("c", SPEC)).rejects.toBeInstanceOf(MemoryAttemptCounterFullError);
		time.advance(1_000);
		expect((await counter.consume("c", SPEC)).allowed).toBe(true);
		// The live window was kept.
		await counter.consume("long", SPEC);
		expect((await counter.consume("long", SPEC)).allowed).toBe(false);
	});

	it("makes room from a window that ends before one seen when the counter was last full", async () => {
		const time = clock();
		const counter = createMemoryAttemptCounter({ now: time.now, maxEntries: 2 });
		await counter.consume("long-1", SPEC);
		await counter.consume("long-2", { limit: 1, windowSeconds: 120 });
		await expect(counter.consume("x", SPEC)).rejects.toBeInstanceOf(MemoryAttemptCounterFullError);
		time.advance(60_000);
		// long-1's window has ended, and a key with a shorter window than
		// long-2's takes its place: its end is the next room the counter has.
		await counter.consume("short", { limit: 1, windowSeconds: 1 });
		await expect(counter.consume("y", SPEC)).rejects.toBeInstanceOf(MemoryAttemptCounterFullError);
		time.advance(1_000);
		expect((await counter.consume("y", SPEC)).allowed).toBe(true);
	});

	it(`holds ${DEFAULT_MEMORY_ATTEMPT_COUNTER_MAX_ENTRIES} keys by default`, async () => {
		expect(DEFAULT_MEMORY_ATTEMPT_COUNTER_MAX_ENTRIES).toBe(100_000);
	});

	it.each([
		["zero", 0],
		["a fraction", 1.5],
		["NaN", Number.NaN],
		["past what a Map holds", MAX_MEMORY_STORE_ENTRIES + 1],
	])("refuses a maxEntries of %s, never falling back to the default", (_label, maxEntries) => {
		expect(() => createMemoryAttemptCounter({ maxEntries })).toThrow(RangeError);
	});

	it("rejects a clock reading that is not a finite number, counting nothing", async () => {
		let reading = Number.NaN;
		const counter = createMemoryAttemptCounter({ now: () => reading });
		await expect(counter.consume("k", SPEC)).rejects.toThrow(RangeError);
		reading = 0;
		expect((await counter.consume("k", SPEC)).remaining).toBe(1);
	});
});
