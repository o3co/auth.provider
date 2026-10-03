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
 * bound, at which it sweeps ended windows and then evicts the live window
 * that ends first, saying so at most once a minute; its clock; its options.
 */

import { describe, expect, it, type Mock, vi } from "vitest";
import type { Logger } from "#/logging/Logger.mjs";
import type { AttemptSpec } from "#/ratelimit/attempts.mjs";
import {
	ATTEMPT_COUNTER_EVICTION_WARN_INTERVAL_MS,
	createMemoryAttemptCounter,
	DEFAULT_MEMORY_ATTEMPT_COUNTER_MAX_ENTRIES,
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

const quietWarn = (): Pick<Logger, "warn"> & { warn: Mock<(...args: unknown[]) => void> } => ({
	warn: vi.fn<(...args: unknown[]) => void>(),
});

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

	it("at its cap, evicts the least-counted live window, the one that ends first among equals, and warns with counts and its tag", async () => {
		const time = clock();
		const logger = quietWarn();
		const spec: AttemptSpec = { limit: 3, windowSeconds: 60 };
		const counter = createMemoryAttemptCounter({
			now: time.now,
			maxEntries: 3,
			logger,
			tag: "login",
		});
		await counter.consume("twice", spec);
		await counter.consume("twice", spec);
		time.advance(1);
		await counter.consume("once-early", spec);
		time.advance(1);
		await counter.consume("once-late", spec);
		time.advance(1);
		await counter.consume("new", spec);
		// The kept keys are still counted; the evicted one starts again.
		expect((await counter.consume("twice", spec)).remaining).toBe(0);
		expect((await counter.consume("once-late", spec)).remaining).toBe(1);
		expect(logger.warn).toHaveBeenCalledTimes(1);
		expect(logger.warn).toHaveBeenCalledWith(
			{ tag: "login", evicted: 1, maxEntries: 3 },
			"attempt_counter_evicted",
		);
		expect((await counter.consume("once-early", spec)).remaining).toBe(2);
	});

	it("keeps an exhausted key through a fill of fresh keys", async () => {
		const time = clock();
		const counter = createMemoryAttemptCounter({
			now: time.now,
			maxEntries: 10,
			logger: quietWarn(),
		});
		const spec: AttemptSpec = { limit: 3, windowSeconds: 900 };
		for (let i = 0; i < 4; i++) await counter.consume("victim", spec);
		for (let i = 0; i < 1_000; i++) {
			time.advance(1);
			await counter.consume(`fresh-${i}`, spec);
		}
		expect((await counter.consume("victim", spec)).allowed).toBe(false);
	});

	it("evicts a batch of one in a hundred of maxEntries at once", async () => {
		const time = clock();
		const logger = quietWarn();
		const counter = createMemoryAttemptCounter({ now: time.now, maxEntries: 200, logger });
		for (let i = 0; i < 200; i++) {
			time.advance(1);
			await counter.consume(`k${i}`, SPEC);
		}
		await counter.consume("new", SPEC);
		expect(logger.warn).toHaveBeenCalledWith(
			{ evicted: 2, maxEntries: 200 },
			"attempt_counter_evicted",
		);
		// k0 and k1 ended first among equals; k2 is kept.
		expect((await counter.consume("k2", SPEC)).remaining).toBe(0);
		// A second new key fits in the room the batch left: no second eviction.
		await counter.consume("new-2", SPEC);
		expect((await counter.consume("k3", SPEC)).remaining).toBe(0);
	});

	it("picks a batch's windows by fewest attempts, then earliest end, among many", async () => {
		const time = clock();
		const logger = quietWarn();
		const counter = createMemoryAttemptCounter({ now: time.now, maxEntries: 300, logger });
		const spec: AttemptSpec = { limit: 10, windowSeconds: 600 };
		// k0..k299: every key but three is counted twice; k150, k10 and k200 once, in that order.
		const once = ["k150", "k10", "k200"];
		for (const key of once) {
			time.advance(1);
			await counter.consume(key, spec);
		}
		for (let i = 0; i < 300; i++) {
			const key = `k${i}`;
			if (once.includes(key)) continue;
			time.advance(1);
			await counter.consume(key, spec);
			await counter.consume(key, spec);
		}
		await counter.consume("new", spec);
		expect(logger.warn).toHaveBeenCalledWith(
			{ evicted: 3, maxEntries: 300 },
			"attempt_counter_evicted",
		);
		// The three counted once are gone and start again; a key counted twice is kept.
		expect((await counter.consume("k0", spec)).remaining).toBe(7);
		for (const key of once) expect((await counter.consume(key, spec)).remaining).toBe(9);
	});

	it("holds many keys when built without maxEntries", async () => {
		const logger = quietWarn();
		const counter = createMemoryAttemptCounter({ logger });
		for (let i = 0; i < 2_000; i++) await counter.consume(`k${i}`, SPEC);
		expect((await counter.consume("k0", SPEC)).remaining).toBe(0);
		expect(logger.warn).not.toHaveBeenCalled();
	});

	it("makes room from windows that have ended before it evicts a live one", async () => {
		const time = clock();
		const logger = quietWarn();
		const counter = createMemoryAttemptCounter({ now: time.now, maxEntries: 2, logger });
		await counter.consume("short", { limit: 1, windowSeconds: 1 });
		await counter.consume("long", SPEC);
		time.advance(1_000);
		expect((await counter.consume("c", SPEC)).allowed).toBe(true);
		await counter.consume("long", SPEC);
		expect((await counter.consume("long", SPEC)).allowed).toBe(false);
		expect(logger.warn).not.toHaveBeenCalled();
	});

	it("warns at most once a minute, counting the evictions since the last warning", async () => {
		expect(ATTEMPT_COUNTER_EVICTION_WARN_INTERVAL_MS).toBe(60_000);
		const time = clock();
		const logger = quietWarn();
		const counter = createMemoryAttemptCounter({ now: time.now, maxEntries: 1, logger });
		for (let i = 0; i < 5; i++) await counter.consume(`k${i}`, { limit: 1, windowSeconds: 600 });
		expect(logger.warn).toHaveBeenCalledTimes(1);
		time.advance(60_000);
		await counter.consume("k-late", { limit: 1, windowSeconds: 600 });
		expect(logger.warn).toHaveBeenCalledTimes(2);
		expect(logger.warn).toHaveBeenLastCalledWith(
			{ evicted: 4, maxEntries: 1 },
			"attempt_counter_evicted",
		);
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
