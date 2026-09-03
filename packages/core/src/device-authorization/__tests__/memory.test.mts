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

/** The in-memory `DeviceCodeStore` against the shared conformance suite. */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
	createMemoryDeviceCodeStore,
	DEFAULT_MEMORY_DEVICE_CODE_STORE_MAX_ENTRIES,
	DEFAULT_MEMORY_DEVICE_CODE_STORE_SWEEP_INTERVAL,
} from "../memory.mjs";
import { runDeviceCodeStoreContract } from "./adapters.contract.mjs";

runDeviceCodeStoreContract("memory", {
	create: () => createMemoryDeviceCodeStore(),
	destroy: (store) => {
		(store as { dispose?: () => void }).dispose?.();
	},
});

describe("memory DeviceCodeStore — sweep", () => {
	it("reclaims expired entries without waiting for a lookup", async () => {
		// `poll` and `findPendingByUserCode` already refuse expired records, so
		// the sweep is about memory, not correctness — which is exactly why it
		// needs its own assertion. Asserting through a lookup would pass with
		// no sweep at all.
		vi.useFakeTimers();
		try {
			const store = createMemoryDeviceCodeStore({ sweepIntervalMs: 50 });
			await store.create({
				deviceCode: "dc-1",
				userCode: "BCDFGHJK",
				clientId: "tv",
				expiresAtMs: Date.now() + 10,
				intervalSeconds: 5,
			});
			expect(store.size()).toBe(1);

			await vi.advanceTimersByTimeAsync(120);
			expect(store.size()).toBe(0);
			store.dispose();
		} finally {
			vi.useRealTimers();
		}
	});
});

/*
 * The store was unbounded. The module built it with no `sweepIntervalMs`, so
 * the timer was null; `findPendingByUserCode`, `approve` and `deny` answered
 * "expired" without dropping the entry; only `poll` reclaimed. A device that
 * asks for a code and never polls -- or an attacker who asks for ten thousand
 * -- left a record resident until process exit.
 *
 * Same shape as the access-token denylist fix (#293 item 6): an amortized
 * sweep on the one operation that grows the map, expired entries reclaimed
 * on every read path, and a cap the rate limiter's `maxBuckets` already set
 * the pattern for.
 */
describe("memory DeviceCodeStore — bounded growth", () => {
	afterEach(() => {
		vi.useRealTimers();
	});

	const entry = (i: number, expiresAtMs: number, prefix = "e") => ({
		deviceCode: `${prefix}-dc-${i}`,
		userCode: `${prefix}-uc-${i}`,
		clientId: "tv",
		expiresAtMs,
		intervalSeconds: 5,
	});

	const fill = async (
		store: ReturnType<typeof createMemoryDeviceCodeStore>,
		count: number,
		ttlMs: number,
		prefix: string,
	) => {
		for (let i = 0; i < count; i += 1) {
			await store.create(entry(i, Date.now() + ttlMs, prefix));
		}
	};

	it("reclaims an expired entry when a lookup finds it, not only when a poll does", async () => {
		// The verification page's `lookup` is the read that happens; a poll
		// from a device that gave up is the read that does not.
		const store = createMemoryDeviceCodeStore();
		await store.create(entry(1, 1_000));
		expect(store.size()).toBe(1);

		expect(await store.findPendingByUserCode("e-uc-1", 1_001)).toBeNull();
		expect(store.size()).toBe(0);
	});

	it("reclaims an expired entry that approve or deny finds", async () => {
		const store = createMemoryDeviceCodeStore();
		await store.create(entry(1, 1_000));
		await store.create(entry(2, 1_000));

		expect(await store.approve({ userCode: "e-uc-1", subject: "u", nowMs: 1_001 })).toEqual({
			status: "expired",
		});
		expect(await store.deny("e-uc-2", 1_001)).toEqual({ status: "expired" });
		expect(store.size()).toBe(0);
	});

	it("sweeps expired entries amortized on create, with no timer configured", async () => {
		// The module builds the store with no `sweepIntervalMs`, so the timer
		// is not the mechanism that bounds it — `create` is.
		vi.useFakeTimers();
		const store = createMemoryDeviceCodeStore();
		await fill(store, DEFAULT_MEMORY_DEVICE_CODE_STORE_SWEEP_INTERVAL, 1_000, "dead");
		vi.advanceTimersByTime(60_000);
		await fill(store, DEFAULT_MEMORY_DEVICE_CODE_STORE_SWEEP_INTERVAL, 600_000, "live");
		expect(store.size()).toBe(DEFAULT_MEMORY_DEVICE_CODE_STORE_SWEEP_INTERVAL);
	});

	it("does not sweep on every create — the work is amortized", async () => {
		vi.useFakeTimers();
		const store = createMemoryDeviceCodeStore();
		await fill(store, 5, 1_000, "dead");
		vi.advanceTimersByTime(60_000);
		await store.create(entry(0, Date.now() + 600_000, "live"));
		// Well under the interval, so the expired five are still resident.
		expect(store.size()).toBe(6);
	});

	it("keeps every live entry when it sweeps", async () => {
		// A sweep that drops a live pending code strands a device mid-flow,
		// which is worse than the growth it is fixing.
		vi.useFakeTimers();
		const store = createMemoryDeviceCodeStore({ sweepInterval: 5 });
		await fill(store, 10, 600_000, "live");
		await fill(store, 5, 1_000, "dead");
		vi.advanceTimersByTime(60_000);
		await fill(store, 5, 600_000, "trigger");
		expect(store.size()).toBe(15);
		for (let i = 0; i < 10; i += 1) {
			expect(await store.findPendingByUserCode(`live-uc-${i}`, Date.now())).not.toBeNull();
		}
	});

	it("caps the resident set at maxEntries, evicting the entry closest to expiry", async () => {
		// Under a flood the one closest to expiring is the least harm to
		// drop: it is the one about to be reclaimed anyway. Same choice the
		// rate limiter's `maxBuckets` makes.
		const base = Date.now();
		const store = createMemoryDeviceCodeStore({ maxEntries: 2 });
		await store.create(entry(1, base + 100_000, "a"));
		await store.create(entry(2, base + 50_000, "b"));
		await store.create(entry(3, base + 200_000, "c"));

		expect(store.size()).toBe(2);
		expect(await store.findPendingByUserCode("b-uc-2", base)).toBeNull();
		expect(await store.findPendingByUserCode("a-uc-1", base)).not.toBeNull();
		expect(await store.findPendingByUserCode("c-uc-3", base)).not.toBeNull();
	});

	it("prunes expired entries before evicting a live one at the cap", async () => {
		vi.useFakeTimers();
		const store = createMemoryDeviceCodeStore({ maxEntries: 2 });
		await store.create(entry(1, Date.now() + 1_000, "dead"));
		await store.create(entry(2, Date.now() + 600_000, "live"));
		vi.advanceTimersByTime(60_000);
		await store.create(entry(3, Date.now() + 600_000, "new"));

		expect(store.size()).toBe(2);
		expect(await store.findPendingByUserCode("live-uc-2", Date.now())).not.toBeNull();
		expect(await store.findPendingByUserCode("new-uc-3", Date.now())).not.toBeNull();
	});

	it("falls back to the defaults for a non-positive cap or interval", async () => {
		// `0` from an empty env var must not mean "no cap" or "sweep never".
		const store = createMemoryDeviceCodeStore({ maxEntries: 0, sweepInterval: -1 });
		await store.create(entry(1, 100_000));
		await store.create(entry(2, 100_000));
		expect(store.size()).toBe(2);
		expect(DEFAULT_MEMORY_DEVICE_CODE_STORE_MAX_ENTRIES).toBeGreaterThan(2);
	});
});
