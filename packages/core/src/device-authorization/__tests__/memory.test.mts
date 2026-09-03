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
import { DeviceCodeStoreError } from "#/device-authorization/errors.mjs";
import {
	createMemoryDeviceCodeStore,
	DEFAULT_MEMORY_DEVICE_CODE_STORE_MAX_ENTRIES,
	DEFAULT_MEMORY_DEVICE_CODE_STORE_SWEEP_INTERVAL,
} from "#/device-authorization/memory.mjs";
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
 * the pattern for -- except that at the cap this store refuses rather than
 * evicts (#445), because what it holds is not a counter that can be reset.
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

	it("refuses a create at maxEntries rather than evicting a live record", async () => {
		// #445: a pending or approved-not-yet-polled record is a human's
		// answer in flight, and a flood that reaches the cap carries the
		// newest expiries -- so "evict the one closest to expiry" evicted every
		// legitimate authorization before any of the attacker's. Refusing the
		// newcomer is the answer that costs the flooder rather than the user
		// already mid-flow; the per-IP guard ahead of the endpoint bounds how
		// often anyone is refused.
		const base = Date.now();
		const store = createMemoryDeviceCodeStore({ maxEntries: 2 });
		await store.create(entry(1, base + 100_000, "a"));
		await store.create(entry(2, base + 50_000, "b"));

		await expect(store.create(entry(3, base + 200_000, "c"))).rejects.toThrow(DeviceCodeStoreError);
		await expect(store.create(entry(3, base + 200_000, "c"))).rejects.toMatchObject({
			reason: "full",
		});

		expect(store.size()).toBe(2);
		expect(await store.findPendingByUserCode("a-uc-1", base)).not.toBeNull();
		expect(await store.findPendingByUserCode("b-uc-2", base)).not.toBeNull();
		expect(await store.findPendingByUserCode("c-uc-3", base)).toBeNull();
	});

	it("admits a create again once a slot is freed", async () => {
		// The refusal is per request, not a latched state: a redeemed
		// approval, a polled denial, an expiry or an explicit `remove` frees a
		// slot and the next create takes it.
		const base = Date.now();
		const store = createMemoryDeviceCodeStore({ maxEntries: 1 });
		await store.create(entry(1, base + 100_000, "a"));
		await expect(store.create(entry(2, base + 100_000, "b"))).rejects.toMatchObject({
			reason: "full",
		});

		await store.remove("a-dc-1");
		await expect(store.create(entry(2, base + 100_000, "b"))).resolves.toBeUndefined();
		expect(store.size()).toBe(1);
	});

	it("reclaims expired entries at the cap before refusing", async () => {
		// The cap counts live records. An expired one still resident between
		// amortized sweeps is not a reason to refuse anybody.
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

	it("sweeps at most once per create, even where the cadence and the cap coincide", async () => {
		// Copilot on #451: the amortized boundary and the cap both wanted the
		// expired records gone and each asked for its own O(n) pass — two
		// sweeps on the one create where they coincide, on the refusal path a
		// flood exercises. A second pass straight after the first has nothing
		// left to find. `sweep` is the only reader of the clock inside
		// `create`, so one clock read per create is one sweep per create.
		const store = createMemoryDeviceCodeStore({ sweepInterval: 3, maxEntries: 2 });
		const base = Date.now();
		await store.create(entry(1, base + 600_000, "live"));
		await store.create(entry(2, base + 600_000, "live"));
		const third = entry(3, base + 600_000, "live");

		const clock = vi.spyOn(Date, "now");
		await expect(store.create(third)).rejects.toMatchObject({ reason: "full" });
		expect(clock).toHaveBeenCalledTimes(1);
		clock.mockRestore();
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

describe("memory DeviceCodeStore — eviction and decision edge cases", () => {
	const record = (n: number, expiresAtMs: number) => ({
		deviceCode: `edge-dc-${n}`,
		userCode: `edge-uc-${n}`,
		clientId: "c",
		expiresAtMs,
		intervalSeconds: 5,
	});

	it("drops a record with a non-finite expiry on sight when the cap is reached", async () => {
		// `NaN` and `Infinity` never satisfy `expiresAtMs <= now`, so a record
		// carrying one would sit in the map until process exit and, under a
		// cap that refuses rather than evicts (#445), hold a slot forever. It
		// is the record least entitled to stay, so the sweep reclaims it
		// alongside the expired ones and the newcomer is admitted.
		const base = Date.now();
		const store = createMemoryDeviceCodeStore({ maxEntries: 1 });
		await store.create(record(1, Number.POSITIVE_INFINITY));
		await store.create(record(2, base + 100_000));

		expect(store.size()).toBe(1);
		expect(await store.findPendingByUserCode("edge-uc-1", base)).toBeNull();
		expect(await store.findPendingByUserCode("edge-uc-2", base)).not.toBeNull();
	});

	it("answers already_decided when a decided record is denied", async () => {
		const base = Date.now();
		const store = createMemoryDeviceCodeStore();
		await store.create(record(3, base + 100_000));
		expect(await store.approve({ userCode: "edge-uc-3", subject: "u", nowMs: base })).toMatchObject(
			{
				status: "ok",
			},
		);

		expect(await store.deny("edge-uc-3", base)).toEqual({
			status: "already_decided",
			current: "approved",
		});
	});
});
