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

// The lock a refresh holds, over a connection (#593, D12).
//
// Against a stub rather than a container, because what has to be proved here
// is timing: how long the store says it waited, what it does when an
// acknowledgement arrives late, and that a release frees this holder's lock
// and no other's. A real Redis proves exclusion — the shared contract suite
// does that — and would prove none of these deterministically.

import { describe, expect, it, vi } from "vitest";
import { createFederationGrantLock } from "../../src/internal/federation-grant-lock.mjs";

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

interface Attempt {
	readonly token: string;
	readonly ttlMs: number;
	readonly at: number;
}

/**
 * A connection that answers what the test tells it to, and records what it
 * was asked. `answers` is consumed one attempt at a time; `delayMs` is how
 * long the answer takes to come back, which is what an overloaded server,
 * a script-cache miss or a slow link all look like from here.
 */
const stub = (answers: boolean[], delayMs = 0) => {
	const attempts: Attempt[] = [];
	const released: string[] = [];
	let held: string | null = null;
	return {
		attempts,
		released,
		heldToken: () => held,
		client: {
			async tryLock(_key: string, token: string, ttlMs: number) {
				attempts.push({ token, ttlMs, at: performance.now() });
				if (delayMs > 0) await sleep(delayMs);
				const taken = answers.shift() ?? true;
				if (taken) held = token;
				return taken;
			},
			async unlock(_key: string, token: string) {
				released.push(token);
				if (held === token) held = null;
			},
		},
	};
};

const lock = (client: { tryLock: unknown; unlock: unknown }) =>
	createFederationGrantLock({
		client: client as Parameters<typeof createFederationGrantLock>[0]["client"],
		lockKey: () => "fg:{g-1}:lock",
		pollIntervalMs: 5,
	});

describe("the refresh lock over a connection (#593, D12)", () => {
	it("takes it on the first attempt and says it waited all but nothing", async () => {
		// Not exactly zero, and not asserted to be: what is reported is what
		// elapsed before the attempt was SENT, which on a loaded process is the
		// millisecond or two this call itself took. That is honest — it is time
		// the lease had not started for — and the rule that it excludes the
		// ANSWER's travel is what the next case pins.
		const { client, attempts } = stub([true]);
		const taken = await lock(client).acquire("g-1", { ttlMs: 30_000, waitForMs: 5_000 });
		expect(taken.acquired).toBe(true);
		expect(taken.acquired && taken.waitedMs).toBeGreaterThanOrEqual(0);
		expect(taken.acquired && taken.waitedMs).toBeLessThan(50);
		expect(attempts).toHaveLength(1);
		expect(attempts[0]?.ttlMs).toBe(30_000);
	});

	it("says how long it waited before the attempt that took it, and not how long the answer took", async () => {
		// The lease is spent from when the store took the lock (D12), and the
		// acknowledgement's own travel is spent too — core measures that part
		// itself. A `waitedMs` that included it would say the lease started later
		// than it did, which is the one direction that is unsafe.
		const { client } = stub([false, true], 40);
		const result = await lock(client).acquire("g-1", { ttlMs: 30_000, waitForMs: 5_000 });
		expect(result.acquired).toBe(true);
		if (!result.acquired) return;
		// One refused attempt (40 ms) plus the poll interval, and not the second
		// attempt's own 40 ms.
		expect(result.waitedMs).toBeGreaterThanOrEqual(40);
		expect(result.waitedMs).toBeLessThan(80);
	});

	it("rounds the wait DOWN to a whole millisecond: a lower bound is never overstated", async () => {
		// One millisecond, and it is the direction that matters: `waitedMs` dates
		// the lease at `askedAt + waitedMs`, so rounding up says the lease began
		// later than it did — and core would let a refresh run past the end of an
		// exclusion that had already lapsed.
		const { client } = stub([false, true]);
		const readings = [0, 10.7, 10.7, 10.7, 10.7];
		let next = 0;
		const held = createFederationGrantLock({
			client: client as Parameters<typeof createFederationGrantLock>[0]["client"],
			lockKey: () => "fg:{g-1}:lock",
			pollIntervalMs: 0,
			now: () => readings[Math.min(next++, readings.length - 1)] as number,
		});
		const result = await held.acquire("g-1", { ttlMs: 30_000, waitForMs: 5_000 });
		expect(result.acquired).toBe(true);
		expect(result.acquired && result.waitedMs).toBe(10);
	});

	it("hands over a lock it took, however late the answer came back", async () => {
		// Not a `timeout`: that word means another holder has it, and core turns
		// it into "serve what is stored, come back later". This caller HELD the
		// lock; throwing it away would leave a grant unrefreshed with nothing
		// competing for it. Core measures the acknowledgement and refuses to
		// start upstream work when the budget is spent (`retrieve.mts`), which is
		// the decision that belongs there and not here.
		const { client, released } = stub([true], 60);
		const result = await lock(client).acquire("g-1", { ttlMs: 30_000, waitForMs: 10 });
		expect(result.acquired).toBe(true);
		expect(released).toStrictEqual([]);
	});

	it("gives up when the wait is spent, and never asks again after the deadline", async () => {
		const { client, attempts } = stub([false, false, false, false, false, false, false, false]);
		const started = performance.now();
		const result = await lock(client).acquire("g-1", { ttlMs: 30_000, waitForMs: 20 });
		expect(result).toStrictEqual({ acquired: false, reason: "timeout" });
		const spent = performance.now() - started;
		expect(spent).toBeLessThan(200);
		for (const attempt of attempts) {
			expect(attempt.at - started).toBeLessThanOrEqual(20 + 5);
		}
	});

	it("asks exactly once when told to wait for nothing, and does not sleep", async () => {
		const { client, attempts } = stub([false]);
		const started = performance.now();
		const result = await lock(client).acquire("g-1", { ttlMs: 30_000, waitForMs: 0 });
		expect(result).toStrictEqual({ acquired: false, reason: "timeout" });
		expect(attempts).toHaveLength(1);
		expect(performance.now() - started).toBeLessThan(50);
	});

	it("frees its own lock once, however many times it is asked to", async () => {
		const { client, released } = stub([true]);
		const result = await lock(client).acquire("g-1", { ttlMs: 30_000, waitForMs: 0 });
		expect(result.acquired).toBe(true);
		if (!result.acquired) return;
		await Promise.all([result.release(), result.release(), result.release()]);
		await result.release();
		expect(released).toStrictEqual([result.acquired ? released[0] : ""]);
		expect(released).toHaveLength(1);
	});

	it("frees the lock it holds and never another holder's", async () => {
		const { client, attempts, released } = stub([true]);
		const result = await lock(client).acquire("g-1", { ttlMs: 30_000, waitForMs: 0 });
		expect(result.acquired).toBe(true);
		if (!result.acquired) return;
		await result.release();
		// The token released is the one this acquisition sent, and it is not
		// guessable from the key: past the TTL another caller holds the lock, and
		// a release that deleted the key would free theirs.
		expect(released).toStrictEqual([attempts[0]?.token]);
		expect(attempts[0]?.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
	});

	it("lets a failed release be seen, and does not retry it: a lock nobody freed is freed by its own TTL", async () => {
		const failing = {
			async tryLock() {
				return true;
			},
			async unlock() {
				throw new Error("connection lost");
			},
		};
		const result = await lock(failing).acquire("g-1", { ttlMs: 30_000, waitForMs: 0 });
		expect(result.acquired).toBe(true);
		if (!result.acquired) return;
		await expect(result.release()).rejects.toThrow("connection lost");
		// The same failure, and not a second attempt at it.
		await expect(result.release()).rejects.toThrow("connection lost");
	});

	it("refuses a TTL or a wait that is not a number it can hold to", async () => {
		const { client } = stub([true]);
		const held = lock(client);
		for (const ttlMs of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
			await expect(held.acquire("g-1", { ttlMs, waitForMs: 0 }), String(ttlMs)).rejects.toThrow(
				RangeError,
			);
		}
		for (const waitForMs of [-1, Number.NaN, Number.POSITIVE_INFINITY]) {
			await expect(
				held.acquire("g-1", { ttlMs: 30_000, waitForMs }),
				String(waitForMs),
			).rejects.toThrow(RangeError);
		}
	});

	it("asks for a whole number of milliseconds: a fractional TTL is rounded up, never down to nothing", async () => {
		const { client, attempts } = stub([true]);
		await lock(client).acquire("g-1", { ttlMs: 0.4, waitForMs: 0 });
		expect(attempts[0]?.ttlMs).toBe(1);
	});

	it("lets a connection failure through rather than reporting a lock that is held", async () => {
		const failing = {
			async tryLock() {
				throw new Error("connection lost");
			},
			async unlock() {},
		};
		await expect(lock(failing).acquire("g-1", { ttlMs: 30_000, waitForMs: 0 })).rejects.toThrow(
			"connection lost",
		);
	});

	it("measures the wait on a clock that cannot be moved by the system's", async () => {
		// `Date.now()` steps when the host's clock is set; the wait would then be
		// reported as negative, or as hours, and core would refuse the lease of a
		// lock that was in fact taken at once.
		const { client } = stub([false, true]);
		vi.useFakeTimers({ toFake: ["Date"] });
		try {
			vi.setSystemTime(new Date("2026-09-18T00:00:00.000Z"));
			const pending = lock(client).acquire("g-1", { ttlMs: 30_000, waitForMs: 5_000 });
			vi.setSystemTime(new Date("2020-01-01T00:00:00.000Z"));
			const result = await pending;
			expect(result.acquired).toBe(true);
			expect(result.acquired && result.waitedMs).toBeGreaterThanOrEqual(0);
			expect(result.acquired && result.waitedMs).toBeLessThan(1_000);
		} finally {
			vi.useRealTimers();
		}
	});
});
