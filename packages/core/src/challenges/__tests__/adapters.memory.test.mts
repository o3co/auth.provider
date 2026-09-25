/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	createMemoryChallengeStore,
	DEFAULT_MEMORY_CHALLENGE_STORE_MIN_SWEEP_INTERVAL_MS,
	DEFAULT_MEMORY_CHALLENGE_STORE_SWEEP_INTERVAL,
} from "../adapters/memory.mjs";
import { runChallengeStoreContract } from "./adapters.contract.mjs";

runChallengeStoreContract("memory", {
	create: () => createMemoryChallengeStore(),
});

afterEach(() => {
	vi.useRealTimers();
});

type Store = ReturnType<typeof createMemoryChallengeStore>;

/** Issue `count` challenges under `scope` that expire `ttlMs` from now. */
const issueMany = async (
	store: Store,
	count: number,
	ttlMs: number,
	prefix: string,
	scope = "webauthn-registration:user-1",
) => {
	for (let i = 0; i < count; i += 1) {
		await store.issue(scope, `${prefix}-${i}`, Date.now() + ttlMs);
	}
};

/*
 * The in-memory challenge store grew until restart.
 *
 * It reclaimed an expired challenge only when that exact (scope, value) was
 * looked up again, and a challenge nobody finishes is never looked up again:
 * a WebAuthn prompt the user closes, an options request a script repeats. Each
 * left one entry resident for the life of the process. The replay seen-set had
 * the same leak and the same fix (#673); so did the access-token denylist
 * (#293 item 6).
 */
describe("createMemoryChallengeStore — bounded growth", () => {
	it("drops challenges issued and abandoned, and still finds a live one", async () => {
		// Pinned first so the fills below cannot be vacuous.
		expect(DEFAULT_MEMORY_CHALLENGE_STORE_SWEEP_INTERVAL).toBe(1_000);
		vi.useFakeTimers();
		const store = createMemoryChallengeStore();
		await store.issue("webauthn-authentication", "in-progress", Date.now() + 600_000);
		await issueMany(store, DEFAULT_MEMORY_CHALLENGE_STORE_SWEEP_INTERVAL, 60_000, "abandoned");
		vi.advanceTimersByTime(120_000);
		await issueMany(store, DEFAULT_MEMORY_CHALLENGE_STORE_SWEEP_INTERVAL, 600_000, "fresh");
		// The abandoned thousand are gone; the ceremony still in progress and
		// the fresh ones remain.
		expect(store.size).toBe(DEFAULT_MEMORY_CHALLENGE_STORE_SWEEP_INTERVAL + 1);
		expect(await store.find("webauthn-authentication", "in-progress")).not.toBeNull();
		expect(await store.consume("webauthn-authentication", "in-progress")).toBe(true);
	});

	it("bounds the resident set at live challenges plus one sweep interval", async () => {
		// The sweep is amortized: an expired challenge is reclaimed within an
		// interval, not the instant it expires.
		vi.useFakeTimers();
		const store = createMemoryChallengeStore({ sweepInterval: 10 });
		await issueMany(store, 100, 1_000, "dead");
		vi.advanceTimersByTime(60_000);
		await issueMany(store, 25, 600_000, "live");
		expect(store.size).toBeLessThanOrEqual(25 + 10);
	});

	it("keeps every live challenge when it sweeps, whatever scope it is in", async () => {
		// A sweep that dropped a live challenge would fail the ceremony the user
		// is in the middle of. Asserted on `size` as well as on `find`: `find`
		// drops the one entry it finds expired, so reading through it alone
		// hides whether the sweep ran.
		vi.useFakeTimers();
		const store = createMemoryChallengeStore({ sweepInterval: 5 });
		await issueMany(store, 10, 600_000, "live", "webauthn-authentication");
		await issueMany(store, 5, 1_000, "dead", "webauthn-registration:user-2");
		vi.advanceTimersByTime(60_000);
		// Five more issues guarantee a sweep now that the dead ones have expired.
		await issueMany(store, 5, 600_000, "trigger", "webauthn-registration:user-3");
		expect(store.size).toBe(15);
		for (let i = 0; i < 10; i += 1) {
			expect(await store.find("webauthn-authentication", `live-${i}`)).not.toBeNull();
		}
	});

	it("does not sweep on every issue — the work is amortized", async () => {
		vi.useFakeTimers();
		const store = createMemoryChallengeStore();
		await issueMany(store, 5, 1_000, "dead");
		vi.advanceTimersByTime(60_000);
		await store.issue("webauthn-authentication", "one-more", Date.now() + 600_000);
		// Well under the interval, so the expired five are still resident.
		expect(store.size).toBe(6);
	});

	it("does not count a refused issue as a write", async () => {
		// Only a write grows the store, so only a write pays towards the next
		// sweep: a duplicate, an expiry already past and one that is not a
		// number are refused without adding work.
		vi.useFakeTimers();
		const store = createMemoryChallengeStore({ sweepInterval: 3 });
		await issueMany(store, 2, 1_000, "dead");
		vi.advanceTimersByTime(60_000);
		await store.issue("webauthn-authentication", "live", Date.now() + 600_000);
		// That third write swept the two expired challenges.
		expect(store.size).toBe(1);
		await issueMany(store, 1, 1_000, "dying");
		vi.advanceTimersByTime(60_000);
		for (let i = 0; i < 3; i += 1) {
			await expect(
				store.issue("webauthn-authentication", "live", Date.now() + 600_000),
			).rejects.toMatchObject({ reason: "duplicate" });
			await expect(
				store.issue("webauthn-authentication", `past-${i}`, Date.now()),
			).rejects.toThrow();
			await expect(store.issue("webauthn-authentication", `nan-${i}`, Number.NaN)).rejects.toThrow(
				RangeError,
			);
		}
		// Nine refusals and no sweep: the expired `dying` challenge is still resident.
		expect(store.size).toBe(2);
	});

	it("still answers correctly for an expired challenge it has not swept yet", async () => {
		vi.useFakeTimers();
		const store = createMemoryChallengeStore();
		await store.issue("webauthn-authentication", "v-1", Date.now() + 1_000);
		vi.advanceTimersByTime(60_000);
		expect(await store.find("webauthn-authentication", "v-1")).toBeNull();
		expect(await store.consume("webauthn-authentication", "v-1")).toBe(false);
		await store.issue("webauthn-authentication", "v-1", Date.now() + 1_000);
		expect(await store.consume("webauthn-authentication", "v-1")).toBe(true);
	});

	it("exposes its size so an operator can see the bound holding", async () => {
		const store = createMemoryChallengeStore();
		expect(store.size).toBe(0);
		await store.issue("webauthn-authentication", "v-1", Date.now() + 600_000);
		expect(store.size).toBe(1);
		await store.consume("webauthn-authentication", "v-1");
		expect(store.size).toBe(0);
	});

	it("refuses a sweep interval that is not a positive whole number, rather than using another", () => {
		// It used to fall back to the default: a setting given and unusable was
		// quietly replaced, which is what a boot refusal exists to prevent.
		for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
			expect(() => createMemoryChallengeStore({ sweepInterval: bad }), String(bad)).toThrow(
				new RangeError(
					`createMemoryChallengeStore: sweepInterval must be a positive whole number (got ${String(bad)})`,
				),
			);
		}
	});
});

/*
 * A sweep scans the whole map, and a write count alone does not bound how
 * often that happens: WebAuthn authentication options are asked for without
 * a credential, so a client that asks fast enough would make every issue pay
 * for a full scan. A time floor caps the scans at one per interval whatever the
 * issue rate, for a resident set larger by at most the challenges that expire
 * within it.
 */
describe("createMemoryChallengeStore — sweeps are also bounded in time", () => {
	it("sweeps at most once per minSweepIntervalMs, however fast the issues come", async () => {
		vi.useFakeTimers();
		const store = createMemoryChallengeStore({ sweepInterval: 5, minSweepIntervalMs: 1_000 });
		// The fifth issue sweeps (nothing has expired yet).
		await issueMany(store, 5, 10, "early");
		vi.advanceTimersByTime(20);
		// Five more issues reach the interval again, but inside the floor: the
		// five expired challenges are still resident.
		await issueMany(store, 5, 600_000, "burst");
		expect(store.size).toBe(10);
		// Once the floor has passed, the next issue sweeps them.
		vi.advanceTimersByTime(1_000);
		await store.issue("webauthn-authentication", "late", Date.now() + 600_000);
		expect(store.size).toBe(6);
	});

	it("has a default floor of ten seconds", async () => {
		expect(DEFAULT_MEMORY_CHALLENGE_STORE_MIN_SWEEP_INTERVAL_MS).toBe(10_000);
		vi.useFakeTimers();
		const store = createMemoryChallengeStore({ sweepInterval: 2 });
		await issueMany(store, 2, 10, "a"); // first sweep
		vi.advanceTimersByTime(9_000);
		await issueMany(store, 2, 600_000, "b");
		expect(store.size).toBe(4);
		vi.advanceTimersByTime(1_000);
		await store.issue("webauthn-authentication", "c", Date.now() + 600_000);
		expect(store.size).toBe(3);
	});

	it("measures the floor on a monotonic clock, so a backward wall-clock jump does not stall sweeps", async () => {
		// Expiry is wall-clock (the callers' `expiresAtMs`); the floor is only
		// "how long since the last sweep". vitest's fake timers drive
		// `performance.now()` too, and leave it untouched by `setSystemTime` —
		// as the real monotonic clock is by a wall-clock step.
		vi.useFakeTimers();
		const store = createMemoryChallengeStore({ sweepInterval: 2, minSweepIntervalMs: 1_000 });
		await issueMany(store, 2, 600_000, "before"); // first sweep
		vi.setSystemTime(Date.now() - 3_600_000);
		await issueMany(store, 2, 10, "after-jump"); // inside the floor: no sweep
		expect(store.size).toBe(4);
		vi.advanceTimersByTime(1_000);
		await store.issue("webauthn-authentication", "trigger", Date.now() + 600_000);
		// A second of monotonic time has passed: the two challenges that expired
		// on the (jumped) wall clock are gone; the live ones stay.
		expect(store.size).toBe(3);
	});

	it("takes a floor of zero as no floor, and refuses one that is not a whole number of milliseconds", async () => {
		vi.useFakeTimers();
		const unfloored = createMemoryChallengeStore({ sweepInterval: 2, minSweepIntervalMs: 0 });
		await issueMany(unfloored, 2, 10, "a");
		vi.advanceTimersByTime(20);
		await issueMany(unfloored, 2, 600_000, "b");
		expect(unfloored.size).toBe(2);

		for (const bad of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
			expect(
				() => createMemoryChallengeStore({ sweepInterval: 2, minSweepIntervalMs: bad }),
				String(bad),
			).toThrow(
				new RangeError(
					`createMemoryChallengeStore: minSweepIntervalMs must be a whole number of milliseconds, 0 or more (got ${String(bad)})`,
				),
			);
		}
	});
});
