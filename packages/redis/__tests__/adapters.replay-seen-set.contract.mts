/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import type { ReplaySeenSet } from "@o3co/auth-provider-core";
import { ChallengeStorageError } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";

export interface ReplaySeenSetContractFactory {
	create(): Promise<ReplaySeenSet> | ReplaySeenSet;
	teardown?(set: ReplaySeenSet): Promise<void> | void;
}

/**
 * How a test reaches an entry's expiry on the store's own terms.
 *
 * An in-process store judges expiry on this process's clock. A Redis key
 * expires on the server's, which sits to either side of the host's, and a
 * relative `PX` runs from when the command reached the server; a loaded run
 * also reaches its next line late. A fixed sleep after a short expiry therefore
 * either read an entry the store had already dropped, or checked one it had
 * not dropped yet. The default is this process's clock; a Redis runner passes
 * one that reads the server's `TIME`, or waits for the keys to be gone.
 */
export interface ExpiryClock {
	/** Epoch milliseconds on the clock the store expires entries by. */
	now(): Promise<number>;
	/** Resolves once the store has let everything expiring at `at` go. */
	passed(at: Date): Promise<void>;
}

const hostExpiry: ExpiryClock = {
	now: async () => Date.now(),
	passed: async (at) => {
		while (Date.now() <= at.getTime()) {
			await new Promise((r) => setTimeout(r, at.getTime() - Date.now() + 1));
		}
	},
};

/**
 * An expiry a second ahead of whichever clock is later — the host's, which a
 * write checks it against, and the store's, which expires it — so a read that
 * follows the write lands well inside it however loaded the run is.
 */
const aheadOf = async (clock: ExpiryClock): Promise<Date> =>
	new Date(Math.max(Date.now(), await clock.now()) + 1_000);

/**
 * Adapter contract suite for ReplaySeenSet. Memory + Redis adapters both
 * call this and MUST pass identically.
 *
 * Per A1 §13.1 + master roadmap §3.6.
 */
export function runReplaySeenSetContract(
	factoryName: string,
	factory: ReplaySeenSetContractFactory,
	options: { readonly expiry?: ExpiryClock } = {},
): void {
	describe(`ReplaySeenSet contract — ${factoryName}`, () => {
		const future = (): number => Date.now() + 60_000;

		async function withSet(body: (set: ReplaySeenSet) => Promise<void>): Promise<void> {
			const set = await factory.create();
			try {
				await body(set);
			} finally {
				await factory.teardown?.(set);
			}
		}

		it("markSeen returns true on first call, false on replay", async () => {
			await withSet(async (set) => {
				expect(await set.markSeen("scope-A", "k1", future())).toBe(true);
				expect(await set.markSeen("scope-A", "k1", future())).toBe(false);
			});
		});

		it("contains returns false before markSeen, true after", async () => {
			await withSet(async (set) => {
				expect(await set.contains("scope-A", "k2")).toBe(false);
				await set.markSeen("scope-A", "k2", future());
				expect(await set.contains("scope-A", "k2")).toBe(true);
			});
		});

		it("markSeen throws 'expired-at-issue' for past expiresAtMs", async () => {
			await withSet(async (set) => {
				const past = Date.now() - 1_000;
				await expect(set.markSeen("scope-A", "k3", past)).rejects.toMatchObject({
					name: "ChallengeStorageError",
					reason: "expired-at-issue",
				});
			});
		});

		it("markSeen refuses an expiry that is not a finite number, and records nothing", async () => {
			// A NaN expiry is never `<= now`, so it slipped past the expired-at-issue
			// check: the memory adapter kept the record forever and Redis was sent
			// `PX NaN`. A non-finite expiry is a caller fault, not the timing race
			// `expired-at-issue` names, so it is a RangeError — which the challenge
			// ceremony, swallowing `expired-at-issue`, does not swallow.
			await withSet(async (set) => {
				for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
					await expect(set.markSeen("scope-A", "k-bad", bad)).rejects.toThrow(RangeError);
					expect(await set.contains("scope-A", "k-bad")).toBe(false);
				}
				expect(await set.markSeen("scope-A", "k-bad", future())).toBe(true);
			});
		});

		it("markSeen accepts a fractional expiry, and keeps the record at least until it", async () => {
			// JWT NumericDates may be non-integer, and a lifetime in fractional
			// seconds makes one too. Redis's PX takes whole milliseconds, so an
			// adapter rounds the record's life up, never down.
			await withSet(async (set) => {
				expect(await set.markSeen("scope-A", "k-frac", Date.now() + 60_000.5)).toBe(true);
				expect(await set.markSeen("scope-A", "k-frac", Date.now() + 60_000.5)).toBe(false);
				expect(await set.contains("scope-A", "k-frac")).toBe(true);
			});
		});

		it("expired entries treated as absent (contains=false after TTL)", async () => {
			// Dated from, and waited out on, the set's own clock (see
			// `ExpiryClock`), not a 50 ms expiry and a 100 ms sleep.
			const expiry = options.expiry ?? hostExpiry;
			await withSet(async (set) => {
				const soon = await aheadOf(expiry);
				await set.markSeen("scope-A", "k4", soon.getTime());
				expect(await set.contains("scope-A", "k4")).toBe(true);
				await expiry.passed(soon);
				expect(await set.contains("scope-A", "k4")).toBe(false);
			});
		});

		it("concurrency: N parallel markSeen for same key → exactly 1 returns true", async () => {
			await withSet(async (set) => {
				const N = 50;
				const exp = future();
				const results = await Promise.all(
					Array.from({ length: N }, () => set.markSeen("scope-A", "race", exp)),
				);
				const winners = results.filter((r) => r === true).length;
				expect(winners).toBe(1);
				expect(results.length - winners).toBe(N - 1);
			});
		});

		it("ChallengeStorageError type-import unused-warning guard", () => {
			// Placeholder to anchor the import; vitest will complain if the import
			// is unused above (it's used in the toMatchObject above, kept by ts).
			expect(ChallengeStorageError.name).toBe("ChallengeStorageError");
		});
	});
}
