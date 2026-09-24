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
import { canonicalKey } from "../canonical-key.mjs";
import { ChallengeStorageError } from "../errors.mjs";
import { type AmortizedSweepOptions, createAmortizedSweep } from "../sweep.mjs";
import type { Challenge, ChallengeStore } from "../types.mjs";

/**
 * How many writing `issue` calls pass between amortized sweeps.
 *
 * A sweep is O(size), so one per issue would make every WebAuthn options
 * request linear in the store. Every 1000th write keeps the amortized cost
 * constant while bounding the resident set at "live challenges, plus at most
 * one interval of expired ones" — the replay seen-set's trade, for the same
 * kind of store.
 */
export const DEFAULT_MEMORY_CHALLENGE_STORE_SWEEP_INTERVAL = 1_000;

/**
 * The least time, in milliseconds, between two sweeps, whatever the issue
 * rate.
 *
 * The write interval alone does not bound how often the O(size) scan runs:
 * WebAuthn authentication options are asked for without a credential, so a
 * client that asks fast enough would reach the interval every few
 * milliseconds and make each request pay for a full scan. With a ten-second
 * floor the scans are at
 * most one per ten seconds, and the resident set grows by at most the
 * challenges that expire inside those ten seconds.
 */
export const DEFAULT_MEMORY_CHALLENGE_STORE_MIN_SWEEP_INTERVAL_MS = 10_000;

/**
 * How the sweep is paced: `sweepInterval` writing `issue` calls, and at least
 * `minSweepIntervalMs` between two sweeps (see {@link AmortizedSweepOptions}).
 */
export type MemoryChallengeStoreOptions = AmortizedSweepOptions;

/** In-process challenge store, with the entry count exposed for observability. */
export interface MemoryChallengeStore extends ChallengeStore {
	/** Challenges currently resident, expired-but-unswept included. */
	readonly size: number;
}

/**
 * In-process Map-backed ChallengeStore. Atomicity comes from the Node.js
 * single-event-loop guarantee: synchronous Map.get → check → Map.set/Map.delete
 * blocks contain NO `await`, so concurrent calls cannot interleave at micro-
 * task boundaries.
 *
 * ## Why the sweep exists
 *
 * An expired challenge is dropped when its (scope, value) is looked up again,
 * and a challenge nobody finishes is never looked up again: a WebAuthn prompt
 * the user closes, an options request a client repeats. Lazy reclamation
 * alone therefore left one entry per abandoned ceremony resident until the
 * process restarted — and authentication options are asked for without a
 * credential, so anyone could grow the map.
 *
 * The sweep is the replay seen-set's, paced by the same schedule
 * (`challenges/sweep.mts`): amortized on the writing `issue`, once
 * `sweepInterval` writes have accumulated and at least `minSweepIntervalMs`
 * has passed on the monotonic clock since the last one. A refused `issue` — a
 * duplicate, an expiry already past or not a number — writes nothing and pays
 * nothing. The guarantee is bounded growth, not zero-lag reclamation: an
 * expired challenge is dropped within an interval, and `find` / `consume` /
 * `issue` keep answering correctly for one that has not been swept yet.
 *
 * Per A1 §7.1.
 */
export function createMemoryChallengeStore(
	options: MemoryChallengeStoreOptions = {},
): MemoryChallengeStore {
	const map = new Map<string, { expiresAtMs: number }>();
	const schedule = createAmortizedSweep(options, {
		sweepInterval: DEFAULT_MEMORY_CHALLENGE_STORE_SWEEP_INTERVAL,
		minSweepIntervalMs: DEFAULT_MEMORY_CHALLENGE_STORE_MIN_SWEEP_INTERVAL_MS,
	});

	function getLive(key: string, nowMs: number): { expiresAtMs: number } | undefined {
		const entry = map.get(key);
		if (entry === undefined) return undefined;
		if (entry.expiresAtMs <= nowMs) {
			map.delete(key);
			return undefined;
		}
		return entry;
	}

	function sweep(nowMs: number): void {
		for (const [key, entry] of map) {
			if (entry.expiresAtMs <= nowMs) map.delete(key);
		}
	}

	return {
		kind: "memory",

		get size() {
			return map.size;
		},

		async issue(scope, value, expiresAtMs) {
			// NaN is never `<= now`, and ±Infinity is no expiry: without this the
			// challenge would be kept forever (the sweep never drops it either).
			if (!Number.isFinite(expiresAtMs)) {
				throw new RangeError(
					`ChallengeStore.issue: expiresAtMs must be a finite number (got ${String(expiresAtMs)})`,
				);
			}
			const nowMs = Date.now();
			if (expiresAtMs <= nowMs) {
				throw new ChallengeStorageError({ reason: "expired-at-issue" });
			}
			const key = canonicalKey(scope, value);
			if (getLive(key, nowMs) !== undefined) {
				throw new ChallengeStorageError({ reason: "duplicate" });
			}
			map.set(key, { expiresAtMs });
			if (schedule.wrote()) sweep(nowMs);
		},

		async find(scope, value): Promise<Challenge | null> {
			const entry = getLive(canonicalKey(scope, value), Date.now());
			if (entry === undefined) return null;
			return { expiresAtMs: entry.expiresAtMs };
		},

		async consume(scope, value) {
			const key = canonicalKey(scope, value);
			const entry = getLive(key, Date.now());
			if (entry === undefined) return false;
			map.delete(key);
			return true;
		},
	};
}
