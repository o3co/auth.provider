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

import { isStorableExpiry } from "../../adapters/expiry.mjs";
import { canonicalKey } from "../../challenges/canonical-key.mjs";
import { ChallengeStorageError } from "../../challenges/errors.mjs";
import { type AmortizedSweepOptions, createAmortizedSweep } from "../../challenges/sweep.mjs";
import type { ReplaySeenSet } from "../types.mjs";

/**
 * How many writing `markSeen` calls pass between amortized sweeps.
 *
 * A sweep is O(size), so one per write would make every accepted assertion
 * or proof linear in the set. Every 1000th write keeps the amortized cost
 * constant while bounding the resident set at "live records, plus at most
 * one interval of expired ones" — the access-token denylist's trade (#293
 * item 6), for the same kind of store.
 */
export const DEFAULT_MEMORY_REPLAY_SEEN_SET_SWEEP_INTERVAL = 1_000;

/**
 * The least time, in milliseconds, between two sweeps, whatever the write
 * rate.
 *
 * The write interval alone does not bound how often the O(size) scan runs:
 * DPoP writes a record per request at every protected resource, so at 1000
 * requests a second a 1000-write interval is a full scan every second — of
 * roughly 300,000 records at the default 300-second replay TTL. With a
 * ten-second floor the scans are at most one per ten seconds, and the
 * resident set grows by at most the records that expire inside those ten
 * seconds (about 3% of the live set in that example).
 */
export const DEFAULT_MEMORY_REPLAY_SEEN_SET_MIN_SWEEP_INTERVAL_MS = 10_000;

/**
 * How the sweep is paced: `sweepInterval` writing `markSeen` calls, and at
 * least `minSweepIntervalMs` between two sweeps (see
 * {@link AmortizedSweepOptions}).
 */
export type MemoryReplaySeenSetOptions = AmortizedSweepOptions;

/** In-process seen-set, with the record count exposed for observability. */
export interface MemoryReplaySeenSet extends ReplaySeenSet {
	/** Records currently resident, expired-but-unswept included. */
	readonly size: number;
}

/**
 * In-process Map-backed ReplaySeenSet. Same atomicity argument as the
 * memory ChallengeStore: Node.js single-event-loop + no awaits inside the
 * critical section between Map.get/check and Map.set/delete.
 *
 * ## Why the sweep exists
 *
 * A record is looked up again only when its value is presented again, and
 * what every consumer records — a client assertion's `jti`, an ID-JAG's
 * `jti`, a DPoP proof's `jti`, a consumed WebAuthn challenge — is exactly
 * the value that stops being presented once it has been honoured. Dropping
 * expired records only on lookup therefore reclaimed almost nothing: one
 * permanent entry per accepted credential, and with DPoP one per request at
 * every protected resource. The set is keyed by single-use values, so
 * nothing bounds it but time, and the sweep has to be its own step.
 *
 * Amortized on the writing `markSeen` rather than on a timer, as the
 * access-token denylist's is, and paced by the schedule the memory
 * ChallengeStore shares (`challenges/sweep.mts`): once `sweepInterval`
 * writes have accumulated and at least `minSweepIntervalMs` has passed on the
 * monotonic clock since the last sweep. A replay is refused without writing
 * and pays nothing. The guarantee is bounded growth, not zero-lag
 * reclamation: an expired record is dropped within an interval, and
 * `markSeen` / `contains` keep answering correctly for one that has not been
 * swept yet.
 *
 * The `getLive` helper is deliberately duplicated rather than shared with
 * the memory ChallengeStore — three similar lines is preferable to a
 * premature abstraction here, since the two stores have semantically
 * distinct contracts (`issue` throws on duplicate; `markSeen` returns false
 * on duplicate). The sweep's pacing is shared, because there the two are the
 * same rule and its edge cases — the floor, the monotonic clock — are where a
 * copy would drift.
 *
 * Per A1 §7.1.
 */
export function createMemoryReplaySeenSet(
	options: MemoryReplaySeenSetOptions = {},
): MemoryReplaySeenSet {
	const map = new Map<string, { expiresAtMs: number }>();
	const schedule = createAmortizedSweep(options, {
		sweepInterval: DEFAULT_MEMORY_REPLAY_SEEN_SET_SWEEP_INTERVAL,
		minSweepIntervalMs: DEFAULT_MEMORY_REPLAY_SEEN_SET_MIN_SWEEP_INTERVAL_MS,
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

		async markSeen(scope, key, expiresAtMs) {
			// NaN is never `<= now`, and ±Infinity is no expiry: without this the
			// record would be kept forever (the sweep never drops it either).
			if (!isStorableExpiry(expiresAtMs)) {
				throw new RangeError(
					`ReplaySeenSet.markSeen: expiresAtMs must be a finite instant within the Date range (got ${String(expiresAtMs)})`,
				);
			}
			const nowMs = Date.now();
			if (expiresAtMs <= nowMs) {
				throw new ChallengeStorageError({ reason: "expired-at-issue" });
			}
			const k = canonicalKey(scope, key);
			if (getLive(k, nowMs) !== undefined) {
				return false;
			}
			map.set(k, { expiresAtMs });
			if (schedule.wrote()) sweep(nowMs);
			return true;
		},

		async contains(scope, key) {
			return getLive(canonicalKey(scope, key), Date.now()) !== undefined;
		},
	};
}
