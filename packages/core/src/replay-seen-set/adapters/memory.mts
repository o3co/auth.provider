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
import { canonicalKey } from "../../challenges/canonical-key.mjs";
import { ChallengeStorageError } from "../../challenges/errors.mjs";
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

export interface MemoryReplaySeenSetOptions {
	/**
	 * Writing `markSeen` calls between sweeps. Lower trades work for memory.
	 * A non-integer or non-positive value falls back to the default rather
	 * than disabling the sweep.
	 */
	readonly sweepInterval?: number;
}

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
 * access-token denylist's is: a background interval would need lifecycle
 * registration to avoid holding the process open, and a write is the only
 * operation that grows the map. A replay is refused without writing and
 * pays nothing. The guarantee is bounded growth, not zero-lag reclamation:
 * an expired record is dropped within an interval, and `markSeen` /
 * `contains` keep answering correctly for one that has not been swept yet.
 *
 * The `getLive` helper is deliberately duplicated rather than shared with
 * the memory ChallengeStore — three similar lines is preferable to a
 * premature abstraction here, since the two stores have semantically
 * distinct contracts (`issue` throws on duplicate; `markSeen` returns false
 * on duplicate).
 *
 * Per A1 §7.1.
 */
export function createMemoryReplaySeenSet(
	options: MemoryReplaySeenSetOptions = {},
): MemoryReplaySeenSet {
	const map = new Map<string, { expiresAtMs: number }>();
	const sweepInterval =
		typeof options.sweepInterval === "number" &&
		Number.isInteger(options.sweepInterval) &&
		options.sweepInterval > 0
			? options.sweepInterval
			: DEFAULT_MEMORY_REPLAY_SEEN_SET_SWEEP_INTERVAL;
	let writesSinceSweep = 0;

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
			if (!Number.isFinite(expiresAtMs)) {
				throw new RangeError(
					`ReplaySeenSet.markSeen: expiresAtMs must be a finite number (got ${String(expiresAtMs)})`,
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
			writesSinceSweep += 1;
			if (writesSinceSweep >= sweepInterval) {
				writesSinceSweep = 0;
				sweep(nowMs);
			}
			return true;
		},

		async contains(scope, key) {
			return getLive(canonicalKey(scope, key), Date.now()) !== undefined;
		},
	};
}
