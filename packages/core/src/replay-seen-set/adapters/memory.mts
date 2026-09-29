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
import { canonicalKey } from "../../single-use/canonical-key.mjs";
import { ChallengeStorageError } from "../../single-use/errors.mjs";
import { usableMaxEntries } from "../../single-use/max-entries.mjs";
import { type AmortizedSweepOptions, createAmortizedSweep } from "../../single-use/sweep.mjs";
import { DPOP_PROOF_REPLAY_SCOPE_PREFIX, DPOP_PROOF_REPLAY_SHARE } from "../scopes.mjs";
import type { ReplaySeenSet } from "../types.mjs";

/**
 * How many writing `markSeen` calls pass between amortized sweeps. A sweep is
 * O(size), so running one only after this many writes, and no sooner than the
 * minimum interval below, keeps the amortized cost constant. It is a write
 * threshold, not a bound on how many expired records stay resident.
 */
export const DEFAULT_MEMORY_REPLAY_SEEN_SET_SWEEP_INTERVAL = 1_000;

/**
 * The least time, in milliseconds, between two sweeps, whatever the write
 * rate. DPoP writes a record per request, so at 1000 requests a second the
 * write interval alone would scan ~300,000 records (default 300 s TTL) every
 * second; the floor allows one scan per ten seconds, at the cost of holding
 * the records that expire within those ten seconds.
 */
export const DEFAULT_MEMORY_REPLAY_SEEN_SET_MIN_SWEEP_INTERVAL_MS = 10_000;

/**
 * The most records the set holds by default. The set fills at
 * `maxEntries / window` records a second (window: DPoP's
 * `oauth.dpop.replay-store-ttl-seconds`, 300 s by default). At a million that
 * is ~3,300 signature-verified DPoP proofs a second, about what one process
 * can verify at all, so reaching the cap costs a flooder as much as taking the
 * CPU. A lower cap would let one client fill it idly, and while it is full
 * every consumer is refused. Memory: ~200 MB with UUID `jti`s, up to ~725 MB
 * with 256-character non-Latin-1 ones. Read from
 * `replaySeenSet.memory.maxEntries`; past one replica, use the Redis seen-set.
 */
export const DEFAULT_MEMORY_REPLAY_SEEN_SET_MAX_ENTRIES = 1_000_000;

/**
 * How the sweep is paced — `sweepInterval` writing `markSeen` calls, and at
 * least `minSweepIntervalMs` between two sweeps (see
 * {@link AmortizedSweepOptions}) — and the cap on the records it holds.
 */
export interface MemoryReplaySeenSetOptions extends AmortizedSweepOptions {
	/**
	 * The most records the set holds, expired-but-unswept ones included;
	 * {@link DEFAULT_MEMORY_REPLAY_SEEN_SET_MAX_ENTRIES} when absent. A value
	 * that is not a positive whole number, or is above 2^24 (the most entries
	 * a `Map` holds), is a `RangeError`, never read as no cap.
	 */
	readonly maxEntries?: number;
}

/**
 * Thrown by `markSeen` when the set (or, for a DPoP proof, DPoP's share of it)
 * is full of live records. A store fault, like a Redis seen-set's refused
 * write at `maxmemory`, not a port contract error (`ChallengeStorageError`,
 * `RangeError`) that a consumer reads as its own mistake. Consumers refuse
 * what they were recording: `private_key_jwt` with `503
 * temporarily_unavailable`, DPoP likewise with reason `replay_store_full`.
 */
export class ReplaySeenSetFullError extends Error {
	readonly reason = "full" as const;

	/**
	 * @param maxEntries The set's cap.
	 * @param dpopShare For a DPoP proof refused at DPoP's share: that share,
	 *   in records.
	 */
	constructor(maxEntries: number, dpopShare?: number) {
		super(
			dpopShare === undefined
				? `memory ReplaySeenSet is at its cap of ${maxEntries} live records; refusing a new one rather than evicting one`
				: `memory ReplaySeenSet holds ${dpopShare} live records, the share of its cap of ${maxEntries} that DPoP proofs may fill; refusing a new proof so the rest stays for the other consumers`,
		);
		this.name = "ReplaySeenSetFullError";
	}
}

/** In-process seen-set, with the record count and its cap exposed for observability. */
export interface MemoryReplaySeenSet extends ReplaySeenSet {
	/** Records currently resident, expired-but-unswept included. */
	readonly size: number;
	/** The most records it holds (`maxEntries`); at it, a new record is refused. */
	readonly maxEntries: number;
}

/**
 * In-process Map-backed ReplaySeenSet. Atomic because nothing awaits between
 * the Map read and write on the single event loop.
 *
 * Sweep: consumers record single-use values (`jti`s, consumed WebAuthn
 * challenges) that are never presented again once honoured, so dropping
 * expired records on lookup reclaims almost nothing. An amortized sweep runs
 * on the writing `markSeen`, paced by the schedule shared with the memory
 * ChallengeStore (`single-use/sweep.mts`): after `sweepInterval` writes and at
 * least `minSweepIntervalMs` on the monotonic clock. A refused replay writes
 * nothing and pays nothing; unswept expired records still answer correctly.
 *
 * Cap: anyone can make DPoP write (before the token endpoint's rate limit,
 * before a resource verifies the access token), so `maxEntries` bounds the
 * count. At the cap the set reclaims expired records (at most once per sweep
 * floor), then refuses with {@link ReplaySeenSetFullError}. It never evicts a
 * live record: an evicted value could be accepted again, i.e. replayed. While
 * full, every consumer refuses what it would record (fail-closed).
 *
 * DPoP proofs may fill only {@link DPOP_PROOF_REPLAY_SHARE} of the cap
 * (`scopes.mts`), so a DPoP flood refuses DPoP proofs while `private_key_jwt`,
 * ID-JAG and WebAuthn, whose writes follow authentication or a rate limit,
 * keep the rest.
 *
 * `getLive` is duplicated rather than shared with the memory ChallengeStore:
 * the contracts differ (`issue` throws on a duplicate, `markSeen` returns
 * false).
 */
export function createMemoryReplaySeenSet(
	options: MemoryReplaySeenSetOptions = {},
): MemoryReplaySeenSet {
	const maxEntries = usableMaxEntries(
		// Only a cap left out takes the default: an explicit `null` is refused.
		options.maxEntries === undefined
			? DEFAULT_MEMORY_REPLAY_SEEN_SET_MAX_ENTRIES
			: options.maxEntries,
		"createMemoryReplaySeenSet",
	);
	// DPoP's share, rounded up, and always a record short of the cap so the
	// other consumers keep one; a cap of one has no reserve (`scopes.mts`).
	const dpopShare =
		maxEntries >= 2
			? Math.min(Math.ceil(maxEntries * DPOP_PROOF_REPLAY_SHARE), maxEntries - 1)
			: maxEntries;
	const map = new Map<string, { expiresAtMs: number }>();
	const schedule = createAmortizedSweep(
		options,
		{
			sweepInterval: DEFAULT_MEMORY_REPLAY_SEEN_SET_SWEEP_INTERVAL,
			minSweepIntervalMs: DEFAULT_MEMORY_REPLAY_SEEN_SET_MIN_SWEEP_INTERVAL_MS,
		},
		"createMemoryReplaySeenSet",
	);

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

		maxEntries,

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
			// At the cap (DPoP's share, for a proof): reclaim expired records, at
			// most once per sweep floor, and refuse if still at the limit.
			const dpop = scope.startsWith(DPOP_PROOF_REPLAY_SCOPE_PREFIX);
			const limit = dpop ? dpopShare : maxEntries;
			if (map.size >= limit) {
				if (schedule.due()) sweep(nowMs);
				if (map.size >= limit) {
					throw new ReplaySeenSetFullError(maxEntries, dpop ? dpopShare : undefined);
				}
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
