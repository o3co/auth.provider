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
import { type AmortizedSweepOptions, createAmortizedSweep } from "../../single-use/sweep.mjs";
import { DPOP_PROOF_REPLAY_SCOPE_PREFIX, DPOP_PROOF_REPLAY_SHARE } from "../scopes.mjs";
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
 * The most records the set holds by default.
 *
 * The set fills at `maxEntries / window` records a second, the window being
 * the longest a consumer keeps a record — DPoP's
 * `oauth.dpop.replay-store-ttl-seconds`, 300 s by default. At a million that
 * is about 3 300 fresh DPoP proofs a second held for five minutes, each one
 * signature-verified before it is recorded: about what one process can
 * verify at all, so reaching the cap costs a flooder as much as taking the
 * process's CPU would. A lower cap would let one client fill the set at a
 * rate it sends idly — and while it is full every consumer is refused (see
 * the factory). The memory it bounds is about 200 MB with the UUID `jti`s
 * clients send, and up to about 725 MB when every `jti` is a 256-character
 * one outside Latin-1. A longer DPoP window lowers the rate that fills it in
 * proportion. `memoryReplaySeenSetModule` reads the cap from
 * `replaySeenSet.memory.maxEntries`; past one replica, use the Redis
 * seen-set.
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
	 * that is not a positive whole number is a `RangeError`, never read as no
	 * cap.
	 */
	readonly maxEntries?: number;
}

/**
 * What `markSeen` throws when the set is at its cap — or, for a DPoP proof,
 * at DPoP's share of it — and none of its records has expired: a store fault,
 * as a Redis seen-set's refused write at `maxmemory` is — not one of the
 * port's contract errors (`ChallengeStorageError`, `RangeError`), which a
 * consumer reads as its own mistake. Every consumer refuses what it was
 * recording, unrecorded: `private_key_jwt` answers `503
 * temporarily_unavailable`, and DPoP the same under its reason
 * `replay_store_full`. `reason` is `"full"`, which a logged projection keeps;
 * the message says which limit was reached.
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
 * ChallengeStore shares (`single-use/sweep.mts`): once `sweepInterval`
 * writes have accumulated and at least `minSweepIntervalMs` has passed on the
 * monotonic clock since the last sweep. A replay is refused without writing
 * and pays nothing. The guarantee is bounded growth, not zero-lag
 * reclamation: an expired record is dropped within an interval, and
 * `markSeen` / `contains` keep answering correctly for one that has not been
 * swept yet.
 *
 * ## Why it has a cap, and refuses at it
 *
 * The sweep bounds the set by time, not by count: what it holds is the
 * records written within their lifetime, so the write rate decides its size.
 * DPoP writes one for every freshly signed proof — at the token endpoint
 * before its rate limit runs, at a protected resource before the access
 * token is verified — so anyone can make it write at will. `maxEntries`
 * bounds it. At the cap the set first reclaims what has expired, at most
 * once per sweep floor (`minSweepIntervalMs`), so a flood that holds it at
 * the cap does not make every write a full scan; if it is still full it
 * refuses the new record with {@link ReplaySeenSetFullError}, a store fault.
 * It never evicts a live record to make room: an evicted record is a value
 * that can be accepted again — a replay. A replay of a value it holds needs
 * no room and is still refused (`false`). While it is full every consumer
 * sharing it refuses what it would record — DPoP proofs, `private_key_jwt`
 * assertions, ID-JAGs, WebAuthn challenges — until records expire, which is
 * the fail-closed answer the port asks of a store that cannot write.
 *
 * DPoP proofs — the one consumer anyone can make write, before a rate limit
 * or a token check — may fill only {@link DPOP_PROOF_REPLAY_SHARE} of the cap
 * (`scopes.mts`): a proof is refused once the set holds that many records of
 * any consumer, and the rest is kept for `private_key_jwt`, ID-JAG and
 * WebAuthn, whose writes follow an authentication or a rate limit. So a DPoP
 * flood refuses DPoP proofs, and client authentication goes on until the set
 * itself is full. The default cap sits where filling even DPoP's share costs
 * a flooder about as much as the process's CPU
 * ({@link DEFAULT_MEMORY_REPLAY_SEEN_SET_MAX_ENTRIES}).
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
	const maxEntries = options.maxEntries ?? DEFAULT_MEMORY_REPLAY_SEEN_SET_MAX_ENTRIES;
	if (!Number.isInteger(maxEntries) || maxEntries <= 0) {
		throw new RangeError(
			`createMemoryReplaySeenSet: maxEntries must be a positive whole number (got ${String(maxEntries)})`,
		);
	}
	const dpopShare = Math.ceil(maxEntries * DPOP_PROOF_REPLAY_SHARE);
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
			// At the cap — DPoP's share of it, for a proof: reclaim what has
			// expired, no more often than the sweep floor, and refuse if the set
			// is still at the limit. See "Why it has a cap, and refuses at it"
			// above.
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
