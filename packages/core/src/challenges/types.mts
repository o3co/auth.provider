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

/**
 * Server-issued challenge metadata returned by ChallengeStore.find(). Epoch
 * ms rather than a Date, whose mutation `Object.freeze` cannot prevent.
 */
export interface Challenge {
	readonly expiresAtMs: number;
}

/**
 * Atomic primitives for server-issued challenge tracking: a single winner
 * across N concurrent calls. Ceremony classification (replayed vs unknown)
 * is ChallengeCeremony's, not this primitive's.
 *
 * Concurrency contract:
 *   - issue(scope, value): N parallel → exactly 1 success, N-1 throws "duplicate"
 *   - consume(scope, value): N parallel on live entry → exactly 1 returns true,
 *     N-1 return false
 *   - find: read-only, no atomicity required
 *
 * Adapters MUST throw ChallengeStorageError per the throw matrix in
 * `single-use/errors.mts`; find / consume MUST NOT throw on a missing or
 * expired entry (they return null / false). The shared adapter contract
 * suite (`__tests__/adapters.contract.mts`) enforces this.
 */
export interface ChallengeStore {
	readonly kind: string;

	/**
	 * Atomically register a server-issued challenge.
	 *
	 * @throws ChallengeStorageError({ reason: "duplicate" }) when (scope, value)
	 *   has a non-expired entry.
	 * @throws ChallengeStorageError({ reason: "expired-at-issue" }) when
	 *   expiresAtMs <= now() at call time.
	 * @throws RangeError when expiresAtMs is not a finite instant within the
	 *   Date range (NaN, ±Infinity, past ±8.64e15 ms — `isStorableExpiry`) —
	 *   a caller fault, not the timing race above. Nothing is
	 *   recorded. A fractional expiresAtMs is valid; the challenge lives at
	 *   least until it.
	 */
	issue(scope: string, value: string, expiresAtMs: number): Promise<void>;

	/**
	 * Non-mutating lookup; null for an absent or expired entry. Safe to call
	 * repeatedly.
	 *
	 * The expiresAtMs answered is never later than the issued expiry, beyond
	 * the time the store took to record it, on the clock of the host that
	 * reads it: an adapter that rebuilds it from a remaining life (Redis
	 * `PTTL`) adds that life to an instant read before asking, so a slow
	 * reply makes it earlier, never later. Hosts' clocks differ by what the
	 * deployment's skew allowance covers.
	 * `ChallengeCeremony` uses it for the following `markSeen` TTL and reports
	 * it on the `consumed` outcome; the security window stays TTL-bounded.
	 */
	find(scope: string, value: string): Promise<Challenge | null>;

	/**
	 * Atomically delete the entry if it exists. Returns true iff THIS call
	 * deleted a non-expired entry.
	 */
	consume(scope: string, value: string): Promise<boolean>;
}

/**
 * Outcome of one ChallengeCeremony.consume call: the wrapper's complete
 * return contract. System errors (Redis network, …) propagate as native
 * errors and are not classified here.
 *
 *   "consumed": deleted by this call and recorded in ReplaySeenSet. The
 *     caller MAY proceed with the protected operation. `expiresAtMs` is the
 *     expiry `ChallengeStore.find` answered for this challenge, never later
 *     than the issued one (see `find`); a ceremony
 *     that cannot tell it omits it, so a reader MUST handle its absence.
 *   "replayed": consumed before (race loss, or an earlier call recorded in
 *     ReplaySeenSet). The caller MUST reject and treat it as a replay-attack
 *     audit signal.
 *   "unknown": no record matches (scope, value). The caller MUST reject; the
 *     expected outcome for an attacker probing random values.
 */
export type ChallengeCeremonyOutcome =
	| { readonly outcome: "consumed"; readonly expiresAtMs?: number }
	| { readonly outcome: "replayed" }
	| { readonly outcome: "unknown" };

/**
 * Composes ChallengeStore + ReplaySeenSet primitives into the 3-outcome
 * server-issued challenge ceremony. The default implementation is in
 * `./ceremony.mts`; consumers can replace it by providing their own module.
 */
export interface ChallengeCeremony {
	/**
	 * Returns one of the three discriminated outcomes. Does NOT throw
	 * ChallengeStorageError or any other domain error in normal flow —
	 * the union IS the complete return contract.
	 */
	consume(scope: string, value: string): Promise<ChallengeCeremonyOutcome>;
}

// ---------------------------------------------------------------------------
// ComponentMap declaration-merge
// ---------------------------------------------------------------------------
//
// Optional slots: a composition may omit the whole challenge stack. The
// `declare module` block names the package ("@o3co/auth-provider-core"), not
// a relative path: only the package name merges with consumer augmentations
// of the same `ComponentMap`. Unnamespaced names are reserved for first-party
// slots; consumer keys MUST namespace (e.g. "acme.cacheChallengeStore").
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly challengeStore?: ChallengeStore;
		readonly challengeCeremony?: ChallengeCeremony;
	}
}

// ---------------------------------------------------------------------------
// Backing client interface
// ---------------------------------------------------------------------------

// The ChallengeStoreClient backing-client interface lives in
// @o3co/auth-provider-redis: its shape is Redis-flavoured and belongs with
// its consumers.
