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
 * Server-issued challenge metadata returned by ChallengeStore.find().
 * Per A1 §5.1 (lines 89-95).
 */
export interface Challenge {
	readonly expiresAt: Date;
}

/**
 * Atomic primitives for server-issued challenge tracking. Identifies a single-
 * winner across N concurrent calls; ceremony classification (replayed vs
 * unknown) is layered above by ChallengeCeremony, NOT by this primitive.
 *
 * Per A1 §5.1 (lines 89-138). Concurrency contract:
 *   - issue(scope, value): N parallel → exactly 1 success, N-1 throws "duplicate"
 *   - consume(scope, value): N parallel on live entry → exactly 1 returns true,
 *     N-1 return false
 *   - find: read-only, no atomicity required
 *
 * Adapters MUST throw ChallengeStorageError per the throw matrix in
 * `./errors.mts`. find / consume MUST NOT throw on nonexistent / expired
 * entries (return null / false respectively).
 * This contract is enforced by the shared adapter contract test suite
 * (`__tests__/adapters.contract.mts`, established in Tasks 3 + 4 and re-imported
 * by the Redis adapter tests in Tasks 11 + 12).
 */
export interface ChallengeStore {
	readonly kind: string;

	/**
	 * Atomically register a server-issued challenge.
	 *
	 * @throws ChallengeStorageError({ reason: "duplicate" }) when (scope, value)
	 *   has a non-expired entry.
	 * @throws ChallengeStorageError({ reason: "expired-at-issue" }) when
	 *   expiresAt <= now() at call time.
	 */
	issue(scope: string, value: string, expiresAt: Date): Promise<void>;

	/**
	 * Non-mutating lookup. Returns null for absent / expired entries.
	 * Reading does not mutate state; safe to call repeatedly.
	 *
	 * Note: Redis-backed adapters reconstruct expiresAt from PTTL and may
	 * drift by <10ms vs the originally-issued Date. The drift is benign —
	 * the wrapper layer (`ChallengeCeremony`, Task 5) only uses expiresAt
	 * to set the subsequent `markSeen` TTL; the security window remains
	 * TTL-bounded. Per A1 §5.1 (lines 117-122).
	 */
	find(scope: string, value: string): Promise<Challenge | null>;

	/**
	 * Atomically delete the entry if it exists. Returns true iff THIS call
	 * deleted a non-expired entry.
	 */
	consume(scope: string, value: string): Promise<boolean>;
}

/**
 * Discriminated outcome of one ChallengeCeremony.consume call. The wrapper's
 * complete return contract is one of these three values; system errors
 * (Redis network, etc.) propagate as native errors and are NOT classified
 * here.
 *
 * Per A1 §5.3 (lines 185-218).
 *
 *   "consumed": Atomically deleted by THIS call; recorded in ReplaySeenSet
 *     for future replay detection. Caller MAY proceed with the protected op.
 *   "replayed": Previously consumed (race-loss branch OR an earlier call
 *     recorded in ReplaySeenSet). Caller MUST reject AND treat as a replay-
 *     attack audit signal.
 *   "unknown": No record matches (scope, value). Caller MUST reject. This is
 *     the expected outcome for attacker probing of random values.
 */
export type ChallengeCeremonyOutcome =
	| { readonly outcome: "consumed" }
	| { readonly outcome: "replayed" }
	| { readonly outcome: "unknown" };

/**
 * Composes ChallengeStore + ReplaySeenSet primitives into the 3-outcome
 * server-issued challenge ceremony. The default implementation is in
 * `./ceremony.mts`; consumers can replace it by providing their own module.
 *
 * Per A1 §5.3.
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
// ComponentMap declaration-merge (A1 §5.5)
// ---------------------------------------------------------------------------
//
// Slots:
//   - challengeStore?: ChallengeStore
//   - challengeCeremony?: ChallengeCeremony
//
// Per A1 §5.5: optional slots — modules MAY omit the entire challenge-related
// stack. Per Phase 4 lesson (project_v050_phase4_complete memory): declare
// module uses the PACKAGE NAME ("@o3co/auth-provider-core"), NOT a relative
// path — only the package name pulls in consumer augmentations.
//
// Per master roadmap §3.1: unnamespaced names are reserved for o3co. Consumer
// keys MUST namespace (e.g., "acme.cacheChallengeStore").
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly challengeStore?: ChallengeStore;
		readonly challengeCeremony?: ChallengeCeremony;
	}
}
