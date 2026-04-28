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
