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
 * Atomic replay-detection primitive: records (scope, key) pairs and answers
 * "seen before?".
 *
 * Concurrency: N parallel `markSeen` calls for one key give exactly one
 * `true` (fresh, this call wrote) and N-1 `false` (replay). `contains` need
 * not be atomic against `markSeen`; callers query it only after `find`
 * returned null, where that race is benign.
 *
 * `markSeen` MUST throw `ChallengeStorageError({ reason: "expired-at-issue" })`
 * for `expiresAtMs <= now()`, and `RangeError` for an `expiresAtMs` that is
 * not a finite instant within the Date range (`isStorableExpiry`): a caller
 * fault, not a timing race, so consumers do not swallow it. Either way
 * nothing is recorded. A fractional `expiresAtMs` is valid; the record lives
 * at least until it.
 *
 * `contains` never writes and MUST NOT throw domain errors, so attacker
 * probes through `ChallengeCeremony.consume` cost no storage. The adapter
 * contract suite (`__tests__/adapters.contract.mts`) enforces this.
 */
export interface ReplaySeenSet {
	readonly kind: string;

	/**
	 * @returns true iff this call wrote (= first observation = fresh).
	 *          false iff (scope, key) already had a non-expired record (= replay).
	 * @throws ChallengeStorageError({ reason: "expired-at-issue" }) for
	 *   expiresAtMs <= now().
	 * @throws RangeError for an expiresAtMs that is not a finite instant within
	 *   the Date range.
	 */
	markSeen(scope: string, key: string, expiresAtMs: number): Promise<boolean>;

	/**
	 * Read-only check. Returns true iff a non-expired record exists.
	 * Does NOT throw domain errors.
	 */
	contains(scope: string, key: string): Promise<boolean>;
}

// ---------------------------------------------------------------------------
// ComponentMap declaration-merge
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly replaySeenSet?: ReplaySeenSet;
	}
}
