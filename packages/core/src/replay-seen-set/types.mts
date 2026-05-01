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
 * Atomic replay-detection primitive. Records (scope, key) pairs and answers
 * "has this been seen before?" without amplifying storage on attacker probes
 * (the read path is `contains`, which never writes).
 *
 * Per A1 §5.2 (lines 146-177). Concurrency contract:
 *   - markSeen(scope, key, expiresAtMs): N parallel for same key → exactly 1
 *     returns true ("fresh, this call wrote"), N-1 return false ("replay").
 *   - contains(scope, key): read-only; atomicity vs concurrent markSeen NOT
 *     required (the wrapper layer queries contains only when find returned
 *     null, so the read-vs-write race window is benign).
 *
 * markSeen MUST throw ChallengeStorageError({ reason: "expired-at-issue" })
 * for expiresAtMs <= now(). contains MUST NOT throw domain errors.
 *
 * `contains` is the security-friendly disambiguation primitive — attacker
 * probing via ChallengeCeremony.consume hits `contains` (read-only, zero
 * storage amplification) rather than `markSeen` (which would amplify
 * storage proportional to probe rate).
 *
 * The no-throws contract on `contains` is enforced by the shared adapter
 * contract test suite (`__tests__/adapters.contract.mts`, established in
 * Task 4 and re-imported by the Redis adapter test in Task 12).
 */
export interface ReplaySeenSet {
	readonly kind: string;

	/**
	 * @returns true iff this call wrote (= first observation = fresh).
	 *          false iff (scope, key) already had a non-expired record (= replay).
	 * @throws ChallengeStorageError({ reason: "expired-at-issue" }) for
	 *   expiresAtMs <= now().
	 */
	markSeen(scope: string, key: string, expiresAtMs: number): Promise<boolean>;

	/**
	 * Read-only check. Returns true iff a non-expired record exists.
	 * Does NOT throw domain errors.
	 */
	contains(scope: string, key: string): Promise<boolean>;
}

// ---------------------------------------------------------------------------
// ComponentMap declaration-merge (A1 §5.5)
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly replaySeenSet?: ReplaySeenSet;
	}
}

// ---------------------------------------------------------------------------
// Backing client interface (Phase 10 addendum §3)
// ---------------------------------------------------------------------------

/**
 * Backing client for ReplaySeenSet adapters. Adapter implementations
 * (e.g. `@o3co/auth-provider-redis`'s `createRedisReplaySeenSet`) consume
 * exactly these methods.
 *
 * Per Phase 10 addendum §3.
 */
export interface ReplaySeenSetClient {
	set(key: string, value: string, mode: "PX", ttlMs: number, condition: "NX"): Promise<"OK" | null>;
	exists(key: string): Promise<number>;
}

declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly replaySeenSetClient?: ReplaySeenSetClient;
	}
}
