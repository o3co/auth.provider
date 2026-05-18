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
 * DPoP proof replay protection store. See Wave 2 Phase 2 spec §5.5.
 *
 * Atomic `seen(jti, jkt, ttl)` returns true when the (jti, jkt) pair
 * was already seen within the replay window; false when not seen, AND
 * atomically records the pair with the given TTL.
 *
 * Atomicity is REQUIRED — a two-step "check then mark" pattern would
 * leave a TOCTOU window. In-memory implementations rely on JS single-
 * threaded execution; clustered deployments MUST use a Redis backend
 * (the in-memory adapter is dev-only).
 */
export interface DPoPReplayStore {
	/**
	 * @param jti          DPoP proof JWT-ID (RFC 9449 §4.2 `jti` claim).
	 * @param jkt          RFC 7638 SHA-256 thumbprint of the proof JWK —
	 *                     pair-scopes the key so the same `jti` reissued
	 *                     under a different key is NOT a replay.
	 * @param ttlSeconds   Replay window in seconds; MUST be a positive
	 *                     finite number. Implementations SHOULD throw
	 *                     `RangeError` on non-positive values rather than
	 *                     silently emitting an expired entry.
	 * @returns `true` when this (jti, jkt) pair was already seen within
	 *          the replay window; `false` when this call is the first
	 *          observation (and the pair has been atomically recorded).
	 */
	seen(jti: string, jkt: string, ttlSeconds: number): Promise<boolean>;
}
