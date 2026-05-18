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
	seen(jti: string, jkt: string, ttlSeconds: number): Promise<boolean>;
}
