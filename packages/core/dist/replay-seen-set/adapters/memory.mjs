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
/**
 * In-process Map-backed ReplaySeenSet. Same atomicity argument as the
 * memory ChallengeStore: Node.js single-event-loop + no awaits inside the
 * critical section between Map.get/check and Map.set/delete.
 *
 * GC is lazy (per-operation cleanup of expired entries). No background sweep.
 *
 * The `getLive` helper is deliberately duplicated rather than shared with
 * the memory ChallengeStore — three similar lines is preferable to a
 * premature abstraction here, since the two stores have semantically
 * distinct contracts (`issue` throws on duplicate; `markSeen` returns false
 * on duplicate). A shared helper would either branch on that distinction
 * (defeating the purpose) or share trivial Map+TTL plumbing only.
 *
 * Per A1 §7.1.
 */
export function createMemoryReplaySeenSet() {
    const map = new Map();
    function getLive(key, nowMs) {
        const entry = map.get(key);
        if (entry === undefined)
            return undefined;
        if (entry.expiresAtMs <= nowMs) {
            map.delete(key);
            return undefined;
        }
        return entry;
    }
    return {
        kind: "memory",
        async markSeen(scope, key, expiresAtMs) {
            const nowMs = Date.now();
            if (expiresAtMs <= nowMs) {
                throw new ChallengeStorageError({ reason: "expired-at-issue" });
            }
            const k = canonicalKey(scope, key);
            if (getLive(k, nowMs) !== undefined) {
                return false;
            }
            map.set(k, { expiresAtMs });
            return true;
        },
        async contains(scope, key) {
            return getLive(canonicalKey(scope, key), Date.now()) !== undefined;
        },
    };
}
