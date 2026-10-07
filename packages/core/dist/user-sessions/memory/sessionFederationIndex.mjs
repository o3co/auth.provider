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
import { createMemorySidSortedSet } from "./internalSidSortedSet.mjs";
/**
 * In-memory SessionFederationIndex. Wraps `createMemorySidSortedSet` for
 * insertion-order-preserving, idempotent-add federation name tracking.
 *
 * Insertion order is LOAD-BEARING per A4 §5.4: the cascade orchestrator reads
 * `(await listFederations(sid))[0]` to choose the IdP for post-logout redirect.
 * Re-add of an existing member does NOT promote position (ZADD NX equivalent).
 *
 * Supports per-element `removeFederation(sid, name)` for federation logout
 * completion in addition to full `removeBySid` cleanup. Per A4 §5.4 + §7.1.
 */
export function createInMemorySessionFederationIndex() {
    const set = createMemorySidSortedSet();
    return {
        kind: "memory",
        async addFederation(sid, federationName, expiresAt) {
            set.add(sid, federationName, expiresAt);
        },
        async listFederations(sid) {
            return set.list(sid);
        },
        async removeFederation(sid, federationName) {
            set.remove(sid, federationName);
        },
        async removeBySid(sid) {
            set.removeBySid(sid);
        },
    };
}
