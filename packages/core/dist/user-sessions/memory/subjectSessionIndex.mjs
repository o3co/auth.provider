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
 * In-memory {@link SubjectSessionIndex} (#296).
 *
 * Deliberately **not** built on `createMemorySidSortedSet`, despite the shape
 * looking identical. That primitive keeps one expiry per *key*, which is
 * correct for the sid-keyed indexes — every member there belongs to the one
 * session and shares its expiry, and its own comment says so: "same-sid writes
 * always carry the SAME expiresAt".
 *
 * A subject-keyed index breaks that assumption. One subject's sessions expire
 * at different times, so a single bucket expiry would either keep an expired
 * session listed (when a later session extends the bucket) or drop a live one
 * early (when an earlier-expiring session shortens it). Neither is acceptable
 * for the index a credential change enumerates. Expiry is therefore tracked
 * per member.
 *
 * GC is lazy — expired members are dropped when the subject is read — with no
 * background sweep, matching the other in-memory stores here.
 */
export function createInMemorySubjectSessionIndex() {
    /** subject → (sid → expiry ms). Insertion order is preserved by Map. */
    const bySubject = new Map();
    /** Drop expired members, and the subject entry itself once it is empty. */
    const prune = (subject) => {
        const sids = bySubject.get(subject);
        if (sids === undefined)
            return undefined;
        const now = Date.now();
        for (const [sid, expiresAtMs] of sids) {
            if (expiresAtMs <= now)
                sids.delete(sid);
        }
        if (sids.size === 0) {
            bySubject.delete(subject);
            return undefined;
        }
        return sids;
    };
    return {
        kind: "memory",
        async addSid(subject, sid, expiresAt) {
            const expiresAtMs = expiresAt.getTime();
            // An already-expired session is not worth indexing; it would only be
            // pruned on the next read.
            if (expiresAtMs <= Date.now())
                return;
            const sids = bySubject.get(subject) ?? new Map();
            // `set` on an existing key keeps its original insertion position, so a
            // repeated add is idempotent in both membership and order.
            sids.set(sid, expiresAtMs);
            bySubject.set(subject, sids);
        },
        async listSids(subject) {
            const sids = prune(subject);
            return sids === undefined ? [] : [...sids.keys()];
        },
        async removeSid(subject, sid) {
            const sids = bySubject.get(subject);
            if (sids === undefined)
                return;
            sids.delete(sid);
            if (sids.size === 0)
                bySubject.delete(subject);
        },
        async removeBySubject(subject) {
            bySubject.delete(subject);
        },
    };
}
