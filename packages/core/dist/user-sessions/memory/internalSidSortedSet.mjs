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
export function createMemorySidSortedSet() {
    const store = new Map();
    return {
        add(sid, member, expiresAt) {
            const expiresAtMs = expiresAt.getTime();
            if (expiresAtMs <= Date.now())
                return;
            const existing = store.get(sid);
            // Lazy GC: if the previous bucket has already expired, drop its state
            // so a re-used sid does not leak federation/family IDs from a prior
            // session into the new one. (Aligns with the `list()` GC path.)
            const isStale = existing != null && existing.expiresAtMs <= Date.now();
            if (existing && !isStale) {
                if (!existing.seen.has(member)) {
                    existing.ordered.push(member);
                    existing.seen.add(member);
                }
                // expiresAt is immutable per A4 §5.1; same-sid writes always carry
                // the SAME expiresAt. Refreshing the local mirror is a no-op when
                // inputs are valid, and benign otherwise (mirrors PEXPIREAT idempotence).
                existing.expiresAtMs = expiresAtMs;
            }
            else {
                store.set(sid, {
                    ordered: [member],
                    seen: new Set([member]),
                    expiresAtMs,
                });
            }
        },
        list(sid) {
            const it = store.get(sid);
            if (!it)
                return [];
            if (it.expiresAtMs <= Date.now()) {
                store.delete(sid);
                return [];
            }
            return [...it.ordered];
        },
        remove(sid, member) {
            const it = store.get(sid);
            if (!it)
                return;
            const idx = it.ordered.indexOf(member);
            if (idx >= 0) {
                it.ordered.splice(idx, 1);
                it.seen.delete(member);
            }
        },
        removeBySid(sid) {
            store.delete(sid);
        },
    };
}
