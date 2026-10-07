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
import { WebAuthnCredentialStorageError } from "./errors.mjs";
/**
 * In-process Map-backed WebAuthnCredentialStore.
 *
 * Atomicity argument (single-process, single-event-loop):
 *   - `registerCredential`: the Map.has check and Map.set are SYNCHRONOUS —
 *     no `await` between them. Node's microtask queue cannot interleave
 *     non-async work, so concurrent callers do not race.
 *   - `updateSignCount` is an atomic compare-and-set (CAS) under the same
 *     guarantee.
 *   - Production deployments requiring multi-process or distributed
 *     deployments should use a real backing store (e.g. a Redis adapter).
 *
 * `remove` is idempotent: deleting a non-existent credentialId is a no-op.
 */
export function createMemoryWebAuthnCredentialStore() {
    const byCredentialId = new Map();
    return {
        kind: "memory",
        async registerCredential(record) {
            // Check FIRST before any mutation so a failed insert leaves zero
            // state changes (atomicity guarantee).
            if (byCredentialId.has(record.credentialId)) {
                throw new WebAuthnCredentialStorageError({ reason: "duplicate-credential" });
            }
            byCredentialId.set(record.credentialId, record);
        },
        async findByCredentialId(credentialId) {
            return byCredentialId.get(credentialId) ?? null;
        },
        async listByUserId(userId) {
            return [...byCredentialId.values()].filter((c) => c.userId === userId);
        },
        async updateSignCount(credentialId, { expectedCurrentSignCount, newSignCount, lastUsedAt }) {
            const cur = byCredentialId.get(credentialId);
            if (!cur)
                return false;
            if (cur.signCount !== expectedCurrentSignCount)
                return false;
            byCredentialId.set(credentialId, { ...cur, signCount: newSignCount, lastUsedAt });
            return true;
        },
        async remove(credentialId) {
            byCredentialId.delete(credentialId);
        },
    };
}
