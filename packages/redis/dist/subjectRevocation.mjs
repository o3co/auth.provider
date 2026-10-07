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
export function createRedisSubjectRevocation(deps) {
    const prefix = deps.keyPrefix ?? "ss:rev:";
    const key = (subject) => `${prefix}${subject}`;
    return {
        kind: "redis",
        async revokeBefore(subject, before, expiresAt) {
            await deps.client.setWatermarkMonotonic(key(subject), before.getTime(), expiresAt.getTime());
        },
        async revokedBefore(subject) {
            const raw = await deps.client.get(key(subject));
            if (raw === null)
                return null;
            const ms = Number(raw);
            // A value this adapter did not write, or one corrupted in the store, is
            // not a watermark. Answering `null` would silently disable revocation
            // for the subject, so it is refused loudly instead — the caller
            // (`verifyJwt`) already fails closed on a throw from this store.
            if (!Number.isFinite(ms)) {
                throw new Error(`SubjectRevocation: watermark for a subject is not a number (key prefix "${prefix}")`);
            }
            return new Date(ms);
        },
    };
}
/**
 * AdapterFactory builder for the Redis-backed `SubjectRevocation` (#321).
 *
 * Use when per-adapter `AdapterFactory` granularity is needed; for the common
 * case the bundled `redisSessionStoresModule` is sufficient. Default
 * `keyPrefix` matches the bundle's production layout (`ss:rev:`) so swapping
 * between bundle and individual builder does not change the keyspace.
 *
 * Missing `client` throws at boot rather than crashing at the first Redis op,
 * matching every other builder in this package.
 */
export const redisSubjectRevocationBuilder = (config, _ctx) => {
    const c = config;
    if (!c.client) {
        throw new Error("redisSubjectRevocationBuilder: 'client' option is required");
    }
    return createRedisSubjectRevocation({
        client: c.client,
        keyPrefix: c.keyPrefix ?? "ss:rev:",
    });
};
