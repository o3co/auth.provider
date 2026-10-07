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
export function createRedisSubjectSessionIndex(deps) {
    const prefix = deps.keyPrefix ?? "ss:sub:";
    const key = (subject) => `${prefix}${subject}`;
    return {
        kind: "redis",
        async addSid(subject, sid, expiresAt) {
            const expiresAtMs = expiresAt.getTime();
            // An already-expired session is not worth indexing; it would only be
            // swept on the next read. Mirrors the in-process adapter.
            //
            // This one comparison is deliberately local: `expiresAt` was computed
            // on this host, so checking it against this host's clock is
            // self-consistent, and it is an optimisation rather than the
            // correctness gate — the server-clock sweep in `listSids` is. Reading
            // the store's clock here would buy a round-trip to make a
            // short-circuit slightly more accurate.
            if (expiresAtMs <= Date.now())
                return;
            const k = key(subject);
            await deps.client
                .multi()
                .zAdd(k, { score: expiresAtMs, value: sid })
                .pExpireGT(k, expiresAtMs)
                .exec();
        },
        async listSids(subject) {
            return deps.client.pruneExpiredAndList(key(subject));
        },
        async removeSid(subject, sid) {
            // Redis removes a sorted set that loses its last member, so there is no
            // emptied-key case to clean up here.
            await deps.client.zRem(key(subject), sid);
        },
        async removeBySubject(subject) {
            await deps.client.unlink(key(subject));
        },
    };
}
/**
 * AdapterFactory builder for the Redis-backed `SubjectSessionIndex` (#321).
 *
 * Use when per-adapter `AdapterFactory` granularity is needed; for the common
 * case the bundled `redisSessionStoresModule` is sufficient. Default
 * `keyPrefix` matches the bundle's production layout (`ss:sub:`) so swapping
 * between bundle and individual builder does not change the keyspace.
 *
 * Missing `client` throws at boot rather than crashing at the first Redis op,
 * matching every other builder in this package.
 */
export const redisSubjectSessionIndexBuilder = (config, _ctx) => {
    const c = config;
    if (!c.client) {
        throw new Error("redisSubjectSessionIndexBuilder: 'client' option is required");
    }
    return createRedisSubjectSessionIndex({
        client: c.client,
        keyPrefix: c.keyPrefix ?? "ss:sub:",
    });
};
