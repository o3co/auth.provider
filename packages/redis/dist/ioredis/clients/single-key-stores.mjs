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
import { redisDurability } from "../durability.mjs";
export function makeIoredisChallengeStoreClient(io) {
    const challengeStoreClient = {
        set: (k, v, _mode, ttl, _cond) => io.set(k, v, "PX", ttl, "NX"),
        pttl: (k) => io.pttl(k),
        del: (k) => io.del(k),
        get: (k) => io.get(k),
    };
    return challengeStoreClient;
}
export function makeIoredisAccessTokenDenylistClient(io, options = {}) {
    // Revoked access-token jtis. Plain PX SET (no NX): re-revoking a jti is idempotent, and the
    // last write sets the expiry.
    const accessTokenDenylistClient = {
        set: (k, v, _mode, ttlMs) => io.set(k, v, "PX", ttlMs),
        exists: (k) => io.exists(k),
        durability: () => redisDurability(io, options),
    };
    return accessTokenDenylistClient;
}
export function makeIoredisReplaySeenSetClient(io, options = {}) {
    const replaySeenSetClient = {
        set: (k, v, _mode, ttl, _cond) => io.set(k, v, "PX", ttl, "NX"),
        exists: (k) => io.exists(k),
        durability: () => redisDurability(io, options),
    };
    return replaySeenSetClient;
}
export function makeIoredisCodeRepositoryClient(io) {
    // Authorization codes: short-lived, high-volume records mapped directly onto ioredis commands.
    const codeRepositoryClient = {
        set: (k, v, _mode, ttlMs) => io.set(k, v, "PX", ttlMs),
        get: (k) => io.get(k),
        getDel: (k) => io.getdel(k),
        del: (k) => io.del(k),
    };
    return codeRepositoryClient;
}
