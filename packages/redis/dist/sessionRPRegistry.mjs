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
import { createRedisSidHash } from "./internal/redisSidHash.mjs";
function serialize(rp) {
    const env = { clientId: rp.clientId, registeredAtMs: rp.registeredAt.getTime() };
    // Only write defined optional fields to avoid "" / false coercion on round-trip.
    if (rp.backchannelLogoutUri !== undefined)
        env.backchannelLogoutUri = rp.backchannelLogoutUri;
    if (rp.backchannelLogoutSessionRequired !== undefined)
        env.backchannelLogoutSessionRequired = rp.backchannelLogoutSessionRequired;
    if (rp.frontchannelLogoutUri !== undefined)
        env.frontchannelLogoutUri = rp.frontchannelLogoutUri;
    if (rp.frontchannelLogoutSessionRequired !== undefined)
        env.frontchannelLogoutSessionRequired = rp.frontchannelLogoutSessionRequired;
    return JSON.stringify(env);
}
function deserialize(json) {
    const env = JSON.parse(json);
    return {
        clientId: env.clientId,
        registeredAt: new Date(env.registeredAtMs),
        // Absent keys are `undefined` — do not fallback to false/null/empty.
        backchannelLogoutUri: env.backchannelLogoutUri,
        backchannelLogoutSessionRequired: env.backchannelLogoutSessionRequired,
        frontchannelLogoutUri: env.frontchannelLogoutUri,
        frontchannelLogoutSessionRequired: env.frontchannelLogoutSessionRequired,
    };
}
/**
 * Redis-backed SessionRPRegistry. Per A4 §5.2 + §7.2.1.
 *
 * Storage shape: one Redis HASH per sid, key = `${keyPrefix}${sid}`.
 * Each field in the hash is a `clientId`; its value is a JSON-encoded
 * `RPEnvelope`. HSET deduplication: writing the same `clientId` replaces
 * the earlier value (upsert semantics), satisfying the "same clientId
 * upserts" contract without any CAS loop.
 *
 * Why HSET-keyed-by-clientId over SADD-of-JSON:
 *   SADD-of-JSON cannot dedup when other RP fields change: a different
 *   `backchannelLogoutUri` produces different bytewise JSON for the same
 *   logical clientId, creating duplicate set members. HSET uses the field
 *   name as the dedup key, which is exactly `clientId`.
 *
 * TTL: PEXPIREAT is applied atomically in the same pipeline as HSET via
 * `createRedisSidHash.setField`. The timestamp is `session.expiresAt`,
 * which is post-create immutable per A4 §5.1.
 */
export function createRedisSessionRPRegistry(opts) {
    const hash = createRedisSidHash({ client: opts.client, keyPrefix: opts.keyPrefix });
    return {
        kind: "redis",
        async registerRP(sid, rp, expiresAt) {
            await hash.setField(sid, rp.clientId, serialize(rp), expiresAt);
        },
        async listRPs(sid) {
            const values = await hash.listValues(sid);
            return values.map(deserialize);
        },
        async removeBySid(sid) {
            await hash.removeBySid(sid);
        },
    };
}
