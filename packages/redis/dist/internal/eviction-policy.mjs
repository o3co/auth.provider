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
/** What `policy` may evict, for a refusal's message. */
const evictedBy = (policy) => policy.startsWith("allkeys-")
    ? "any key"
    : policy.startsWith("volatile-")
        ? "any key with a TTL"
        : "keys under memory pressure";
/**
 * The refusal of a server whose `maxmemory-policy` is not known to be
 * `noeviction`. `maxmemoryPolicy` is the policy the server reported, or
 * `undefined` when it could not be read; `cause` is then the reply that
 * refused the question, if one did. It quotes the server's policy and
 * nothing else.
 */
export class RedisStoreEvictableError extends Error {
    reason;
    maxmemoryPolicy;
    constructor(store, maxmemoryPolicy, refusal, options) {
        super(maxmemoryPolicy === undefined
            ? `${store}: the Redis server's maxmemory-policy could not be read, so nothing shows it is "noeviction" — the store keeps ${refusal.holds}; let the connection run INFO memory, or, where the server does run "noeviction", build the clients with assumeNoEviction: true (${refusal.reason})`
            : `${store}: the Redis server's maxmemory-policy is "${maxmemoryPolicy}", which may evict ${evictedBy(maxmemoryPolicy)} — the store keeps ${refusal.holds}; set maxmemory-policy to "noeviction", or give ${store} a server of its own (${refusal.reason})`, options);
        this.name = "RedisStoreEvictableError";
        this.reason = refusal.reason;
        this.maxmemoryPolicy = maxmemoryPolicy;
    }
}
/**
 * Reads the policy once through `durability` and resolves only when it is
 * `noeviction`, or is unread and asserted (`assumeNoEviction`). Otherwise it
 * throws a {@link RedisStoreEvictableError} for `store`; a failure to read
 * rejects as it is.
 */
export async function requireNoEviction(store, durability, refusal) {
    const report = await durability();
    const policy = report.maxmemoryPolicy;
    if (policy === "noeviction")
        return;
    if (policy === undefined && report.assumeNoEviction === true)
        return;
    throw new RedisStoreEvictableError(store, policy, refusal, policy === undefined && report.refusal !== undefined ? { cause: report.refusal } : undefined);
}
