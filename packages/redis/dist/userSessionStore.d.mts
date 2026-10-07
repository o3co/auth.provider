import type { UserSessionStore } from "@o3co/auth-provider-core";
import type { UserSessionStoreClient } from "./clients.mjs";
export interface RedisUserSessionStoreOptions {
    readonly client: UserSessionStoreClient;
    readonly keyPrefix: string;
}
/**
 * Redis-backed UserSessionStore. Per A4 §5.1 + §7.2.
 *
 * Storage shape: each session is a single Redis string key
 * `${keyPrefix}${sid}` whose value is a JSON-encoded envelope, with TTL
 * applied via SET PX. The v0.4.x lost-update window is **structurally
 * absent**: this adapter exposes only `create` (atomic SET NX),
 * `get`, `delete`. No GET → mutate → SET path exists at the v0.5.0
 * `UserSessionStore` interface level; claims update is deferred post-publish.
 *
 * Atomicity:
 *  - `create` uses SET NX PX — atomic insert-only, same primitive as A1
 *    ChallengeStore.issue and A3 registerFamily.
 *  - `get` is a read-only GET (no PTTL round-trip needed; expiresAtMs is
 *    embedded in the JSON envelope and the SET PX TTL eventually deletes
 *    the key).
 *  - `delete` is single-key DEL.
 */
export declare function createRedisUserSessionStore(opts: RedisUserSessionStoreOptions): UserSessionStore;
//# sourceMappingURL=userSessionStore.d.mts.map