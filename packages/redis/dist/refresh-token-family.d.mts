import { type AdapterBuilder, type RefreshTokenFamilyStore } from "@o3co/auth-provider-core";
import type { RefreshTokenFamilyClient } from "./clients.mjs";
/**
 * Options for createRedisRefreshTokenFamilyStore.
 */
export interface RedisRefreshTokenFamilyStoreOptions {
    readonly client: RefreshTokenFamilyClient;
    readonly keyPrefix: string;
    /**
     * Maximum CAS retry attempts before throwing
     * RefreshTokenStorageError({ reason: "conflict-exhausted" }). Default 3
     * matches A3 §7.2 recommendation.
     */
    readonly casRetryLimit?: number;
}
/**
 * Redis-backed RefreshTokenFamilyStore.
 *
 * Storage shape: each family is stored as a single Redis string key
 * `${keyPrefix}${familyId}` whose value is a JSON serialisation of the
 * RefreshTokenFamily aggregate, with a TTL set via the SET command's PX
 * argument. JSON serialisation (rather than a Redis hash) keeps the
 * RefreshTokenFamilyClient surface narrow (no HSET/HGETALL needed) and
 * matches A1's single-key SET-NX pattern.
 *
 * Atomicity:
 *   - registerFamily uses `SET key value PX ttlMs NX` — atomic insert-only,
 *     same primitive as A1's ChallengeStore.issue.
 *   - updateFamily uses single-key WATCH/GET/MULTI/SET/EXEC — the canonical
 *     Redis CAS primitive. Single-key only (not a multi-key transaction).
 *
 * Connection isolation: WATCH is connection-scoped in Redis, so each
 * `updateFamily` call obtains its own connection via `client.duplicate()`
 * (disposed via `await using` on function exit). Within that connection
 * the CAS retry loop reuses the SAME duplicate across attempts — Redis
 * auto-clears WATCH on every EXEC, so a fresh `WATCH` at the top of
 * each iteration sets up a clean CAS context without churning
 * connections per retry (1 connection per call, not per attempt).
 *
 * The base `client` is used only for non-WATCH ops (registerFamily,
 * findFamily) where command serialisation is sufficient.
 *
 * Per A3 §7.2.
 */
export declare function createRedisRefreshTokenFamilyStore(opts: RedisRefreshTokenFamilyStoreOptions): RefreshTokenFamilyStore;
/**
 * AdapterFactory builder for runtime-config-driven backend selection
 * (composition pattern §8.4). Consumer registers via:
 *   factory.register("redis", redisRefreshTokenFamilyStoreBuilder);
 * Then calls:
 *   factory.create({ type: "redis", client, keyPrefix: "rtfam:", casRetryLimit: 3 });
 */
export declare const redisRefreshTokenFamilyStoreBuilder: AdapterBuilder<RefreshTokenFamilyStore>;
/**
 * `defineModule` manifest for the Redis RefreshTokenFamilyStore. Static
 * composition path (A3 §8.1). For runtime-config-driven selection use the
 * builder above.
 *
 * configSchema: top-level key `redisRefreshTokenFamilyStore`
 * (module-namespaced per master roadmap §3.5).
 */
export declare const redisRefreshTokenFamilyStoreModule: import("@o3co/auth-provider-core").Module;
//# sourceMappingURL=refresh-token-family.d.mts.map