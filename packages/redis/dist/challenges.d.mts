import { type AdapterBuilder, type ChallengeStore } from "@o3co/auth-provider-core";
import type { ChallengeStoreClient } from "./clients.mjs";
/**
 * Options for createRedisChallengeStore.
 */
export interface RedisChallengeStoreOptions {
    readonly client: ChallengeStoreClient;
    readonly keyPrefix: string;
}
/**
 * Redis-backed ChallengeStore. All three ops are 1-Redis-op atomic primitives:
 *   - issue:   SET <prefix><key> "1" PX <ttlMs> NX  → "OK" | null
 *   - find:    PTTL <prefix><key>                   → -2 absent, -1 no-TTL, ≥0 ms
 *   - consume: DEL <prefix><key>                    → count deleted
 *
 * No Lua, no MULTI/EXEC — explicitly rejected by Theme A (the entire reason
 * A1 split into primitives is to NOT need transaction blocks).
 *
 * No-TTL defensive handling: if PTTL returns -1 (key exists without expiry,
 * e.g. external mutation), `find` returns null (fail-closed for lifecycle).
 *
 * Per A1 §7.2.
 */
export declare function createRedisChallengeStore(opts: RedisChallengeStoreOptions): ChallengeStore;
/**
 * AdapterFactory builder for runtime-config-driven backend selection
 * (composition pattern §8.4). Consumer registers via:
 *   factory.register("redis", redisChallengeStoreBuilder);
 * Then calls:
 *   factory.create({ type: "redis", client, keyPrefix: "chal:" });
 */
export declare const redisChallengeStoreBuilder: AdapterBuilder<ChallengeStore>;
/**
 * `defineModule` manifest for the Redis ChallengeStore. Static composition
 * path (§8.1). For runtime-config-driven selection use the builder above.
 *
 * configSchema: top-level key `redisChallengeStore` (module-namespaced per
 * master roadmap §3.5 — NO bare `keyPrefix` top-level key).
 */
export declare const redisChallengeStoreModule: import("@o3co/auth-provider-core").Module;
//# sourceMappingURL=challenges.d.mts.map