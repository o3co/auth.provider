import { type AdapterBuilder, type ReplaySeenSet } from "@o3co/auth-provider-core";
import type { ReplaySeenSetClient } from "./clients.mjs";
/**
 * Options for createRedisReplaySeenSet.
 */
export interface RedisReplaySeenSetOptions {
    readonly client: ReplaySeenSetClient;
    readonly keyPrefix: string;
}
/**
 * Redis-backed ReplaySeenSet. Two ops are 1-Redis-op primitives:
 *   - markSeen: SET <prefix><key> "1" PX <ttlMs> NX → "OK" | null
 *   - contains: EXISTS <prefix><key> → 1 | 0
 *
 * Note: markSeen returns true on "OK" (= first observation), false on null
 * (= already present, replay). This is the ONE difference from
 * ChallengeStore.issue which throws on duplicate — markSeen returns the
 * boolean because replays are an EXPECTED outcome of the wrapper, not an
 * error.
 *
 * No-TTL key defensive handling: contains treats a no-TTL key as present
 * (fail-closed for replay detection — asymmetric with ChallengeStore.find
 * which treats no-TTL as null for lifecycle fail-closed). The asymmetry
 * minimises false-positive "consumed" outcomes; sweeps surface as
 * conservative "replayed".
 *
 * Per A1 §7.2.
 */
export declare function createRedisReplaySeenSet(opts: RedisReplaySeenSetOptions): ReplaySeenSet;
/**
 * AdapterFactory builder for runtime-config-driven backend selection
 * (composition pattern §8.4). Consumer registers via:
 *   factory.register("redis", redisReplaySeenSetBuilder);
 * Then calls:
 *   factory.create({ type: "redis", client, keyPrefix: "replay:" });
 */
export declare const redisReplaySeenSetBuilder: AdapterBuilder<ReplaySeenSet>;
/**
 * `defineModule` manifest for the Redis ReplaySeenSet. Static composition
 * path (§8.1). For runtime-config-driven selection use the builder above.
 *
 * configSchema: top-level key `redisReplaySeenSet` (module-namespaced per
 * master roadmap §3.5 — NO bare `keyPrefix` top-level key).
 */
export declare const redisReplaySeenSetModule: import("@o3co/auth-provider-core").Module;
//# sourceMappingURL=replay-seen-set.d.mts.map