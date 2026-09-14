import type { SessionRPRegistry } from "@o3co/auth-provider-core";
import type { SessionRPRegistryClient } from "./clients.mjs";
export interface RedisSessionRPRegistryOptions {
    readonly client: SessionRPRegistryClient;
    readonly keyPrefix: string;
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
export declare function createRedisSessionRPRegistry(opts: RedisSessionRPRegistryOptions): SessionRPRegistry;
//# sourceMappingURL=sessionRPRegistry.d.mts.map