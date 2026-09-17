import type { SessionRPRegistryClient } from "../clients.mjs";
export interface RedisSidHashOptions {
    readonly client: SessionRPRegistryClient;
    readonly keyPrefix: string;
}
export interface RedisSidHash {
    setField(sid: string, id: string, jsonValue: string, expiresAt: Date): Promise<void>;
    listValues(sid: string): Promise<string[]>;
    removeBySid(sid: string): Promise<void>;
}
/**
 * Private redis helper used by `SessionRPRegistry`. Single-key HSET +
 * PEXPIREAT pipeline keyed by `${keyPrefix}${sid}`. Per A4 §7.2.1.
 *
 * **HASH-keyed-by-element-id rationale**: SADD-of-JSON cannot dedup by
 * `clientId` when other RP fields change (different bytewise JSON for the
 * same logical clientId would create duplicate entries). HSET dedups on
 * field name = `clientId`, semantically correct for RP upsert.
 *
 * **TTL contract**: callers MUST pass `session.expiresAt`. PEXPIREAT is
 * NOT monotonic; passing a different timestamp across writes for the same
 * sid would shorten the TTL. This restriction is enforced structurally:
 * `UserSession.expiresAt` is post-create immutable per A4 §5.1, so the
 * only legal `expiresAt` is the session-create-time value.
 *
 * **Writes after expiry are no-op**: prevents zombie keys with no TTL.
 */
export declare function createRedisSidHash(opts: RedisSidHashOptions): RedisSidHash;
//# sourceMappingURL=redisSidHash.d.mts.map