/**
 * What a Redis server says about keeping what it is written, for the stores' eviction gate and
 * the MFA modules' persistence notices, with the operator's `assumeNoEviction` assertion beside
 * it. A reply that refuses a question leaves that part unread; any other failure rejects.
 */
import type { Redis } from "ioredis";
import type { RedisDurability } from "../clients.mjs";
/** What a client's durability report carries beside what the server says. */
export interface IoredisDurabilityOptions {
    /**
     * The operator's assertion that the server runs `maxmemory-policy noeviction`, reported as
     * `RedisDurability.assumeNoEviction`. Set it only for a server that will not say (`INFO` and
     * `CONFIG` refused or renamed) and is known to run `noeviction`: a policy the server reports
     * always decides. Default `false`.
     */
    readonly assumeNoEviction?: boolean;
}
/**
 * What `io`'s server says about keeping what it is written. The policy from `INFO memory`
 * (`CONFIG GET maxmemory-policy` only where INFO does not say, so a managed server that blocks
 * `CONFIG` still reports it); AOF from `INFO persistence`; `CONFIG GET save` only when AOF is
 * off, to tell RDB snapshots from none. A refused question leaves its part unread; a policy
 * reply it cannot read either way (another shape, or INFO naming the policy twice, differently)
 * throws, as any other failure does, and is the caller's. `assumeNoEviction` is reported only
 * when set.
 */
export declare function redisDurability(io: Redis, options?: IoredisDurabilityOptions): Promise<RedisDurability>;
//# sourceMappingURL=durability.d.mts.map