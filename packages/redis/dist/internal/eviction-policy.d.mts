/**
 * The one eviction gate every store whose keys must stay until they expire
 * passes before its factory hands it out: the attempt counter, the session
 * lifecycle store, the federation token store, the two MFA stores, the
 * stores that hold revocation state — the access-token denylist, subject
 * revocation and the refresh-token family store — and the replay seen-set.
 *
 * - A policy the server reports as `noeviction` passes.
 * - Any other policy it reports refuses, known or not.
 * - A policy it does not report refuses, unless the client reports the
 *   operator's `assumeNoEviction` assertion. A reported policy always decides
 *   over the assertion.
 * - A server that cannot answer rejects, as any store outage at boot does.
 *
 * Boot carries the refusal as the `cause` of a `provides-factory-failed`
 * BootError naming the module.
 */
import type { RedisDurability } from "../clients.mjs";
/** What a store's refusal says beside the policy. */
export interface EvictableRefusal<R extends string> {
    /** The refusal's `reason`, also named at the end of its message. */
    readonly reason: R;
    /** What the store keeps, and what losing it to an eviction would do. */
    readonly holds: string;
}
/**
 * The refusal of a server whose `maxmemory-policy` is not known to be
 * `noeviction`. `maxmemoryPolicy` is the policy the server reported, or
 * `undefined` when it could not be read; `cause` is then the reply that
 * refused the question, if one did. It quotes the server's policy and
 * nothing else.
 */
export declare class RedisStoreEvictableError<R extends string = string> extends Error {
    readonly reason: R;
    readonly maxmemoryPolicy: string | undefined;
    constructor(store: string, maxmemoryPolicy: string | undefined, refusal: EvictableRefusal<R>, options?: ErrorOptions);
}
/**
 * Reads the policy once through `durability` and resolves only when it is
 * `noeviction`, or is unread and asserted (`assumeNoEviction`). Otherwise it
 * throws a {@link RedisStoreEvictableError} for `store`; a failure to read
 * rejects as it is.
 */
export declare function requireNoEviction<R extends string>(store: string, durability: () => Promise<RedisDurability>, refusal: EvictableRefusal<R>): Promise<void>;
//# sourceMappingURL=eviction-policy.d.mts.map