import type { AccessTokenDenylist } from "./types.mjs";
/**
 * In-process Map-backed AccessTokenDenylist.
 *
 * GC is lazy (per-operation cleanup of expired entries on `has`). No background
 * sweep. Idempotent `add`: a second call for the same jti overwrites the
 * expiry timestamp.
 */
export declare function createMemoryAccessTokenDenylist(): AccessTokenDenylist;
//# sourceMappingURL=memory.d.mts.map