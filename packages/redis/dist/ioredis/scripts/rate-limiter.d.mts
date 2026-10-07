/**
 * The rate limiter's script: a counter's increment and its expiry in one step.
 */
/**
 * Rate-limit counter increment, atomic with its expiry: `INCR` then a separate `EXPIRE` can
 * leave the key with no TTL, and a counter that never resets 429s its client forever.
 *
 * The expiry is set whenever the key has none (`TTL` < 0), not only on the first hit, so a key
 * left without a TTL is repaired. An existing expiry is left alone, so steady traffic cannot
 * hold the window open.
 *
 * Returns `{count, pttl}`, both read in the script so they describe one counter state. The
 * limiter turns `pttl` into `resetAt`, the 429's `Retry-After`.
 */
export declare const LUA_INCREMENT_WITH_TTL: string;
//# sourceMappingURL=rate-limiter.d.mts.map