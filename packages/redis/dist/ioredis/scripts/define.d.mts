/**
 * A script, its digest, and whether the server is expected to hold it, for `runScript`'s
 * EVALSHA-first path.
 */
export interface CachedScript {
    readonly source: string;
    /**
     * SHA-1 of `source`: Redis keys its script cache by it, so the digest is what `SCRIPT LOAD`
     * would return, without that round trip.
     */
    readonly sha: string;
    /** `true` lets the next run use `EVALSHA`; a `NOSCRIPT` clears it and `EVAL` sets it again. */
    cached: boolean;
}
export declare const defineScript: (source: string) => CachedScript;
//# sourceMappingURL=define.d.mts.map