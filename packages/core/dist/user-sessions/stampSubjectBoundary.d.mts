/**
 * How a subject revocation stamps its boundary: so that it covers everything
 * minted before the write took effect, not only what was minted before the
 * stamp time was read.
 */
/** One boundary write: `revokeBefore`, or `revokeSessionsBefore`, bound to its subject. */
export type BoundaryWrite = (before: Date, expiresAt: Date) => Promise<void>;
/** What {@link stampSubjectBoundary} did. */
export interface BoundaryStamp {
    /** Whether any write took effect: a boundary is in force. */
    readonly written: boolean;
    /**
     * Why the boundary may not cover the in-flight issuance, if it may not:
     * the first write threw (`1`), or a later one threw or none settled (`2`).
     */
    readonly failure?: {
        readonly error: unknown;
        readonly stamp: 1 | 2;
    };
}
/**
 * Writes the boundary at `now()` plus {@link SETTLED_WRITE_MS}, and once that
 * write has taken effect, writes it again from a fresh `now()`, each lasting
 * `ttlMs` past the boundary; then again while the last write did not settle,
 * up to {@link MAX_STAMPS} writes in all.
 *
 * A write settles when it commits within {@link SETTLED_WRITE_MS} on the
 * monotonic clock (`elapsed`) and the wall clock moved forward by no more
 * than that across it: a token minted before it committed then predates the
 * boundary it wrote. A store keeps the later of two boundaries (the port's
 * rule), so no stamp moves the boundary back. The second is tried even when
 * the first throws: a write can fail after it committed.
 *
 * A wall clock seen going back during the stamping (a reading lower than an
 * earlier one, or one fallen behind the monotonic clock's progress by more
 * than {@link CLOCK_AGREEMENT_MS}) ends it as a failure of the second stamp,
 * whatever the writes did: a token minted before the step can postdate every
 * boundary read after it.
 */
export declare function stampSubjectBoundary(write: BoundaryWrite, now: () => number, ttlMs: number, elapsed?: () => number): Promise<BoundaryStamp>;
//# sourceMappingURL=stampSubjectBoundary.d.mts.map