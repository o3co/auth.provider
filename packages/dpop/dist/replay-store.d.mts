/**
 * DPoP proof replay protection store. See Wave 2 Phase 2 spec §5.5.
 *
 * Atomic `seen(jti, jkt, ttl)` returns true when the (jti, jkt) pair
 * was already seen within the replay window; false when not seen, AND
 * atomically records the pair with the given TTL.
 *
 * Atomicity is REQUIRED — a two-step "check then mark" pattern would
 * leave a TOCTOU window. In-memory implementations rely on JS single-
 * threaded execution; clustered deployments MUST use a Redis backend
 * (the in-memory adapter is dev-only).
 */
export interface DPoPReplayStore {
    /**
     * @param jti          DPoP proof JWT-ID (RFC 9449 §4.2 `jti` claim).
     * @param jkt          RFC 7638 SHA-256 thumbprint of the proof JWK —
     *                     pair-scopes the key so the same `jti` reissued
     *                     under a different key is NOT a replay.
     * @param ttlSeconds   Replay window in seconds; MUST be a positive
     *                     finite number. Implementations SHOULD throw
     *                     `RangeError` on non-positive values rather than
     *                     silently emitting an expired entry.
     * @returns `true` when this (jti, jkt) pair was already seen within
     *          the replay window; `false` when this call is the first
     *          observation (and the pair has been atomically recorded).
     */
    seen(jti: string, jkt: string, ttlSeconds: number): Promise<boolean>;
}
//# sourceMappingURL=replay-store.d.mts.map