/**
 * Atomic replay-detection primitive. Records (scope, key) pairs and answers
 * "has this been seen before?" without amplifying storage on attacker probes
 * (the read path is `contains`, which never writes).
 *
 * Per A1 §5.2 (lines 146-177). Concurrency contract:
 *   - markSeen(scope, key, expiresAtMs): N parallel for same key → exactly 1
 *     returns true ("fresh, this call wrote"), N-1 return false ("replay").
 *   - contains(scope, key): read-only; atomicity vs concurrent markSeen NOT
 *     required (the wrapper layer queries contains only when find returned
 *     null, so the read-vs-write race window is benign).
 *
 * markSeen MUST throw ChallengeStorageError({ reason: "expired-at-issue" })
 * for expiresAtMs <= now(). contains MUST NOT throw domain errors.
 *
 * `contains` is the security-friendly disambiguation primitive — attacker
 * probing via ChallengeCeremony.consume hits `contains` (read-only, zero
 * storage amplification) rather than `markSeen` (which would amplify
 * storage proportional to probe rate).
 *
 * The no-throws contract on `contains` is enforced by the shared adapter
 * contract test suite (`__tests__/adapters.contract.mts`, established in
 * Task 4 and re-imported by the Redis adapter test in Task 12).
 */
export interface ReplaySeenSet {
    readonly kind: string;
    /**
     * @returns true iff this call wrote (= first observation = fresh).
     *          false iff (scope, key) already had a non-expired record (= replay).
     * @throws ChallengeStorageError({ reason: "expired-at-issue" }) for
     *   expiresAtMs <= now().
     */
    markSeen(scope: string, key: string, expiresAtMs: number): Promise<boolean>;
    /**
     * Read-only check. Returns true iff a non-expired record exists.
     * Does NOT throw domain errors.
     */
    contains(scope: string, key: string): Promise<boolean>;
}
declare module "@o3co/auth-provider-core" {
    interface ComponentMap {
        readonly replaySeenSet?: ReplaySeenSet;
    }
}
//# sourceMappingURL=types.d.mts.map