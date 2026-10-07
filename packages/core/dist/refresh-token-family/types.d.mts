/**
 * Refresh-token family aggregate value type.
 *
 * The single-active-jti-per-family invariant is encoded structurally:
 * `activeJti` is always a non-empty string. The aggregate is registered
 * atomically with its initial activeJti via `registerFamily` and remains
 * a string field for the family's lifetime; rotation updates the value
 * (via `updateFamily`); revocation does NOT clear it (a revoked family
 * retains the jti that was active when it was revoked, for audit purposes).
 *
 * `expiresAtMs` stores the expiry as a Unix epoch millisecond timestamp
 * (number). Using epoch-ms eliminates the Date mutation surface that
 * Object.freeze cannot defend against — a caller holding a reference to
 * a Date object could call setTime(0) and corrupt store state.
 *
 * Per A3 §5.1.
 */
export interface RefreshTokenFamily {
    readonly familyId: string;
    readonly activeJti: string;
    readonly revoked: boolean;
    readonly expiresAtMs: number;
}
/**
 * Result of a `RefreshTokenFamilyStore.updateFamily` call.
 *
 * - `committed`: CAS commit succeeded. `family` is the newly persisted state.
 * - `not-found`: the family does not exist (or expired). The updater was
 *   NOT invoked.
 * - `aborted`: the updater returned null (caller signalled no-op). No state
 *   change.
 *
 * Per A3 §5.1.
 */
export type RefreshTokenFamilyUpdateResult = {
    readonly outcome: "committed";
    readonly family: RefreshTokenFamily;
} | {
    readonly outcome: "not-found";
} | {
    readonly outcome: "aborted";
};
/**
 * Storage primitive for refresh-token families.
 *
 * Theme A: this interface exposes only single-key atomic primitives. The
 * 4-outcome rotation ceremony (`rotated | replayed | revoked |
 * unknown_family`) is composed in the wrapper layer (`RefreshTokenFamilyRotation`),
 * NOT classified by the adapter.
 *
 * Per A3 §5.1.
 */
export interface RefreshTokenFamilyStore {
    readonly kind: string;
    /**
     * Atomically register a new refresh-token family.
     *
     * MUST throw `RefreshTokenStorageError({ reason: "duplicate-family" })`
     * if a family with the same `familyId` already exists (regardless of
     * revoke / TTL state — duplicate `familyId` indicates RNG collision or
     * programming bug).
     *
     * MUST throw `RefreshTokenStorageError({ reason: "expired-at-issue" })`
     * if `family.expiresAtMs <= now()` at call time.
     *
     * Concurrency contract: N concurrent calls with the same `familyId`
     * MUST result in exactly one success and N-1 throws of
     * `"duplicate-family"`.
     *
     * Per A3 §5.1.
     */
    registerFamily(family: RefreshTokenFamily): Promise<void>;
    /**
     * Non-mutating lookup of the family aggregate.
     *
     * Returns `null` if no record exists OR the record is expired (lazy GC).
     *
     * Per A3 §5.1.
     */
    findFamily(familyId: string): Promise<RefreshTokenFamily | null>;
    /**
     * Atomically read-modify-write the family aggregate.
     *
     * Adapter performs:
     *   1. Read current family state (or null if non-existent).
     *   2. Invoke `updater(current)`.
     *   3. If updater returns a new RefreshTokenFamily, attempt atomic CAS
     *      commit using an adapter-internal version token (NOT exposed in
     *      RefreshTokenFamily — adapters may use a separate version field,
     *      ETag, Redis WATCH, or any backend-native CAS primitive).
     *   4. On CAS conflict, retry by re-reading state and re-invoking updater
     *      up to a bounded retry limit; on exhaustion, throws
     *      `RefreshTokenStorageError({ reason: "conflict-exhausted" })`.
     *   5. If updater returns null, abort without state change (no retry).
     *
     * Updater contract (NORMATIVE):
     *   - Updater is invoked with the current RefreshTokenFamily value (NEVER
     *     null — when the family does not exist, the adapter returns
     *     `{ outcome: "not-found" }` directly without invoking the updater).
     *   - Updater MUST be a pure function (no observable side effects, no
     *     async I/O). Adapter MAY invoke updater multiple times due to CAS
     *     retry; consumers MUST NOT rely on exactly-once invocation.
     *   - Updater MUST NOT mutate the input RefreshTokenFamily (it is
     *     `readonly` at the type level; runtime adapters MAY freeze it
     *     additionally as defence-in-depth).
     *   - Updater MUST return either a new RefreshTokenFamily (commit) or
     *     null (abort).
     *   - Updater MAY use a closure-captured variable to communicate the
     *     abort reason to the caller; the closure is reset at the top of
     *     each updater invocation. This is the wrapper pattern used by
     *     `createRefreshTokenFamilyRotation` to translate "aborted"
     *     results into "replayed" or "revoked" outcomes.
     *   - Updater MUST NOT return a RefreshTokenFamily whose `expiresAtMs` is
     *     `<= now()`. Both adapters fail-closed by throwing
     *     `RefreshTokenStorageError({ reason: "expired-at-issue" })` —
     *     symmetric with `registerFamily` and prevents committing a
     *     dead-on-arrival entry. Callers shrinking TTL during rotation
     *     should compute the new `expiresAtMs` from a forward window.
     *
     * Return value:
     *   - `{ outcome: "committed", family }` — CAS succeeded; family is the
     *     newly-persisted state.
     *   - `{ outcome: "not-found" }` — family did not exist; updater not
     *     invoked.
     *   - `{ outcome: "aborted" }` — updater returned null; no state change.
     *
     * Per A3 §5.1.
     */
    updateFamily(familyId: string, updater: (current: RefreshTokenFamily) => RefreshTokenFamily | null): Promise<RefreshTokenFamilyUpdateResult>;
}
/**
 * 4-outcome union for the rotation ceremony.
 *
 * - `rotated`: family exists, not revoked, previousJti matched the active
 *   jti, CAS commit succeeded with newJti.
 * - `replayed`: family exists, not revoked, but previousJti did NOT match
 *   the active jti (e.g., previous jti was already rotated out). Caller
 *   MUST reject and treat as a replay-attack audit signal.
 * - `revoked`: family exists but its `revoked` flag is set. Caller MUST
 *   reject and treat as a logout-cascade signal.
 * - `unknown_family`: no family record matches. Caller policy decides
 *   whether to accept or reject — the v0.4.x default was accept; the
 *   v0.5.0 default is configurable via `oauth.refreshToken.unknownFamilyPolicy`
 *   (owned by the oauth grant handler module, NOT this wrapper).
 *
 * Per A3 §5.2.
 */
export type RefreshTokenFamilyRotationOutcome = {
    readonly outcome: "rotated";
} | {
    readonly outcome: "replayed";
} | {
    readonly outcome: "revoked";
} | {
    readonly outcome: "unknown_family";
};
/**
 * Rotation ceremony wrapper. Composes `RefreshTokenFamilyStore.updateFamily`
 * into the 4-outcome union. The default impl
 * (`createRefreshTokenFamilyRotation`) is shipped as
 * `defaultRefreshTokenFamilyRotationModule`; consumers needing custom policy
 * (audit-emitting rotation, grace-period rotation, etc.) replace the
 * module with their own.
 *
 * Per A3 §5.2.
 */
export interface RefreshTokenFamilyRotation {
    /**
     * Register a new refresh-token family at initial issue time (e.g., from
     * the authorization_code grant handler).
     *
     * Delegates to `RefreshTokenFamilyStore.registerFamily(family)` after
     * constructing a `RefreshTokenFamily` aggregate from the inputs.
     *
     * MUST throw `RefreshTokenStorageError({ reason: "duplicate-family" })`
     * if `familyId` already exists. MUST throw
     * `RefreshTokenStorageError({ reason: "expired-at-issue" })` if
     * `expiresAtMs <= now()`.
     *
     * Use this for **initial issue**, not for rotation.
     */
    register(newJti: string, familyId: string, expiresAtMs: number): Promise<void>;
    /**
     * Compose the storage primitive into the 4-outcome rotation ceremony.
     *
     * Normal flow does NOT throw `RefreshTokenStorageError` or any other
     * domain error — the discriminated outcome union IS the complete
     * return contract. System errors (Redis network failure, CAS conflict
     * exhaustion) propagate as native errors / `RefreshTokenStorageError(
     * { reason: "conflict-exhausted" })`.
     *
     * Per A3 §5.2.
     */
    rotate(previousJti: string, newJti: string, familyId: string, expiresAtMs: number): Promise<RefreshTokenFamilyRotationOutcome>;
}
/**
 * Family revocation wrapper. Distinct from rotation per Theme B
 * (per `feedback_split_interface_unless_responsibility_intersects`):
 * different triggers (admin operation / logout cascade vs. normal
 * authentication flow), different callers, different expected outcomes.
 *
 * Idempotent revoke + read-only check. The default impl
 * (`createRefreshTokenFamilyRevocation`) ships as
 * `defaultRefreshTokenFamilyRevocationModule`.
 *
 * Per A3 §5.3.
 */
export interface RefreshTokenFamilyRevocation {
    /**
     * Mark a refresh-token family as revoked. Idempotent:
     *   - family exists, not revoked → set revoked: true, commit
     *   - family exists, already revoked → no-op success
     *   - family does not exist → no-op success (target was already GC'd or
     *     never existed; admin tools / logout cascade should not fail in
     *     that case)
     *
     * Per A3 §5.3.
     */
    revokeFamily(familyId: string): Promise<void>;
    /**
     * Read-only check whether a family is revoked.
     *
     * Returns `true` iff a family record exists AND its `revoked` flag is
     * set. Returns `false` if the family does not exist OR is not revoked.
     *
     * Hot-path operation (called per request from token-validation routes).
     *
     * Per A3 §5.3.
     */
    isFamilyRevoked(familyId: string): Promise<boolean>;
}
declare module "@o3co/auth-provider-core" {
    interface ComponentMap {
        readonly refreshTokenFamilyStore?: RefreshTokenFamilyStore;
        readonly refreshTokenFamilyRotation?: RefreshTokenFamilyRotation;
        readonly refreshTokenFamilyRevocation?: RefreshTokenFamilyRevocation;
    }
}
//# sourceMappingURL=types.d.mts.map