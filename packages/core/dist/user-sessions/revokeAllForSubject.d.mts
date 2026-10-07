import type { Logger } from "../logging/Logger.mjs";
import type { SubjectRevocation, SubjectSessionIndex } from "./types.mjs";
/**
 * Per-session teardown, supplied by the caller.
 *
 * `@o3co/auth-provider-oauth` owns `cascadeLogout`, which performs the
 * carefully ordered four-step store cascade for one session. Core cannot
 * import it without inverting the package dependency, so the caller passes it
 * in and this helper stays responsible only for *which* sessions and *in what
 * order relative to the watermark*.
 */
export type CascadeSession = (sid: string) => Promise<{
    readonly ok: boolean;
}>;
/**
 * The two optional slots this helper consumes. Named rather than free strings
 * so a caller can branch on them, and so the set is greppable when #321 adds
 * the Redis adapters that fill them.
 */
export type RevokeAllForSubjectCapability = "subjectSessionIndex" | "subjectRevocation";
/**
 * One store call that was attempted and threw.
 *
 * Distinct from {@link RevokeAllForSubjectResult.unavailable}, and the
 * distinction matters operationally: `unavailable` is a composition gap fixed
 * by wiring a module, a failure here is a backend outage fixed by retrying.
 * Collapsing them would send an operator to the wrong runbook.
 */
export interface RevokeAllForSubjectFailure {
    readonly capability: RevokeAllForSubjectCapability;
    readonly operation: "revokeBefore" | "listSids" | "removeSid";
    /** The session the failing call concerned, for the per-session operations. */
    readonly sid?: string;
    readonly error: unknown;
}
export interface RevokeAllForSubjectOptions {
    readonly subject: string;
    /**
     * How long the watermark must outlive. Size it to the longest-lived
     * **refresh token**, not the access token: the refresh grant consults the
     * watermark as the backstop for a family revocation that did not complete,
     * so a watermark that expires first takes the backstop with it. See the TTL
     * contract on {@link SubjectRevocation}.
     */
    readonly watermarkTtlMs: number;
    readonly cascadeSession: CascadeSession;
    readonly subjectSessionIndex?: SubjectSessionIndex;
    readonly subjectRevocation?: SubjectRevocation;
    readonly logger?: Logger;
    /** Injectable for tests; defaults to `Date.now`. */
    readonly now?: () => number;
}
export interface RevokeAllForSubjectResult {
    /** Session ids whose cascade completed. */
    readonly sessionsRevoked: readonly string[];
    /** Session ids whose cascade failed — still live, safe to retry. */
    readonly sessionsFailed: readonly string[];
    /** Whether the access-token watermark was written. */
    readonly tokensRevoked: boolean;
    /**
     * Capabilities that were not wired, and therefore not exercised.
     *
     * Load-bearing rather than informational: the caller invokes this
     * immediately after writing a new credential, and a bare success while
     * nothing was revoked is the worst outcome this helper could produce. A
     * non-empty list means the revocation was **partial** and the caller must
     * treat it as a failure.
     */
    readonly unavailable: readonly RevokeAllForSubjectCapability[];
    /**
     * Store calls that were wired, attempted, and threw. Empty on the happy
     * path. See {@link RevokeAllForSubjectFailure} for why this is separate
     * from `unavailable`.
     */
    readonly failures: readonly RevokeAllForSubjectFailure[];
    /**
     * Everything that was asked for actually happened.
     *
     * The one field a caller has to check. Deriving it from the other four is a
     * four-way condition every integrator would have to get right independently,
     * and getting it wrong reads as a successful revocation — so it is computed
     * here once.
     */
    readonly complete: boolean;
}
/**
 * Invalidate everything this authorization server issued for one subject
 * (#296).
 *
 * The Store owns the credential-change flow — issuing the reset token,
 * delivering it, writing the new password. What it cannot do from outside is
 * kill the sessions and tokens already minted against the old credential, and
 * that is this function's whole job. The service calls it immediately after
 * the credential write.
 *
 * **The watermark is written first, before any session is cascaded.** Two
 * reasons, and both are the difference between working and not:
 *
 *   - A refresh rotation or a concurrent login on another replica can mint a
 *     token *during* the cascade loop. Enumerating sessions first and writing
 *     the watermark afterwards leaves that token outside both mechanisms —
 *     its session was not in the list, and its `iat` predates the watermark
 *     that had not yet been written.
 *   - On partial failure the safe direction is "tokens dead, some sessions
 *     perhaps alive", not the reverse. A live session with no usable token
 *     can be cleaned up on retry; a live token is the thing being revoked.
 *
 * **This never throws.** The caller has already written the new credential and
 * has no undo, so an exception would replace a partial result it could act on
 * — retry these sids, alert on that outage — with nothing at all. Every store
 * call is therefore reported rather than propagated, and `complete` is the one
 * field a caller has to check.
 *
 * Does **not** fix #276 — the local logout route still does not run the
 * cascade for its own session. This builds on `cascadeLogout`, which is
 * complete; the gap there is that one caller does not invoke it.
 */
export declare function revokeAllForSubject(opts: RevokeAllForSubjectOptions): Promise<RevokeAllForSubjectResult>;
//# sourceMappingURL=revokeAllForSubject.d.mts.map