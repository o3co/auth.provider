/**
 * Subject-wide revocation with an operator's policy attached (#593, D13).
 *
 * `revokeAllForSubject` is a function a Store calls with every store it has
 * and a TTL it has to size correctly. This is the same work behind a component
 * a module wires once: the caller names a subject and, at most, what should
 * happen to their federation grants.
 *
 * **Keeping is the reason it exists.** A subject-wide revocation exists for
 * two very different events. A user changing their password wants their
 * sessions gone; whether the calendar integration a backend has been using for
 * a month should die with it is a question about residual access, and the
 * answer differs per deployment. So the allowance is configuration
 * (`federationGrants.allowKeepOnSubjectRevocation`, default `false`) rather
 * than an argument: a flag on the call would let any caller decide it, which
 * is not what an operator policy is.
 *
 * What the caller asks for and what happened are both reported, because they
 * can differ: a `"keep"` refused by policy is carried out as a full
 * revocation. See {@link SubjectRevocationReport.complete} for the sentence
 * that matters operationally.
 */
import type { FederationGrantAuditEvent } from "../federation-grants/retrieve.mjs";
import type { FederationGrantStore } from "../federation-grants/store.mjs";
import type { Logger } from "../logging/Logger.mjs";
import { type CascadeSession, type RevokeAllForSubjectResult } from "./revokeAllForSubject.mjs";
import { type SubjectRevocation, type SubjectSessionIndex } from "./types.mjs";
/** What should become of the subject's federation grants. */
export type FederationGrantDisposition = "revoke" | "keep";
export interface SubjectRevocationRequest {
    readonly subject: string;
    /** Defaults to `"revoke"`. `"keep"` is a request, not an instruction — see the module note. */
    readonly federationGrants?: FederationGrantDisposition;
    /**
     * While keeping, end the grants consented at or after this instant anyway.
     *
     * What it is for: a compromise an operator can date. Everything the subject
     * agreed to from that moment on may have been agreed to by somebody else,
     * and is ended; what they agreed to before it is what "keep" keeps. The
     * comparison is against `consent.at`, is inclusive, and is not widened by
     * any clock skew — an operator's instant is not a guess.
     *
     * Ignored when the applied disposition is `"revoke"`: everything is already
     * being ended.
     */
    readonly revokeGrantsConsentedSince?: Date;
}
export interface SubjectRevocationReport extends RevokeAllForSubjectResult {
    /**
     * Grants that were kept, and whose renewal in flight was ended (D13).
     *
     * Empty on the revoking path, where there is nothing to keep a renewal for.
     */
    readonly grantsRetired: readonly string[];
    /**
     * Grants that were **kept**, and whose renewal could not be ended.
     *
     * Separate from `grantsFailed`, and the separation is the point: that
     * field means "the revocation write threw — still live, safe to retry",
     * and a Store that read these two as one would retry by revoking grants
     * the operator's policy had just chosen to keep. Retrying one of these
     * means asking for the retirement again, not for a revocation.
     */
    readonly grantsRetireFailed: readonly string[];
    /**
     * What was asked for, what was done, and — when they differ — why.
     *
     * `complete: true` means the **applied** action completed. It does not mean
     * the requested one was honoured: a Store that asked to keep, was refused
     * by policy, and reads only `complete` will believe the subject's grants
     * survived when every one of them was revoked. Read all three fields.
     *
     * And `complete: false` is worse under `"keep"` than under `"revoke"`. A
     * full revocation stamps the grants boundary before it enumerates
     * anything, so a grant its pass could not reach is refused at `/token` and
     * revoked durably there; the retry only tidies up. `"keep"` advances no
     * grants boundary — that is the mode — so a grant in `grantsFailed`,
     * selected by `revokeGrantsConsentedSince` and left unwritten by an
     * outage, stays usable until the retry succeeds. Nothing else will end it.
     */
    readonly federationGrants: {
        readonly requested: FederationGrantDisposition;
        readonly applied: FederationGrantDisposition;
        readonly reason?: "keep_not_allowed";
    };
}
export interface SubjectRevocationService {
    revokeAllForSubject(request: SubjectRevocationRequest): Promise<SubjectRevocationReport>;
}
export interface SubjectRevocationServiceDeps {
    /**
     * Optional for the reason the free function's are: #406 lets a deployment
     * declare either capability absent, and a service that could not be
     * *installed* in such a deployment would be a harder demand than the
     * operation it wraps. An absence is reported exactly as
     * `revokeAllForSubject` reports it — in `unavailable`, with
     * `complete: false` — rather than refused here. What IS refused is a
     * missing boundary while federation grants are enabled, which the module
     * checks: a grant ends when nothing else does.
     */
    readonly subjectSessionIndex?: SubjectSessionIndex;
    readonly subjectRevocation?: SubjectRevocation;
    readonly cascadeSession: CascadeSession;
    /**
     * How long a boundary must outlive, from
     * `resolveSubjectRevocationHorizonMs`. Required rather than defaulted: the
     * number depends on configuration this module cannot see, and a guess makes
     * the backstop expire before what it is the backstop for.
     */
    readonly watermarkTtlMs: number;
    readonly federationGrantStore?: FederationGrantStore;
    /** `federationGrants.allowKeepOnSubjectRevocation`, already resolved. */
    readonly allowKeep: boolean;
    readonly federationGrantAudit?: (event: FederationGrantAuditEvent) => void | Promise<void>;
    readonly correlationId?: string;
    readonly logger?: Logger;
    /** Injectable for tests; defaults to `Date.now`. */
    readonly now?: () => number;
}
/**
 * Wiring errors are refused here, once, rather than answered per request.
 *
 * An operator who turned the allowance on and got a full revocation on every
 * call would read the outcome as the policy working — `"keep"` is precisely
 * the mode whose failure looks like success from the outside. So an adapter
 * that cannot stamp the two boundaries separately is a refusal at
 * construction, where a composition error belongs.
 */
export declare function createSubjectRevocationService(deps: SubjectRevocationServiceDeps): SubjectRevocationService;
/**
 * Optional, and installed by a module of its own (`@o3co/auth-provider-oauth`),
 * because building it needs the whole session cascade. A deployment that only
 * serves grants has no use for it, and a route bundle that suddenly required
 * every session store would break the deployments that have none.
 */
declare module "@o3co/auth-provider-core" {
    interface ComponentMap {
        readonly subjectRevocationService?: SubjectRevocationService;
    }
}
//# sourceMappingURL=subjectRevocationService.d.mts.map