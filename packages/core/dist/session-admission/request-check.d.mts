/**
 * What admission accepts as a request, checked before anything is read: a
 * claim one of the builders branded here (a module-private `WeakSet`), the
 * action by its registration or its issued identity, and well-formed asks.
 * A caller's fault is a `RangeError`; every input is read once and copied,
 * except the session store, the revocation boundary and the audit sink,
 * which `readLiveSession` reads off `deps` in the step that uses it, once
 * each however often that step runs: a store's read that throws is its
 * outage, the sink's a failed audit.
 */
import type { AuditSink } from "../audit/types.mjs";
import type { Logger } from "../logging/Logger.mjs";
import type { CodeReading } from "../user-sessions/authentication.mjs";
import type { SessionLifecycleStore } from "../user-sessions/lifecycle/types.mjs";
import type { SubjectRevocation, UserSessionStore } from "../user-sessions/types.mjs";
import type { AcrTable } from "./acr.mjs";
import type { AdmissionAction } from "./actions.mjs";
import { type AdmissionAsks, type AdmissionDeps, type AdmissionRequest, type SessionClaim, type SessionRequirementResolver } from "./requirement.mjs";
/**
 * Freezes and brands a claim a builder made, so `checkRequest` accepts it,
 * with what a code claim's builder read of the code. Called only by
 * `admit.mts`'s claim builders.
 */
export declare const brandClaim: (fields: Omit<SessionClaim, never>, codeReading?: CodeReading) => SessionClaim;
/**
 * What `checkRequest` answers: every untrusted input (claim, action, `asks`,
 * each other dependency off `deps`) read once and copied, so a getter
 * answering one thing to the check and another to the steps changes
 * nothing, and a requirement cannot reach the caller's objects. The session
 * store, the lifecycle store, the revocation boundary and the audit sink are
 * not read here:
 * `readLiveSession` calls each reader in the guarded step that uses it, so
 * a read that throws never escapes admission — a store's is `unavailable`,
 * the sink's fails as the audit it was read for. Each reader reads `deps`
 * once and answers that reading to every later call. `now` is the clock's
 * reading at the check; `clock` is the same clock, read once off `deps`,
 * for a later reading.
 */
export interface CheckedRequest {
    readonly claim: SessionClaim;
    /** A code claim's: what its builder read of the code; `undefined` when the code carries no readable authentication — refused once its session is read — and for every other carrier. */
    readonly codeReading: CodeReading | undefined;
    readonly action: AdmissionAction;
    readonly asks: AdmissionAsks | undefined;
    readonly requirements: SessionRequirementResolver;
    readonly readUserSessionStore: () => UserSessionStore | undefined;
    readonly readSubjectRevocation: () => SubjectRevocation | undefined;
    readonly readSessionLifecycleStore: () => SessionLifecycleStore | undefined;
    readonly acrTable: AcrTable;
    readonly logger: Logger | undefined;
    readonly readAuditSink: () => AuditSink | undefined;
    readonly now: Date;
    readonly clock: () => Date;
}
/** A caller's fault is a `RangeError` before anything is read. Answers core's copy of what it read, each input read once, and the readers of the three stores and the audit sink. */
export declare function checkRequest(deps: AdmissionDeps, request: AdmissionRequest): CheckedRequest;
//# sourceMappingURL=request-check.d.mts.map