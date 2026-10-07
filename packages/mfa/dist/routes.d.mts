/**
 * The MFA routes under `/session/mfa`: `GET /transaction`, `POST /challenge`,
 * `POST /verify`, an enrollment — a login's first binding, or one from a
 * signed-in session — `POST /enrollment` and `POST /enrollment/complete`,
 * and a session's step-up, `POST /step-up`, over the coordinator; a
 * verified second factor, or a factor bound at a login that counts at once,
 * resumes the login through core's `resumePrimary` and finishes it through
 * the `loginCompletion` slot; one verified on a session's step-up, or bound
 * in a session and counting at once, escalates that session. See README,
 * "The routes".
 *
 * - Every answer is `no-store`. Bodies are parsed on these paths alone.
 * - Every POST sits behind the deployment's CSRF guard, then the flood guard
 *   (`mfa:ip:<ip>`), before anything is read.
 * - The transaction id is read from the body or the `MFA-Transaction` header,
 *   never from the URL, and never logged; a missing, malformed, foreign,
 *   spent or expired one is answered alike. A login's begun at or before
 *   its subject's sessions boundary is `401 login_required`.
 * - A signed-in session is admitted before its transaction is read: as
 *   `mfa.manage` to enroll, and through the step-up's remediation for its
 *   proof; its `User` is the one its cookie holds (`cookieSessionUser`).
 *   The step-up asks the requirement, as `mfa.manage`, what a first binding
 *   in the session is answered, and opens the proof only where it would not
 *   be refused outright — this requirement's `unmet`, a session without
 *   `mfa` whose subject holds nothing that adds it, is not: the step-up
 *   still serves the baseline and an `acr`; another requirement's step-up
 *   is answered as its own. Requirements are asked in order and the first that is not met
 *   answers, so where this one's gate asks the proof, the trip opens before
 *   a later requirement is asked, and that one may still hold the binding
 *   back once the proof is given. A binding in a session that the subject's
 *   factors no longer allow is `409`: the session stands.
 * - For a subject holding a record that may count, the step-up opens a
 *   `step_up` transaction, with the `acr_values` the body hints read
 *   strictly — at most 16 values of at most 256 characters, else none — as a
 *   hint only; `403 mfa_no_qualifying_factor` when no factor can be used, and
 *   `401` where admission's view says no second factor can be recorded on
 *   the session (`secondFactorRecordable`), before anything is opened.
 * - The account page's management of the subject's factors, under
 *   `/factors`, is `management.mts`'s, mounted here behind the same guards
 *   and admitted through `sessionFor`, which takes a session admitted as
 *   `mfa.manage` with where its factor-set write begins (`factorSet.mts`),
 *   read before the admission. The subject's own release of its lock,
 *   `POST /lock/release`, is `lockRelease.mts`'s, and the regeneration of its
 *   recovery codes, `POST /recovery-codes`, `recoveryCodes.mts`'s, each
 *   mounted and admitted the same way.
 * - A factor that is not guessable verified at a login once its session is
 *   established, or at a step-up once its session is escalated, mints the
 *   authorization that release takes (`lockRecovery.mts`), for that session;
 *   one that cannot be minted is said at warn, the answer standing.
 * - A step-up's verification and a binding in a session escalate that
 *   session (`escalation.mts`). A step-up answers as the escalation came to;
 *   a binding answers its factor and codes, shown once, whatever it came to.
 *   Neither reaches a login's completion.
 * - A binding that adds nothing — a first binding by a sign-in alone, whose
 *   factor counts from the next sign-in that uses it (`enrollment.mts`) —
 *   escalates no session and completes no login: it answers its factor and
 *   codes alone, with no `message`, and a login's establishes no session.
 * - A login's binding marks its recovery codes shown just before the answer
 *   that carries them, once nothing else can answer the login: one answered
 *   otherwise — another requirement's interruption, `401`, `503` — leaves
 *   the set unshown, and a mark that fails answers `recovery_codes_issued:
 *   false`.
 * - A factor's own failure is logged by its name and code, never its text;
 *   one that cannot start an enrollment, or say whether the user may enroll
 *   it, is `503` (`mfa_factor_enrollment_unavailable`, its kind).
 * - An enrollment of a factor the subject holds already is `409
 *   mfa_factor_duplicate`, at its start or its completion, naming no record.
 * - Each outage is answered `503` and logged once, at error. A mail the
 *   sender refused at its limit is `429`; a factor whose recorded address no
 *   longer matches the login's is `403`, recorded as
 *   `mfa.email_address_mismatch`. Neither the code nor the address is logged.
 * - A guessable proof the subject lock holds is `429 mfa_locked`, with the
 *   hold, the exempt kinds the subject holds, the transaction's attempts
 *   left, and `Retry-After` in whole seconds rounded up — none for the hard
 *   hold — recorded as `mfa.locked`, and also as `mfa.locked.first` when it
 *   begins an episode.
 * - A recovery code spent answers, and records as `mfa.recovery_code.used`,
 *   how many codes the set has left.
 * - A verified proof that completes no login under `required` — it does not
 *   count, and the subject has no counting factor it can use — answers the
 *   login's own `403 mfa_enrollment_required`, naming the transaction
 *   reopened for a binding; a proof that gate asks nobody can give is said at
 *   warn, as at a login. A new transaction that cannot be opened is `503`, the
 *   proof spent; a login's `User` that says the subject enrolled is `503`,
 *   recorded as `mfa.enrollment_state_inconsistent`, nothing spent.
 */
import { type AdmissionDeps, type AuditSink, type CsrfGuard, type IssuedRemediationAction, type Logger, type LoginCompletion, type SupportsSecondFactorUpdate, type UserSessionStore } from "@o3co/auth-provider-core";
import { type RequestHandler, type Router } from "express";
import type { MfaCoordinator } from "./coordinator.mjs";
import type { MfaLockRecovery } from "./lockRecovery.mjs";
import { type MfaManagementOptions } from "./management.mjs";
import { type MfaRecoveryCodesOptions } from "./recoveryCodes.mjs";
export interface MfaRoutesOptions {
    readonly coordinator: MfaCoordinator;
    /**
     * What `admitSession` and `resumePrimary` are handed: the registered
     * requirements, the session store, the subjects' revocation boundary, the
     * logger.
     */
    readonly admission: AdmissionDeps;
    /** The `mfa.step_up` remediation core issued the requirement: what the step-up's trip is admitted as. */
    readonly stepUp: IssuedRemediationAction;
    readonly loginCompletion: LoginCompletion;
    /** The session store's step-up capability, when it has it: where a session's escalation is recorded. */
    readonly secondFactorStore: (UserSessionStore & SupportsSecondFactorUpdate) | undefined;
    /** The deployment's CSRF guard: every POST runs its middleware, and a login it completes is handed a fresh token. */
    readonly csrfGuard: CsrfGuard;
    /** The flood guard every POST runs after the CSRF guard. */
    readonly floodGuard: RequestHandler;
    readonly logger: Logger;
    readonly auditSink: AuditSink | undefined;
    /** What the account page's management of the subject's factors reads and writes (`management.mts`). */
    readonly management: Omit<MfaManagementOptions, "admit" | "logger" | "auditSink">;
    /** The authorized-recovery entry: minted at an exempt verification, applied by the subject's release. */
    readonly lockRecovery: MfaLockRecovery;
    /** What the regeneration of recovery codes reads beside the management's (`recoveryCodes.mts`). */
    readonly recoveryCodes: Pick<MfaRecoveryCodesOptions, "maxFactorsPerSubject" | "firstBindingAt" | "firstBindingMark">;
}
/**
 * Where a user-session store is wired, core's session lifecycle is required:
 * admission reads the session's lifecycle record through the port, so a
 * session closing or closed is admitted to nothing. Throws when the store is
 * wired without the port.
 */
export declare function requireSessionLifecycleStore(admission: Pick<AdmissionDeps, "userSessionStore" | "sessionLifecycleStore">): void;
/** The MFA routes' router (see this file's header). */
export declare function createMfaRouter(options: MfaRoutesOptions): Router;
//# sourceMappingURL=routes.d.mts.map