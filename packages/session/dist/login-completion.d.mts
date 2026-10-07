/**
 * The tail of a login as core's `LoginCompletion` — the `loginCompletion`
 * slot `./modules/loginCompletionModule.mts` provides (see ADR
 * 2026-09-28-session-admission), over the deployment's `csrfGuard`.
 *
 * A requirement's completion (the MFA package's, after `resumePrimary`)
 * finishes a login as the login routes do, but a package imports only core,
 * so it requires this slot instead of importing `establishSession` and
 * `answerInterruption`, and renews a signed-in session's id the same way
 * (`renewSession`). The session stores, the session's lifetime and the
 * CSRF guard (whose fresh token an interruption's `403` carries) are bound
 * here, so a caller hands only the request, the response where one is
 * answered, and a reporter that logs in its own vocabulary.
 */
import type { CsrfGuard, LoginCompletion, SessionLifecycle, SubjectSessionIndex, UserSessionStore } from "@o3co/auth-provider-core";
/** What the completion holds: what `establishSession` and `answerInterruption` take beside a call's own. */
export interface LoginCompletionDeps {
    /** Absent: no record is created, and the express session alone is signed in. */
    readonly userSessionStore?: UserSessionStore;
    readonly subjectSessionIndex?: SubjectSessionIndex;
    /**
     * Core's session lifecycle: a login opens the session's lifecycle record
     * in it. Required with a `userSessionStore`.
     */
    readonly sessionLifecycle?: SessionLifecycle;
    /** The session's lifetime: a record expires this long after its `authTime`. */
    readonly sessionTtlMs: number;
    /** Issues the fresh token an interruption's `403` carries: the deployment's CSRF guard. */
    readonly csrf: Pick<CsrfGuard, "issue">;
}
/** The session package's two login tails and its session renewal over `deps`, as core's `LoginCompletion`. Frozen. */
export declare function createLoginCompletion(deps: LoginCompletionDeps): LoginCompletion;
//# sourceMappingURL=login-completion.d.mts.map