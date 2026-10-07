import { type Establishment, type SessionLifecycle, type SessionRenewalReporter, type SessionRenewalResult, type SubjectSessionIndex, type UserSessionStore } from "@o3co/auth-provider-core";
import type { Request } from "express";
declare module "express-session" {
    interface SessionData {
        /** Written by {@link establishSession}, carried over by {@link renewSession}: the session is a login's. */
        isAuthenticated?: boolean;
        /** Written by {@link establishSession}, carried over by {@link renewSession}: the `User` the login verified. */
        user?: Record<string, unknown>;
        /** Written by {@link establishSession} when the login carried a `redirect_to` its allowlist accepted. */
        redirectTo?: string;
        /** The `UserSession` record's id, written by {@link establishSession} when a record was created, carried over by {@link renewSession}. */
        sid?: string;
        /** Written by {@link renewSession}: the renewal nonce an escalation of the record binds it to, never carried over. */
        renewalNonce?: string;
    }
}
/** The record a login's tail wrote, as the caller's steps see it. */
export interface EstablishedRecord {
    readonly sid: string;
    readonly sub: string;
    readonly expiresAt: Date;
}
/**
 * A write the caller makes beside the record — a federation's upstream
 * tokens, its join through the session lifecycle — named as its log lines
 * name it: `store` and `step` for a `run` that fails, `undo.step` for an
 * undo that fails.
 */
export interface EstablishSessionStep<S extends string = string, T extends string = string> {
    readonly store: S;
    readonly step: T;
    run(record: EstablishedRecord): Promise<unknown>;
    /** Undoes a completed `run` when a later write fails. Absent: nothing to undo. */
    readonly undo?: {
        readonly step: T;
        run(record: EstablishedRecord): Promise<unknown>;
    };
}
/**
 * What the caller logs, in its own vocabulary — the two routes' event names
 * and fields differ, and stay theirs. Built once per login, with the `sid`
 * (when a record is made) and the subject, before the first write, so a
 * caller can bind its logger to them.
 */
export interface EstablishSessionReporter<S extends string = never, T extends string = never> {
    /** A store the login cannot do without could not answer; the caller answers the outage. */
    storeUnavailable(store: "user_session" | "cookie_session" | S, step: "create" | "regenerate" | "save" | T, cause: unknown): void;
    /** A best-effort rollback step failed; the login's own answer stands. */
    cleanupFailed(store: "user_session" | "subject_session_index" | S, step: "delete" | "remove_sid" | T, cause: unknown): void;
    /** The subject index could not record the session; the login proceeds. */
    subjectIndexWriteFailed(cause: unknown): void;
}
/** The stores, the steps and the request a login's tail writes. */
export interface EstablishSessionDeps<S extends string = never, T extends string = never> {
    readonly req: Request;
    /** Absent: no record is created, and the express session alone is authenticated. */
    readonly userSessionStore?: UserSessionStore;
    readonly subjectSessionIndex?: SubjectSessionIndex;
    /**
     * Core's session lifecycle: the record's lifecycle is opened in it, and
     * closed in it by a rollback. Required with a `userSessionStore`.
     */
    readonly sessionLifecycle?: Pick<SessionLifecycle, "open" | "close">;
    /** The session's lifetime: the record expires this long after `authTime`. */
    readonly sessionTtlMs: number;
    /** Writes beside the record before the express session is regenerated. */
    readonly beforeRegenerate?: ReadonlyArray<EstablishSessionStep<S, T>>;
    /** Writes beside the record after the regeneration — what needs the new session to exist. */
    readonly afterRegenerate?: ReadonlyArray<EstablishSessionStep<S, T>>;
    readonly reporter: (record: {
        readonly sid: string | undefined;
        readonly sub: string;
    }) => EstablishSessionReporter<S, T>;
}
/**
 * The session was established, with the record's `sid` when one was made;
 * or a store the login cannot do without could not answer, named as the
 * reporter was told, and everything written was rolled back.
 */
export type EstablishSessionResult<S extends string = never, T extends string = never> = {
    readonly outcome: "established";
    readonly sid: string | undefined;
} | {
    readonly outcome: "unavailable";
    readonly store: "user_session" | "cookie_session" | S;
    readonly step: "create" | "regenerate" | "save" | T;
};
/**
 * Establish the session admission established (sequence and rollback in this
 * file's header). Answers `established` with the record's `sid` (`undefined`
 * without a store), or `unavailable` naming the store and step that failed,
 * after rolling back; the reporter has already been told what to log.
 *
 * @throws RangeError, before anything is written, when `establishment` was not
 * built by core; TypeError when a `userSessionStore` is handed without a
 * `sessionLifecycle`.
 */
export declare function establishSession<S extends string = never, T extends string = never>(establishment: Establishment, deps: EstablishSessionDeps<S, T>): Promise<EstablishSessionResult<S, T>>;
/**
 * Move the request's signed-in express session to a new id (sequence in this
 * file's header). Answers `renewed` with the new session's renewal nonce, or
 * `unavailable` at the step that failed after telling the reporter, the
 * request's cookie session dropped. A session that is not signed in stays
 * so: only the signed-in fields it holds are carried over.
 */
export declare function renewSession(req: Request, reporter: SessionRenewalReporter): Promise<SessionRenewalResult>;
//# sourceMappingURL=establish-session.d.mts.map