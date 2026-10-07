/**
 * The answer to a login a session requirement interrupted, as one function.
 * `POST /session/login` (`routes/Session.mts`) calls it when `admitPrimary`
 * answers `interrupt`, and a requirement's completion route when
 * `resumePrimary` does (another requirement interrupts the login the first
 * one resumed), so the package exports it and the MFA package's completion
 * answers the same way.
 *
 * Two phases, because the express session is regenerated between them:
 *
 * 1. `req.session.regenerate`: a fresh session id, left unauthenticated (no
 *    `isAuthenticated`, `user`, `sid` or `redirectTo` is written).
 * 2. `admission.open(req.sessionID)`: the requirement's ceremony, bound to
 *    that id. The requirement persists the continuation core built, and core
 *    validates its answer against the closed body before it comes back.
 * 3. `req.session.save`, before the answer.
 * 4. The requirement's `403` with its body, and a fresh CSRF token, as a
 *    successful login gets one after the regeneration.
 *
 * No `UserSession` is written: the requirement's completion establishes the
 * session, through `resumePrimary` and `establishSession`.
 *
 * Each point that can fail answers `503 temporarily_unavailable`, drops the
 * request's cookie session (`abandonCookieSession`) and tells the caller's
 * reporter once, so each caller logs in its own vocabulary: the regeneration
 * as `cookie_session` / `regenerate`; a throw from `open` (the requirement's
 * outage, or an answer core refused) under the requirement's name, `open`;
 * the save as `cookie_session` / `save`, after which the requirement's record
 * is left to its own expiry, bound to a session id no browser holds.
 * See ADR 2026-09-28-session-admission, D5.
 */
import { type InterruptAdmission } from "@o3co/auth-provider-core";
import type { Request, Response } from "express";
import type { CsrfProtection } from "./csrf.mjs";
/** Where an interruption's answer failed: the store, and the step. */
export type InterruptionStep = "regenerate" | "open" | "save";
/**
 * What the caller logs, in its own vocabulary. `store` is `cookie_session`
 * for the regeneration and the save, and the interrupting requirement's name
 * for `open`.
 */
export interface InterruptionReporter {
    /** A store the answer cannot do without could not answer; the `503` is already being sent. */
    storeUnavailable(store: string, step: InterruptionStep, cause: unknown): void;
}
/** What the helper needs beside the admission: the request, the response, the CSRF mechanism and the reporter. */
export interface AnswerInterruptionDeps {
    readonly req: Request;
    readonly res: Response;
    /**
     * Issues the fresh CSRF token the `403` carries: the login route's
     * `CsrfProtection`, or the deployment's `csrfGuard` — `issue` is all
     * that is read.
     */
    readonly csrf: Pick<CsrfProtection, "issue">;
    readonly reporter: InterruptionReporter;
}
/**
 * The response has been sent: the requirement's `403`, or a `503` naming the
 * store and the step that could not answer (the reporter has been told).
 */
export type AnswerInterruptionResult = {
    readonly outcome: "answered";
} | {
    readonly outcome: "unavailable";
    readonly store: string;
    readonly step: InterruptionStep;
};
/**
 * Answer the login `admission` interrupted: regenerate, open, save, answer
 * the requirement's `403` with a fresh CSRF token — the sequence, and the
 * `503` at each point it can fail, are in this file's header. Sends the
 * response either way and answers what it sent. Rejects with a `RangeError`,
 * before the session is touched, when `admission` is not an interruption
 * `admitPrimary` or `resumePrimary` answered (core's `isInterruptAdmission`:
 * a copy, or an object shaped like one, is not).
 */
export declare function answerInterruption(admission: InterruptAdmission, { req, res, csrf, reporter }: AnswerInterruptionDeps): Promise<AnswerInterruptionResult>;
//# sourceMappingURL=answer-interruption.d.mts.map