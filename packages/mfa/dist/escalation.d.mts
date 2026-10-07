/**
 * The session's escalation: the second-factor authority's write that a
 * second factor was verified in a signed-in session, and what a step-up
 * answers it. The routes call `escalate` and `answer`; the sequence behind
 * them is this module's alone.
 *
 * - The `amr` added is held to the mfa requirement's sealed reach.
 * - The express id is renewed first, then the second factor recorded on the
 *   `UserSession` once, with the renewal's nonce and the one admission
 *   compared, never retried.
 * - A record left without the renewal's nonce ends the session (`unbound`).
 * - Each failure is logged here, once, and is its own outcome; a step-up
 *   answers each as `ESCALATION_REFUSALS` says.
 */
import { type CsrfGuard, type Logger, type LoginCompletion, type SupportsSecondFactorUpdate, type UserSessionStore } from "@o3co/auth-provider-core";
import type { Request, Response } from "express";
/** How a session's escalation ended (`escalate`). */
export type Escalation = "escalated" | "unrecordable_store" | "not_renewed" | "not_recorded" | "unbound" | "invalid" | "unavailable";
/** What a step-up answers an escalation that did not land: a new login, an outage, or one nobody can retry. */
export declare const ESCALATION_REFUSALS: Readonly<Record<Exclude<Escalation, "escalated">, readonly [status: number, body: object]>>;
/** What an escalation is built over; `Route` names the route a line is logged by. */
export interface SessionEscalationOptions<Route extends string> {
    /** The session store's step-up capability, when it has it. */
    readonly secondFactorStore: (UserSessionStore & SupportsSecondFactorUpdate) | undefined;
    readonly loginCompletion: LoginCompletion;
    /** The mfa requirement's sealed reach, read at each escalation; `undefined` when none is registered. */
    readonly reach: () => ReadonlySet<string> | undefined;
    /** Issues the fresh CSRF token an escalation that landed answers with. */
    readonly csrfGuard: CsrfGuard;
    readonly logger: Logger;
    /** Logs a store's outage at `step`, once. */
    readonly storeUnavailable: (route: Route, store: string, step: string, cause: unknown, context: {
        readonly sid: string;
    }) => void;
}
/** A session's escalation, and a step-up's answer for how it ended. */
export interface SessionEscalation<Route extends string> {
    /**
     * The signed-in session `session` escalated by `adds`: its express id
     * renewed, then the second factor recorded on its `UserSession` with the
     * renewal nonce, expecting `expected`, the one admission compared — called
     * once, never again, since a retry after a write that landed would expect
     * the old nonce and undo it. A fresh CSRF token on `res` once recorded.
     * Each failure is logged here, once; the caller chooses the answer.
     *
     * - No step-up capability: `unrecordable_store`, nothing renewed.
     * - `adds` names a value outside the mfa requirement's sealed reach:
     *   `invalid`, nothing renewed.
     * - The renewal fails, or answers no renewal nonce: `not_renewed`, nothing
     *   recorded.
     * - The record answers `null` — the session is gone, another completion
     *   from the same cookie session was recorded first, or it predates how a
     *   session was established: `not_recorded`. The renewed cookie session is
     *   left as it is: at its next admission each cause is `not_live` or
     *   below the level the step-up was for.
     * - A session without the renewal nonce: `unbound`. The escalation would
     *   stand bound to no cookie session, so the session is ended.
     * - A `RangeError`: `invalid`. Any other rejection, or an answer that is
     *   not this session: `unavailable`.
     *
     * After a renewal, no failure but `unbound` ends the renewed cookie session.
     */
    escalate(route: Route, req: Request, res: Response, session: {
        readonly sid: string;
        readonly sub: string;
    }, expected: string | undefined, adds: {
        readonly amr: readonly string[];
        readonly mfaAt: Date;
    }): Promise<Escalation>;
    /** A step-up's answer for how its escalation ended: `answer` once escalated, else its refusal. */
    answer(res: Response, escalation: Escalation, answer: object): void;
}
/** The session's escalation over `options` (see this file's header). */
export declare function createSessionEscalation<Route extends string>(options: SessionEscalationOptions<Route>): SessionEscalation<Route>;
//# sourceMappingURL=escalation.d.mts.map