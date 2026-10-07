/**
 * What the request asks of the session — `prompt`, `max_age`, `acr_values` —
 * and the trips that answer it: the login trip and the step-up trip, each
 * recorded as a re-authentication ask bound to this request
 * (`./reauthAsk.mts`). The ask is read on every pass, spent by the next trip's
 * write and by the pass that mints; a session that comes back from a trip it
 * was already sent on is refused, never sent again.
 */
import { type Admission, type Logger, type UserSession } from "@o3co/auth-provider-core";
import type { Request } from "express";
import { type AuthorizeContext } from "./authorizeContext.mjs";
import { type ReauthAskRecord, type ReauthAskStore } from "./reauthAsk.mjs";
/** The `prompt` values this server honours. */
export type PromptDirective = {
    readonly silent: boolean;
    readonly login: boolean;
    readonly consent: boolean;
};
/**
 * OIDC Core §3.1.2.1 `prompt`. `none` answers `login_required` instead of a
 * login page, which a hidden iframe doing silent renewal cannot act on.
 * `consent` forces the consent page for a client that is not first-party (a
 * no-op for first-party). `login` goes through the re-authentication ask
 * (`./reauthAsk.mts`), which keeps it from looping. Anything else
 * (`select_account`) is refused with `invalid_request`, not ignored: ignoring
 * it would return a token the RP believes honoured it.
 *
 * Returns the directive, or `null` when it has already answered.
 */
export declare const resolvePrompt: (ctx: AuthorizeContext) => PromptDirective | null;
/**
 * `max_age` (OIDC Core §3.1.2.1): a non-negative integer, or a refusal.
 * Absent or empty means no constraint (RFC 6749 §3.1).
 */
export declare const parseMaxAge: (ctx: AuthorizeContext) => {
    readonly value: number | undefined;
} | null;
/**
 * `acr_values` (OIDC Core §3.1.2.1), read strictly: a malformed list is the
 * request's fault, not an acr this deployment lacks. Whether the values are
 * met is admission's decision (`asks.acrValues`).
 */
export declare const parseAcrValues: (ctx: AuthorizeContext) => readonly string[] | null;
/**
 * The parameter this endpoint adds to a page it sends the browser to, naming
 * the request to come back to: core's `LOGIN_RETURN_PARAMETER`, which the
 * login page and a requirement's step-up page both read. The login page's own
 * URL may not carry it (core's `LoginEntry` contract).
 */
export declare const REDIRECT_TO_PARAM = "redirect_to";
/**
 * The presented ask, read without spending it, so a later pass of this
 * request (after consent, or another trip) finds it too: `null` when absent,
 * unknown, bound to another request or expired; `undefined` after an outage
 * has been answered. Read only when a decision needs it.
 */
export declare const presentedAsk: (ctx: AuthorizeContext, askStore: ReauthAskStore | undefined) => Promise<ReauthAskRecord | null | undefined>;
/**
 * The pass that mints spends the presented ask, so the ask cannot carry its
 * login into a second code; a replayed URL is then decided as a request with
 * no ask. An ask gone by now — spent by another pass of the same request —
 * refuses with `login_required` when the session's freshness rested on it,
 * and is ignored otherwise. `false` once answered.
 */
export declare const spendAskAtMint: (ctx: AuthorizeContext, askStore: ReauthAskStore | undefined, freshByAsk: boolean) => Promise<boolean>;
/**
 * How a trip ended: the browser sent, or answered (an outage, a refusal);
 * or `spent` — the ask it was presented was spent by another pass of the
 * request between this pass's read and its write, nothing was written or
 * answered, and the request is to be judged again with no ask.
 */
export type TripOutcome = "sent" | "answered" | "spent";
/**
 * The longest authorize request, as the canonical URL an ask binds, for
 * which an ask is recorded before the client is looked up: the record holds
 * that URL, and an anonymous caller chooses its size.
 */
export declare const ANONYMOUS_ASK_MAX_REQUEST_BYTES: number;
/**
 * Where the login page returns a browser that is not signed in — or whose
 * dead session was just signed out — and sent `prompt=login`: this request with a login ask recorded before the login,
 * so the login it makes meets the prompt on the way back. Recorded only for
 * a request of the shape a client sends — a well-formed `client_id`, the
 * canonical request within `ANONYMOUS_ASK_MAX_REQUEST_BYTES` — a check of its
 * shape, not a lookup. Otherwise, without an ask store, or when the ask
 * cannot be recorded (logged), the request as it came: the user is then
 * asked to log in again on the way back.
 */
export declare const loginReturnWithAsk: (req: Request, issuerOrigin: string, askStore: ReauthAskStore | undefined, logger: Logger) => Promise<string>;
/**
 * How far ahead of this clock a session's authentication instant may be and
 * still be compared with an ask: the skew tolerated between replicas for an
 * instant one of them recorded — a login on one replica whose return reaches
 * another moments later, whose clock runs a little behind. Read as now
 * within it. Not core's `DEFAULT_CLOCK_SKEW_MS` (five minutes), which would
 * let a session stamped that far ahead meet an ask without a new login.
 */
export declare const ASK_REPLICA_SKEW_MS = 1000;
/**
 * The session's authentication instant in milliseconds, for comparing with
 * an ask's, capped at the clock: `undefined` when core's `authTimeAt` cannot
 * read it against the clock, or when it is more than `ASK_REPLICA_SKEW_MS`
 * ahead — stamped by a clock this one cannot check, so it shows no login
 * made since an ask. Unreadable is a login trip, or `login_required` once a
 * login was asked for or under `prompt=none`.
 */
export declare const readableAuthTime: (session: UserSession, nowMs: number) => number | undefined;
/**
 * Whether a login was made since `instant` (an ask's, in milliseconds):
 * the session authenticated strictly after it — an authentication earlier
 * in the same second is not one made since — or `unreadable` when its
 * authentication time cannot be read (`readableAuthTime`). Reads when this
 * provider established the session, which is what a trip's loop control
 * needs; a freshness ask reads `freshSince`.
 */
export declare const loginSince: (session: UserSession, instant: number, nowMs: number) => boolean | "unreadable";
/**
 * The instant the session's authentication is as fresh as (core's
 * `sessionFreshness`: for a federated login, the earlier of its
 * establishment and the upstream's authentication), in milliseconds and read
 * as `readableAuthTime` reads `authTime`: `undefined` when there is none —
 * the upstream showed no time — or the clock cannot read it.
 */
export declare const readableFreshness: (session: UserSession, nowMs: number) => number | undefined;
/**
 * Whether the authentication a freshness ask judges was made since
 * `instant`, or `unreadable`; never looser than `loginSince`, which it asks
 * first: the session must have been established strictly after the ask.
 * Then its freshness (`readableFreshness`) must be since it too — the
 * establishment itself when that is the freshness, else the upstream's
 * authentication, compared in whole seconds because an `auth_time` is
 * whole seconds: one in the ask's second counts.
 */
export declare const freshSince: (session: UserSession, instant: number, nowMs: number) => boolean | "unreadable";
/**
 * `fresh_by_ask`: the session is fresh because of the login the presented
 * ask asked for, which the pass that mints then holds it to.
 */
type ReauthOutcome = "proceed" | "fresh_by_ask" | "login" | "answered";
/**
 * Whether the session's authentication is fresh enough, judged on its
 * freshness (`readableFreshness`), not only on when this provider
 * established it. `prompt=login`, or a `max_age` older than that freshness,
 * sends the browser to log in
 * with the ask recorded (`login_required` under `prompt=none`). When the
 * presented ask records a login trip, a session authenticated after the ask
 * satisfies both; one that was not is refused with `login_required` rather
 * than looped. Decided before admission's verdict is acted on.
 */
export declare const evaluateReauthentication: (ctx: AuthorizeContext, prompt: PromptDirective, maxAge: number | undefined, session: UserSession | null, askStore: ReauthAskStore | undefined, ask: ReauthAskRecord | null) => ReauthOutcome;
/**
 * The login trip. The ask is a store record named by an opaque id on the URL:
 * a caller cannot invent an id that exists, the record survives the session
 * regeneration login performs, and it is bound to this request so it cannot
 * satisfy another's freshness requirement. A step-up trip already asked is
 * carried over, so the session is not sent on it twice.
 */
export declare const sendToLogin: (ctx: AuthorizeContext, askStore: ReauthAskStore, ask: ReauthAskRecord | null) => Promise<TripOutcome>;
/**
 * An `unmet` admission: `unmet_authentication_requirements` when the
 * requested `acr` is what nothing meets (naming values not configured here
 * rather than accepting them silently), else `login_required`, since only a
 * new login can change what the requirement decides on.
 */
export declare const refuseUnmet: (ctx: AuthorizeContext, requirement: string, requested: readonly string[]) => void;
/**
 * A `step_up` admission: send the browser to the requirement's registered
 * page with `acr_values` (when the request asked for an acr) and
 * `redirect_to` naming this request with the ask recorded. A session that
 * comes back no later than the recorded trip is refused rather than sent
 * again (`unmet_authentication_requirements` or `login_required`); one
 * established after it may make one more. `prompt=none` is
 * `interaction_required`.
 */
export declare const stepUpTrip: (ctx: AuthorizeContext, admission: Extract<Admission, {
    outcome: "step_up";
}>, prompt: PromptDirective, askStore: ReauthAskStore | undefined, ask: ReauthAskRecord | null) => Promise<TripOutcome>;
export {};
//# sourceMappingURL=authorizeAsk.d.mts.map