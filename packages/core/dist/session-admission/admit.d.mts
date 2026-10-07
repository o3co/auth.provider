import type { Logger } from "../logging/Logger.mjs";
import type { UserSession, UserSessionClaims } from "../user-sessions/types.mjs";
import type { Admission, AdmissionDeps, AdmissionRequest, CompletedRequirement, Establishment, PrimaryAdmission, PrimaryAuthentication, PrimaryContinuation, SessionClaim, SessionView } from "./requirement.mjs";
export { isEstablishment, isInterruptAdmission } from "./establishment.mjs";
export { checkResolver, type SessionRequirementSource, sessionRequirementResolverOver, } from "./requirement-resolver.mjs";
/** What a cookie claim is built from: the express session, when the request has one. */
export interface CookieCarrier {
    readonly session?: {
        readonly isAuthenticated?: unknown;
        readonly sid?: unknown;
        readonly user?: unknown;
        readonly renewalNonce?: unknown;
    } | null;
}
/**
 * The cookie's claim: `authenticated` is `isAuthenticated === true`, the one
 * reading of the flag; `sid`, `subject` (`user.id`) and the renewal nonce a
 * renewal wrote (`renewalNonce`) are copied when they are non-empty strings.
 * A request without a session claims nothing.
 */
export declare function cookieClaim(req: CookieCarrier): SessionClaim;
/**
 * The `User` the cookie session holds — its login's snapshot — read back as
 * a login reads one (`readUserSnapshot`: the fields `User` declares, each by
 * name once, frozen at every depth and sharing nothing with it), when the
 * session is authenticated (`isAuthenticated === true`, as `cookieClaim`
 * reads it) and the copy's `id` is `subject`; else `undefined`, a user the
 * snapshot refuses included. For a route that admitted `subject` over the
 * cookie's claim. A request that is not an object, or a `subject` that is
 * not a non-empty string, is a `RangeError`.
 */
export declare function cookieSessionUser(req: CookieCarrier, subject: string): Readonly<Record<string, unknown>> | undefined;
/** What a code claim is built from: the code record, which carries a `sid` when a session minted it. */
export interface CodeCarrier {
    readonly sid?: unknown;
}
/**
 * A code record's claim on its first read: authenticated (a session minted
 * the code), with the code's `sid` and no subject, since `CodeData` carries
 * no `sub`; `admitSession`'s subject check has nothing to compare. How the
 * code's session had authenticated is read here, once, and held beside the
 * claim: the requirements judge the code on it.
 */
export declare function codeClaimFirstRead(code: CodeCarrier): SessionClaim;
/**
 * A code record's claim on the `authorization_code` grant's second read:
 * the first read's `subject`, required, so the two reads are compared and
 * the comparison cannot be left out by omitting an option. The code is read
 * as the first read reads it.
 */
export declare function codeClaimRevalidation(code: CodeCarrier, subject: string): SessionClaim;
/** What a link claim is built from: the link transaction's envelope, which records the session and its subject at the start. */
export interface LinkCarrier {
    readonly sid: unknown;
    readonly subject: unknown;
}
/**
 * A link transaction's claim: authenticated, its `sid` and the subject
 * recorded at the start — a form_post callback arrives on a fresh cookie
 * session and has no other binding. An envelope without either is not one.
 */
export declare function linkClaim(link: LinkCarrier): SessionClaim;
/** What a token claim is built from: a verified token's claims. */
export interface TokenCarrier {
    readonly sid?: unknown;
    readonly sub: unknown;
    readonly amr?: unknown;
}
/**
 * A verified token's claim: authenticated, its `sid` when it carries one
 * (without one the live read is skipped), its `sub`, and its `amr` for the
 * requirements (`tokenAmr`, absent unless a well-formed list). A token
 * without a `sub` is not one a session issued.
 */
export declare function tokenClaim(claims: TokenCarrier): SessionClaim;
/**
 * The view a requirement is handed, and an admitted or `step_up` admission
 * carries: a copy of four fields, and of the record's `enrollmentFacts` when
 * it holds ones the type admits — never the record — with whether a second
 * factor can be recorded on the session: `storeRecords`, whether the store
 * it was read from has the step-up capability (`readLiveSession` reads it),
 * and `canRecordSecondFactor` over the record. The one place admission
 * decides it. Each call is a fresh copy.
 * @internal
 */
export declare const viewOf: (session: UserSession, storeRecords: boolean) => SessionView;
/**
 * Whether the session `request.claim` names may proceed with
 * `request.action`. The steps, in order, each failing closed:
 *
 * 1. claim: not authenticated → `unauthenticated`; a cookie without a
 *    subject → `not_live` (`no_subject`).
 * 2. live read, with a store: no `sid` → `not_live` (`no_sid`), except a
 *    token carrier, which skips the read; no record, no `sub` or expired →
 *    `not_live` (`gone`). Without a store the session is `null` and the
 *    requirements decide what that means.
 * 3. subject: a claim's subject that is not the record's → `not_live`
 *    (`subject_mismatch`), logged and audited. Then, for a cookie claim, a
 *    record that carries a renewal nonce the cookie session does not hold →
 *    `not_live` (`renewed`).
 * 4. revocation boundary, for a live record; skipped for a token carrier,
 *    whose boundary `verifyJwt` reads. Then the record's expiry again, on a
 *    clock reading taken after the lifecycle and the boundary were read:
 *    expired → `not_live` (`gone`).
 * 5. requirements, for `use` and `credential_change`: each `admit` in
 *    registration order, the first verdict that is not `met` taken (see
 *    `stepUpVerdict` for `step_up`). A token carrier is judged on the
 *    token's own `amr`, record or not; a code carrier, over a record, on
 *    how its session had authenticated at `/authorize` as the code carries
 *    it (`codeReadingOver`). A code that carries no readable
 *    `authentication`, or whose primary is not the record's, is
 *    `unauthenticated`, nothing asked.
 * 6. `acr_values`: `selectAcr` over the `amr` step 5 judged on, with reach the union
 *    of every requirement's when the session is live.
 * 7. `merge` of 5 and 6. In the met + step_up row, a step-up through the
 *    second-factor authority is never offered for `acr_values` onto a
 *    session the view says no second factor can be recorded on
 *    (`secondFactorRecordable`: a store without `recordSecondFactor`, or a
 *    record `canRecordSecondFactor` refuses): the answer is a new login
 *    (`reauthenticate`, `acr`). The requirements of step 5 were handed the
 *    same answer, on their copy of the view.
 * 8. the last reading, once a requirement was asked about a live record:
 *    steps 1 to 4 again, on a fresh clock reading and with the claim's
 *    subject held to the first reading's, whatever step 7 answered. An
 *    answer they give is the admission's; else step 7's stands, carrying the
 *    first reading's session, view and renewal nonce. A code whose primary
 *    the record read last does not hold, or whose record can no longer be
 *    read, is `unauthenticated`, as on the first reading. A requirement that
 *    throws has already answered `unavailable`.
 */
export declare function admitSession(deps: AdmissionDeps, request: AdmissionRequest): Promise<Admission>;
/** What a password login produces: the facts, never a `recorded`. */
export interface PasswordLoginFacts {
    readonly subject: string;
    readonly user: Readonly<Record<string, unknown>>;
    /**
     * The route's `extractUserClaims(user)`: what the session record's `claims` will hold.
     *
     * Core reads it by name, each claim once, into a plain frozen copy. It
     * must be an object; a class instance is read by the declared claims'
     * names and its own enumerable keys, nothing else of it. A claim
     * `UserSessionClaims` declares must, when present, be of its declared
     * type: `email`, `name` and `picture` a string, `emailVerified` a
     * boolean, `groups` a list of strings (an ORM's list or an Array
     * subclass is copied by index into a plain array). `null`, or any other
     * value, is refused with a `RangeError`. A claim read as `undefined` is
     * left out.
     *
     * A custom claim is stored as its JSON form — `JSON.stringify`, parsed
     * back — so it should be JSON data: a string, a finite number, a
     * boolean, `null`, or a list or plain object of those. Anything else is
     * stored as JSON stores it, as a Redis-backed session store already read
     * it back: a `Date` as its ISO string, an object with `toJSON` as what it
     * answers, NaN or Infinity as `null`, and one whose JSON form is nothing
     * (`undefined`, a function, a symbol) left out. One whose JSON form
     * cannot be taken — a bigint, a cycle, a `toJSON` or a getter that
     * throws — is dropped, and the login goes on; `admitPrimary` logs
     * `login_claim_dropped` (warn) with its key, never its value.
     */
    readonly claims: UserSessionClaims;
    readonly authTime: Date;
    readonly redirectTo: string | undefined;
    readonly request: {
        readonly ip?: string;
        readonly userAgent?: string;
    };
}
/**
 * The one builder a password login has: `recorded` is
 * `passwordSessionAuthentication()` — `amr` `["pwd"]`, primary `pwd`, no
 * second factor — so a route cannot hand in an `amr` or an `mfaAt`. A
 * frozen copy of the facts, checked (`checkPrimaryAuthentication`), which
 * `admitPrimary` alone accepts.
 */
export declare function passwordPrimary(facts: PasswordLoginFacts): PrimaryAuthentication;
/**
 * What `POST /session/login` calls once the user is verified and before
 * anything is written. The primary must be one a core builder made, else a
 * `RangeError`; then every requirement with `admitPrimary` is asked in
 * order. The first interruption wins; only when every one answers
 * `establish` is an `Establishment` answered.
 */
export declare function admitPrimary(deps: AdmissionDeps, primary: PrimaryAuthentication): Promise<PrimaryAdmission>;
/**
 * Continues a login after a requirement's ceremony completes. Refuses,
 * before asking anything, a continuation `checkPrimaryContinuation` cannot
 * read, a completion by any requirement but the one that interrupted (or
 * one not registered with `admitPrimary`, or already done), and additions —
 * this completion's and each read back from `done` — their requirement may
 * not make as registered (`checkPrimaryAdditions`). Then composes `recorded`
 * from the primary and every completion and asks each requirement not yet
 * done; any may interrupt again with the updated continuation.
 */
export declare function resumePrimary(deps: AdmissionDeps, continuation: PrimaryContinuation, completed: CompletedRequirement): Promise<PrimaryAdmission>;
/** What a federated login legitimately produces: the federation's own facts, never a `recorded`. */
export interface FederatedLogin {
    readonly subject: string;
    readonly user: Readonly<Record<string, unknown>>;
    /**
     * The merged claims envelope the callback composed: what the session
     * record's `claims` will hold. Read as {@link PasswordLoginFacts.claims}
     * is: declared claims of their declared types, `null` refused; custom
     * claims stored as their JSON form, one that cannot be taken dropped —
     * said as `login_claim_dropped` only when `establishWithoutAsking` is
     * handed a logger.
     */
    readonly claims: UserSessionClaims;
    /** The federation's name (`core.federations.<name>`). */
    readonly federation: string;
    /** The upstream IdP's `amr`, as it surfaced it. */
    readonly upstreamAmr: readonly string[];
    /** Whether that federation's upstream `amr` counts (`federationTrustsUpstreamAmr`). */
    readonly trusted: boolean;
    /** When the upstream last authenticated the user (`FederationProfile.authTime`), when it showed one. */
    readonly upstreamAuthTime?: Date;
    /**
     * Whether that federation's callback alone meets a freshness ask
     * (`federationCallbackMeetsFreshness`); decides what is recorded when the
     * upstream showed no instant (`federatedSessionAuthentication`).
     */
    readonly callbackMeetsFreshness?: boolean;
    readonly authTime: Date;
    readonly redirectTo: string | undefined;
    readonly request: {
        readonly ip?: string;
        readonly userAgent?: string;
    };
}
/**
 * The federation callback's establishment, built from the federation's own
 * facts with no requirement asked. `recorded` is composed here through
 * `federatedSessionAuthentication`, so a caller cannot mark an arbitrary
 * `amr` or an `mfaAt` as a federated primary. A drift guard pins its
 * callers to the callback.
 *
 * A federated login asks no requirement's `admitPrimary`: the requirements
 * judge the resulting session only through `admit`, when a consumer admits it
 * (ADR 2026-09-28-session-admission, D5).
 *
 * `options.logger`, when given, is told of each custom claim the envelope
 * dropped (`login_claim_dropped`); without one, a dropped claim is silent.
 */
export declare function establishWithoutAsking(login: FederatedLogin, options?: {
    readonly logger?: Logger;
}): Establishment;
//# sourceMappingURL=admit.d.mts.map