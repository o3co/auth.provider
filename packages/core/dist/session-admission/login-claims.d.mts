/**
 * A login's claims envelope — what the session record's `claims` will hold
 * (`UserSessionClaims`) — as a primary carries it: one read of the object a
 * route hands in, into a plain copy frozen at every depth that shares
 * nothing with it. Not the claim a carrier is read into (`SessionClaim`,
 * `admit.mts`): these are the OIDC claims a session records.
 *
 * Two rules, one for each kind of claim:
 *
 * - A claim `UserSessionClaims` declares (`email`, `emailVerified`, `name`,
 *   `picture`, `groups`) is read by name, once, however the object holds it
 *   — own data, a getter, inherited, behind a Proxy — through the by-name
 *   plain-data copy a login's user goes through (`readPlainFields`): a list
 *   by index into a plain array, nothing else of it. When present it must
 *   be of its declared type; `null` or any other value is refused.
 * - A custom claim — each other own enumerable key — is read once and
 *   stored as its JSON form: `JSON.stringify` (a `toJSON` applies, so a
 *   `Date` becomes its ISO string; NaN and the infinities become `null`),
 *   parsed back. One whose JSON form is nothing (`undefined`, a function, a
 *   symbol) is left out, as JSON leaves it out. One whose JSON form cannot
 *   be taken (a bigint, a cycle, a `toJSON` or a getter that throws, a
 *   value that refers back to the claims themselves) is dropped and the
 *   login goes on; whoever holds a logger says so with
 *   `warnDroppedClaims`, naming the key and never the value. That is what a
 *   Redis-backed session store already read back of a custom claim.
 *
 * Core-internal: not exported from the package.
 */
import type { Logger } from "../logging/Logger.mjs";
import type { UserSessionClaims } from "../user-sessions/types.mjs";
/** Why a custom claim was dropped: its JSON form could not be taken. */
export type DroppedClaimReason = "unserialisable";
/** A custom claim a reading dropped: its key and why, never its value. */
export interface DroppedClaim {
    readonly claim: string;
    readonly reason: DroppedClaimReason;
}
/** What `readLoginClaims` answers: the envelope, or why the claims are refused. */
export type LoginClaimsReading = {
    readonly ok: true;
    readonly claims: UserSessionClaims;
} | {
    readonly ok: false;
    readonly refused: "not_an_object";
} | {
    readonly ok: false;
    readonly refused: "declared_claim";
    readonly claim: string;
    readonly as: string;
};
/**
 * `claims` read once into the envelope a primary carries, by the two rules
 * in this file's header. Refused: `claims` that are not an object
 * (`not_an_object`), and a declared claim that is not plain data of its
 * declared type (`declared_claim`, naming it and the type). A class instance
 * is read by the declared names and its own enumerable keys, nothing else of
 * it. A read of the object's keys or of a declared claim that throws is let
 * through as it was thrown; a custom claim whose read throws is dropped.
 */
export declare function readLoginClaims(claims: unknown): LoginClaimsReading;
/** The custom claims `readLoginClaims` dropped from `claims`, an envelope it answered; none for any other object. */
export declare const droppedClaimsOf: (claims: UserSessionClaims) => readonly DroppedClaim[];
/**
 * Logs `login_claim_dropped` at warn once for each custom claim
 * `readLoginClaims` dropped from `claims`: its key and the reason, never
 * its value. Said once for an envelope, however often it is handed here
 * with a logger. Nothing without a logger.
 */
export declare function warnDroppedClaims(logger: Logger | undefined, claims: UserSessionClaims): void;
//# sourceMappingURL=login-claims.d.mts.map