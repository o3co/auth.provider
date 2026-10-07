import type { CodeAuthentication } from "../repositories/types.mjs";
import type { Admission, RequirementSession } from "../session-admission/requirement.mjs";
import type { SecondFactorEvent, SessionAuthentication, UserSession } from "./types.mjs";
/** A copy of `authentication` that shares nothing with it: its list and its dates are new. */
export declare function copySessionAuthentication(authentication: SessionAuthentication): SessionAuthentication;
/**
 * The instant `authentication` is as fresh as, for a session established at
 * `authTime`: the earlier of `authTime` and `upstreamAuthTime`; `authTime`
 * when the record holds no upstream instant (absent, or no `authentication`);
 * `undefined` — never fresh — for `null`, or an instant that is not a valid
 * date. A new `Date`. What a freshness ask (`max_age`, `prompt=login`, a
 * recent primary) is judged against; `authTime` itself stays when this
 * provider established the session.
 */
export declare function authenticationFreshness(authTime: Date, authentication: SessionAuthentication | undefined): Date | undefined;
/**
 * {@link authenticationFreshness} of `session`, its record read once by the
 * one reading of it: a recorded `authentication` that reading refuses is
 * `undefined`, never fresher than it was written; one written before the key
 * is as fresh as `authTime`.
 */
export declare function sessionFreshness(session: UserSession): Date | undefined;
/**
 * How `session` was established, or `undefined` when that cannot be told: a
 * session written before the `authentication` key whose `amr` names neither a
 * federation nor a password, or one whose `authentication` or pre-upgrade
 * `amr` is not in a shape it admits. The baseline re-authenticates such a
 * session rather than guess. A copy: nothing done to the answer reaches the
 * session.
 */
export declare function sessionAuthentication(session: UserSession): SessionAuthentication | undefined;
/**
 * The `amr` this provider vouches for in `session`, copied: what `acr` is
 * matched against and a token may carry. A recorded session's `amr`, which
 * holds nothing else; for one written before the `authentication` key, the
 * split: a federated session vouches for `fed` alone. Otherwise a stored
 * `amr` that is not `wellFormedAmr`, or an `authentication` not in a shape
 * it admits, vouches for nothing: a custom store's record is not trusted for
 * its shape.
 */
export declare function vouchedAmr(session: UserSession): readonly string[];
/**
 * Whether a second factor can be recorded on `session`: its primary can be
 * told and what it vouches for can be read. `sessionAfterSecondFactor`
 * answers `null` exactly when this is false.
 */
export declare function canRecordSecondFactor(session: UserSession): boolean;
/** What a login path records about how the user authenticated: the `amr` and `authentication` a session is created with. */
export interface RecordedAuthentication {
    readonly amr: readonly string[];
    readonly authentication: SessionAuthentication;
}
/**
 * What `POST /session/login` records: `amr` `["pwd"]` (RFC 8176), primary
 * `pwd`, no second factor verified yet.
 */
export declare function passwordSessionAuthentication(): RecordedAuthentication;
/**
 * What a federation callback records for the federation named `federation`,
 * whose upstream IdP asserted `upstreamAmr`. When `trusted`
 * (`federationTrustsUpstreamAmr`), the IdP's values sit beside `fed` in
 * `amr`, where tokens carry them and `acr` is matched against them;
 * otherwise `amr` is `fed` alone and the values, if any, are kept in
 * `authentication.upstreamAmr` for the record, where nothing stamps them or
 * reads them for `acr`. The values are copied.
 *
 * `upstreamAuthTime` is the upstream's authentication instant
 * (`FederationProfile.authTime`), recorded as a copy. When it showed none,
 * `callbackMeetsFreshness` (`federationCallbackMeetsFreshness`) decides:
 * `false` records `null`, never fresh; `true` records nothing, so the
 * session is as fresh as `authTime`. A caller that passes neither records
 * nothing.
 */
export declare function federatedSessionAuthentication(login: {
    readonly federation: string;
    readonly upstreamAmr: readonly string[];
    readonly trusted: boolean;
    readonly upstreamAuthTime?: Date;
    readonly callbackMeetsFreshness?: boolean;
}): RecordedAuthentication;
/**
 * Refuses, with a `RangeError`, an event that is not a second factor's: no
 * values; a value that is not a non-empty string; a primary's marker (`pwd`,
 * `fed`: a second factor must not change the primary the baseline is
 * decided on); `mfa` alone (it comes beside a factor's own values, and alone
 * names no factor); a time `isRecordableSessionInstant` refuses on
 * `nowMs`, the store's clock. Every bundled store's `recordSecondFactor`
 * runs this, and {@link readRenewalNonces}, before it reads anything. The
 * message quotes nothing but a primary's marker.
 */
export declare function checkSecondFactorEvent(event: SecondFactorEvent, nowMs: number): void;
/** An event's two renewal nonces, as {@link readRenewalNonces} read them. */
export interface RenewalNonces {
    readonly renewalNonce?: string;
    readonly expectedRenewalNonce?: string;
}
/**
 * The event's `renewalNonce` and `expectedRenewalNonce`, each read once and
 * answered as a frozen copy: what a store compares and records is what was
 * checked. Refuses, with a `RangeError`, one that is not a nonce
 * (`isRenewalNonce`).
 */
export declare function readRenewalNonces(event: SecondFactorEvent): RenewalNonces;
/**
 * Whether a session holding `held` may record an event whose nonces are
 * `nonces`: its renewal nonce is the one expected, absent matching absent.
 * Every bundled store asks it in the same atomic step as its write.
 */
export declare function expectsRenewalNonce(held: string | undefined, nonces: RenewalNonces): boolean;
/**
 * What a store records as a session's `authentication`: the value given,
 * checked, answered as a copy whose `mfaAt` and `upstreamAuthTime` are no
 * later than `nowMs`, the store's clock (a time a little ahead is a clock, but kept as it came it
 * would count as recent for longer than it is). Every bundled store's
 * `create` records this answer, never its own input, so both refuse the
 * same values.
 *
 * `undefined` is a session written as one from before the key; anything
 * else must be what `SessionAuthentication` admits, its `mfaAt` and a
 * `Date` `upstreamAuthTime` passing `isRecordableSessionInstant`.
 *
 * @throws RangeError naming the session and the field, quoting nothing of
 *   the value.
 */
export declare function recordableSessionAuthentication(sid: string, authentication: unknown, nowMs: number): SessionAuthentication | undefined;
/**
 * What a store records as a session's `authTime`: a new `Date` no later than
 * `nowMs`, the store's clock, by the rule `mfaAt` is recorded by
 * (`isRecordableSessionInstant`, then `notAfter`). Every bundled store's `create`
 * records this answer, never its own input.
 *
 * @throws RangeError naming the session, quoting nothing of the value, for a
 *   value that is not a valid `Date`, is before the epoch, or is further
 *   ahead of `nowMs` than `DEFAULT_CLOCK_SKEW_MS`.
 */
export declare function recordableAuthTime(sid: string, authTime: unknown, nowMs: number): Date;
/**
 * What a session records once a second factor was verified in it; both
 * bundled stores' `recordSecondFactor` write this, so they cannot differ.
 * `amr`: `vouchedAmr(session)`, then the event's values, each once, in
 * order. `authentication`: `sessionAuthentication(session)` with `mfaAt`
 * the later of the two, each first capped at `nowMs`, the store's clock, so
 * nothing recorded is still to come and a stored `mfaAt` from a replica
 * whose clock ran ahead is repaired rather than kept.
 *
 * A pre-upgrade session is split first: `["hwk", "fed"]` plus TOTP becomes
 * `amr` `["fed", "otp", "mfa"]` and `upstreamAmr` `["hwk"]`, so an untrusted
 * IdP's `hwk` never meets `phr`. `null` when `canRecordSecondFactor` is
 * false: the primary cannot be told, or the stored `amr` `vouchedAmr` cannot
 * read. The session is read once. The event is checked first
 * (`checkSecondFactorEvent`).
 */
export declare function sessionAfterSecondFactor(session: UserSession, event: SecondFactorEvent, nowMs: number): RecordedAuthentication | null;
/**
 * How a carrier had authenticated, as admission judges it: how the session
 * was established (`undefined` when that cannot be told) and what this
 * provider vouches for. One reading, two projections: what a requirement is
 * handed ({@link requirementSessionOf}) and what a code minted on the
 * admission records ({@link codeFieldsOf}).
 */
export interface AuthenticationReading {
    readonly established: SessionAuthentication | undefined;
    readonly vouched: readonly string[];
}
/** `session` read once by the D9 reading: a copy. */
export declare function sessionReading(session: UserSession): AuthenticationReading;
/**
 * A token that carries no live session: the primary read from the token's
 * `amr` (`fed`, else `pwd`, else unknown, as for an older token that carries
 * no `amr`), no second factor on record, and the `amr` as vouched, since a
 * token is minted from `vouchedAmr` and carries nothing an IdP asserted.
 */
export declare function tokenReading(amr: readonly string[] | undefined): AuthenticationReading;
/**
 * What a code carries of how its session had authenticated at `/authorize`,
 * read once ({@link readCodeAtExchange}): the primary, `mfaAt` and the
 * vouched `amr`.
 */
export interface CodeReading {
    readonly primary: string | undefined;
    readonly mfaAt: Date | undefined;
    readonly vouched: readonly string[];
}
/**
 * A code over the live record `session` names: the code's primary, `mfaAt`
 * and `amr` — a step-up recorded since moves the session, not the code — and
 * what a step-up never changes (`federation`, `upstreamAmr`,
 * `upstreamAuthTime`) from the record. A code that recorded no primary
 * cannot tell it, as `/authorize` could not. `undefined` when the record's
 * primary is not the code's, or cannot be read: the record's other facts are
 * not that code's, and the code is refused rather than read as one whose
 * primary cannot be told, which a freshness ask reads as fresh.
 */
export declare function codeReadingOver(code: CodeReading, session: UserSession): AuthenticationReading | undefined;
/**
 * What a session requirement is handed: `reading` as a frozen copy of its
 * own (its `mfaAt` a `Date` of its own), so what one holder does to it
 * reaches no other.
 */
export declare function requirementSessionOf(reading: AuthenticationReading): RequirementSession;
/**
 * What a session requirement is asked about `session`: how it was
 * established and what it vouches for, as the two readers above answer them
 * from one reading of the record, or `null` when there is no session (no
 * `sid`, or no `UserSessionStore`). Its `acr` selection reads the `amr` from
 * it: one built from the record's own `amr` would let a value an untrusted
 * IdP asserted in a pre-upgrade session meet an `acr`.
 */
export declare function requirementSession(session: UserSession | null): RequirementSession | null;
/**
 * What a session requirement is asked about a token that carries no live
 * session: {@link tokenReading} of its `amr`. A frozen copy.
 */
export declare function requirementSessionFromAmr(amr: readonly string[] | undefined): RequirementSession;
/** The `CodeData` fields a code records of how its session had authenticated: the admitted answer's. */
type CodeFields = Extract<Admission, {
    readonly outcome: "admitted";
}>["codeFields"];
/**
 * What a code minted on `reading` records, a frozen copy: the vouched `amr`
 * and the primary with `mfaAt` — the primary `undefined` when it cannot be
 * told, never left out. Nothing for no reading (no user-session store).
 */
export declare function codeFieldsOf(reading: AuthenticationReading | null): CodeFields;
/**
 * A code record's `authentication` as a frozen copy (its `mfaAt` a `Date`
 * of its own), or `undefined` when the record carries none or one not in a
 * shape a code records: not a plain object (its prototype `Object.prototype`
 * or `null`), or one without both keys its own — each is recorded,
 * `undefined` included; a `primary` that is neither `undefined`
 * nor a non-empty string; an `mfaAt` that is neither `undefined` nor a
 * `Date` at or after the epoch. The one rule a code repository copies it by and the
 * exchange reads it by: the record is a deployment's store's, not trusted for
 * its shape.
 */
export declare function readCodeAuthentication(code: {
    readonly authentication?: unknown;
}): CodeAuthentication | undefined;
/**
 * What the exchange judges a code on, read once: its `authentication`
 * ({@link readCodeAuthentication}) and its `amr` — vouching for nothing when
 * not `wellFormedAmr` — or `undefined` when it carries no readable
 * `authentication`. `carrier` is the code record a claim builder was handed,
 * read by `CodeData`'s field names.
 */
export declare function readCodeAtExchange(carrier: object): CodeReading | undefined;
/**
 * Whether federation `name`'s upstream IdP's `amr` counts: only when
 * `core.federations.<name>.trustUpstreamAmr` is `true` beside `enabled: true`.
 * Then the IdP's values sit in the session's `amr` beside `fed`, where tokens
 * carry them and `acr` is matched against them; otherwise they are kept
 * apart, for the record only. An entry is flat: a key named after its type is
 * one of the type's keys, and a switch under it is not read.
 *
 * A non-boolean value is a `RangeError` naming the key and quoting nothing of
 * the value: read either way, a typo would decide what this provider vouches
 * for. A disabled section's bad switch still refuses the composition. Core's
 * schema coerces environment-variable spellings first; a hand-built
 * configuration meets the refusal.
 *
 * The federation callback (which writes the split) and the `acr` drop both
 * read this function's answer, which boot carries in the
 * `federationSettings` slot (`trustsUpstreamAmr`), so they cannot disagree.
 */
export declare function federationTrustsUpstreamAmr(config: unknown, name: string): boolean;
/**
 * What an absent `callbackMeetsFreshness` reads as: `false`, so a federation
 * whose upstream shows no `auth_time` meets no freshness ask until an
 * operator says its callback does.
 */
export declare const CALLBACK_MEETS_FRESHNESS_DEFAULT = false;
/**
 * Whether federation `name`'s callback alone meets a freshness ask
 * (`prompt=login`, `max_age`) when its upstream shows no `auth_time`:
 * `core.federations.<name>.callbackMeetsFreshness`, absent read as
 * `CALLBACK_MEETS_FRESHNESS_DEFAULT`, and `false` unless `enabled: true`.
 * The federation callback decides with it what a session records, so the
 * readers of a session's freshness never read configuration. A non-boolean
 * value is a `RangeError`, as for `federationTrustsUpstreamAmr`.
 */
export declare function federationCallbackMeetsFreshness(config: unknown, name: string): boolean;
export {};
//# sourceMappingURL=authentication.d.mts.map