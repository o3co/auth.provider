/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * How a session was established and what this provider vouches for, read
 * one way by every consumer (session admission through `sessionReading`,
 * `tokenReading` and `codeReadingOver`, projected by `requirementSessionOf`
 * for the requirements and `codeFieldsOf` for the code `/authorize` mints and
 * `/token` stamps, and the `session` grant through `vouchedAmr`), beside what each
 * login path records (`passwordSessionAuthentication`,
 * `federatedSessionAuthentication`, `federationTrustsUpstreamAmr`,
 * `federationCallbackMeetsFreshness`), so the write and the read are one
 * design. See ADR
 * 2026-09-25-multi-factor-authentication.
 *
 * Also what a code record carries of it (`readCodeAuthentication`,
 * `readCodeAtExchange`): the one reading a code repository copies the code's
 * `authentication` by and the exchange judges the code on.
 *
 * Also how fresh a session's authentication is (`authenticationFreshness`,
 * `sessionFreshness`): what a freshness ask is judged against — the earlier
 * of `authTime` and a federated login's recorded upstream authentication,
 * never fresh when the upstream showed no time. `authTime` stays when this
 * provider established the session.
 *
 * A session carrying `authentication` holds in `amr` only what this
 * provider vouches for. One written before that key is split as it is read:
 * `fed` makes it federated and every other value an upstream IdP's, never
 * vouched for, whatever that federation's trust is now, because the session
 * does not say which federation wrote it; else `pwd` makes it a password
 * login; else its primary cannot be told. It has no second factor on
 * record. A pre-upgrade session is never read as more trusted than it was
 * written.
 *
 * A record comes from the deployment's own store, which may answer a value
 * in a shape the types do not admit. Such an `authentication` reads as one
 * that cannot be told: no primary, nothing vouched for. A stored `amr` in
 * such a shape vouches for nothing; a pre-upgrade one names no primary
 * unless it is an array that holds `fed`. No reader throws on either.
 */
import { federationsOf } from "../federations/configured.mjs";
import { FEDERATED_AMR, MFA_AMR, PASSWORD_AMR, wellFormedAmr, } from "../grants/authenticationClaims.mjs";
import { DEFAULT_CLOCK_SKEW_MS } from "../jwt/verify.mjs";
import { isRenewalNonce } from "./renewalNonce.mjs";
/** A copy of `authentication` that shares nothing with it: its list and its dates are new. */
export function copySessionAuthentication(authentication) {
    const { upstreamAuthTime } = authentication;
    return {
        primary: authentication.primary,
        federation: authentication.federation,
        upstreamAmr: authentication.upstreamAmr === undefined ? undefined : [...authentication.upstreamAmr],
        mfaAt: authentication.mfaAt === undefined ? undefined : new Date(authentication.mfaAt.getTime()),
        ...upstreamAuthTimeEntry(upstreamAuthTime instanceof Date ? new Date(upstreamAuthTime.getTime()) : upstreamAuthTime),
    };
}
/** `upstreamAuthTime` as an entry to spread: none for `undefined`, so absence stays absence. */
const upstreamAuthTimeEntry = (value) => value === undefined ? {} : { upstreamAuthTime: value };
/**
 * The instant `authentication` is as fresh as, for a session established at
 * `authTime`: the earlier of `authTime` and `upstreamAuthTime`; `authTime`
 * when the record holds no upstream instant (absent, or no `authentication`);
 * `undefined` — never fresh — for `null`, or an instant that is not a valid
 * date. A new `Date`. What a freshness ask (`max_age`, `prompt=login`, a
 * recent primary) is judged against; `authTime` itself stays when this
 * provider established the session.
 */
export function authenticationFreshness(authTime, authentication) {
    const authMs = authTime instanceof Date ? authTime.getTime() : Number.NaN;
    if (!Number.isFinite(authMs))
        return undefined;
    const upstream = authentication?.upstreamAuthTime;
    if (upstream === undefined)
        return new Date(authMs);
    if (upstream === null)
        return undefined;
    const upstreamMs = upstream instanceof Date ? upstream.getTime() : Number.NaN;
    return Number.isFinite(upstreamMs) ? new Date(Math.min(authMs, upstreamMs)) : undefined;
}
/**
 * {@link authenticationFreshness} of `session`, its record read once by the
 * one reading of it: a recorded `authentication` that reading refuses is
 * `undefined`, never fresher than it was written; one written before the key
 * is as fresh as `authTime`.
 */
export function sessionFreshness(session) {
    const reading = readRecord(session);
    return reading.unreadable
        ? undefined
        : authenticationFreshness(session.authTime, reading.established);
}
/**
 * How `session` was established, or `undefined` when that cannot be told: a
 * session written before the `authentication` key whose `amr` names neither a
 * federation nor a password, or one whose `authentication` or pre-upgrade
 * `amr` is not in a shape it admits. The baseline re-authenticates such a
 * session rather than guess. A copy: nothing done to the answer reaches the
 * session.
 */
export function sessionAuthentication(session) {
    return readRecord(session).established;
}
/**
 * The `amr` this provider vouches for in `session`, copied: what `acr` is
 * matched against and a token may carry. A recorded session's `amr`, which
 * holds nothing else; for one written before the `authentication` key, the
 * split: a federated session vouches for `fed` alone. Otherwise a stored
 * `amr` that is not `wellFormedAmr`, or an `authentication` not in a shape
 * it admits, vouches for nothing: a custom store's record is not trusted for
 * its shape.
 */
export function vouchedAmr(session) {
    return readRecord(session).vouched ?? [];
}
/**
 * Whether a second factor can be recorded on `session`: its primary can be
 * told and what it vouches for can be read. `sessionAfterSecondFactor`
 * answers `null` exactly when this is false.
 */
export function canRecordSecondFactor(session) {
    return isRecordable(readRecord(session));
}
const isRecordable = (reading) => reading.established !== undefined && reading.vouched !== undefined;
/**
 * The one reading of a session record: `authentication` and `amr` each read
 * once, and answered as copies. An `authentication` that
 * {@link readAuthentication} refuses by {@link READ_RULES} tells nothing. A pre-upgrade record is
 * split on an array that holds `fed` before its shape is read, so one that
 * also holds a value no token may carry is still federated and vouches for
 * `fed`; what is beside `fed` is kept as its upstream `amr` only when
 * `wellFormedAmr`. Any other stored `amr` vouches only when it is absent, an
 * empty array, or `wellFormedAmr`.
 */
function readRecord(session) {
    const stored = session.authentication;
    const amr = session.amr;
    const values = Array.isArray(amr) ? Array.from(amr) : undefined;
    const vouched = amr === undefined || values?.length === 0 ? [] : wellFormedAmr(values);
    if (stored !== undefined) {
        const read = readAuthentication(stored, READ_RULES);
        return read.admitted === undefined
            ? { established: undefined, vouched: undefined, unreadable: true }
            : { established: read.admitted, vouched };
    }
    if (values?.includes(FEDERATED_AMR)) {
        const upstream = values.filter((value) => value !== FEDERATED_AMR);
        return {
            established: {
                primary: FEDERATED_AMR,
                federation: undefined,
                upstreamAmr: upstream.length > 0 ? wellFormedAmr(upstream) : undefined,
                mfaAt: undefined,
            },
            vouched: [FEDERATED_AMR],
        };
    }
    return {
        established: vouched?.includes(PASSWORD_AMR)
            ? { primary: PASSWORD_AMR, federation: undefined, upstreamAmr: undefined, mfaAt: undefined }
            : undefined,
        vouched,
    };
}
/**
 * What `POST /session/login` records: `amr` `["pwd"]` (RFC 8176), primary
 * `pwd`, no second factor verified yet.
 */
export function passwordSessionAuthentication() {
    return {
        amr: [PASSWORD_AMR],
        authentication: {
            primary: PASSWORD_AMR,
            federation: undefined,
            upstreamAmr: undefined,
            mfaAt: undefined,
        },
    };
}
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
export function federatedSessionAuthentication(login) {
    const upstream = [...login.upstreamAmr];
    const upstreamAuthTime = login.upstreamAuthTime !== undefined
        ? new Date(login.upstreamAuthTime.getTime())
        : login.callbackMeetsFreshness === false
            ? null
            : undefined;
    return {
        amr: login.trusted ? [...new Set([...upstream, FEDERATED_AMR])] : [FEDERATED_AMR],
        authentication: {
            primary: FEDERATED_AMR,
            federation: login.federation,
            upstreamAmr: !login.trusted && upstream.length > 0 ? upstream : undefined,
            mfaAt: undefined,
            ...upstreamAuthTimeEntry(upstreamAuthTime),
        },
    };
}
/**
 * Whether `ms` is an instant a session may record as when the user
 * authenticated (`authTime`) or a second factor was verified (`mfaAt`), on
 * the store's clock `nowMs`: at or after the epoch, and no further ahead than
 * the clock skew tolerated between hosts (`DEFAULT_CLOCK_SKEW_MS`, the JWT
 * verifier's `iat` tolerance). Clocks are NTP-synced; one further ahead is no
 * clock's reading. What is accepted is still recorded no later than `nowMs`
 * (`notAfter`).
 */
const isRecordableSessionInstant = (ms, nowMs) => isReadableVerificationTime(ms) && ms <= nowMs + DEFAULT_CLOCK_SKEW_MS;
/**
 * Whether `ms` is an instant a stored `mfaAt` may hold as it is read: at or
 * after the epoch. The readers hold no clock; what reads `mfaAt` against one
 * caps it there.
 */
const isReadableVerificationTime = (ms) => Number.isFinite(ms) && ms >= 0;
/**
 * The rules a stored `authentication` is read by. A `null` `federation` is
 * none: a store may map an empty column to `null`, and the federation grants
 * nothing. A `null` `upstreamAuthTime` is a value of its own (never fresh).
 * Any other `null` field is refused.
 */
const READ_RULES = {
    admitsInstant: isReadableVerificationTime,
    nullFederationIsNone: true,
};
/** `ms` as an instant no later than `nowMs`, the store's clock: a new `Date`. */
const notAfter = (ms, nowMs) => new Date(Math.min(ms, nowMs));
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
export function checkSecondFactorEvent(event, nowMs) {
    const amr = event?.amr;
    if (!Array.isArray(amr) || amr.length === 0) {
        throw new RangeError("recordSecondFactor: a second factor adds at least one amr value");
    }
    for (const value of amr) {
        if (typeof value !== "string" || value.length === 0) {
            throw new RangeError("recordSecondFactor: amr values must be non-empty strings");
        }
        if (value === PASSWORD_AMR || value === FEDERATED_AMR) {
            throw new RangeError(`recordSecondFactor: "${value}" marks a primary authentication, never a second factor's amr`);
        }
    }
    if (amr.every((value) => value === MFA_AMR)) {
        throw new RangeError(`recordSecondFactor: "${MFA_AMR}" comes beside a factor's own amr values, never alone`);
    }
    const at = event.at;
    const atMs = at instanceof Date ? at.getTime() : Number.NaN;
    if (!isRecordableSessionInstant(atMs, nowMs)) {
        throw new RangeError("recordSecondFactor: at must be a valid date at or after the epoch, and no further ahead than hosts' clocks drift");
    }
}
/**
 * The event's `renewalNonce` and `expectedRenewalNonce`, each read once and
 * answered as a frozen copy: what a store compares and records is what was
 * checked. Refuses, with a `RangeError`, one that is not a nonce
 * (`isRenewalNonce`).
 */
export function readRenewalNonces(event) {
    const renewalNonce = event?.renewalNonce;
    if (renewalNonce !== undefined && !isRenewalNonce(renewalNonce)) {
        throw new RangeError("recordSecondFactor: renewalNonce must be one newRenewalNonce spells");
    }
    const expectedRenewalNonce = event?.expectedRenewalNonce;
    if (expectedRenewalNonce !== undefined && !isRenewalNonce(expectedRenewalNonce)) {
        throw new RangeError("recordSecondFactor: expectedRenewalNonce must be one newRenewalNonce spells");
    }
    return Object.freeze({
        ...(renewalNonce === undefined ? {} : { renewalNonce }),
        ...(expectedRenewalNonce === undefined ? {} : { expectedRenewalNonce }),
    });
}
/**
 * Whether a session holding `held` may record an event whose nonces are
 * `nonces`: its renewal nonce is the one expected, absent matching absent.
 * Every bundled store asks it in the same atomic step as its write.
 */
export function expectsRenewalNonce(held, nonces) {
    return held === nonces.expectedRenewalNonce;
}
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
export function recordableSessionAuthentication(sid, authentication, nowMs) {
    if (authentication === undefined)
        return undefined;
    const read = readAuthentication(authentication, {
        admitsInstant: (ms) => isRecordableSessionInstant(ms, nowMs),
        nullFederationIsNone: false,
    });
    if (read.admitted === undefined) {
        throw new RangeError(`UserSession ${sid}: ${read.refused} must be ${RECORDABLE_RULES[read.refused]}`);
    }
    const { mfaAt, upstreamAuthTime } = read.admitted;
    return {
        ...read.admitted,
        mfaAt: mfaAt === undefined ? undefined : notAfter(mfaAt.getTime(), nowMs),
        ...upstreamAuthTimeEntry(upstreamAuthTime instanceof Date
            ? notAfter(upstreamAuthTime.getTime(), nowMs)
            : upstreamAuthTime),
    };
}
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
export function recordableAuthTime(sid, authTime, nowMs) {
    const ms = authTime instanceof Date ? authTime.getTime() : Number.NaN;
    if (!isRecordableSessionInstant(ms, nowMs)) {
        throw new RangeError(`UserSession ${sid}: authTime must be a valid date at or after the epoch, no further ahead than hosts' clocks drift`);
    }
    return notAfter(ms, nowMs);
}
/** What `recordableSessionAuthentication` says each field must be. */
const RECORDABLE_RULES = {
    authentication: "an object, or undefined",
    "authentication.primary": "a non-empty string",
    "authentication.federation": "a string, or undefined",
    "authentication.upstreamAmr": "a list of strings, or undefined",
    "authentication.mfaAt": "a valid date at or after the epoch, no further ahead than hosts' clocks drift, or undefined",
    "authentication.upstreamAuthTime": "a valid date at or after the epoch, no further ahead than hosts' clocks drift, null, or undefined — undefined for a password primary",
};
/**
 * `value` as a `SessionAuthentication`, each field read once and the answer
 * a copy, or the first field it refuses: not an object; a `primary` that is
 * not a non-empty string; a `federation` that is not a string (a `null` one
 * is none when `rules.nullFederationIsNone`); an `upstreamAmr` that is not a
 * list of strings; an `mfaAt` that is not a `Date` whose time
 * `rules.admitsInstant`; an `upstreamAuthTime` that is neither `null` nor
 * such a `Date`, or any on a password primary, which has no upstream. A field may be `undefined`, `primary` excepted; an
 * `upstreamAuthTime` that is `undefined` is left out of the answer. The one
 * rule a store records by and the readers read by.
 */
function readAuthentication(value, rules) {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        return { refused: "authentication" };
    }
    const a = value;
    const primary = a.primary;
    if (typeof primary !== "string" || primary.length === 0) {
        return { refused: "authentication.primary" };
    }
    const stored = a.federation;
    const federation = stored === null && rules.nullFederationIsNone ? undefined : stored;
    if (federation !== undefined && typeof federation !== "string") {
        return { refused: "authentication.federation" };
    }
    const upstream = a.upstreamAmr;
    const upstreamAmr = Array.isArray(upstream) ? Array.from(upstream) : upstream;
    if (upstreamAmr !== undefined &&
        !(Array.isArray(upstreamAmr) && upstreamAmr.every((v) => typeof v === "string"))) {
        return { refused: "authentication.upstreamAmr" };
    }
    const mfaAt = a.mfaAt;
    const mfaAtMs = mfaAt instanceof Date ? mfaAt.getTime() : Number.NaN;
    if (mfaAt !== undefined && !rules.admitsInstant(mfaAtMs)) {
        return { refused: "authentication.mfaAt" };
    }
    const upstreamAuthTime = a.upstreamAuthTime;
    const upstreamAuthTimeMs = upstreamAuthTime instanceof Date ? upstreamAuthTime.getTime() : Number.NaN;
    if (upstreamAuthTime !== undefined &&
        (primary === PASSWORD_AMR ||
            (upstreamAuthTime !== null && !rules.admitsInstant(upstreamAuthTimeMs)))) {
        return { refused: "authentication.upstreamAuthTime" };
    }
    return {
        admitted: {
            primary,
            federation,
            upstreamAmr: upstreamAmr,
            mfaAt: mfaAt === undefined ? undefined : new Date(mfaAtMs),
            ...upstreamAuthTimeEntry(upstreamAuthTime === undefined || upstreamAuthTime === null
                ? upstreamAuthTime
                : new Date(upstreamAuthTimeMs)),
        },
    };
}
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
export function sessionAfterSecondFactor(session, event, nowMs) {
    checkSecondFactorEvent(event, nowMs);
    const reading = readRecord(session);
    if (!isRecordable(reading))
        return null;
    const { established: authentication, vouched } = reading;
    const atMs = Math.min(event.at.getTime(), nowMs);
    const storedMs = authentication.mfaAt === undefined
        ? undefined
        : Math.min(authentication.mfaAt.getTime(), nowMs);
    const mfaAt = new Date(storedMs !== undefined && storedMs >= atMs ? storedMs : atMs);
    return {
        amr: [...new Set([...vouched, ...event.amr])],
        authentication: { ...authentication, mfaAt },
    };
}
/** `session` read once by the D9 reading: a copy. */
export function sessionReading(session) {
    const { established, vouched } = readRecord(session);
    return { established, vouched: vouched ?? [] };
}
/**
 * A token that carries no live session: the primary read from the token's
 * `amr` (`fed`, else `pwd`, else unknown, as for an older token that carries
 * no `amr`), no second factor on record, and the `amr` as vouched, since a
 * token is minted from `vouchedAmr` and carries nothing an IdP asserted.
 */
export function tokenReading(amr) {
    const held = amr === undefined ? [] : [...amr];
    const primary = held.includes(FEDERATED_AMR)
        ? FEDERATED_AMR
        : held.includes(PASSWORD_AMR)
            ? PASSWORD_AMR
            : undefined;
    return {
        established: primary === undefined
            ? undefined
            : { primary, federation: undefined, upstreamAmr: undefined, mfaAt: undefined },
        vouched: held,
    };
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
export function codeReadingOver(code, session) {
    if (code.primary === undefined)
        return { established: undefined, vouched: code.vouched };
    const { established } = readRecord(session);
    if (established === undefined || established.primary !== code.primary)
        return undefined;
    return {
        established: {
            ...established,
            mfaAt: code.mfaAt === undefined ? undefined : new Date(code.mfaAt.getTime()),
        },
        vouched: code.vouched,
    };
}
/**
 * What a session requirement is handed: `reading` as a frozen copy of its
 * own (its `mfaAt` a `Date` of its own), so what one holder does to it
 * reaches no other.
 */
export function requirementSessionOf(reading) {
    return frozenRequirementSession(reading.established, reading.vouched);
}
/**
 * What a session requirement is asked about `session`: how it was
 * established and what it vouches for, as the two readers above answer them
 * from one reading of the record, or `null` when there is no session (no
 * `sid`, or no `UserSessionStore`). Its `acr` selection reads the `amr` from
 * it: one built from the record's own `amr` would let a value an untrusted
 * IdP asserted in a pre-upgrade session meet an `acr`.
 */
export function requirementSession(session) {
    return session === null ? null : requirementSessionOf(sessionReading(session));
}
/**
 * A requirement's reading, frozen with its `amr` and `upstreamAmr`: each
 * call's own copy (its dates of its own), so what one holder does to it
 * reaches no other.
 */
const frozenRequirementSession = (authentication, amr) => {
    const copy = authentication === undefined ? undefined : copySessionAuthentication(authentication);
    return Object.freeze({
        authentication: copy === undefined
            ? undefined
            : Object.freeze({
                ...copy,
                upstreamAmr: copy.upstreamAmr === undefined ? undefined : Object.freeze(copy.upstreamAmr),
            }),
        amr: Object.freeze([...amr]),
    });
};
/**
 * What a session requirement is asked about a token that carries no live
 * session: {@link tokenReading} of its `amr`. A frozen copy.
 */
export function requirementSessionFromAmr(amr) {
    return requirementSessionOf(tokenReading(amr));
}
/**
 * What a code minted on `reading` records, a frozen copy: the vouched `amr`
 * and the primary with `mfaAt` — the primary `undefined` when it cannot be
 * told, never left out. Nothing for no reading (no user-session store).
 */
export function codeFieldsOf(reading) {
    if (reading === null)
        return Object.freeze({ amr: undefined, authentication: undefined });
    const mfaAt = reading.established?.mfaAt;
    return Object.freeze({
        amr: Object.freeze([...reading.vouched]),
        authentication: Object.freeze({
            primary: reading.established?.primary,
            mfaAt: mfaAt === undefined ? undefined : new Date(mfaAt.getTime()),
        }),
    });
}
/** Whether `value` is a plain object: its prototype `Object.prototype` or `null`, never an array, a `Date` or another instance. */
const isPlainObject = (value) => {
    if (typeof value !== "object" || value === null)
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
};
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
export function readCodeAuthentication(code) {
    const stored = code.authentication;
    if (!isPlainObject(stored) ||
        !Object.hasOwn(stored, "primary") ||
        !Object.hasOwn(stored, "mfaAt")) {
        return undefined;
    }
    const { primary, mfaAt } = stored;
    if (primary !== undefined && (typeof primary !== "string" || primary.length === 0)) {
        return undefined;
    }
    const mfaAtMs = mfaAt instanceof Date ? mfaAt.getTime() : Number.NaN;
    if (mfaAt !== undefined && !READ_RULES.admitsInstant(mfaAtMs))
        return undefined;
    return Object.freeze({
        primary,
        mfaAt: mfaAt === undefined ? undefined : new Date(mfaAtMs),
    });
}
/**
 * What the exchange judges a code on, read once: its `authentication`
 * ({@link readCodeAuthentication}) and its `amr` — vouching for nothing when
 * not `wellFormedAmr` — or `undefined` when it carries no readable
 * `authentication`. `carrier` is the code record a claim builder was handed,
 * read by `CodeData`'s field names.
 */
export function readCodeAtExchange(carrier) {
    const code = carrier;
    const authentication = readCodeAuthentication(code);
    if (authentication === undefined)
        return undefined;
    return Object.freeze({
        primary: authentication.primary,
        mfaAt: authentication.mfaAt,
        vouched: Object.freeze([...(wellFormedAmr(code.amr) ?? [])]),
    });
}
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
export function federationTrustsUpstreamAmr(config, name) {
    return enabledFederationSwitch(config, name, "trustUpstreamAmr", false);
}
/**
 * What an absent `callbackMeetsFreshness` reads as: `false`, so a federation
 * whose upstream shows no `auth_time` meets no freshness ask until an
 * operator says its callback does.
 */
export const CALLBACK_MEETS_FRESHNESS_DEFAULT = false;
/**
 * Whether federation `name`'s callback alone meets a freshness ask
 * (`prompt=login`, `max_age`) when its upstream shows no `auth_time`:
 * `core.federations.<name>.callbackMeetsFreshness`, absent read as
 * `CALLBACK_MEETS_FRESHNESS_DEFAULT`, and `false` unless `enabled: true`.
 * The federation callback decides with it what a session records, so the
 * readers of a session's freshness never read configuration. A non-boolean
 * value is a `RangeError`, as for `federationTrustsUpstreamAmr`.
 */
export function federationCallbackMeetsFreshness(config, name) {
    return enabledFederationSwitch(config, name, "callbackMeetsFreshness", CALLBACK_MEETS_FRESHNESS_DEFAULT);
}
/**
 * A boolean switch of federation `name`'s entry, read as an own key of the
 * flat entry: `absent` when not written, and `false` unless the entry is
 * enabled. A written value that is not a boolean is a `RangeError` naming
 * the key and quoting nothing of the value, enabled or not.
 */
function enabledFederationSwitch(config, name, key, absent) {
    const federations = federationsOf(config);
    if (!Object.hasOwn(federations, name))
        return false;
    const section = federations[name];
    if (typeof section !== "object" || section === null)
        return false;
    const value = Object.hasOwn(section, key)
        ? section[key]
        : undefined;
    if (value !== undefined && typeof value !== "boolean") {
        throw new RangeError(`core.federations.${name}.${key} must be true or false`);
    }
    const enabled = Object.hasOwn(section, "enabled") && section.enabled === true;
    return enabled && (value ?? absent);
}
