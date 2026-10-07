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
import { isStorableExpiry, isStorableLifetime } from "../adapters/expiry.mjs";
import { DEFAULT_CLOCK_SKEW_MS } from "../jwt/verify.mjs";
import { constantTimeStringEqual } from "../security/timingSafe.mjs";
import { checkPrimaryContinuation } from "../session-admission/primary.mjs";
/** The keys an {@link MfaTransactionPatch} may carry, for an adapter that copies one field by field. */
export const MFA_TRANSACTION_PATCH_KEYS = [
    "enrollment",
    "emailProof",
    "challenge",
    "pendingEnrollment",
];
const isCount = (value) => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
const isInstant = (value) => typeof value === "number" && Number.isFinite(value);
const isText = (value) => typeof value === "string";
const isRecord = (value) => typeof value === "object" && value !== null && !Array.isArray(value);
/**
 * `value` as an admitted binding, copied to its known fields, or `undefined`.
 * A session id must be a non-empty, well-formed string: lone surrogates all
 * encode as U+FFFD, so two different ids would compare alike. An unknown kind
 * is no binding. `kind` and `id` are read once, so a getter cannot pass the
 * check and hand over something else; a read that throws is no binding.
 */
const bindingOf = (value) => {
    try {
        if (!isRecord(value))
            return undefined;
        const { kind, id } = value;
        return kind === "session" && isText(id) && id.length > 0 && id.isWellFormed()
            ? { kind, id }
            : undefined;
    }
    catch {
        return undefined;
    }
};
/** The binding `holder` carries, read once through {@link bindingOf}; `undefined` when reading it throws. */
const heldBinding = (holder) => {
    try {
        return isRecord(holder) ? bindingOf(holder.binding) : undefined;
    }
    catch {
        return undefined;
    }
};
/**
 * Each patch field's rule: the value as the store keeps it — sub-objects
 * copied to their known fields only — or `undefined` when the field does not
 * admit it. `null` is decided before this.
 */
const PATCH_VALUE_RULES = {
    enrollment: (v) => v === "none" || v === "allowed" || v === "required" ? { value: v } : undefined,
    emailProof: (v) => {
        if (v === "not_required" || v === "required")
            return { value: v };
        return isRecord(v) && isInstant(v.provedAtMs)
            ? { value: { provedAtMs: v.provedAtMs } }
            : undefined;
    },
    challenge: (v) => isRecord(v) &&
        isText(v.factorId) &&
        isText(v.kind) &&
        isText(v.state) &&
        isInstant(v.expiresAtMs)
        ? {
            value: {
                factorId: v.factorId,
                kind: v.kind,
                state: v.state,
                expiresAtMs: v.expiresAtMs,
            },
        }
        : undefined,
    pendingEnrollment: (v) => isRecord(v) && isText(v.kind) && isText(v.state) && isInstant(v.expiresAtMs)
        ? { value: { kind: v.kind, state: v.state, expiresAtMs: v.expiresAtMs } }
        : undefined,
};
/** The fields `null` may clear. */
const CLEARABLE = new Set([
    "challenge",
    "pendingEnrollment",
]);
/**
 * What a patch writes, per {@link MfaTransactionPatch}: each key with its value
 * as the store keeps it (sub-objects copied to known fields), or `undefined`
 * for a field `null` clears. Absent, `undefined` and unknown keys are skipped.
 * Throws a `RangeError` naming the key before anything is written. Every
 * adapter calls it first, then {@link checkMfaTransactionTransitions} on the
 * record at the expected version.
 */
export function mfaTransactionPatchWrites(patch) {
    if (!isRecord(patch)) {
        throw new RangeError("MfaTransactionStore.update: the patch must be an object");
    }
    const writes = [];
    for (const key of MFA_TRANSACTION_PATCH_KEYS) {
        if (!Object.hasOwn(patch, key))
            continue;
        const value = patch[key];
        if (value === undefined)
            continue;
        if (value === null) {
            if (!CLEARABLE.has(key)) {
                throw new RangeError(`MfaTransactionStore.update: ${key} cannot be cleared`);
            }
            writes.push([key, undefined]);
            continue;
        }
        const admitted = PATCH_VALUE_RULES[key](value);
        if (admitted === undefined) {
            throw new RangeError(`MfaTransactionStore.update: ${key} is not a value it admits`);
        }
        writes.push([key, admitted.value]);
    }
    return writes;
}
const ENROLLMENT_RANK = {
    none: 0,
    allowed: 1,
    required: 2,
};
/**
 * Refuses, with a `RangeError`, writes that would undo a requirement of
 * `current`: a required email proof becoming anything but met or a met one
 * undone (a required proof is met, never waived), `enrollment` lowered
 * (`none` < `allowed` < `required`). Every adapter calls it on the record at
 * the expected version, before writing.
 */
export function checkMfaTransactionTransitions(current, writes) {
    for (const [key, next] of writes) {
        if (key === "enrollment" &&
            ENROLLMENT_RANK[next] < ENROLLMENT_RANK[current.enrollment]) {
            throw new RangeError("MfaTransactionStore.update: enrollment cannot be lowered");
        }
        if (key === "emailProof") {
            const met = typeof next === "object";
            if (typeof current.emailProof === "object" && !met) {
                throw new RangeError("MfaTransactionStore.update: a met email proof stays met");
            }
            if (current.emailProof === "required" && next !== "required" && !met) {
                throw new RangeError("MfaTransactionStore.update: a required email proof can only be met");
            }
        }
    }
}
const isTextOrAbsent = (value) => value === undefined || isText(value);
/**
 * The record a store keeps for a new transaction, or a `RangeError`. Every
 * field is held to its type (patch fields by the patch rules, `enrollment` and
 * `emailProof` required), `attempts` must be `0`, and `version` a safe
 * non-negative integer: a limit is only as good as the count it starts from
 * (with `attempts` NaN, `NaN + 1 > max` is false and every reservation
 * passes). Only a transaction's fields are kept, sub-objects copied to known
 * fields. Every adapter calls it in `create`, beside its own expiry check.
 */
export function newMfaTransactionRecord(tx) {
    const refuse = (what) => {
        throw new RangeError(`MfaTransactionStore.create: ${what}`);
    };
    if (!isRecord(tx))
        refuse("the transaction must be an object");
    if (tx.attempts !== 0)
        refuse("attempts must be 0");
    if (!isCount(tx.version))
        refuse("version must be a safe non-negative integer");
    if (!isText(tx.id) || !isText(tx.subject))
        refuse("id and subject must be strings");
    const binding = heldBinding(tx) ??
        refuse('binding must be { kind: "session", id } with id a non-empty, well-formed string');
    if (tx.purpose !== "login" && tx.purpose !== "step_up" && tx.purpose !== "enroll") {
        refuse("purpose is not a value it admits");
    }
    if (!isTextOrAbsent(tx.sid) || !isTextOrAbsent(tx.redirectTo)) {
        refuse("sid and redirectTo must be strings or absent");
    }
    let continuation;
    if (tx.continuation !== undefined) {
        try {
            continuation = checkPrimaryContinuation(tx.continuation);
        }
        catch (cause) {
            throw new RangeError("MfaTransactionStore.create: continuation is not a value it admits", {
                cause,
            });
        }
        // One record, one login: the transaction's subject and redirectTo are
        // the continuation's primary's, so a record cannot resume one login
        // under another's name or send it elsewhere afterwards.
        if (continuation.primary.subject !== tx.subject) {
            refuse("subject must be the continuation's primary's");
        }
        if (continuation.primary.redirectTo !== tx.redirectTo) {
            refuse("redirectTo must be the continuation's primary's");
        }
    }
    if (tx.acrValues !== undefined && !(Array.isArray(tx.acrValues) && tx.acrValues.every(isText))) {
        refuse("acrValues must be a list of strings or absent");
    }
    if (!isInstant(tx.createdAtMs))
        refuse("createdAtMs must be an instant");
    const field = (key, optional) => {
        const value = tx[key];
        if (value === undefined && optional)
            return undefined;
        const admitted = PATCH_VALUE_RULES[key](value);
        if (admitted === undefined)
            return refuse(`${key} is not a value it admits`);
        return admitted.value;
    };
    return {
        id: tx.id,
        purpose: tx.purpose,
        binding,
        subject: tx.subject,
        sid: tx.sid,
        continuation,
        redirectTo: tx.redirectTo,
        enrollment: field("enrollment", false),
        emailProof: field("emailProof", false),
        acrValues: tx.acrValues === undefined ? undefined : [...tx.acrValues],
        challenge: field("challenge", true),
        pendingEnrollment: field("pendingEnrollment", true),
        attempts: 0,
        createdAtMs: tx.createdAtMs,
        expiresAtMs: tx.expiresAtMs,
        version: tx.version,
    };
}
/**
 * The most live transactions one binding holds — a browser session's tabs,
 * each in a ceremony of its own. `create` past it ends the binding's oldest
 * rather than refusing the new one: the transaction a user opened last is the
 * one they are looking at. A core constant, not configuration: it bounds the
 * state the store owns, which no deployment needs to raise.
 */
export const MFA_MAX_TRANSACTIONS_PER_BINDING = 5;
/**
 * Whether `tx` is bound to `binding`, the whole binding compared, kind
 * included. Another kind, a binding either side does not admit (such as an id
 * that is not a well-formed string), or one whose reading throws never matches.
 * Each side is read once and the ids compared in constant time. Every use of a
 * transaction makes this comparison, through {@link getBoundMfaTransaction}.
 *
 * Constant time holds only for ids of equal length (`security/timingSafe.mts`).
 * The session kind's length is public (an express session id is 32 characters,
 * carried in the cookie); a kind with secret-length ids must compare
 * fixed-length digests instead.
 */
export function isMfaTransactionBoundTo(tx, binding) {
    const held = heldBinding(tx);
    const presented = bindingOf(binding);
    if (held === undefined || presented === undefined)
        return false;
    return held.kind === presented.kind && constantTimeStringEqual(held.id, presented.id);
}
/**
 * The transaction `id` names if it is bound to `binding`
 * ({@link isMfaTransactionBoundTo}), else `null`: a transaction bound to
 * anything else reads as an unknown id, so a mismatch reveals nothing. A store
 * that cannot answer rejects, as its `get` does.
 *
 * - **It comes first.** Every use of a transaction starts with this read, then
 *   calls only operations carrying the version it read (`update`,
 *   `takeChallenge`, `consume`), plus `reserveAttempt` once the read held: that
 *   deletes the transaction past `max`, so on a bare id anyone holding it could
 *   destroy the ceremony.
 * - **It is necessary, not sufficient.** A `step_up` or `enroll` transaction
 *   upgrades one `UserSession`; the route also compares `tx.sid` with the
 *   session's `sid`.
 */
export async function getBoundMfaTransaction(store, id, binding) {
    const tx = await store.get(id);
    return tx !== null && isMfaTransactionBoundTo(tx, binding) ? tx : null;
}
/**
 * `answer`, what `reserveAttempt(id, max)` answered, as the port promises
 * it: `ok` the literal boolean, `attempts` a safe integer — from 1 to `max`
 * when reserved, from 0 when not. `undefined` for anything else, which the
 * caller answers as the store's outage before any proof is checked: a count
 * it cannot read limits nothing. Each field is read once.
 */
export function readMfaAttemptReservation(answer, max) {
    try {
        if (!isRecord(answer))
            return undefined;
        const { ok, attempts } = answer;
        if (typeof ok !== "boolean" || !isCount(attempts))
            return undefined;
        if (ok && (attempts < 1 || attempts > max))
            return undefined;
        return { ok, attempts };
    }
    catch {
        return undefined;
    }
}
const SUBJECT_HOLDS = new Set(["backoff", "weekly", "hard"]);
/**
 * `answer`, what `reserveSubjectAttempt` answered, as the port promises it:
 * a pass with its reservation, a non-empty string; or a hold the port names,
 * with `first` a boolean and a time to come back — `null` for the hard hold,
 * else a finite number of milliseconds above 0, since the hold applies at the
 * time asked about. Copied to those fields. `undefined` for anything else,
 * which the caller answers as the store's outage: never a pass, never a hold.
 * Each field is read once.
 */
export function readMfaSubjectAttemptReservation(answer) {
    try {
        if (!isRecord(answer))
            return undefined;
        const { ok, reservation, hold, retryAfterMs, first } = answer;
        if (ok === true) {
            return isText(reservation) && reservation.length > 0 ? { ok, reservation } : undefined;
        }
        if (ok !== false || !SUBJECT_HOLDS.has(hold) || typeof first !== "boolean")
            return undefined;
        if (hold === "hard") {
            return retryAfterMs === null ? { ok, hold, retryAfterMs, first } : undefined;
        }
        return typeof retryAfterMs === "number" && Number.isFinite(retryAfterMs) && retryAfterMs > 0
            ? { ok, hold: hold, retryAfterMs, first }
            : undefined;
    }
    catch {
        return undefined;
    }
}
/**
 * `answer`, what `sessionEmailProofAt(subject, sid, nowMs)` answered, as the
 * port promises it: `null` for no proof, or when the proof was given — a
 * finite instant from the epoch to `nowMs`. `undefined` for anything else,
 * which the caller answers as the store's outage: a proof it cannot read
 * admits nothing.
 */
export function readSessionEmailProof(answer, nowMs) {
    if (answer === null)
        return null;
    return typeof answer === "number" && Number.isFinite(answer) && answer >= 0 && answer <= nowMs
        ? answer
        : undefined;
}
/** A non-empty string: a session's subject and `sid`, as a proof is kept for them. */
const isNonEmptyText = (value) => typeof value === "string" && value.length > 0;
/** Epoch milliseconds a proof is kept in: a safe integer at or after the epoch. */
const isEpochMs = (value) => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
/**
 * Refuses, with a `RangeError` naming what is wrong, a session's
 * account-email proof a store cannot keep, on `storeNowMs`, its clock:
 * `subject` and `sid` non-empty strings; `provedAtMs` and `untilMs` epoch
 * milliseconds, `untilMs` after `provedAtMs` and after `storeNowMs`, within
 * the Date range; `provedAtMs` no further ahead of `storeNowMs` than
 * {@link MFA_CLOCK_SKEW_ALLOWANCE_MS}. Every adapter runs it before it
 * records a proof, and on one it reads back.
 */
export function checkSessionEmailProof(subject, sid, provedAtMs, untilMs, storeNowMs) {
    const refuse = (what) => {
        throw new RangeError(`MfaTransactionStore.recordSessionEmailProof: ${what}`);
    };
    if (!isNonEmptyText(subject) || !isNonEmptyText(sid)) {
        refuse("subject and sid must be non-empty strings");
    }
    if (!isEpochMs(provedAtMs))
        refuse("provedAtMs must be epoch milliseconds");
    if (!isEpochMs(untilMs) || !isStorableExpiry(untilMs)) {
        refuse("untilMs must be epoch milliseconds within the Date range");
    }
    if (untilMs <= provedAtMs)
        refuse("untilMs must be after provedAtMs");
    if (!(untilMs > storeNowMs))
        refuse("untilMs must be after the store's clock");
    if (!(provedAtMs <= storeNowMs + MFA_CLOCK_SKEW_ALLOWANCE_MS)) {
        refuse("provedAtMs must be no further ahead of the store's clock than MFA_CLOCK_SKEW_ALLOWANCE_MS");
    }
}
/**
 * What a store answers of `proof` asked about at `nowMs`, on `storeNowMs`,
 * its clock: when it was given, no later than `nowMs`, while its `untilMs`
 * is after both; else `null`. Every adapter answers through it.
 */
export function sessionEmailProofAnswer(proof, nowMs, storeNowMs) {
    return proof.untilMs > nowMs && proof.untilMs > storeNowMs
        ? Math.min(proof.provedAtMs, nowMs)
        : null;
}
/**
 * Refuses, with a `RangeError`, a question `sessionEmailProofAt` cannot
 * answer: `subject` and `sid` non-empty strings, `nowMs` an instant from the
 * epoch within the Date range. Every adapter runs it first.
 */
export function checkSessionEmailProofQuestion(subject, sid, nowMs) {
    if (!isNonEmptyText(subject) || !isNonEmptyText(sid)) {
        throw new RangeError("MfaTransactionStore.sessionEmailProofAt: subject and sid must be non-empty strings");
    }
    if (typeof nowMs !== "number" || !isStorableExpiry(nowMs) || nowMs < 0) {
        throw new RangeError("MfaTransactionStore.sessionEmailProofAt: nowMs must be an instant from the epoch within the Date range");
    }
}
/**
 * `answer`, what `firstBindingAt(subject, nowMs)` answered, as the port
 * promises it: `null` for no mark, or when it was noted — whole epoch
 * milliseconds, no further ahead of `nowMs` than `DEFAULT_CLOCK_SKEW_MS`.
 * `undefined` for anything else, which the caller answers as the store's
 * outage: a mark it cannot read trusts no session. This is the mark's one
 * reading.
 */
export function readFirstBindingAt(answer, nowMs) {
    if (answer === null)
        return null;
    return isEpochMs(answer) && answer <= nowMs + DEFAULT_CLOCK_SKEW_MS ? answer : undefined;
}
/**
 * Refuses, with a `RangeError` naming what is wrong, a first-binding mark a
 * store cannot keep. Its shape: `subject` a non-empty string; `atMs` and
 * `untilMs` whole epoch milliseconds within the Date range, `untilMs` after
 * `atMs` by at most {@link MFA_CLOCK_SKEW_ALLOWANCE_MS} (a mark stands a day
 * at most). On `storeNowMs`, the store's clock, when it is given: `untilMs`
 * after it, and `atMs` no further from it, either way, than
 * `DEFAULT_CLOCK_SKEW_MS`. Every adapter runs it before it notes a mark; an
 * adapter whose store judges the clock in a script runs the shape first and
 * the rest on the clock that script answers. A mark read back is held to the
 * shape, as an outage; where its time sits on the clock is the caller's
 * reading ({@link readFirstBindingAt}) to judge.
 */
export function checkFirstBindingNote(subject, atMs, untilMs, storeNowMs) {
    const refuse = (what) => {
        throw new RangeError(`MfaTransactionStore.noteFirstBinding: ${what}`);
    };
    if (!isNonEmptyText(subject))
        refuse("subject must be a non-empty string");
    if (!isEpochMs(atMs) || !isStorableExpiry(atMs)) {
        refuse("atMs must be epoch milliseconds within the Date range");
    }
    if (!isEpochMs(untilMs) || !isStorableExpiry(untilMs)) {
        refuse("untilMs must be epoch milliseconds within the Date range");
    }
    if (untilMs <= atMs)
        refuse("untilMs must be after atMs");
    if (untilMs - atMs > MFA_CLOCK_SKEW_ALLOWANCE_MS) {
        refuse("untilMs must be no more than MFA_CLOCK_SKEW_ALLOWANCE_MS after atMs");
    }
    if (storeNowMs === undefined)
        return;
    if (!(untilMs > storeNowMs))
        refuse("untilMs must be after the store's clock");
    if (!(atMs <= storeNowMs + DEFAULT_CLOCK_SKEW_MS)) {
        refuse("atMs must be no further ahead of the store's clock than DEFAULT_CLOCK_SKEW_MS");
    }
    if (!(atMs >= storeNowMs - DEFAULT_CLOCK_SKEW_MS)) {
        refuse("atMs must be no further behind the store's clock than DEFAULT_CLOCK_SKEW_MS");
    }
}
/**
 * Refuses, with a `RangeError`, a question `firstBindingAt` cannot answer:
 * `subject` a non-empty string, `nowMs` an instant from the epoch within the
 * Date range. Every adapter runs it first.
 */
export function checkFirstBindingQuestion(subject, nowMs) {
    if (!isNonEmptyText(subject)) {
        throw new RangeError("MfaTransactionStore.firstBindingAt: subject must be a non-empty string");
    }
    if (typeof nowMs !== "number" || !isStorableExpiry(nowMs) || nowMs < 0) {
        throw new RangeError("MfaTransactionStore.firstBindingAt: nowMs must be an instant from the epoch within the Date range");
    }
}
/**
 * The mark a store keeps of `held`, a mark that still stands on its clock,
 * and `next`: the later `atMs` and the later `untilMs`, whichever mark each
 * comes from. A mark distrusts, so no note moves it back or shortens it.
 */
export function laterFirstBindingMark(held, next) {
    return {
        atMs: Math.max(held.atMs, next.atMs),
        untilMs: Math.max(held.untilMs, next.untilMs),
    };
}
/**
 * What a store answers of `mark` on `storeNowMs`, its clock: `atMs`, never
 * moved earlier, while `untilMs` is after it; else `null`. The caller's time
 * never ends a mark. Every adapter answers through it.
 */
export function firstBindingAnswer(mark, storeNowMs) {
    return mark.untilMs > storeNowMs ? mark.atMs : null;
}
/**
 * Whether `consumed`, what `consume(bound.id, bound.version)` answered other
 * than `null`, is the transaction the bound read returned: the same id,
 * version, purpose, subject and `redirectTo`, bound to the same binding, and
 * a continuation — when the read had one — for the same subject and
 * redirect. The caller answers anything else as the store's outage and writes
 * nothing, before a factor moves on or a login resumes.
 */
export function isConsumedMfaTransaction(consumed, bound) {
    try {
        if (!isRecord(consumed))
            return false;
        const { id, version, purpose, subject, redirectTo, continuation } = consumed;
        if (id !== bound.id ||
            version !== bound.version ||
            purpose !== bound.purpose ||
            subject !== bound.subject ||
            redirectTo !== bound.redirectTo ||
            !isMfaTransactionBoundTo(consumed, bound.binding)) {
            return false;
        }
        const expected = bound.continuation;
        if (expected === undefined)
            return continuation === undefined;
        if (!isRecord(continuation) || !isRecord(continuation.primary))
            return false;
        const { primary } = continuation;
        return (primary.subject === expected.primary.subject &&
            primary.redirectTo === expected.primary.redirectTo);
    }
    catch {
        return false;
    }
}
/** The weekly budget's window: any rolling seven days. */
export const MFA_WEEKLY_WINDOW_MS = 7 * 86_400_000;
/**
 * How long a store keeps a failure after it stops counting: a day, on the
 * store's clock. A caller whose clock runs ahead by less erases nothing
 * a caller on time still counts. With NTP-synced clocks a day is ample; it
 * costs a day of extra state.
 */
export const MFA_CLOCK_SKEW_ALLOWANCE_MS = 86_400_000;
/** The most consecutive failures a lockout policy may allow: NIST SP 800-63B-4's cap. */
export const MFA_LOCKOUT_MAX_HARD_LIMIT = 100;
/**
 * The smallest `hardLimit` a configured policy may set
 * ({@link checkConfiguredMfaLockoutPolicy}).
 */
export const MFA_LOCKOUT_MIN_HARD_LIMIT = 10;
/**
 * The longest `maxSeconds` a configured policy may set, a week
 * ({@link checkConfiguredMfaLockoutPolicy}).
 */
export const MFA_LOCKOUT_MAX_BACKOFF_SECONDS = MFA_WEEKLY_WINDOW_MS / 1000;
/** The shortest subject lease a store gives. */
export const MFA_SUBJECT_LEASE_MIN_MS = 1_000;
/** The longest subject lease a store gives. */
export const MFA_SUBJECT_LEASE_MAX_MS = 600_000;
/**
 * The lease a factor-set write takes when its configuration names none: above
 * the few Store calls one write makes at the Store transport's default timeout.
 */
export const DEFAULT_MFA_SUBJECT_LEASE_MS = 60_000;
/** A non-empty string, read once by the caller. */
const isSubject = (value) => typeof value === "string" && value.length > 0;
/**
 * The request {@link MfaTransactionStore.acquireSubjectLease} acts on, its
 * fields read once, or a `RangeError`: `subject` a non-empty string, `ttlMs`
 * a whole number from {@link MFA_SUBJECT_LEASE_MIN_MS} to
 * {@link MFA_SUBJECT_LEASE_MAX_MS}, `generation` a safe whole number from 0.
 * Every adapter calls it first.
 */
export function checkSubjectLeaseRequest(subject, request) {
    const refuse = (what) => {
        throw new RangeError(`MfaTransactionStore.acquireSubjectLease: ${what}`);
    };
    if (!isSubject(subject))
        refuse("subject must be a non-empty string");
    if (!isRecord(request))
        return refuse("the request must be an object");
    const { ttlMs, generation } = request;
    if (typeof ttlMs !== "number" ||
        !Number.isSafeInteger(ttlMs) ||
        ttlMs < MFA_SUBJECT_LEASE_MIN_MS ||
        ttlMs > MFA_SUBJECT_LEASE_MAX_MS) {
        refuse(`ttlMs must be a whole number from MFA_SUBJECT_LEASE_MIN_MS (${MFA_SUBJECT_LEASE_MIN_MS}) to MFA_SUBJECT_LEASE_MAX_MS (${MFA_SUBJECT_LEASE_MAX_MS})`);
    }
    if (!isCount(generation)) {
        refuse("generation, the one the writer captured, must be a safe whole number from 0");
    }
    return { ttlMs: ttlMs, generation: generation };
}
/**
 * Refuses, with a `RangeError` naming `operation`, a subject that is not a
 * non-empty string. Every adapter runs it first for the operations that take
 * a subject alone.
 */
export function checkSubjectQuestion(operation, subject) {
    if (!isSubject(subject)) {
        throw new RangeError(`MfaTransactionStore.${operation}: subject must be a non-empty string`);
    }
}
/**
 * Refuses, with a `RangeError`, a release `releaseSubjectLease` cannot make:
 * `subject` and `token` non-empty strings. Every adapter runs it first.
 */
export function checkSubjectLeaseRelease(subject, token) {
    checkSubjectQuestion("releaseSubjectLease", subject);
    if (!isSubject(token)) {
        throw new RangeError("MfaTransactionStore.releaseSubjectLease: the token must be a non-empty string");
    }
}
/**
 * `answer`, what `acquireSubjectLease` answered, as the port promises it,
 * copied to its outcome's fields, each read once; `undefined` for anything
 * else, which the caller answers as the store's outage: never a lease, never
 * a refusal.
 */
export function readMfaSubjectLeaseAnswer(answer) {
    try {
        if (!isRecord(answer))
            return undefined;
        const { outcome } = answer;
        if (outcome === "acquired") {
            const { token } = answer;
            return isSubject(token) ? { outcome, token } : undefined;
        }
        if (outcome === "busy") {
            const { retryAfterMs } = answer;
            return typeof retryAfterMs === "number" && Number.isFinite(retryAfterMs) && retryAfterMs > 0
                ? { outcome, retryAfterMs }
                : undefined;
        }
        return outcome === "stale" ? { outcome } : undefined;
    }
    catch {
        return undefined;
    }
}
/**
 * `answer`, a subject's generation or recovery-set floor as the port promises
 * it: a safe whole number from 0. `undefined` for anything else, which the
 * caller answers as the store's outage.
 */
export function readMfaSubjectCount(answer) {
    return isCount(answer) ? answer : undefined;
}
/**
 * The raise `raiseRecoverySetFloor` makes, its fields read once, or a
 * `RangeError`: `subject` a non-empty string, `setGeneration` a safe whole
 * number from 1, `leaseToken` a non-empty string. Every adapter calls it
 * first.
 */
export function checkRecoverySetFloorRaise(subject, raise) {
    const refuse = (what) => {
        throw new RangeError(`MfaTransactionStore.raiseRecoverySetFloor: ${what}`);
    };
    checkSubjectQuestion("raiseRecoverySetFloor", subject);
    if (!isRecord(raise))
        return refuse("the raise must be an object");
    const { setGeneration, leaseToken } = raise;
    if (!isCount(setGeneration) || setGeneration < 1) {
        refuse("setGeneration, a recovery-code set's generation, must be a safe whole number from 1");
    }
    if (!isSubject(leaseToken))
        refuse("leaseToken must be a non-empty string");
    return { setGeneration: setGeneration, leaseToken: leaseToken };
}
/**
 * `answer`, what `raiseRecoverySetFloor` answered, as the port promises it:
 * a raise with the floor after it, a safe whole number from 1, or the
 * refusal without the lease. `undefined` for anything else, which the caller
 * answers as the store's outage.
 */
export function readMfaRecoverySetFloorAnswer(answer) {
    try {
        if (!isRecord(answer))
            return undefined;
        const { outcome } = answer;
        if (outcome === "raised") {
            const { floor } = answer;
            return isCount(floor) && floor >= 1 ? { outcome, floor } : undefined;
        }
        if (outcome === "refused") {
            const { reason } = answer;
            return reason === "lease_not_held" ? { outcome, reason } : undefined;
        }
        return undefined;
    }
    catch {
        return undefined;
    }
}
/**
 * The consume `consumeEmailProofRequirement` makes under a lease, its field
 * read once, or a `RangeError`: `subject` and `leaseToken` non-empty strings.
 * Every adapter calls it first.
 */
export function checkEmailProofRequirementConsume(subject, consume) {
    const refuse = (what) => {
        throw new RangeError(`MfaTransactionStore.consumeEmailProofRequirement: ${what}`);
    };
    checkSubjectQuestion("consumeEmailProofRequirement", subject);
    if (!isRecord(consume))
        return refuse("the consume must be an object");
    const { leaseToken } = consume;
    if (!isSubject(leaseToken))
        refuse("leaseToken must be a non-empty string");
    return { leaseToken: leaseToken };
}
/**
 * `answer`, what `consumeEmailProofRequirement` answered under a lease, as
 * the port promises it. `undefined` for anything else, which the caller
 * answers as the store's outage.
 */
export function readMfaEmailProofRequirementConsumeAnswer(answer) {
    try {
        if (!isRecord(answer))
            return undefined;
        const { outcome } = answer;
        if (outcome === "consumed" || outcome === "absent")
            return { outcome };
        if (outcome === "refused") {
            const { reason } = answer;
            return reason === "lease_not_held" ? { outcome, reason } : undefined;
        }
        return undefined;
    }
    catch {
        return undefined;
    }
}
/** The furthest an authorization may end ahead of the store's clock: the most `mfa.manage.maxAgeSeconds` allows. */
export const MFA_RECOVERY_AUTHORIZATION_MAX_MS = 3_600_000;
const RECOVERY_REFUSALS = new Set([
    "unauthorized",
    "expired",
    "not_revoked_since",
    "boundary_ahead",
    "lease_not_held",
]);
const isWellFormedText = (value) => isSubject(value) && value.isWellFormed();
/** Whole epoch milliseconds within the Date range. */
const isRecoveryInstant = (value) => isEpochMs(value) && isStorableExpiry(value);
/** The `sid` an operation takes: a well-formed string for `recover`, none for `reset`. */
function recoverySid(operation, sid, refuse) {
    if (operation === "recover") {
        return isWellFormedText(sid)
            ? sid
            : refuse("a recover's sid must be a non-empty, well-formed string");
    }
    if (operation === "reset")
        return sid === undefined ? undefined : refuse("a reset has no sid");
    return refuse("operation must be recover or reset");
}
/**
 * The authorization {@link MfaTransactionStore.authorizeSubjectRecovery}
 * records, its fields read once, or a `RangeError` naming what is wrong:
 * `subject` a non-empty string; `operation` and `sid` as
 * {@link MfaSubjectRecoveryAuthorization} says; `recoveryId` a non-empty,
 * well-formed string; `expiresAtMs` whole epoch milliseconds within the Date
 * range. On `storeNowMs`, the store's clock, when it is given: `expiresAtMs`
 * after it, and no further ahead than {@link MFA_RECOVERY_AUTHORIZATION_MAX_MS}
 * plus `DEFAULT_CLOCK_SKEW_MS`. An adapter whose store judges the clock in a
 * script runs the shape first and the rest on the clock that script answers.
 */
export function checkSubjectRecoveryAuthorization(subject, authorization, storeNowMs) {
    const refuse = (what) => {
        throw new RangeError(`MfaTransactionStore.authorizeSubjectRecovery: ${what}`);
    };
    if (!isSubject(subject))
        refuse("subject must be a non-empty string");
    if (!isRecord(authorization))
        return refuse("the authorization must be an object");
    const { operation, sid, recoveryId, expiresAtMs } = authorization;
    const checkedSid = recoverySid(operation, sid, refuse);
    if (!isWellFormedText(recoveryId))
        refuse("recoveryId must be a non-empty, well-formed string");
    if (!isRecoveryInstant(expiresAtMs)) {
        refuse("expiresAtMs must be whole epoch milliseconds within the Date range");
    }
    const ends = expiresAtMs;
    if (storeNowMs !== undefined) {
        if (!(ends > storeNowMs))
            refuse("expiresAtMs must be after the store's clock");
        if (!(ends <= storeNowMs + MFA_RECOVERY_AUTHORIZATION_MAX_MS + DEFAULT_CLOCK_SKEW_MS)) {
            refuse("expiresAtMs must be no further ahead of the store's clock than MFA_RECOVERY_AUTHORIZATION_MAX_MS and DEFAULT_CLOCK_SKEW_MS");
        }
    }
    return {
        operation: operation,
        sid: checkedSid,
        recoveryId: recoveryId,
        expiresAtMs: ends,
    };
}
/**
 * The application {@link MfaTransactionStore.applySubjectRecovery} acts on,
 * its fields read once, or a `RangeError` naming what is wrong: `subject` a
 * non-empty string; `operation` and `sid` as for an authorization; `nowMs` an
 * instant from the epoch within the Date range; `leaseToken` a non-empty
 * string; for `recover`, `sessionsBoundaryMs` `undefined` or whole epoch
 * milliseconds within the Date range, and `guessableBoundSinceMs` whole epoch
 * milliseconds within the Date range or `null` (none remains), never
 * absent; for `reset` both `undefined`. Every adapter calls it first.
 */
export function checkSubjectRecoveryApplication(subject, application) {
    const refuse = (what) => {
        throw new RangeError(`MfaTransactionStore.applySubjectRecovery: ${what}`);
    };
    if (!isSubject(subject))
        refuse("subject must be a non-empty string");
    if (!isRecord(application))
        return refuse("the application must be an object");
    const { operation, sid, nowMs, leaseToken, sessionsBoundaryMs, guessableBoundSinceMs } = application;
    const checkedSid = recoverySid(operation, sid, refuse);
    if (typeof nowMs !== "number" || !isStorableExpiry(nowMs) || nowMs < 0) {
        refuse("nowMs must be an instant from the epoch within the Date range");
    }
    if (!isSubject(leaseToken))
        refuse("leaseToken must be a non-empty string");
    if (operation === "reset") {
        if (sessionsBoundaryMs !== undefined)
            refuse("a reset takes no sessionsBoundaryMs");
        if (guessableBoundSinceMs !== undefined)
            refuse("a reset takes no guessableBoundSinceMs");
    }
    else {
        if (sessionsBoundaryMs !== undefined && !isRecoveryInstant(sessionsBoundaryMs)) {
            refuse("sessionsBoundaryMs must be undefined or whole epoch milliseconds within the Date range");
        }
        if (guessableBoundSinceMs !== null && !isRecoveryInstant(guessableBoundSinceMs)) {
            refuse("a recover's guessableBoundSinceMs must be whole epoch milliseconds within the Date range, or null when no guessable record remains");
        }
    }
    return {
        operation: operation,
        sid: checkedSid,
        nowMs: nowMs,
        leaseToken: leaseToken,
        sessionsBoundaryMs: sessionsBoundaryMs,
        guessableBoundSinceMs: guessableBoundSinceMs,
    };
}
/**
 * Whether `cleared` and `hard` are what one apply can answer. A lifted hard
 * hold ends its run and leaves none standing; otherwise the week ended, and
 * the run with it exactly when no hard hold stands (a standing hold keeps
 * the run it counted).
 */
const isAppliedState = (cleared, hard) => (cleared.hard ? cleared.run && !hard : cleared.week && cleared.run === !hard);
/** The hold an answer carries: `rebindAfterMs` whole epoch milliseconds exactly while `hard`, else `null`. */
const recoveryHoldOf = (hard, rebindAfterMs) => hard === true && isEpochMs(rebindAfterMs)
    ? { hard, rebindAfterMs }
    : hard === false && rebindAfterMs === null
        ? { hard, rebindAfterMs }
        : undefined;
/**
 * `answer`, what `applySubjectRecovery` answered, as the port promises it,
 * copied to its outcome's fields, each read once: a non-empty `recoveryId`,
 * a generation from 1, booleans, a refusal the port names, `rebindAfterMs`
 * whole epoch milliseconds while `hard` and `null` otherwise, never absent,
 * and an applied answer whose `cleared` and `hard` one apply can give —
 * never one that has lifted the hard hold while it still stands. `undefined`
 * for anything else, which the caller answers as the store's outage: never
 * released.
 */
export function readMfaSubjectRecoveryAnswer(answer) {
    try {
        if (!isRecord(answer))
            return undefined;
        const { outcome, hard, rebindAfterMs } = answer;
        const hold = recoveryHoldOf(hard, rebindAfterMs);
        if (hold === undefined)
            return undefined;
        if (outcome === "refused") {
            const { reason } = answer;
            return RECOVERY_REFUSALS.has(reason)
                ? { outcome, reason: reason, ...hold }
                : undefined;
        }
        if (outcome !== "applied" && outcome !== "already_applied")
            return undefined;
        const { recoveryId, generation } = answer;
        if (!isSubject(recoveryId) || !isCount(generation) || generation < 1)
            return undefined;
        if (outcome === "already_applied")
            return { outcome, recoveryId, generation, ...hold };
        const { cleared } = answer;
        if (!isRecord(cleared))
            return undefined;
        const { week, run, hard: lifted } = cleared;
        if (typeof week !== "boolean" || typeof run !== "boolean" || typeof lifted !== "boolean") {
            return undefined;
        }
        const parts = { week, run, hard: lifted };
        return isAppliedState(parts, hold.hard)
            ? { outcome, recoveryId, generation, cleared: parts, ...hold }
            : undefined;
    }
    catch {
        return undefined;
    }
}
const isPositiveWhole = (value) => typeof value === "number" && Number.isSafeInteger(value) && value > 0;
/**
 * The store's port check. Refuses a lockout policy a store cannot apply as
 * written, with a `RangeError` naming `setting` and the field: an object,
 * every field a positive whole number, `maxSeconds` ≥ `baseSeconds`,
 * `threshold` ≤ `hardLimit` (a threshold above it is never reached),
 * `hardLimit` ≤ {@link MFA_LOCKOUT_MAX_HARD_LIMIT}, and every duration ending
 * within the Date range. Every store operation taking a policy calls it. A
 * policy a deployment configures is checked by
 * {@link checkConfiguredMfaLockoutPolicy}, which runs this first and adds its
 * own bounds (a `hardLimit` floor, a `maxSeconds` cap). Answers the policy it checked, each field read once: a store applies
 * that copy, so what it applies is what was checked.
 *
 * @param setting - where the policy was read from, for the message.
 */
export function checkMfaLockoutPolicy(policy, setting = "mfa.lockout") {
    if (!isRecord(policy)) {
        throw new RangeError(`${setting} must be an object`);
    }
    const checked = {
        threshold: policy.threshold,
        baseSeconds: policy.baseSeconds,
        maxSeconds: policy.maxSeconds,
        memorySeconds: policy.memorySeconds,
        weeklyBudget: policy.weeklyBudget,
        hardLimit: policy.hardLimit,
    };
    for (const field of [
        "threshold",
        "baseSeconds",
        "maxSeconds",
        "memorySeconds",
        "weeklyBudget",
        "hardLimit",
    ]) {
        if (!isPositiveWhole(checked[field])) {
            throw new RangeError(`${setting}.${field} must be a positive whole number`);
        }
    }
    if (checked.maxSeconds < checked.baseSeconds) {
        throw new RangeError(`${setting}.maxSeconds must be at least ${setting}.baseSeconds`);
    }
    if (checked.threshold > checked.hardLimit) {
        throw new RangeError(`${setting}.threshold must be at most ${setting}.hardLimit`);
    }
    if (checked.hardLimit > MFA_LOCKOUT_MAX_HARD_LIMIT) {
        throw new RangeError(`${setting}.hardLimit must be at most ${MFA_LOCKOUT_MAX_HARD_LIMIT} (NIST SP 800-63B-4's cap on consecutive failures)`);
    }
    for (const [field, ms] of [
        ["maxSeconds", checked.maxSeconds * 1000],
        ["memorySeconds", checked.memorySeconds * 1000],
    ]) {
        if (!isStorableLifetime(ms)) {
            throw new RangeError(`${setting}.${field} must end within the Date range`);
        }
    }
    return Object.freeze(checked);
}
/**
 * Checks a lockout policy a deployment configures: the store's port check
 * ({@link checkMfaLockoutPolicy}), then its own bounds. A `RangeError`
 * naming `setting` and the reason refuses a `hardLimit` below
 * {@link MFA_LOCKOUT_MIN_HARD_LIMIT}, one not above `threshold`, or a
 * `maxSeconds` above {@link MFA_LOCKOUT_MAX_BACKOFF_SECONDS}. Answers the
 * port check's copy.
 *
 * @param setting - where the policy was read from, for the message.
 */
export function checkConfiguredMfaLockoutPolicy(policy, setting = "mfa.lockout") {
    const checked = checkMfaLockoutPolicy(policy, setting);
    if (checked.hardLimit < MFA_LOCKOUT_MIN_HARD_LIMIT) {
        throw new RangeError(`${setting}.hardLimit must be at least ${MFA_LOCKOUT_MIN_HARD_LIMIT}: the hardLimit-th attempt since the last success fixes the hard hold whatever its outcome, so a small value holds guessable factors even after a correct code`);
    }
    if (checked.hardLimit <= checked.threshold) {
        throw new RangeError(`${setting}.hardLimit must be above ${setting}.threshold: the staged backoff must act before the hard hold`);
    }
    if (checked.maxSeconds > MFA_LOCKOUT_MAX_BACKOFF_SECONDS) {
        throw new RangeError(`${setting}.maxSeconds must be at most ${MFA_LOCKOUT_MAX_BACKOFF_SECONDS} (a week): standing failures are counted over the week, so a longer backoff can outlast every failure that justified it`);
    }
    return checked;
}
