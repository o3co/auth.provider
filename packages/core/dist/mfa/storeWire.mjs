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
 * The wire format of the Store's MFA endpoints: the JSON bodies the Store
 * adapter sends and reads, and a Store (or a fake of one) reads and answers.
 * The endpoints, their statuses and what each answer means are
 * `@o3co/auth-provider-foundation`'s README, "The Store's MFA endpoints".
 *
 * Guarantees: times are epoch milliseconds named `…Ms`; an optional field
 * with no value is left out, and `null` is never read as "unset"; the fields
 * a page shows are read only in the record's shape (`isMfaFactorId`,
 * `isMfaFactorKind`, `isMfaFactorLabel`), anything else being a record the
 * provider cannot read; a list is read whole, refused for one unreadable
 * record, one of another subject or a repeated id; what a writer makes, the
 * reader reads back whole, and what the reader refuses, the writer refuses
 * with a `RangeError`; an update names the record by `subject` and `id` and
 * carries the expected version and, as its changes, only `data`, `label` and
 * `lastUsedAtMs`.
 *
 * The factor set's store generation travels under the conditional-write
 * convention's HTTP wire (docs/adapter-surface.md, "Conditional writes"):
 * the versioned list answers `factors` with the set's `generation`, `null`
 * only for an absent set; a conditional create or remove carries
 * `expectedGeneration` (`null`, for a create only: the set was read as
 * absent) and `deadlineMs`, and is answered `200`, `404` or `409` with an
 * outcome body. `deadlineMs` is an instant on the provider's clock, the send
 * time plus the adapter's request timeout. The Store checks it against its own
 * clock in the same atomic step as the conditional write; at or after it, the
 * write is not applied and the answer is `408`. This assumes the provider's
 * and the Store's clocks agree within the clock skew assumed between the two;
 * under that assumption a conditional write commits or fails within W, the
 * request timeout plus that skew. This codec is
 * the only place those field names and statuses meet the port's words: its
 * readers answer the port's types, and throw a `TypeError` for any other
 * answer, a bare `404` or `409` and a `408` included.
 */
import { isStoreGeneration, readConditionalCreateAnswer, readConditionalSetRemoveAnswer, readVersionedSet, } from "../adapters/conditionalWrite.mjs";
import { isStorableExpiry } from "../adapters/expiry.mjs";
import { isMfaFactorId, isMfaFactorKind, isMfaFactorLabel, } from "./factorStore.mjs";
import { checkMfaVersionAdvances } from "./version.mjs";
const BINDING_NAMES = {
    password: true,
    email_proof: true,
    federated: true,
    mfa: true,
};
const BINDINGS = new Set(Object.keys(BINDING_NAMES));
const CHANGE_KEYS = new Set(["data", "label", "lastUsedAtMs"]);
const refuse = (what) => new RangeError(`MfaStoreFactor: ${what}`);
const isInstant = (value) => typeof value === "number" && Number.isInteger(value) && isStorableExpiry(value);
const isVersion = (value) => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
const isRecord = (value) => typeof value === "object" && value !== null && !Array.isArray(value);
/** `record[key]` when it is the record's own, else `undefined`. */
const own = (record, key) => Object.hasOwn(record, key) ? record[key] : undefined;
/** The epoch milliseconds of `date`, or a `RangeError` naming `field` for one the reader would refuse. */
function instantOf(date, field) {
    const ms = date instanceof Date ? date.getTime() : Number.NaN;
    if (!isInstant(ms))
        throw refuse(`${field} must be a valid date within the Date range`);
    return ms;
}
function checkString(value, field) {
    if (typeof value !== "string")
        throw refuse(`${field} must be a string`);
    return value;
}
function checkId(value) {
    if (!isMfaFactorId(value))
        throw refuse("id must be 22 base64url characters");
    return value;
}
function checkLabel(value) {
    if (!isMfaFactorLabel(value)) {
        throw refuse("label must be 1 to 64 printable characters on one line");
    }
    return value;
}
/** A record as the wire carries it; a `RangeError` for one {@link readMfaStoreFactor} would not read back. */
export function toMfaStoreFactor(record) {
    if (record.binding !== undefined && !BINDINGS.has(record.binding)) {
        throw refuse('binding must be "password", "email_proof", "federated", "mfa" or absent');
    }
    if (!isVersion(record.version))
        throw refuse("version must be a safe non-negative integer");
    if (!isMfaFactorKind(record.kind))
        throw refuse("kind must be a hint token");
    return {
        id: checkId(record.id),
        subject: checkString(record.subject, "subject"),
        kind: record.kind,
        ...(record.label !== undefined ? { label: checkLabel(record.label) } : {}),
        ...(record.binding !== undefined ? { binding: record.binding } : {}),
        createdAtMs: instantOf(record.createdAt, "createdAt"),
        ...(record.lastUsedAt !== undefined
            ? { lastUsedAtMs: instantOf(record.lastUsedAt, "lastUsedAt") }
            : {}),
        version: record.version,
        data: checkString(record.data, "data"),
    };
}
/**
 * `value` as a wire record, when it is one: a fresh object of the record's
 * own fields, any other field left behind. `undefined` for anything else — a
 * field missing, of the wrong type, out of range, out of the record's shape,
 * or `null` — which the provider holds to be a record it cannot read, never
 * an absent one.
 */
export function readMfaStoreFactor(value) {
    if (!isRecord(value))
        return undefined;
    const id = own(value, "id");
    const subject = own(value, "subject");
    const kind = own(value, "kind");
    const label = own(value, "label");
    const binding = own(value, "binding");
    const createdAtMs = own(value, "createdAtMs");
    const lastUsedAtMs = own(value, "lastUsedAtMs");
    const version = own(value, "version");
    const data = own(value, "data");
    if (!isMfaFactorId(id) || typeof subject !== "string" || !isMfaFactorKind(kind)) {
        return undefined;
    }
    if (Object.hasOwn(value, "label") && !isMfaFactorLabel(label))
        return undefined;
    if (Object.hasOwn(value, "binding") && !BINDINGS.has(binding))
        return undefined;
    if (!isInstant(createdAtMs))
        return undefined;
    if (Object.hasOwn(value, "lastUsedAtMs") && !isInstant(lastUsedAtMs))
        return undefined;
    if (!isVersion(version) || typeof data !== "string")
        return undefined;
    return {
        id,
        subject,
        kind,
        ...(label !== undefined ? { label: label } : {}),
        ...(binding !== undefined ? { binding: binding } : {}),
        createdAtMs,
        ...(lastUsedAtMs !== undefined ? { lastUsedAtMs: lastUsedAtMs } : {}),
        version,
        data,
    };
}
/**
 * A list's answer for `subject`, read whole: every record read by
 * {@link readMfaStoreFactor}, each naming `subject`, no id twice. One that
 * fails refuses the whole list, never reads as fewer records.
 */
export function readMfaStoreListAnswer(value, subject) {
    const factors = isRecord(value) ? own(value, "factors") : undefined;
    if (!Array.isArray(factors))
        return { ok: false, reason: "malformed" };
    const read = [];
    const ids = new Set();
    for (const entry of factors) {
        const factor = readMfaStoreFactor(entry);
        if (factor === undefined || factor.subject !== subject || ids.has(factor.id)) {
            return { ok: false, reason: "unreadable" };
        }
        ids.add(factor.id);
        read.push(factor);
    }
    return { ok: true, factors: read };
}
/** A wire record {@link readMfaStoreFactor} answered, as the port's record. */
export function fromMfaStoreFactor(factor) {
    return {
        id: factor.id,
        subject: factor.subject,
        kind: factor.kind,
        label: factor.label,
        binding: factor.binding,
        createdAt: new Date(factor.createdAtMs),
        lastUsedAt: factor.lastUsedAtMs === undefined ? undefined : new Date(factor.lastUsedAtMs),
        version: factor.version,
        data: factor.data,
    };
}
/**
 * An update's `data`, `label` and `lastUsedAtMs` as the wire carries them,
 * and nothing else of `next`, whatever else it holds; a `RangeError` for
 * changes {@link readMfaStoreFactorChanges} would not read back.
 */
export function toMfaStoreFactorChanges(next) {
    return {
        data: checkString(next.data, "data"),
        ...(next.label !== undefined ? { label: checkLabel(next.label) } : {}),
        ...(next.lastUsedAt !== undefined
            ? { lastUsedAtMs: instantOf(next.lastUsedAt, "lastUsedAt") }
            : {}),
    };
}
/**
 * `value` as an update's changes, when it is: `data`, and `label` and
 * `lastUsedAtMs` when present, in a fresh object. `undefined` when a field is
 * of the wrong type or `null`, and when any other field is present — one a
 * Store must not change.
 */
export function readMfaStoreFactorChanges(value) {
    if (!isRecord(value))
        return undefined;
    if (Object.keys(value).some((key) => !CHANGE_KEYS.has(key)))
        return undefined;
    const data = own(value, "data");
    const label = own(value, "label");
    const lastUsedAtMs = own(value, "lastUsedAtMs");
    if (typeof data !== "string")
        return undefined;
    if (Object.hasOwn(value, "label") && !isMfaFactorLabel(label))
        return undefined;
    if (Object.hasOwn(value, "lastUsedAtMs") && !isInstant(lastUsedAtMs))
        return undefined;
    return {
        data,
        ...(label !== undefined ? { label: label } : {}),
        ...(lastUsedAtMs !== undefined ? { lastUsedAtMs: lastUsedAtMs } : {}),
    };
}
/**
 * The body of an update of `(subject, id)` at `expectedVersion`. A
 * `RangeError` for an `expectedVersion` that is no version, or at
 * `Number.MAX_SAFE_INTEGER` (`checkMfaVersionAdvances`), for an id no record
 * can have, and for changes {@link toMfaStoreFactorChanges} refuses.
 */
export function toMfaStoreUpdateRequest(subject, id, expectedVersion, next) {
    checkMfaVersionAdvances(expectedVersion, "MfaStoreUpdateRequest");
    if (!isVersion(expectedVersion)) {
        throw refuse("expectedVersion must be a safe non-negative integer");
    }
    return {
        subject: checkString(subject, "subject"),
        id: checkId(id),
        expectedVersion,
        changes: toMfaStoreFactorChanges(next),
    };
}
/** `expected` as the wire carries it; a `RangeError` for one no Store may answer. */
function checkGeneration(expected) {
    if (!isStoreGeneration(expected)) {
        throw refuse('expectedGeneration must be 1 to 128 visible ASCII characters, none of them "');
    }
    return expected;
}
/**
 * `deadlineMs` as the wire carries it; a `RangeError` for one that is not a
 * whole instant above 0 within the Date range, which a Store could not read
 * as a time and so would never refuse.
 */
function checkDeadline(deadlineMs) {
    if (!isInstant(deadlineMs) || deadlineMs <= 0) {
        throw refuse("deadlineMs must be a whole instant above 0 within the Date range");
    }
    return deadlineMs;
}
/** `value[key]` when it is the answer's own; a `TypeError` naming `what` when it cannot be read. */
function answerField(value, key, what) {
    if (typeof value !== "object" || value === null)
        throw new TypeError(`${what}: not an object`);
    try {
        return Array.isArray(value) ? undefined : own(value, key);
    }
    catch {
        throw new TypeError(`${what}: ${key} could not be read`);
    }
}
/**
 * The list endpoint's `200` to a versioned read of `subject`, as the port's
 * set: `factors` read as `items` by the convention's `readVersionedSet`,
 * each a record of `subject` ({@link readMfaStoreFactor}), no id twice, and
 * `generation` the set's. `{ factors: [], generation: null }` is an absent
 * set. A fresh frozen answer of fresh frozen records. Throws a `TypeError`
 * for anything else, a missing `generation`, one holding `"`, and a single
 * record that cannot be read included: the Store's fault, never a set with
 * fewer records.
 */
export function readMfaStoreVersionedListAnswer(value, subject) {
    const what = "MfaStoreVersionedListAnswer";
    const set = readVersionedSet({
        items: answerField(value, "factors", what),
        generation: answerField(value, "generation", what),
    });
    const ids = new Set();
    const records = [];
    for (const item of set.items) {
        let factor;
        try {
            factor = readMfaStoreFactor(item);
        }
        catch {
            throw new TypeError(`${what}: a record could not be read`);
        }
        if (factor === undefined)
            throw new TypeError(`${what}: a record the provider cannot read`);
        if (factor.subject !== subject)
            throw new TypeError(`${what}: a record of another subject`);
        if (ids.has(factor.id))
            throw new TypeError(`${what}: a record id repeats`);
        ids.add(factor.id);
        records.push(Object.freeze(fromMfaStoreFactor(factor)));
    }
    return Object.freeze({ items: Object.freeze(records), generation: set.generation });
}
/**
 * The body of a create of `record` while its subject's set is at `expected`;
 * `null`: while the set is absent. `deadlineMs` is the send time plus the
 * adapter's request timeout, in epoch milliseconds. A `RangeError` for an
 * `expected` that is neither a store generation nor `null`, a `deadlineMs`
 * that is not a whole instant above 0 within the Date range, and a record
 * {@link toMfaStoreFactor} refuses.
 */
export function toMfaStoreCreateIfRequest(record, expected, deadlineMs) {
    return {
        factor: toMfaStoreFactor(record),
        expectedGeneration: expected === null ? null : checkGeneration(expected),
        deadlineMs: checkDeadline(deadlineMs),
    };
}
/**
 * The body of a removal of `(subject, id)` while the set is at `expected`.
 * `deadlineMs` is the send time plus the adapter's request timeout, in epoch
 * milliseconds. A `RangeError` for an `expected` that is no store generation
 * (`null` included: a removal never targets an absent set), a `deadlineMs`
 * that is not a whole instant above 0 within the Date range, an id no record
 * can have, and a `subject` that is no string.
 */
export function toMfaStoreRemoveIfRequest(subject, id, expected, deadlineMs) {
    return {
        subject: checkString(subject, "subject"),
        id: checkId(id),
        expectedGeneration: checkGeneration(expected),
        deadlineMs: checkDeadline(deadlineMs),
    };
}
/**
 * `body` read by `read`, the convention's reader of the answer, and held to
 * the outcome its `status` stands for. A `TypeError` for a status with no
 * outcome, a body the reader refuses (none at all included), and a body
 * whose outcome is another status's.
 */
function readStatusAnswer(status, body, outcomes, read, what) {
    const outcome = outcomes.get(status);
    if (outcome === undefined)
        throw new TypeError(`${what}: status ${String(status)} has no outcome`);
    const answer = read(body);
    if (answer.outcome !== outcome) {
        throw new TypeError(`${what}: status ${String(status)} answered ${answer.outcome}`);
    }
    return answer;
}
const CREATE_IF_OUTCOMES = new Map([
    [200, "created"],
    [409, "conflict"],
]);
const REMOVE_IF_OUTCOMES = new Map([
    [200, "removed"],
    [404, "missing"],
    [409, "conflict"],
]);
/**
 * A conditional create's answer, its `status` and its parsed `body`, as the
 * port's answer (`readConditionalCreateAnswer`): `200` `created` with the
 * set's new generation, `409` `conflict`. A `TypeError` for anything else: a
 * `404` (a create is never `missing`), a `408` (read past its deadline, it
 * wrote nothing), another status, a `409` or `200` without its body, or a
 * body naming another status's outcome.
 */
export function readMfaStoreCreateIfAnswer(status, body) {
    return readStatusAnswer(status, body, CREATE_IF_OUTCOMES, readConditionalCreateAnswer, "MfaStoreCreateIfAnswer");
}
/**
 * A conditional remove's answer, its `status` and its parsed `body`, as the
 * port's answer (`readConditionalSetRemoveAnswer`): `200` `removed` with the
 * set's new generation, `404` `missing`, `409` `conflict`. A `TypeError` for
 * anything else: a `408` (read past its deadline, it wrote nothing), another
 * status, one of the three without its body, or a body naming another
 * status's outcome.
 */
export function readMfaStoreRemoveIfAnswer(status, body) {
    return readStatusAnswer(status, body, REMOVE_IF_OUTCOMES, readConditionalSetRemoveAnswer, "MfaStoreRemoveIfAnswer");
}
