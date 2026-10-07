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
import { readVersionedSet, } from "../adapters/conditionalWrite.mjs";
import { lineSafeText } from "../logging/loggableError.mjs";
import { isHintToken } from "../session-admission/requirement.mjs";
/** The most characters a factor's label holds. */
export const MFA_FACTOR_LABEL_MAX_LENGTH = 64;
const FACTOR_ID = /^[A-Za-z0-9_-]{22}$/;
/** Whether `value` is a factor id as the provider makes one: 16 random bytes, base64url, 22 characters. */
export const isMfaFactorId = (value) => typeof value === "string" && FACTOR_ID.test(value);
/** Whether `value` is a factor's kind: a hint token, since a first binding's hints name each kind. */
export const isMfaFactorKind = (value) => isHintToken(value);
/**
 * Whether `value` is a label a page can show as it is: 1 to
 * {@link MFA_FACTOR_LABEL_MAX_LENGTH} characters, well formed, none of them
 * one that breaks or reorders a line (`lineSafeText` leaves it unchanged).
 */
export const isMfaFactorLabel = (value) => typeof value === "string" &&
    value.length > 0 &&
    value.length <= MFA_FACTOR_LABEL_MAX_LENGTH * 2 &&
    [...value].length <= MFA_FACTOR_LABEL_MAX_LENGTH &&
    value.isWellFormed() &&
    lineSafeText(value) === value;
/**
 * Whether `written`, what `update` answered other than `null`, is the record
 * as the update wrote it: the same subject and id, the version one past the
 * one expected, and the data written. The caller answers anything else —
 * `undefined` among it — as the store's outage, never as a write that
 * happened. Each field is read once.
 */
export function isMfaFactorUpdateWritten(written, request) {
    try {
        if (typeof written !== "object" || written === null)
            return false;
        const { subject, id, version, data } = written;
        return (subject === request.subject &&
            id === request.id &&
            version === request.expectedVersion + 1 &&
            data === request.next.data);
    }
    catch {
        return false;
    }
}
const RECORD_BINDINGS = new Set([
    "password",
    "email_proof",
    "federated",
    "mfa",
]);
const isInstant = (value) => value instanceof Date && Number.isFinite(value.getTime());
/** Every key of {@link MfaFactorRecord}: each a required key, so each must be an own property. */
const RECORD_KEYS = [
    "id",
    "subject",
    "kind",
    "label",
    "binding",
    "createdAt",
    "lastUsedAt",
    "version",
    "data",
];
/**
 * `item` as a record of `subject`: every key an own property, each read once,
 * and a fresh frozen record built from the values read; `undefined` for
 * anything else.
 */
function recordOf(item, subject) {
    if (typeof item !== "object" || item === null)
        return undefined;
    if (!RECORD_KEYS.every((key) => Object.hasOwn(item, key)))
        return undefined;
    const { id, subject: owner, kind, label, binding, createdAt, lastUsedAt, version, data, } = item;
    if (typeof id !== "string" || owner !== subject || typeof kind !== "string")
        return undefined;
    if (label !== undefined && typeof label !== "string")
        return undefined;
    if (binding !== undefined && !RECORD_BINDINGS.has(binding))
        return undefined;
    if (!isInstant(createdAt) || (lastUsedAt !== undefined && !isInstant(lastUsedAt))) {
        return undefined;
    }
    if (typeof version !== "number" || !Number.isSafeInteger(version) || version < 0) {
        return undefined;
    }
    if (typeof data !== "string")
        return undefined;
    return Object.freeze({
        id,
        subject: owner,
        kind,
        label,
        binding: binding,
        createdAt,
        lastUsedAt,
        version,
        data,
    });
}
/**
 * What `listVersioned` answered for `subject`, read as the port promises it:
 * a versioned set (`readVersionedSet`) whose items are whole records, every
 * key of its type an own property and every field of its type, each naming
 * `subject`, no id twice, and none for an absent set. A fresh frozen answer
 * whose records are fresh frozen copies, each field of the answered record
 * read once. Throws a `TypeError` for anything else, a read that throws
 * included — the store's fault, which the caller answers as the store's
 * outage, never as a set with nothing in it.
 */
export function readMfaFactorSet(answer, subject) {
    const read = readVersionedSet(answer);
    const refuse = (what) => new TypeError(`MfaFactorStore.listVersioned: ${what}`);
    const ids = new Set();
    const records = [];
    for (const item of read.items) {
        let record;
        try {
            record = recordOf(item, subject);
        }
        catch {
            throw refuse("a record could not be read");
        }
        if (record === undefined)
            throw refuse("an item is not a whole record of the subject");
        if (ids.has(record.id))
            throw refuse("a record id repeats");
        ids.add(record.id);
        records.push(record);
    }
    return Object.freeze({ items: Object.freeze(records), generation: read.generation });
}
