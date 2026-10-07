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
import { verifiedAuthenticationOf, } from "./validator/selfIssuedAccessToken.mjs";
/** Below what a stage reads by name: own enumerable keys, nothing by name. */
const ANY = { record: false, names: [], ownKeys: true, of: {} };
/** A `may_act` entry: `sub` and `iss`, read by name (`in` and access) by delegation. */
const MAY_ACT_ENTRY = {
    record: true,
    presence: true,
    names: ["sub", "iss"],
    ownKeys: true,
    of: {},
};
/** A `may_act`: one entry, or an array of them. */
const MAY_ACT = { ...MAY_ACT_ENTRY, record: false, each: MAY_ACT_ENTRY };
/** A `cnf`: the members core's confirmation matcher reads. */
const CNF = { record: true, names: ["jkt", "x5t#S256"], ownKeys: true, of: {} };
/** An `act` chain: the nested `act` the chain-depth count follows. */
const ACT = { record: true, names: ["act"], ownKeys: true, of: {} };
ACT.of.act = ACT;
/** The claims the grant reads by name. */
const CLAIMS = {
    record: true,
    names: ["azp", "exp", "iss", "cnf", "may_act"],
    ownKeys: true,
    of: { cnf: CNF, may_act: MAY_ACT },
};
/** The answer: its members, by name alone. */
const ANSWER = {
    record: true,
    names: ["sub", "scope", "aud", "familyId", "sid", "act", "may_act", "claims"],
    ownKeys: false,
    of: { act: ACT, may_act: MAY_ACT, claims: CLAIMS },
};
const authentications = new WeakMap();
/**
 * The copy of a `may_act` entry that reports neither `sub` nor `iss` to `in`:
 * not a record, so delegation matches no actor or client against it. Actor
 * matching matches no actor against the entry either; client matching, which
 * reads `sub` by value, might have, so this is the conservative answer.
 */
const MATCHES_NOTHING = Object.freeze([]);
/** The greatest length an array can have. */
const MAX_LENGTH = 2 ** 32 - 1;
/**
 * Thrown inside a copy where the answer is no answer: an array where a record
 * is read, or a value that is not plain data.
 */
class NotAnAnswer extends Error {
}
/**
 * Whether `answer` has the shape of an answer — a record (an object that is
 * not an array) with a string `sub` and record `claims` — reading those two
 * members once each and copying nothing. A read that throws propagates.
 */
export function isValidatedShape(answer) {
    return hasAnswerShape(answer, new Reader());
}
/**
 * The plain, frozen copy of `answer`, or `null` when it is no answer: not a
 * record, a `sub` that is not a string, `claims` that are not a record, or an
 * array where a record is read (`cnf`, a `may_act` entry, `act`).
 */
export function snapshotValidated(answer) {
    const reader = new Reader();
    if (!hasAnswerShape(answer, reader))
        return null;
    let snapshot;
    try {
        snapshot = reader.copy(answer, ANSWER);
    }
    catch (err) {
        if (err instanceof NotAnAnswer)
            return null;
        throw err;
    }
    const authentication = verifiedAuthenticationOf(answer);
    if (authentication !== undefined)
        authentications.set(snapshot, authentication);
    return snapshot;
}
/**
 * The authentication context the built-in validator verified for the answer
 * `snapshot` was copied from, or `undefined` when another validator gave it.
 */
export function snapshotAuthentication(snapshot) {
    return authentications.get(snapshot);
}
function hasAnswerShape(answer, reader) {
    if (!isRecord(answer))
        return false;
    if (typeof reader.read(answer, "sub") !== "string")
        return false;
    return isRecord(reader.read(answer, "claims"));
}
function isRecord(value) {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}
/** One answer's reads: each member of each object read once, and each copy made once per `Reads`. */
class Reader {
    values = new Map();
    keys = new Map();
    presence = new Map();
    copies = new Map();
    /** `source[key]`, read on the first call alone. */
    read(source, key) {
        let values = this.values.get(source);
        if (values === undefined) {
            values = new Map();
            this.values.set(source, values);
        }
        if (values.has(key))
            return values.get(key);
        const value = source[key];
        values.set(key, value);
        return value;
    }
    /** Whether `key in source`, asked on the first call alone. */
    has(source, key) {
        let presence = this.presence.get(source);
        if (presence === undefined) {
            presence = new Map();
            this.presence.set(source, presence);
        }
        const known = presence.get(key);
        if (known !== undefined)
            return known;
        const present = key in source;
        presence.set(key, present);
        return present;
    }
    /**
     * `value` as a plain, frozen copy holding what `reads` names; throws
     * {@link NotAnAnswer} for a value that is not plain data — strings, finite
     * numbers, booleans, `null`, and arrays and records of them — or an array
     * where `reads` is a record.
     */
    copy(value, reads) {
        if (value === undefined || value === null)
            return value;
        switch (typeof value) {
            case "string":
            case "boolean":
                return value;
            case "number":
                if (!Number.isFinite(value))
                    throw new NotAnAnswer();
                return value;
            case "object":
                break;
            default:
                // A function (a `toJSON` included), a symbol or a bigint is not data.
                throw new NotAnAnswer();
        }
        if (reads.record && Array.isArray(value))
            throw new NotAnAnswer();
        let byReads = this.copies.get(value);
        if (byReads === undefined) {
            byReads = new Map();
            this.copies.set(value, byReads);
        }
        if (byReads.has(reads))
            return byReads.get(reads);
        if (Array.isArray(value)) {
            // A length a genuine array can have, read once; else no answer.
            const length = this.read(value, "length");
            if (!Number.isSafeInteger(length) ||
                length < 0 ||
                length > MAX_LENGTH) {
                throw new NotAnAnswer();
            }
            const out = new Array(length);
            byReads.set(reads, out);
            // Index by index, each asked for once: an index `in` does not report is
            // left a hole, which native `some`, `every` and `filter` skip as they
            // skip that index on the answer.
            for (let i = 0; i < length; i++) {
                const index = String(i);
                if (this.has(value, index)) {
                    out[i] = this.copy(this.read(value, index), reads.each ?? ANY);
                }
            }
            return Object.freeze(out);
        }
        if (reads.presence && reads.names.every((name) => !this.has(value, name))) {
            // Actor matching finds none of the members it tests with `in`, so the
            // record matches no actor; the copy matches nothing at all.
            byReads.set(reads, MATCHES_NOTHING);
            return MATCHES_NOTHING;
        }
        const out = {};
        byReads.set(reads, out);
        const names = new Set(reads.ownKeys ? this.ownKeys(value) : []);
        for (const name of reads.names) {
            // Read whether or not `in` reports it: a stage reading the member by name
            // sees what this read sees.
            if (this.has(value, name) || this.read(value, name) !== undefined)
                names.add(name);
        }
        for (const name of names) {
            define(out, name, this.copy(this.read(value, name), Object.hasOwn(reads.of, name) ? reads.of[name] : ANY));
        }
        return Object.freeze(out);
    }
    ownKeys(source) {
        let keys = this.keys.get(source);
        if (keys === undefined) {
            keys = Object.keys(source);
            this.keys.set(source, keys);
        }
        return keys;
    }
}
/** `key` defined on `target` as an own, enumerable data property, whatever its name. */
function define(target, key, value) {
    Object.defineProperty(target, key, {
        value,
        enumerable: true,
        writable: false,
        configurable: false,
    });
}
