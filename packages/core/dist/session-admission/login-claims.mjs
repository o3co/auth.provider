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
import { readPlainFields } from "../repositories/userSnapshot.mjs";
const isStringList = (value) => Array.isArray(value) && value.every((entry) => typeof entry === "string");
/**
 * What each declared claim holds when present, and how a refusal says it.
 * A claim `UserSessionClaims` declares that this misses, or one it does not
 * declare, fails to compile.
 */
const DECLARED_CLAIMS = {
    email: { holds: (value) => typeof value === "string", as: "a string" },
    emailVerified: { holds: (value) => typeof value === "boolean", as: "a boolean" },
    name: { holds: (value) => typeof value === "string", as: "a string" },
    picture: { holds: (value) => typeof value === "string", as: "a string" },
    groups: { holds: isStringList, as: "a list of strings" },
};
const DECLARED_CLAIM_NAMES = Object.keys(DECLARED_CLAIMS);
const isDeclaredClaim = (key) => Object.hasOwn(DECLARED_CLAIMS, key);
/** The custom claims each envelope dropped, keyed by the envelope `readLoginClaims` answered. */
const droppedFrom = new WeakMap();
/** Freezes a value `JSON.parse` answered, at every depth, in place; answers it. */
function freezeParsed(value) {
    if (typeof value === "object" && value !== null) {
        for (const entry of Object.values(value))
            freezeParsed(entry);
        Object.freeze(value);
    }
    return value;
}
/** What `jsonFormOf` throws for a value that refers back to the claims it is read from. */
class RefersToClaims extends Error {
}
/** A number JSON holds as it is; NaN, the infinities and a raw spelling past them are `null`. */
const finiteOrNull = (_key, value) => typeof value === "number" && !Number.isFinite(value) ? null : value;
/**
 * The JSON form of what `read` answers, parsed back and frozen: one read,
 * one `JSON.stringify`. A value that refers back to `claims` is not taken:
 * serialising it would read the claims again.
 */
function jsonFormOf(read, claims) {
    try {
        const text = JSON.stringify(read(), (_key, value) => {
            if (value === claims)
                throw new RefersToClaims();
            return value;
        });
        if (text === undefined)
            return { kind: "nothing" };
        return { kind: "value", value: freezeParsed(JSON.parse(text, finiteOrNull)) };
    }
    catch {
        return { kind: "unserialisable" };
    }
}
/** `copy[key] = value`, as an own data property even for `__proto__`. */
function define(copy, key, value) {
    Object.defineProperty(copy, key, { value, enumerable: true, writable: true, configurable: true });
}
/**
 * `claims` read once into the envelope a primary carries, by the two rules
 * in this file's header. Refused: `claims` that are not an object
 * (`not_an_object`), and a declared claim that is not plain data of its
 * declared type (`declared_claim`, naming it and the type). A class instance
 * is read by the declared names and its own enumerable keys, nothing else of
 * it. A read of the object's keys or of a declared claim that throws is let
 * through as it was thrown; a custom claim whose read throws is dropped.
 */
export function readLoginClaims(claims) {
    if (typeof claims !== "object" || claims === null || Array.isArray(claims)) {
        return { ok: false, refused: "not_an_object" };
    }
    const source = claims;
    const declared = readPlainFields(source, DECLARED_CLAIM_NAMES);
    if (!declared.ok) {
        const claim = declared.field;
        return { ok: false, refused: "declared_claim", claim, as: DECLARED_CLAIMS[claim].as };
    }
    for (const claim of DECLARED_CLAIM_NAMES) {
        const value = declared.copy[claim];
        if (value !== undefined && !DECLARED_CLAIMS[claim].holds(value)) {
            return { ok: false, refused: "declared_claim", claim, as: DECLARED_CLAIMS[claim].as };
        }
    }
    const copy = { ...declared.copy };
    const dropped = [];
    for (const key of Object.keys(source)) {
        if (isDeclaredClaim(key))
            continue;
        const form = jsonFormOf(() => source[key], source);
        if (form.kind === "value")
            define(copy, key, form.value);
        else if (form.kind === "unserialisable")
            dropped.push({ claim: key, reason: form.kind });
    }
    const envelope = Object.freeze(copy);
    if (dropped.length > 0)
        droppedFrom.set(envelope, Object.freeze(dropped));
    return { ok: true, claims: envelope };
}
/** The custom claims `readLoginClaims` dropped from `claims`, an envelope it answered; none for any other object. */
export const droppedClaimsOf = (claims) => droppedFrom.get(claims) ?? [];
/**
 * Logs `login_claim_dropped` at warn once for each custom claim
 * `readLoginClaims` dropped from `claims`: its key and the reason, never
 * its value. Said once for an envelope, however often it is handed here
 * with a logger. Nothing without a logger.
 */
export function warnDroppedClaims(logger, claims) {
    if (logger === undefined)
        return;
    const dropped = droppedClaimsOf(claims);
    droppedFrom.delete(claims);
    for (const { claim, reason } of dropped) {
        logger.warn({ claim, reason }, "login_claim_dropped");
    }
}
