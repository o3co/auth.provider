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
 * The refusals the copy threw. A thrown value is told apart by membership
 * alone, so nothing of it runs — a Proxy's traps included — while it is.
 */
const refusals = new WeakSet();
/** A refusal at `at`, to be thrown. */
const refused = (at) => {
    const refusal = Object.freeze({ at });
    refusals.add(refusal);
    return refusal;
};
/** Whether `thrown` is one of the copy's refusals, asked without running any of its code. */
const isRefusal = (thrown) => typeof thrown === "object" && thrown !== null && refusals.has(thrown);
/** What `copies` holds for an object while it is copied: met again inside itself, it is a cycle. */
const COPYING = Symbol("being copied");
/**
 * `value` as its plain JSON copy (see this file's header), or where it is not
 * one. Never throws: whatever a read throws, a Proxy's trap included, is a
 * refusal there, and nothing of the thrown value is run to tell.
 */
export function copyPlainJson(value) {
    return takePlainJson(value, false);
}
/**
 * {@link copyPlainJson}, but `-0` read as `0`, as `JSON.stringify` writes it,
 * rather than refused. Internal to core: stage 1 copies a configuration with
 * it, where HOCON resolves `-0` from what an operator wrote and boot always
 * read it as `0`.
 */
export function copyPlainJsonNegativeZeroAsZero(value) {
    return takePlainJson(value, true);
}
function takePlainJson(value, zero) {
    try {
        const copy = copyAt(value, "", new Map(), zero);
        // Written once here, so a copy JSON cannot write — nesting a shared object
        // keeps shallow for the copy, deep for JSON — is refused where it is taken.
        JSON.stringify(copy);
        return { ok: true, copy };
    }
    catch (thrown) {
        return { ok: false, at: isRefusal(thrown) ? thrown.at : "" };
    }
}
/** `value`'s copy at `at`; a read that throws there is a refusal there. */
function copyAt(value, at, copies, zero) {
    try {
        return copyPlain(value, at, copies, zero);
    }
    catch (thrown) {
        throw isRefusal(thrown) ? thrown : refused(at);
    }
}
function copyPlain(value, at, copies, zero) {
    if (value === null || typeof value === "string" || typeof value === "boolean")
        return value;
    if (typeof value === "number") {
        if (Object.is(value, -0) && zero)
            return 0;
        if (Number.isFinite(value) && !Object.is(value, -0))
            return value;
        throw refused(at);
    }
    if (typeof value !== "object")
        throw refused(at);
    const known = copies.get(value);
    if (known === COPYING)
        throw refused(at);
    if (known !== undefined)
        return known;
    copies.set(value, COPYING);
    const prototype = Object.getPrototypeOf(value);
    const list = Array.isArray(value);
    if (list ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null) {
        throw refused(at);
    }
    const copy = list
        ? copyList(value, at, copies, zero)
        : copyFields(value, at, copies, zero);
    copies.set(value, copy);
    return copy;
}
/**
 * `value`'s own keys, listed once, when each is a field JSON writes: a string
 * key, enumerable — else refused, since a field JSON would skip (a symbol's,
 * a hidden one) or call (a hidden `toJSON`) is content the copy would lose.
 * A list's `length` is not a field.
 */
function fieldsOf(value, list, at) {
    const fields = [];
    for (const key of Reflect.ownKeys(value)) {
        if (list && key === "length")
            continue;
        if (typeof key !== "string" || !Object.prototype.propertyIsEnumerable.call(value, key)) {
            throw refused(at);
        }
        fields.push(key);
    }
    return fields;
}
function copyList(list, at, copies, zero) {
    const length = list.length;
    const keys = fieldsOf(list, true, at);
    if (keys.length !== length || keys.some((key, index) => key !== String(index))) {
        throw refused(at);
    }
    const copy = [];
    for (let index = 0; index < length; index++) {
        const entryAt = `${at}[${index}]`;
        let entry;
        try {
            entry = list[index];
        }
        catch {
            throw refused(entryAt);
        }
        if (entry === undefined)
            throw refused(entryAt);
        copy.push(copyAt(entry, entryAt, copies, zero));
    }
    return Object.freeze(copy);
}
function copyFields(value, at, copies, zero) {
    const source = value;
    const copy = {};
    for (const key of fieldsOf(source, false, at)) {
        const fieldAt = `${at}.${key}`;
        let field;
        try {
            field = source[key];
        }
        catch {
            throw refused(fieldAt);
        }
        if (field === undefined)
            continue;
        // Defined, not assigned: an own `__proto__` stays the field it is.
        Object.defineProperty(copy, key, {
            value: copyAt(field, fieldAt, copies, zero),
            enumerable: true,
            writable: true,
            configurable: true,
        });
    }
    return Object.freeze(copy);
}
