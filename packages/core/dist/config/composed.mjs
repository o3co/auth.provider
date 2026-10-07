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
 * An object literal's kind of object: its prototype is `Object.prototype`, or
 * it has none. Configuration is merged, copied and written only through
 * these; anything else — a list, a `URL`, an instance a transform built — is
 * a value, taken whole.
 */
export function isPlainConfigObject(value) {
    if (typeof value !== "object" || value === null || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
/**
 * `over` (a schema's parse) laid on `under` (what was written), key by key
 * through plain objects (`isPlainConfigObject`):
 *
 * - where both hold a plain object, their keys are merged the same way;
 * - anywhere else the parsed value wins whole (a list, a `URL`, a value whose
 *   type the schema changed);
 * - a key the parse holds as `undefined` is removed: the schema made nothing
 *   of the value written there (an empty environment variable read as unset);
 * - a key the parse does not hold is kept as written, which is how a key no
 *   schema declares survives the parse.
 *
 * An `undefined` `over` answers `under`. Neither input is changed: every
 * object on a merged path is a new one, and a value only one side holds is
 * that side's own.
 */
export function overlayConfig(under, over) {
    if (over === undefined)
        return under;
    if (!isPlainConfigObject(under) || !isPlainConfigObject(over))
        return over;
    const merged = {};
    for (const key of Object.keys(under))
        defineConfigKey(merged, key, under[key]);
    for (const key of Object.keys(over)) {
        const value = over[key];
        if (value === undefined) {
            delete merged[key];
            continue;
        }
        defineConfigKey(merged, key, Object.hasOwn(under, key) ? overlayConfig(under[key], value) : value);
    }
    return merged;
}
/** `target[key] = value`, defined rather than assigned: a key named `__proto__` stays a key. */
export function defineConfigKey(target, key, value) {
    Object.defineProperty(target, key, {
        value,
        enumerable: true,
        writable: true,
        configurable: true,
    });
}
/** A Zod issue path as the operator writes it: its keys joined with dots. */
export function operatorPath(path) {
    return path.map(String).join(".");
}
/**
 * `value` parsed by `schema`, or a `RangeError` naming each issue at its
 * operator path (the whole configuration named as such), with the Zod error
 * as its `cause`. A parse that throws instead of answering — a getter on a
 * hand-built configuration — is a refusal like any other, carrying what it
 * threw as the `cause`, not an error escaping the reader.
 */
export function parsedOrRefused(schema, value) {
    let result;
    try {
        result = schema.safeParse(value);
    }
    catch (thrown) {
        throw new RangeError("Config validation failed — core's configuration schema threw instead of answering, so it could not be parsed synchronously; the error it threw is this error's cause", { cause: thrown });
    }
    if (!result.success) {
        const issues = result.error.issues;
        throw new RangeError(`Config validation failed — ${issues.length} issue(s) found: ${issues
            .map((issue) => `${operatorPath(issue.path) || "(the configuration)"}: ${issue.message}`)
            .join("; ")}`, { cause: result.error });
    }
    return result.data;
}
