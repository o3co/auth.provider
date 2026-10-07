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
 * What `value` is, for a refusal that names a value it cannot trust, never
 * rendered and never throwing: `the string "…"`, `the number 5`,
 * `the bigint 1`, `null`, `undefined`, `a function`, `a Set`, `an Object`,
 * or `an object` when its prototype names no constructor or cannot be read.
 * A primitive is named by its kind and value; an object by its kind alone,
 * so nothing it holds — a secret, a cycle, a getter that throws — is read.
 * Internal to core: not exported from the package.
 */
export const describeValue = (value) => {
    if (value === null || value === undefined)
        return String(value);
    if (typeof value === "string")
        return `the string ${JSON.stringify(value)}`;
    if (typeof value === "number" || typeof value === "bigint" || typeof value === "boolean") {
        return `the ${typeof value} ${String(value)}`;
    }
    if (typeof value !== "object")
        return `a ${typeof value}`;
    let name;
    try {
        const prototype = Object.getPrototypeOf(value);
        name =
            prototype === null
                ? undefined
                : prototype.constructor?.name;
    }
    catch {
        name = undefined;
    }
    if (typeof name !== "string" || name === "")
        return "an object";
    return `${/^[AEIOU]/.test(name) ? "an" : "a"} ${name}`;
};
