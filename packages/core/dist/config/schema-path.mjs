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
const defOf = (schema) => schema._zod.def;
/** A literal's values: every `z.literal` carries at least one. */
const literalValues = (def) => def.values;
/** The wrappers that parse a value as their inner schema does, less or more permissively. */
const WRAPPERS = new Set([
    "optional",
    "nullable",
    "default",
    "prefault",
    "readonly",
    "catch",
    "nonoptional",
]);
/**
 * The schemas `schema` may parse a value with, once its wrappers are seen
 * through: a wrapper's inner schema, a pipe's end that holds the shape (the
 * target of a `z.preprocess`, the source of a `.transform`), each member of a
 * union, both sides of an intersection, a lazy schema's result.
 */
function bodiesOf(schema) {
    const def = defOf(schema);
    const inner = (next) => bodiesOf(next);
    if (WRAPPERS.has(def.type) && def.innerType)
        return inner(def.innerType);
    if (def.type === "pipe" && def.in && def.out) {
        return inner(defOf(def.out).type === "transform" ? def.in : def.out);
    }
    if (def.type === "union" && def.options)
        return def.options.flatMap(inner);
    if (def.type === "intersection" && def.left && def.right) {
        return [...inner(def.left), ...inner(def.right)];
    }
    if (def.type === "lazy" && def.getter) {
        // The schema's own cached result, so a schema that reaches itself is the same object again.
        const cached = schema._zod.innerType;
        return inner(cached ?? def.getter());
    }
    return [schema];
}
/**
 * Every schema that parses the value at `path` inside `schema` — more than
 * one where a union or an intersection offers several — or none when the
 * path leaves what `schema` declares: a key no object on the way declares, a
 * list, a scalar. A record's value schema answers any key. The schemas are
 * the ones declared at the path, wrappers included.
 */
export function schemasAtPath(schema, path) {
    if (path.length === 0)
        return [schema];
    const [key, ...rest] = path;
    return bodiesOf(schema).flatMap((body) => {
        const def = defOf(body);
        if (def.type === "object" && def.shape && Object.hasOwn(def.shape, key)) {
            return schemasAtPath(def.shape[key], rest);
        }
        if (def.type === "record" && def.valueType)
            return schemasAtPath(def.valueType, rest);
        return [];
    });
}
/** The schemas `environmentCoercer` names: core's own readers of an environment string. */
const ENVIRONMENT_COERCERS = new WeakSet();
/**
 * Names `schema` as one of core's environment coercers (`coerceBooleanFromEnv`,
 * each `wholeNumberFromEnv`), whose preprocess reads the string a `${?VAR}`
 * carries into the type its schema takes, so `readsEnvironmentString` trusts
 * it. Tagged rather than probed: a probe ("false", "1") would run the
 * schema's own bounds and refinements, and report a leaf that refuses `"1"`
 * as too small as one that cannot read a string. Any other preprocess is
 * judged by the schema it hands on. Answers `schema`.
 * @internal
 */
export function environmentCoercer(schema) {
    ENVIRONMENT_COERCERS.add(schema);
    return schema;
}
/**
 * Whether `schema` reads the string an environment variable arrives as, seen
 * through its wrappers, a lazy schema and both sides of an intersection:
 * `true` for a string, an enum, a template literal, a literal with a string
 * value, any, unknown, every `z.coerce.*` scalar, and the containers a leaf
 * sits in; `false` for every other type (a plain boolean, number, bigint or
 * date, null, NaN, a symbol, a custom schema, a type it does not know), and
 * for a union only when no member reads a string. A `z.preprocess` counts
 * only on evidence: one of core's environment coercers (`environmentCoercer`)
 * reads it, and any other is judged by the schema it hands on, since its
 * function may do nothing with the string (`z.preprocess((v) => v,
 * z.boolean())` refuses `"false"`).
 */
export function readsEnvironmentString(schema) {
    if (ENVIRONMENT_COERCERS.has(schema))
        return true;
    const def = defOf(schema);
    if (WRAPPERS.has(def.type) && def.innerType)
        return readsEnvironmentString(def.innerType);
    if (def.type === "pipe" && def.in && def.out) {
        // A preprocess (its input a function) by what it hands on; a
        // `.transform` (its output a function) by the schema that reads first.
        return readsEnvironmentString(defOf(def.in).type === "transform" ? def.out : def.in);
    }
    if (def.type === "union" && def.options)
        return def.options.some(readsEnvironmentString);
    if (def.type === "intersection" && def.left && def.right) {
        return readsEnvironmentString(def.left) && readsEnvironmentString(def.right);
    }
    if (def.type === "lazy" && def.getter)
        return readsEnvironmentString(def.getter());
    // No string equals `true` or `1`: a literal reads the string only if one
    // of its values is a string.
    if (def.type === "literal")
        return literalValues(def).some((value) => typeof value === "string");
    // A scalar `z.coerce.*` converts the string: a number, a boolean, a
    // bigint, a date (and a string).
    if (COERCIBLE.has(def.type))
        return def.coerce === true;
    return READS_A_STRING.has(def.type);
}
/** The scalar types whose `z.coerce.*` form reads a string, and whose plain form does not. */
const COERCIBLE = new Set(["number", "boolean", "bigint", "date"]);
/**
 * The types that take the string itself — a string, an enum, a template
 * literal, any and unknown — and the containers a leaf sits in (an object, a
 * record, a list), which `unreadableLeaves` walks into rather than reads.
 * Every other type — null, undefined, void, never, NaN, a symbol, a map, a
 * set, a tuple, a custom schema, a file, a promise, a function, a type Zod
 * adds later — does not read one: an unknown type is reported, not trusted.
 */
const READS_A_STRING = new Set([
    "string",
    "enum",
    "template_literal",
    "any",
    "unknown",
    "object",
    "record",
    "array",
]);
/**
 * The kinds of value `schema` produces — `"boolean"`, `"number"`,
 * `"string"`, `"object"`… — seen through its wrappers and a preprocess, or
 * `undefined` when it cannot be told without running it (a `.transform`, a
 * custom schema): each member of a union adds its own.
 */
export function outputKinds(schema) {
    const def = defOf(schema);
    if (WRAPPERS.has(def.type) && def.innerType)
        return outputKinds(def.innerType);
    if (def.type === "pipe" && def.out) {
        return defOf(def.out).type === "transform" ? undefined : outputKinds(def.out);
    }
    if (def.type === "union" && def.options) {
        const kinds = new Set();
        for (const option of def.options) {
            const found = outputKinds(option);
            if (found === undefined)
                return undefined;
            for (const kind of found)
                kinds.add(kind);
        }
        return kinds;
    }
    if (def.type === "literal")
        return new Set(literalValues(def).map((value) => typeof value));
    if (def.type === "enum")
        return new Set(["string"]);
    if (["transform", "custom", "any", "unknown", "lazy"].includes(def.type))
        return undefined;
    return new Set([def.type]);
}
/**
 * Every leaf `schema` declares that does not read the string an environment
 * variable arrives as (`readsEnvironmentString`), with its dot path under
 * `prefix`: through objects, a record's values (`*`) and a list's elements
 * (`[]`) — any of them a `${?VAR}` in an operator's own file can set, whether
 * or not a shipped file does. Sorted by path, each path once.
 */
export function unreadableLeaves(schema, prefix = "") {
    const found = new Map();
    const walk = (node, path) => {
        if (!readsEnvironmentString(node)) {
            if (!found.has(path))
                found.set(path, node);
            return;
        }
        for (const body of bodiesOf(node)) {
            const def = defOf(body);
            const at = (key) => (path === "" ? key : `${path}.${key}`);
            if (def.type === "object" && def.shape) {
                for (const [key, child] of Object.entries(def.shape))
                    walk(child, at(key));
            }
            else if (def.type === "record" && def.valueType) {
                walk(def.valueType, at("*"));
            }
            else if (def.type === "array" && def.element) {
                walk(def.element, at("[]"));
            }
        }
    };
    walk(schema, prefix);
    // Each path is a key of `found` once, so no two compare equal.
    return [...found].sort(([a], [b]) => (a < b ? -1 : 1)).map(([path, leaf]) => ({ path, leaf }));
}
/**
 * Every object and record `schema` declares, at its path: through objects, a
 * record's values and a list's elements, each form of a union and both sides
 * of an intersection listed at the same path. A lazy schema is followed until
 * it reaches a schema already on the way, which is listed there and not
 * entered again. In walk order, parents first.
 */
export function schemaObjectLevels(schema) {
    const levels = [];
    const walk = (node, path, ancestors) => {
        for (const body of bodiesOf(node)) {
            // A schema met again on its own way down is listed once more, not entered.
            const again = ancestors.has(body);
            const within = new Set(ancestors).add(body);
            const def = defOf(body);
            if (def.type === "object" && def.shape) {
                levels.push({ path, kind: "object", schema: body });
                if (again)
                    continue;
                for (const [key, child] of Object.entries(def.shape))
                    walk(child, [...path, key], within);
            }
            else if (def.type === "record" && def.valueType) {
                levels.push({ path, kind: "record", schema: body });
                if (again)
                    continue;
                walk(def.valueType, [...path, "*"], within);
            }
            else if (def.type === "array" && def.element && !again) {
                walk(def.element, [...path, "*"], within);
            }
        }
    };
    walk(schema, [], new Set());
    return levels;
}
/** The paths of `unreadableLeaves`. */
export function unreadableLeafPaths(schema, prefix = "") {
    return unreadableLeaves(schema, prefix).map(({ path }) => path);
}
