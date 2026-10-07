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
 * The check that a module refuses an unknown key inside its own section, at
 * every object level: a typo, or a key an older version read, then refuses
 * boot naming its path instead of being dropped or kept unread.
 *
 * Each level of each valid sample of the section is given one unknown key and
 * parsed with the section's schema, the key carrying in turn a string (what an
 * environment variable sets), an empty object (what a nested block sets) and
 * a copy of each of the level's own entries (what an entry of a record looks
 * like); a level where any of them parses is named. A level whose keys are
 * open by design — a record keyed by names the deployment chooses — is
 * exempted by the caller, with its reason.
 *
 * The samples must reach every object level the schema declares
 * (`schemaObjectLevels`): each nested object, an entry of each record and an
 * element of each list, and each form of a union — a level they do not reach
 * is named, so a block added to a section is checked as soon as it is
 * declared. A form is reached when a sample's value at its path parses with
 * it; a path with one form, when a sample holds an object there.
 */
import { schemaObjectLevels } from "../config/schema-path.mjs";
/** The key no section declares. */
const UNKNOWN_KEY = "unknownKeyOfTheStrictnessCheck";
const isPlainObject = (value) => typeof value === "object" && value !== null && !Array.isArray(value);
/** The value at `segments` in `tree`, or `undefined`. */
function valueAt(tree, segments) {
    let cursor = tree;
    for (const segment of segments) {
        if (Array.isArray(cursor) && /^\d+$/.test(segment)) {
            cursor = cursor[Number(segment)];
            continue;
        }
        if (!isPlainObject(cursor) || !Object.hasOwn(cursor, segment))
            return undefined;
        cursor = cursor[segment];
    }
    return cursor;
}
/** The path of every plain object in `value`, itself first; a list's elements by index. */
function objectLevels(value, at = []) {
    if (Array.isArray(value)) {
        return value.flatMap((element, index) => objectLevels(element, [...at, String(index)]));
    }
    if (!isPlainObject(value))
        return [];
    return [
        [...at],
        ...Object.entries(value).flatMap(([key, child]) => objectLevels(child, [...at, key])),
    ];
}
/** `value` with the unknown key set to `injected` in the object at `at`, copied along the way. */
function withUnknownKey(value, at, injected) {
    if (at.length === 0)
        return { ...value, [UNKNOWN_KEY]: injected };
    const [head, ...rest] = at;
    if (Array.isArray(value)) {
        const copy = [...value];
        copy[Number(head)] = withUnknownKey(value[Number(head)], rest, injected);
        return copy;
    }
    const object = value;
    return { ...object, [head]: withUnknownKey(object[head], rest, injected) };
}
/** `undefined` when `schema` accepts `value`; otherwise why it does not. */
function refusal(schema, value) {
    try {
        const parsed = schema.safeParse(value);
        if (parsed.success)
            return undefined;
        return parsed.error.issues
            .map((issue) => `${issue.path.map(String).join(".") || "(section)"}: ${issue.message}`)
            .join("; ");
    }
    catch {
        // Boot parses a section synchronously; a schema that throws instead of
        // answering (an async refinement) refuses it there too.
        return "the schema threw instead of answering synchronously";
    }
}
/** Whether the path `pattern` (`*` any one segment) names the path `segments`. */
function matches(pattern, segments) {
    return (pattern.length === segments.length &&
        pattern.every((part, index) => part === "*" || part === segments[index]));
}
/**
 * The keys of the exempt path `pattern` as read against the section of the
 * module `name`: the module's name, dots and all, is one key when the
 * pattern starts with it; the rest splits on dots.
 */
function patternKeys(pattern, name) {
    if (pattern === name)
        return [name];
    if (pattern.startsWith(`${name}.`))
        return [name, ...pattern.slice(name.length + 1).split(".")];
    return pattern.split(".");
}
/** Whether the exempt path `pattern` lies at or under the section of the module `name`. */
function inside(pattern, name) {
    const parts = patternKeys(pattern, name);
    const section = [name];
    return (parts.length >= section.length &&
        section.every((segment, index) => parts[index] === "*" || parts[index] === segment));
}
/** The keys a form declares, for naming it: an object's shape, or "a record". */
function formName(level) {
    if (level.kind === "record")
        return "its record form";
    const shape = level.schema.shape;
    return `its form with keys ${Object.keys(shape).sort().join(", ")}`;
}
/** What the samples leave unreached of the levels the section's schema declares. */
function unreachedLevels(schema, samples, section, name) {
    const reached = samples.flatMap((sample) => objectLevels(sample).map((at) => ({ at, value: valueAt(sample, at) })));
    const byPath = Map.groupBy(schemaObjectLevels(schema), (level) => level.path.join("."));
    return [...byPath.values()].flatMap((forms) => {
        const path = forms[0].path;
        const where = [...section, ...path].join(".");
        const there = reached.filter(({ at }) => matches(path, at));
        if (there.length === 0)
            return [`${where}: not reached by module "${name}"'s samples`];
        if (forms.length === 1)
            return [];
        return forms
            .filter((form) => !there.some(({ value }) => form.schema.safeParse(value).success))
            .map((form) => `${where}: ${formName(form)} is not reached by module "${name}"'s samples`);
    });
}
/**
 * Every object level of the modules' sections where an unknown key is not
 * refused, as `<section>.<path>: …`, one line per problem, sorted — `[]` when
 * nothing is. Also named: a level the schema declares that no sample reaches
 * (`<section>.<path>`, `*` for any record key or list index), a sample its
 * schema refuses (or cannot parse synchronously), an exemption with no
 * reason, and an exemption inside a checked section that matches no level
 * keeping an unknown key. A module without a section is skipped; an
 * exemption outside every checked section is left to the check that holds
 * its module.
 */
export function sectionStrictnessProblems(modules, options = {}) {
    const exempt = Object.entries(options.exempt ?? {});
    const problems = [];
    const used = new Set();
    const checked = [];
    for (const [path, reason] of exempt) {
        if (reason.trim() === "")
            problems.push(`${path}: exempt with no reason`);
    }
    for (const module of modules) {
        const section = module.section;
        if (section === undefined)
            continue;
        // A section is at its module's name, one key, not split on dots.
        const segments = [module.name];
        checked.push({ module, segments });
        const fromTree = valueAt(options.tree, segments);
        const given = [
            ...(fromTree === undefined ? [] : [fromTree]),
            ...(options.samples?.[module.name] ?? []),
        ];
        const valid = [];
        for (const sample of given.length === 0 ? [{}] : given) {
            const refused = refusal(section.schema, sample);
            if (refused === undefined) {
                valid.push(sample);
                continue;
            }
            problems.push(`${segments.join(".")}: module "${module.name}"'s sample is refused by its section schema — ${refused}`);
        }
        if (valid.length === 0)
            continue;
        problems.push(...unreachedLevels(section.schema, valid, segments, module.name));
        // Keyed by the keys themselves: a module's name may hold a dot.
        const keeping = new Set();
        const levels = new Map();
        for (const sample of valid) {
            for (const at of objectLevels(sample)) {
                const level = [...segments, ...at];
                levels.set(JSON.stringify(level), level);
                const entries = Object.values(valueAt(sample, at));
                const keeps = ["unknown", {}, ...entries].some((value) => refusal(section.schema, withUnknownKey(sample, at, value)) === undefined);
                if (keeps)
                    keeping.add(JSON.stringify(level));
            }
        }
        for (const [key, level] of levels) {
            const exemptions = exempt.filter(([pattern]) => matches(patternKeys(pattern, module.name), level));
            if (exemptions.length > 0) {
                if (keeping.has(key))
                    for (const [pattern] of exemptions)
                        used.add(pattern);
                continue;
            }
            if (keeping.has(key)) {
                problems.push(`${level.join(".")}: module "${module.name}"'s section schema does not refuse an unknown key`);
            }
        }
    }
    for (const [pattern] of exempt) {
        if (used.has(pattern))
            continue;
        const owner = checked.find(({ module }) => inside(pattern, module.name));
        if (owner === undefined)
            continue;
        problems.push(`${pattern}: exempt, but no level of module "${owner.module.name}"'s section it matches keeps an unknown key`);
    }
    return problems.sort();
}
