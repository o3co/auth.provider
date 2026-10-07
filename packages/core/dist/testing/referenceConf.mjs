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
 * The check a package runs over its own `config/reference.conf`: the file
 * holds only the sections of the modules that declare it
 * (`section.reference`) — and the captures of renamed variables
 * (`renamed-variables`), which `renamedVariableProblems` holds — and each
 * such module's section schema parses its part without losing a path. Another package's section would set that
 * package's defaults from the wrong place; a dropped path is a default no
 * module reads. The file comes already resolved by the package's own HOCON
 * reader, so core takes no HOCON dependency.
 *
 * Limits: a list is one path, so an element a schema drops is not reported;
 * a key whose value is `undefined` is no path; an empty object counts as
 * kept when the schema's output has keys under it.
 */
import { fileURLToPath } from "node:url";
import { RENAMED_VARIABLES_SECTION } from "../config/removed-keys.mjs";
import { renamedVariableProblems } from "./renamedVariables.mjs";
const isPlainObject = (value) => typeof value === "object" && value !== null && !Array.isArray(value);
/**
 * Every path in `tree` that carries a value, as its keys (a list is one
 * value; an empty object is a path of its own; a key whose value is
 * `undefined` is none). Keys stay apart, so a key holding a dot — a module's
 * name — stays one key.
 */
function leafPaths(tree, prefix) {
    if (!isPlainObject(tree))
        return prefix.length === 0 ? [] : [[...prefix]];
    const entries = Object.entries(tree).filter(([, value]) => value !== undefined);
    if (entries.length === 0)
        return prefix.length === 0 ? [] : [[...prefix]];
    return entries.flatMap(([key, value]) => leafPaths(value, [...prefix, key]));
}
/** The value at `segments` in `tree`, or `undefined`. */
function valueAt(tree, segments) {
    let cursor = tree;
    for (const segment of segments) {
        if (!isPlainObject(cursor) || !Object.hasOwn(cursor, segment))
            return undefined;
        cursor = cursor[segment];
    }
    return cursor;
}
/** Whether `path` is `prefix` or lies under it, key by key. */
const within = (path, prefix) => prefix.length <= path.length && prefix.every((key, index) => path[index] === key);
/** A path as the operator writes it. */
const shown = (path) => path.join(".");
/**
 * What is wrong with a package's `reference.conf`, one line per problem,
 * sorted (`[]` when nothing is): no module declares `reference`; a path
 * outside every declaring module's section; a section its schema refuses,
 * each issue at its operator path; a path its schema's output lacks.
 */
export function referenceConfProblems(check) {
    const owners = check.modules.filter((module) => module.section?.reference?.href === check.reference.href);
    if (owners.length === 0)
        return [`${check.reference.href}: no module declares this reference`];
    const problems = [];
    const sections = owners.map((module) => {
        const section = module.section;
        // A section is at its module's name, one key, not split on dots.
        return { module, schema: section.schema, segments: [module.name] };
    });
    for (const path of leafPaths(check.tree, [])) {
        // The captures are held by `renamedVariableProblems`.
        if (within(path, [RENAMED_VARIABLES_SECTION]))
            continue;
        if (!sections.some((section) => within(path, section.segments))) {
            problems.push(`${shown(path)}: no module declaring this reference owns it`);
        }
    }
    for (const section of sections) {
        const value = valueAt(check.tree, section.segments);
        const parsed = section.schema.safeParse(value);
        if (!parsed.success) {
            for (const issue of parsed.error.issues) {
                const at = [...section.segments, ...issue.path.map(String)].join(".");
                problems.push(`${at}: refused by module "${section.module.name}"'s section schema — ${issue.message}`);
            }
            continue;
        }
        const kept = leafPaths(parsed.data, section.segments);
        for (const path of leafPaths(value, section.segments)) {
            // An empty object the schema filled in is kept: its output has keys under it.
            if (!kept.some((output) => within(output, path))) {
                problems.push(`${shown(path)}: lost by module "${section.module.name}"'s section schema`);
            }
        }
    }
    return problems.sort();
}
/**
 * The check a package's own test runs over its `config/reference.conf`, one
 * line per problem, sorted — `[]` when nothing is: every module in `modules`
 * declares the file as its section's reference,
 * {@link referenceConfProblems} finds nothing wrong with the file as `read`
 * resolves it with no variable set, and `renamedVariableProblems` nothing
 * wrong with the bindings of the renames the modules declare. Core's tests
 * require every package that ships a reference to run it.
 */
export function packageReferenceProblems(check) {
    const problems = [];
    for (const module of check.modules) {
        const declared = module.section?.reference;
        if (declared === undefined) {
            problems.push(`module "${module.name}": declares no section reference`);
        }
        else if (declared.href !== check.reference.href) {
            problems.push(`module "${module.name}": its section's reference is ${declared.href}, not this file`);
        }
    }
    const path = fileURLToPath(check.reference);
    const tree = check.read(path, {});
    problems.push(...referenceConfProblems({ tree, reference: check.reference, modules: check.modules }), ...renamedVariableProblems({ modules: check.modules, layers: [path], read: check.read }));
    return problems.sort();
}
