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
import type { Module } from "../modules/manifest/module-spec.mjs";
import { renamedVariableProblems } from "./renamedVariables.mjs";

export interface ReferenceConfCheck {
	/** The package's `config/reference.conf`, resolved to plain data. */
	readonly tree: unknown;
	/** The file's URL, as its modules declare it in `section.reference`. */
	readonly reference: URL;
	/** The package's modules; those declaring `reference` are the file's owners. */
	readonly modules: readonly Module[];
}

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * Every dotted path in `tree` that carries a value (a list is one value; an
 * empty object is a path of its own; a key whose value is `undefined` is none).
 */
function leafPaths(tree: unknown, prefix: string): string[] {
	if (!isPlainObject(tree)) return prefix === "" ? [] : [prefix];
	const entries = Object.entries(tree).filter(([, value]) => value !== undefined);
	if (entries.length === 0) return prefix === "" ? [] : [prefix];
	return entries.flatMap(([key, value]) =>
		leafPaths(value, prefix === "" ? key : `${prefix}.${key}`),
	);
}

/** The value at `segments` in `tree`, or `undefined`. */
function valueAt(tree: unknown, segments: readonly string[]): unknown {
	let cursor: unknown = tree;
	for (const segment of segments) {
		if (!isPlainObject(cursor) || !Object.hasOwn(cursor, segment)) return undefined;
		cursor = cursor[segment];
	}
	return cursor;
}

/** Whether `path` is `section` or lies under it. */
const within = (path: string, section: string): boolean =>
	path === section || path.startsWith(`${section}.`);

/**
 * What is wrong with a package's `reference.conf`, one line per problem,
 * sorted (`[]` when nothing is): no module declares `reference`; a path
 * outside every declaring module's section; a section its schema refuses,
 * each issue at its operator path; a path its schema's output lacks.
 */
export function referenceConfProblems(check: ReferenceConfCheck): string[] {
	const owners = check.modules.filter(
		(module) => module.section?.reference?.href === check.reference.href,
	);
	if (owners.length === 0) return [`${check.reference.href}: no module declares this reference`];
	const problems: string[] = [];
	const sections = owners.map((module) => {
		const section = module.section as NonNullable<Module["section"]>;
		// A section is at its module's name, one key, not split on dots.
		const segments = [module.name];
		return { module, schema: section.schema, path: segments.join("."), segments };
	});
	for (const path of leafPaths(check.tree, "")) {
		// The captures are held by `renamedVariableProblems`.
		if (within(path, RENAMED_VARIABLES_SECTION)) continue;
		if (!sections.some((section) => within(path, section.path))) {
			problems.push(`${path}: no module declaring this reference owns it`);
		}
	}
	for (const section of sections) {
		const value = valueAt(check.tree, section.segments);
		const parsed = section.schema.safeParse(value);
		if (!parsed.success) {
			for (const issue of parsed.error.issues) {
				const at = [...section.segments, ...issue.path.map(String)].join(".");
				problems.push(
					`${at}: refused by module "${section.module.name}"'s section schema — ${issue.message}`,
				);
			}
			continue;
		}
		const kept = leafPaths(parsed.data, section.path);
		for (const path of leafPaths(value, section.path)) {
			// An empty object the schema filled in is kept: its output has keys under it.
			if (!kept.some((output) => within(output, path))) {
				problems.push(`${path}: lost by module "${section.module.name}"'s section schema`);
			}
		}
	}
	return problems.sort();
}

export interface PackageReferenceCheck {
	/** The package's `config/reference.conf`, as its modules declare it. */
	readonly reference: URL;
	/** The modules that read the file: each must declare it as its section's reference. */
	readonly modules: readonly Module[];
	/**
	 * Resolves the file at a path to plain data with the package's HOCON
	 * reader, under `env` — for `@o3co/ts.hocon`,
	 * `(path, env) => parseFile(path, { env: { ...env } }).toObject()`.
	 */
	readonly read: (path: string, env: Readonly<Record<string, string>>) => unknown;
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
export function packageReferenceProblems(check: PackageReferenceCheck): string[] {
	const problems: string[] = [];
	for (const module of check.modules) {
		const declared = module.section?.reference;
		if (declared === undefined) {
			problems.push(`module "${module.name}": declares no section reference`);
		} else if (declared.href !== check.reference.href) {
			problems.push(
				`module "${module.name}": its section's reference is ${declared.href}, not this file`,
			);
		}
	}
	const path = fileURLToPath(check.reference);
	const tree = check.read(path, {});
	problems.push(
		...referenceConfProblems({ tree, reference: check.reference, modules: check.modules }),
		...renamedVariableProblems({ modules: check.modules, layers: [path], read: check.read }),
	);
	return problems.sort();
}
