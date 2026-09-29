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
 * The check a package runs over its own `config/reference.conf` (#728): the
 * file holds only the sections of the modules that declare it
 * (`section.reference`), and each such module's section schema parses its
 * part of the file without losing a path. A reference that holds another
 * package's section would set that package's defaults from the wrong place;
 * a path the schema drops is a default no module ever reads.
 *
 * It takes the file already resolved — the package's test parses it with
 * the HOCON reader it uses (`@o3co/ts.hocon`) — so core takes no HOCON
 * dependency. Arrays are values, not keys: a list is one path.
 */

import type { Module } from "../modules/manifest/module-spec.mjs";

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

/** Every dotted path in `tree` that carries a value (a list is one value). */
function leafPaths(tree: unknown, prefix: string): string[] {
	if (!isPlainObject(tree)) return prefix === "" ? [] : [prefix];
	const entries = Object.entries(tree);
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
 * sorted — `[]` when nothing is:
 *
 * - no module in `modules` declares `reference`;
 * - a path no module declaring it owns (outside every such module's section,
 *   `section.at` or else its name);
 * - a module's section, as the file holds it, that its schema refuses —
 *   each issue at its operator path;
 * - a path under a module's section that its schema's output lacks.
 */
export function referenceConfProblems(check: ReferenceConfCheck): string[] {
	const owners = check.modules.filter(
		(module) => module.section?.reference?.href === check.reference.href,
	);
	if (owners.length === 0) return [`${check.reference.href}: no module declares this reference`];
	const problems: string[] = [];
	const sections = owners.map((module) => {
		const section = module.section as NonNullable<Module["section"]>;
		// Unset, `at` is the module's name as one key, not split on dots (#736).
		const segments = section.at === undefined ? [module.name] : section.at.split(".");
		return { module, schema: section.schema, path: segments.join("."), segments };
	});
	for (const path of leafPaths(check.tree, "")) {
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
		const kept = new Set(leafPaths(parsed.data, section.path));
		for (const path of leafPaths(value, section.path)) {
			if (!kept.has(path)) {
				problems.push(`${path}: lost by module "${section.module.name}"'s section schema`);
			}
		}
	}
	return problems.sort();
}
