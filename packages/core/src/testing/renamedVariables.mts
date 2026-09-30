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
 * The bindings a declared rename needs across the layers a composition
 * ships, so boot's judgement of what the resolution captured is sound: both
 * names captured in `renamed-variables` (`null` when unset), the new name
 * bound at its path — else a value set under it would be dropped while boot
 * accepts it — and the old name bound nowhere else, else declaring it would
 * refuse every operator who sets it. The layers come resolved by the caller's
 * HOCON reader, so core takes no HOCON dependency.
 */

import { renamedVariablesOf } from "../boot/validate-manifests.mjs";
import type { CoreRelocations } from "../config/core-relocations.mjs";
import { RENAMED_VARIABLES_SECTION } from "../config/removed-keys.mjs";
import type { Module } from "../modules/manifest/module-spec.mjs";

export interface RenamedVariableCheck {
	/** The modules whose `section.renamedVariables` are held. */
	readonly modules: readonly Module[];
	/** Core's own section's declaration, held beside theirs, as module "core". */
	readonly core?: CoreRelocations;
	/** The layers the names are held against, as file paths. */
	readonly layers: readonly string[];
	/**
	 * Resolves a layer to plain data under `env` — for `@o3co/ts.hocon`,
	 * `(path, env) => parseFile(path, { env: { ...env } }).toObject()`.
	 */
	readonly read: (path: string, env: Readonly<Record<string, string>>) => unknown;
}

const MARKER = "__RENAMED_VARIABLE_MARKER__";

const isPlainObject = (value: unknown): value is Readonly<Record<string, unknown>> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/** Every dotted path in `tree` whose value is `MARKER`; list elements by index. */
function markedPaths(tree: unknown, prefix = ""): string[] {
	const join = (key: string) => (prefix === "" ? key : `${prefix}.${key}`);
	if (Array.isArray(tree))
		return tree.flatMap((value, index) => markedPaths(value, join(`${index}`)));
	if (isPlainObject(tree))
		return Object.entries(tree).flatMap(([key, value]) => markedPaths(value, join(key)));
	return tree === MARKER ? [prefix] : [];
}

/** The capture of `name` in `tree`: `undefined` when there is none. */
const capturedIn = (tree: unknown, name: string): unknown => {
	const section = isPlainObject(tree) ? tree[RENAMED_VARIABLES_SECTION] : undefined;
	return isPlainObject(section) && Object.hasOwn(section, name) ? section[name] : undefined;
};

/**
 * What is wrong with the bindings of the renames `check.modules` (and
 * `check.core`) declare across `check.layers`, one line per problem, sorted:
 * a name no layer captures as `null` unset and as its value set; a new name
 * bound at its path in no layer; an old name a layer binds anywhere but its
 * capture. `[]` when nothing is.
 */
export function renamedVariableProblems(check: RenamedVariableCheck): string[] {
	const problems: string[] = [];
	const resolve = (env: Readonly<Record<string, string>>) =>
		check.layers.map((layer) => ({ layer, tree: check.read(layer, env) }));
	const unset = resolve({});
	for (const rename of renamedVariablesOf(check.modules, check.core)) {
		const module = `module "${rename.module}"`;
		for (const name of rename.to === null ? [rename.from] : [rename.from, rename.to]) {
			const set = resolve({ [name]: MARKER });
			const captured = check.layers.some(
				(_layer, index) =>
					capturedIn(unset[index]?.tree, name) === null &&
					capturedIn(set[index]?.tree, name) === MARKER,
			);
			if (!captured) {
				problems.push(
					`${module}: ${name} is not captured: a layer holds \`${RENAMED_VARIABLES_SECTION}.${name} = null\` then \`${RENAMED_VARIABLES_SECTION}.${name} = \${?${name}}\``,
				);
			}
			const marked = set.map(({ layer, tree }) => ({ layer, paths: markedPaths(tree) }));
			if (name === rename.from) {
				for (const { layer, paths } of marked) {
					for (const path of paths) {
						if (path === `${RENAMED_VARIABLES_SECTION}.${name}`) continue;
						problems.push(`${module}: ${name}, declared renamed, is bound at ${path} in ${layer}`);
					}
				}
			} else if (!marked.some(({ paths }) => paths.includes(rename.path as string))) {
				problems.push(`${module}: ${name} is bound at ${rename.path} in no layer`);
			}
		}
	}
	return problems.sort();
}
