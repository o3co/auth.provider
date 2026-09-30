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
 * names captured in `renamed-variables` (`null` when unset) by the declaring
 * module's own `section.reference` — core's own `reference.conf` for core —
 * and by no other layer, since a capture written elsewhere by hand would
 * override what the resolution saw; the new name bound at its path, else a
 * value set under it would be dropped while boot accepts it; and the old name
 * bound nowhere else, else declaring it would refuse every operator who sets
 * it. The layers come resolved by the caller's HOCON reader, so core takes no
 * HOCON dependency. `renamedVariableCaptures` is what such a resolution
 * captures, for a configuration built by hand.
 */

import { resolve as resolvePath } from "node:path";
import { fileURLToPath } from "node:url";
import { renamedVariablesOf } from "../boot/validate-manifests.mjs";
import type { CoreRelocations } from "../config/core-relocations.mjs";
import { coreReference } from "../config/references.mjs";
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

/** The captures `tree` holds, by name; none when it holds no `renamed-variables`. */
const capturesIn = (tree: unknown): Readonly<Record<string, unknown>> => {
	const section = isPlainObject(tree) ? tree[RENAMED_VARIABLES_SECTION] : undefined;
	return isPlainObject(section) ? section : {};
};

/** The file that captures the renames of the module named `name`: core's own reference for "core". */
function captureFileOf(name: string, modules: readonly Module[]): string | undefined {
	if (name === "core") return fileURLToPath(coreReference());
	const reference = modules.find((module) => module.name === name)?.section?.reference;
	return reference === undefined ? undefined : fileURLToPath(reference);
}

/**
 * What is wrong with the bindings of the renames `check.modules` (and
 * `check.core`) declare across `check.layers`, one line per problem, sorted:
 * a declaring module with no `section.reference`; a name its reference does
 * not capture as `null` unset and as its value set; a layer capturing a name
 * no module whose reference it is declares; a new name bound at its path in
 * no layer; an old name a layer binds anywhere but its capture. `[]` when
 * nothing is.
 */
export function renamedVariableProblems(check: RenamedVariableCheck): string[] {
	const problems = new Set<string>();
	const layers = check.layers.map((layer) => resolvePath(layer));
	const resolve = (env: Readonly<Record<string, string>>) =>
		layers.map((layer) => ({ layer, tree: check.read(layer, env) }));
	const unset = resolve({});
	const renames = renamedVariablesOf(check.modules, check.core);
	const declaredBy = new Map<string, Set<string>>();
	for (const rename of renames) {
		const file = captureFileOf(rename.module, check.modules);
		const module = `module "${rename.module}"`;
		const names = rename.to === null ? [rename.from] : [rename.from, rename.to];
		if (file === undefined) {
			problems.add(
				`${module}: declares renamed variables and no section.reference, whose file captures them`,
			);
		} else {
			const declared = declaredBy.get(resolvePath(file)) ?? new Set<string>();
			for (const name of names) declared.add(name);
			declaredBy.set(resolvePath(file), declared);
		}
		for (const name of names) {
			const set = resolve({ [name]: MARKER });
			if (file !== undefined) {
				const index = layers.indexOf(resolvePath(file));
				const captured =
					index !== -1 &&
					capturesIn(unset[index]?.tree)[name] === null &&
					capturesIn(set[index]?.tree)[name] === MARKER;
				if (!captured) {
					const by =
						rename.module === "core" ? "core's own reference.conf" : "its section.reference";
					problems.add(
						`${module}: ${name} is not captured by ${by} (${file}): it holds \`${RENAMED_VARIABLES_SECTION}.${name} = null\` then \`${RENAMED_VARIABLES_SECTION}.${name} = \${?${name}}\``,
					);
				}
			}
			const marked = set.map(({ layer, tree }) => ({ layer, paths: markedPaths(tree) }));
			if (name === rename.from) {
				for (const { layer, paths } of marked) {
					for (const path of paths) {
						if (path === `${RENAMED_VARIABLES_SECTION}.${name}`) continue;
						problems.add(`${module}: ${name}, declared renamed, is bound at ${path} in ${layer}`);
					}
				}
			} else if (!marked.some(({ paths }) => paths.includes(rename.path as string))) {
				problems.add(`${module}: ${name} is bound at ${rename.path} in no layer`);
			}
		}
	}
	for (const { layer, tree } of unset) {
		const declared = declaredBy.get(layer) ?? new Set<string>();
		for (const name of Object.keys(capturesIn(tree))) {
			if (declared.has(name)) continue;
			problems.add(
				`${layer}: captures ${name}, which no module whose section.reference it is declares renamed`,
			);
		}
	}
	return [...problems].sort();
}

export interface RenamedVariableCaptureInput {
	/** The modules whose `section.renamedVariables` are captured. */
	readonly modules: readonly Module[];
	/** Core's own section's declaration, captured beside theirs. */
	readonly core?: CoreRelocations;
	/** The environment the configuration is substituted with. */
	readonly env: Readonly<Record<string, string | undefined>>;
}

/**
 * What a resolution under `env` captures in `renamed-variables` for the
 * renames `input.modules` (and `input.core`) declare: each old and new name's
 * value, `null` when unset. For a configuration built by hand, which must
 * capture every declared name from the environment it is substituted with.
 */
export function renamedVariableCaptures(
	input: RenamedVariableCaptureInput,
): Record<string, string | null> {
	const captures: Record<string, string | null> = {};
	for (const rename of renamedVariablesOf(input.modules, input.core)) {
		for (const name of rename.to === null ? [rename.from] : [rename.from, rename.to]) {
			const value = input.env[name];
			captures[name] = typeof value === "string" ? value : null;
		}
	}
	return captures;
}
