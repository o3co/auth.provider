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
 * The guard that every configuration leaf a module reads takes the string an
 * environment variable arrives as. HOCON substitutes `${?VAR}` as a string,
 * always, and boot's composed parse is plain Zod, which does not coerce a
 * bare `z.boolean()` or `z.number()`. A module's leaf is covered when core's
 * transitional base declares the same path with a leaf that reads a string
 * (and coerces it first); otherwise the module's own leaf must read it.
 */

import type { z } from "zod";
import { TransitionalConfigSchema } from "../config/composed.mjs";
import {
	outputKinds,
	readsEnvironmentString,
	schemasAtPath,
	unreadableLeaves,
} from "../config/schema-path.mjs";
import type { Module } from "../modules/manifest/module-spec.mjs";

/**
 * Whether core's base reads the value at `path` (a `*` key: any) from a
 * string before a module does, and hands on the kind of value `leaf` takes —
 * a base that reads the string and leaves it a string covers no module's
 * number.
 */
function coveredByBase(path: string, leaf: z.ZodType): boolean {
	const wanted = outputKinds(leaf);
	const leaves = schemasAtPath(TransitionalConfigSchema, path.split("."));
	return (
		wanted !== undefined &&
		leaves.length > 0 &&
		leaves.every((base) => {
			const produced = outputKinds(base);
			return (
				readsEnvironmentString(base) &&
				produced !== undefined &&
				[...produced].every((kind) => wanted.has(kind))
			);
		})
	);
}

/**
 * Every leaf the modules' section schemas declare, each at its module's name,
 * that would refuse an environment variable's string — a bare `z.boolean()`, or a
 * `z.number()` that does not coerce, with core's base not coercing the path
 * first — as `<module>: <path>`, sorted. A record's value is `*`, a list's
 * element `[]`.
 */
export function unreadableModuleLeaves(modules: readonly Module[]): string[] {
	return modules
		.flatMap((module) => {
			const section = module.section ? unreadableLeaves(module.section.schema, module.name) : [];
			return section
				.filter(({ path, leaf }) => !coveredByBase(path, leaf))
				.map(({ path }) => `${module.name}: ${path}`);
		})
		.filter((entry, index, all) => all.indexOf(entry) === index)
		.sort();
}
