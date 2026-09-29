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
 * environment variable arrives as (#728). HOCON substitutes `${?VAR}` as a
 * string, always, and boot's one composed parse is plain Zod — the HOCON
 * library's bridge, which coerced a bare `z.boolean()` / `z.number()` leaf on
 * the way into the standalone template's pre-parse, is no longer on the path.
 *
 * A module's `configSchema` and section schema read what core's transitional
 * base made of the configuration, so a leaf of theirs is covered when the base
 * declares the same path with a leaf that reads a string (and coerces it
 * first); otherwise the module's own leaf must read it.
 */

import { TransitionalConfigSchema } from "../config/composed.mjs";
import {
	readsEnvironmentString,
	schemasAtPath,
	unreadableLeafPaths,
} from "../config/schema-path.mjs";
import type { Module } from "../modules/manifest/module-spec.mjs";

/** Whether core's base coerces the value at `path` (a `*` key: any) before a module reads it. */
function coercedByBase(path: string): boolean {
	const leaves = schemasAtPath(TransitionalConfigSchema, path.split("."));
	return leaves.length > 0 && leaves.every(readsEnvironmentString);
}

/**
 * Every leaf the modules' `configSchema`s and section schemas declare that
 * would refuse an environment variable's string — a bare `z.boolean()`, or a
 * `z.number()` that does not coerce, with core's base not coercing the path
 * first — as `<module>: <path>`, sorted. A record's value is `*`, a list's
 * element `[]`.
 */
export function unreadableModuleLeaves(modules: readonly Module[]): string[] {
	return modules
		.flatMap((module) => {
			const configSchema = module.configSchema ? unreadableLeafPaths(module.configSchema) : [];
			const section = module.section
				? unreadableLeafPaths(module.section.schema, module.section.at ?? module.name)
				: [];
			return [...configSchema, ...section]
				.filter((path) => !coercedByBase(path))
				.map((path) => `${module.name}: ${path}`);
		})
		.filter((entry, index, all) => all.indexOf(entry) === index)
		.sort();
}
