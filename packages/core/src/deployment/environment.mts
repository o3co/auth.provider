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
 * The name a deployment selected its configuration by (`CONFIG_ENV`,
 * `NODE_ENV`, or a name a composition root passes), as a guard on a
 * development-only thing reads it: trimmed and in lower case, so
 * "Production" or "production\n" names production as surely; and
 * production or staging whichever of the names consulted says so, none
 * lifting another's.
 */

/** The names that make a deployment one no development-only thing may run in. */
const PRODUCTION_NAMES: ReadonlySet<string> = new Set(["production", "staging"]);

/** `name` trimmed and in lower case, or `undefined` for a value that is no name or an empty one. */
export function readEnvironmentName(name: unknown): string | undefined {
	if (typeof name !== "string") return undefined;
	const read = name.trim().toLowerCase();
	return read === "" ? undefined : read;
}

/** The first of `names` that reads as production or staging, or `undefined` when none does. */
export function productionEnvironmentIn(
	names: readonly unknown[],
): "production" | "staging" | undefined {
	for (const name of names) {
		const read = readEnvironmentName(name);
		if (read !== undefined && PRODUCTION_NAMES.has(read)) return read as "production" | "staging";
	}
	return undefined;
}
