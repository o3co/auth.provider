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
 * boot/config-notices.mts: stage 1's notices about configuration no loaded
 * module reads, each logged once at warn and naming no value: the top-level
 * sections no loaded owner reads, told apart by the configuration's defaults
 * (`config_sections_ignored`, `config_sections_not_loaded`), and the
 * variables the resolution captured set that no loaded module declares
 * renamed (`environment_variables_not_applied`). Which sections are owned and
 * which variables are judged is the caller's to say; this file decides only
 * what is named, and how.
 */

import { isDeepStrictEqual } from "node:util";
import { pathsSetBy, setCaptures, withoutRenamedVariables } from "../config/removed-keys.mjs";
import type { Logger } from "../logging/Logger.mjs";

/** What the notices are read from. */
export interface ConfigNoticeInput {
	/** The configuration as handed to boot, captures of renamed variables included. */
	readonly config: unknown;
	/** The top-level sections something loaded owns: core, or a loaded module. */
	readonly owned: ReadonlySet<string>;
	/**
	 * `bootstrapComponents.configDefaults`: the configuration as the loaded
	 * modules' references and core's set it, with no operator layer and no
	 * environment. `undefined` when the composition handed none; a value that
	 * is not an object is read as one that sets no section.
	 */
	readonly defaults: unknown;
	/** The variable names a loaded module, or core, declares renamed: old and new. */
	readonly judged: ReadonlySet<string>;
}

/** The top-level sections no loaded owner reads, each list sorted. */
interface UnownedSections {
	/** Set by no loaded package's defaults: what a misspelt section name is. */
	readonly ignored: readonly string[];
	/** Set by a loaded package's defaults for a module not loaded, and changed from them. */
	readonly notLoaded: readonly string[];
}

/** The value of `name` in `defaults`, read as an own property; absent when `defaults` is not an object. */
function defaultOf(defaults: unknown, name: string): { readonly value: unknown } | undefined {
	if (typeof defaults !== "object" || defaults === null || !Object.hasOwn(defaults, name)) {
		return undefined;
	}
	return { value: (defaults as Readonly<Record<string, unknown>>)[name] };
}

/**
 * Each top-level section of `config` (its own keys, captures removed) that is
 * not owned and sets something (`pathsSetBy`: an empty section, or one
 * holding only empty ones, sets nothing): silent when `defaults` holds it and
 * it equals that (`isDeepStrictEqual`); not loaded when `defaults` holds it
 * and it differs — the operator's files or the environment changed it;
 * ignored otherwise, as every one is without `defaults`.
 */
function unownedSections(
	config: unknown,
	owned: ReadonlySet<string>,
	defaults: unknown,
): UnownedSections {
	// Boot's parse accepted the configuration as an object before this runs —
	// a plain one or an instance: its own keys are the sections.
	const sections = withoutRenamedVariables(config) as Readonly<Record<string, unknown>>;
	const ignored: string[] = [];
	const notLoaded: string[] = [];
	for (const name of Object.keys(sections).sort()) {
		if (owned.has(name) || pathsSetBy(sections[name]).length === 0) continue;
		const fallback = defaultOf(defaults, name);
		if (fallback === undefined) ignored.push(name);
		else if (!isDeepStrictEqual(sections[name], fallback.value)) notLoaded.push(name);
	}
	return { ignored, notLoaded };
}

/** The variables `config` captured set that no name in `judged` is, sorted. */
function variablesNotApplied(config: unknown, judged: ReadonlySet<string>): readonly string[] {
	return setCaptures(config)
		.filter((name) => !judged.has(name))
		.sort();
}

/**
 * Logs each notice that names something, once, at warn, to `logger`:
 * `config_sections_ignored` and `config_sections_not_loaded` with
 * `{ sections }`, `environment_variables_not_applied` with `{ variables }`.
 * Without a logger, nothing is heard.
 */
export function logConfigNotices(logger: Logger | undefined, input: ConfigNoticeInput): void {
	if (logger === undefined) return;
	const { ignored, notLoaded } = unownedSections(input.config, input.owned, input.defaults);
	if (ignored.length > 0) logger.warn({ sections: [...ignored] }, "config_sections_ignored");
	if (notLoaded.length > 0) logger.warn({ sections: [...notLoaded] }, "config_sections_not_loaded");
	const variables = variablesNotApplied(input.config, input.judged);
	if (variables.length > 0) {
		logger.warn({ variables: [...variables] }, "environment_variables_not_applied");
	}
}
