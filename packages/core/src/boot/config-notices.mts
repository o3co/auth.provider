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
 * what is named, and how. It also reads the configuration's defaults once,
 * into a copy of their plain data (`readConfigDefaults`), so the notices read
 * no getter and no Proxy trap a composition handed in.
 */

import { isDeepStrictEqual } from "node:util";
import { isPlainConfigObject } from "../config/composed.mjs";
import { pathsSetBy, setCaptures, withoutRenamedVariables } from "../config/removed-keys.mjs";
import type { Logger } from "../logging/Logger.mjs";

/** What the notices are read from. */
export interface ConfigNoticeInput {
	/** The configuration as handed to boot, captures of renamed variables included. */
	readonly config: unknown;
	/** The top-level sections something loaded owns: core, or a loaded module. */
	readonly owned: ReadonlySet<string>;
	/**
	 * The configuration's defaults as `readConfigDefaults` copied them;
	 * `undefined` when the composition handed none.
	 */
	readonly defaults: ConfigDefaults | undefined;
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

/** The configuration's defaults, as `readConfigDefaults` copied them: plain data, keyed by section. */
export type ConfigDefaults = Readonly<Record<string, unknown>>;

/** Why `configDefaults` cannot be read as plain data, and where: the keys from its top, `[]` for itself. */
export interface ConfigDefaultsProblem {
	readonly path: readonly string[];
	readonly problem: string;
}

/** A copy of plain data, or why a value is not plain data. */
type Copied = { readonly value: unknown } | ConfigDefaultsProblem;

/** What a value read as an accessor, or not at all, is refused as. */
const NOT_DATA =
	"is not a data property: the defaults are read once as plain data, never through a getter";

/** What a value that is not plain data is refused as. */
const NOT_PLAIN = "is not plain data (a string, a number, a boolean, null, a list or an object)";

/** The copy of the data property `key` of `holder`, or why it has none. */
function copyProperty(holder: object, key: string, path: readonly string[]): Copied {
	const at = [...path, key];
	const descriptor = Object.getOwnPropertyDescriptor(holder, key);
	if (descriptor === undefined || !("value" in descriptor)) return { path: at, problem: NOT_DATA };
	return copyPlainData(descriptor.value, at);
}

/** `value` and what it holds, each read once, copied; an object keeps its prototype (`Object.prototype` or none). */
function copyLevel(value: unknown, path: readonly string[]): Copied {
	if (value === null || ["string", "number", "boolean"].includes(typeof value)) return { value };
	if (Array.isArray(value)) {
		const length = value.length;
		const list: unknown[] = [];
		for (let index = 0; index < length; index++) {
			const element = copyProperty(value, String(index), path);
			if ("problem" in element) return element;
			list.push(element.value);
		}
		return { value: list };
	}
	if (!isPlainConfigObject(value)) return { path, problem: NOT_PLAIN };
	const copy: Record<string, unknown> = Object.create(Object.getPrototypeOf(value));
	for (const key of Object.keys(value)) {
		const member = copyProperty(value, key, path);
		if ("problem" in member) return member;
		Object.defineProperty(copy, key, {
			value: member.value,
			enumerable: true,
			writable: true,
			configurable: true,
		});
	}
	return { value: copy };
}

/** `copyLevel`, with a throw at this level — a getter's, a Proxy trap's — refused at `path`. */
function copyPlainData(value: unknown, path: readonly string[]): Copied {
	try {
		return copyLevel(value, path);
	} catch {
		return { path, problem: "threw as it was read" };
	}
}

/**
 * `bootstrapComponents.configDefaults`, read once into a copy of its plain
 * data — `undefined` when handed none, or handed `undefined` — or why it is
 * not plain data: an object of sections whose every value is a string, a
 * number, a boolean, `null`, a list or an object (prototype `Object.prototype`
 * or none), each an own data property. An accessor is refused whether or not
 * it throws, and so is a throw as it is read, a Proxy's included. The copy
 * keeps each object's prototype, which the notices' comparison reads.
 */
export function readConfigDefaults(
	value: unknown,
): { readonly defaults: ConfigDefaults | undefined } | ConfigDefaultsProblem {
	if (value === undefined) return { defaults: undefined };
	let isObject: boolean;
	try {
		isObject = isPlainConfigObject(value);
	} catch {
		return { path: [], problem: "threw as it was read" };
	}
	if (!isObject) return { path: [], problem: "is not an object of sections" };
	const copied = copyPlainData(value, []);
	return "problem" in copied ? copied : { defaults: copied.value as ConfigDefaults };
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
	defaults: ConfigDefaults | undefined,
): UnownedSections {
	// Boot's parse accepted the configuration as an object before this runs —
	// a plain one or an instance: its own keys are the sections.
	const sections = withoutRenamedVariables(config) as Readonly<Record<string, unknown>>;
	const ignored: string[] = [];
	const notLoaded: string[] = [];
	for (const name of Object.keys(sections).sort()) {
		if (owned.has(name) || pathsSetBy(sections[name]).length === 0) continue;
		if (defaults === undefined || !Object.hasOwn(defaults, name)) ignored.push(name);
		else if (!isDeepStrictEqual(sections[name], defaults[name])) notLoaded.push(name);
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
