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
 * The one way a removed or relocated config key fails boot.
 *
 * Zod strips unknown keys before `superRefine` sees them, so a stale config
 * line would be ignored silently while looking load-bearing. A removed key is
 * therefore detected on the raw input (`z.preprocess`) and fails boot naming the
 * key, the release that removed it, and what to do. `docs/release-policy.md`
 * §"Retiring a config key" decides between this and warn-and-ignore
 * (`INERT_PKCE_KEYS` in `@o3co/auth-provider-oauth`, for keys whose ignored
 * value leaves behavior strictly stronger).
 *
 * A relocated path fails the same way, in the same words: a module declares
 * where its section moved from (`section.relocatedFrom`), and boot refuses a
 * configuration still setting a key there (`config-path-relocated`), naming the
 * new path and its environment variable. Boot reads the rows off the loaded
 * modules' manifests, since an old path may sit in no section any of them
 * parses. A variable renamed with the move is declared beside them
 * (`section.renamedVariables`): while the environment sets its old name, boot
 * refuses unless the new name is set to the same string
 * (`environment-variable-renamed`). Both refusals are removed at the first
 * major release; `relocatedPaths.drift.test.mts` fails the cut that forgets.
 *
 * `z.preprocess` compiles to a pipe the `@o3co/ts.hocon` zod bridge does not
 * descend into, so every field under a wrapped section must coerce on its own
 * (`coerceBooleanFromEnv`, `z.coerce.number()`).
 *
 * Not for a value removed from a live enum (Zod's error names the accepted
 * values) or a key reshaped in place (`LEGACY_JWT_FIELDS`, whose message is a
 * migration pointer).
 */

import { z } from "zod";
import { environmentVariableFor } from "./environment-variable.mjs";

/**
 * Every "this key is gone" message has one shape — the path the operator
 * wrote, what became of it, the CHANGELOG, and what to do — so a removed key
 * and a relocated one read alike.
 */
function goneKeyMessage(path: string, whatBecameOfIt: string, remedy: string): string {
	return `${path} ${whatBecameOfIt}; see CHANGELOG. ${remedy}`;
}

/** One removed key: what to tell the operator still setting it. */
export interface RemovedKey {
	/** The key as it appeared under the section (`legacyTokenCompat`). */
	readonly name: string;
	/**
	 * The release that removed it, with a phase or PR marker
	 * (`v0.6.0 (Phase G / M4)`). Per docs/release-policy.md R5, the tag is
	 * filled in at release-cut time.
	 */
	readonly removedIn: string;
	/** What replaced it / what the operator does instead. Full sentences. */
	readonly note: string;
}

/**
 * Wraps `schema` so that any key in `removed` still present on the RAW
 * input fails parse with a targeted, operator-facing message — instead of
 * being stripped silently by Zod's unknown-key handling.
 *
 * `sectionPath` is the config path the operator writes (`oauth.refreshToken`);
 * it prefixes the key in the message so the boot error names the exact line
 * to delete. Every removed key present is reported, not just the first.
 */
export function withRemovedKeys<S extends z.ZodTypeAny>(
	sectionPath: string,
	removed: readonly RemovedKey[],
	schema: S,
) {
	return z.preprocess((raw, ctx) => {
		if (typeof raw === "object" && raw !== null && !Array.isArray(raw)) {
			const rawObj = raw as Record<string, unknown>;
			for (const entry of removed) {
				if (entry.name in rawObj) {
					ctx.addIssue({
						code: z.ZodIssueCode.custom,
						message: goneKeyMessage(
							`${sectionPath}.${entry.name}`,
							`was removed in ${entry.removedIn}`,
							`${entry.note} Remove this field from your config.`,
						),
						path: [entry.name],
					});
				}
			}
		}
		return raw;
	}, schema);
}

/**
 * One configuration path that moved: the keys it was written at and the keys
 * it is written at now, or `null` for a key removed rather than moved. A subtree
 * moves with everything under it (`oauth.dpop` → `dpop` takes
 * `oauth.dpop.nonce.lifetime` to `dpop.nonce.lifetime`) unless a more specific
 * relocation says otherwise. Declared by the module that now owns the path
 * (`section.relocatedFrom`) and refused by boot before parsing, since the old
 * path may be in no section any loaded module reads.
 */
export interface RelocatedPath {
	readonly from: readonly string[];
	readonly to: readonly string[] | null;
	/**
	 * Whether no environment variable binds the new path yet — it lies under a
	 * section path that is still transitional — so none is named.
	 */
	readonly unbound?: boolean;
}

/**
 * A key a configuration still sets at or under a relocated path: where it was
 * written, where it moved (`null` when removed), and the environment variable
 * bound to the new path (`environmentVariableFor`; list-of-object elements are
 * indexed), absent when removed or when nothing binds the new path yet.
 */
export interface RelocatedKey {
	readonly from: string;
	readonly to: string | null;
	readonly environmentVariable?: string;
}

/** Plain data: an object whose prototype is `Object.prototype` or none — not an array, a Date or a URL. */
const isPlainObject = (value: unknown): value is Readonly<Record<string, unknown>> => {
	if (typeof value !== "object" || value === null) return false;
	const prototype: unknown = Object.getPrototypeOf(value);
	return prototype === Object.prototype || prototype === null;
};

/** The value at `path`, read key by key as own properties; `undefined` when any is absent. */
const readOwn = (config: unknown, path: readonly string[]): unknown => {
	let value: unknown = config;
	for (const key of path) {
		if (value === null || typeof value !== "object" || !Object.hasOwn(value, key)) return undefined;
		value = (value as Readonly<Record<string, unknown>>)[key];
	}
	return value;
};

/** Whether `path` is `prefix` or lies under it. Keys are non-empty, so a shorter path never matches. */
const startsWith = (path: readonly string[], prefix: readonly string[]): boolean =>
	prefix.every((key, index) => path[index] === key);

/**
 * Where the key at `path` moved: the most specific relocation covering it
 * (longest `from`, first on a tie), the key's new path (`null` when removed)
 * and the variable bound there; `undefined` when no relocation covers it.
 */
export function relocateKey<R extends RelocatedPath>(
	path: readonly string[],
	relocations: readonly R[],
): (RelocatedKey & { readonly relocation: R }) | undefined {
	let mapping: R | undefined;
	for (const relocation of relocations) {
		if (!startsWith(path, relocation.from)) continue;
		if (mapping === undefined || relocation.from.length > mapping.from.length) {
			mapping = relocation;
		}
	}
	if (mapping === undefined) return undefined;
	const from = path.join(".");
	if (mapping.to === null) return { from, to: null, relocation: mapping };
	const to = [...mapping.to, ...path.slice(mapping.from.length)];
	return {
		from,
		to: to.join("."),
		...(mapping.unbound === true ? {} : { environmentVariable: environmentVariableFor(to) }),
		relocation: mapping,
	};
}

/**
 * Every key `config` sets at or under a relocated path, each once, in
 * relocation order and then configuration key order; each result carries the
 * relocation that mapped it (`relocateKey`). A value, a list of values (an
 * environment variable carries it whole) and non-plain data (a Date, a URL)
 * are one key each; a subtree and a list of objects (each index a key) are
 * walked, and an empty one sets nothing (HOCON leaves `{}` for an unset
 * `${?VARIABLE}`). Keys are read as own properties.
 */
export function findRelocatedKeys<R extends RelocatedPath>(
	config: unknown,
	relocations: readonly R[],
): (RelocatedKey & { readonly relocation: R })[] {
	const found = new Map<string, RelocatedKey & { readonly relocation: R }>();
	const add = (path: readonly string[]): void => {
		const key = relocateKey(path, relocations);
		if (key !== undefined) found.set(key.from, key);
	};
	const walk = (path: readonly string[], value: unknown): void => {
		if (isPlainObject(value)) {
			for (const key of Object.keys(value)) walk([...path, key], value[key]);
			return;
		}
		if (Array.isArray(value) && value.length > 0 && value.every(isPlainObject)) {
			value.forEach((element, index) => {
				walk([...path, String(index)], element);
			});
			return;
		}
		add(path);
	};
	for (const relocation of relocations) {
		const value = readOwn(config, relocation.from);
		if (value !== undefined) walk(relocation.from, value);
	}
	return [...found.values()];
}

/** What every relocated key's message ends with: remove it, from the file or the environment. */
const THIS_FIELD = "this field from your config (or unset the environment variable that sets it).";

/** What to tell the operator still setting a relocated key, in the words a removed key is refused in. */
export function relocatedKeyMessage(key: RelocatedKey): string {
	if (key.to === null) return goneKeyMessage(key.from, "was removed", `Remove ${THIS_FIELD}`);
	const variable =
		key.environmentVariable === undefined
			? ""
			: ` (environment variable ${key.environmentVariable})`;
	return goneKeyMessage(
		key.from,
		`has moved to ${key.to}`,
		`Write it there${variable} and remove ${THIS_FIELD}`,
	);
}

/**
 * An environment variable whose name changed with a relocation: its old name,
 * its name now, and the path the new name is bound to.
 */
export interface RenamedVariable {
	readonly from: string;
	readonly to: string;
	readonly path: string;
}

/**
 * How the environment breaks a rename while it sets the old name: the new
 * name unset, or set to a different string. Neither value is carried.
 */
export type RenamedVariableProblem = "unset" | "different";

/** The value `name` has as an own string property of `environment`; `undefined` otherwise. */
const variableIn = (
	environment: Readonly<Record<string, string | undefined>>,
	name: string,
): string | undefined => {
	if (!Object.hasOwn(environment, name)) return undefined;
	const value: unknown = environment[name];
	return typeof value === "string" ? value : undefined;
};

/**
 * Every rename `environment` breaks, in `renames` order: the old name set (the
 * empty string included) while the new name is unset, or set to a different
 * string. The two set to the same string, or the old name unset, break
 * nothing. A default at the new path is not the new name set.
 */
export function findRenamedVariables<V extends RenamedVariable>(
	environment: Readonly<Record<string, string | undefined>>,
	renames: readonly V[],
): (V & { readonly newVariable: RenamedVariableProblem })[] {
	return renames.flatMap((rename) => {
		const old = variableIn(environment, rename.from);
		if (old === undefined) return [];
		const current = variableIn(environment, rename.to);
		if (current === old) return [];
		return [{ ...rename, newVariable: current === undefined ? "unset" : "different" }];
	});
}

/**
 * What to tell the operator whose environment breaks a rename, in the words a
 * relocated key is refused in. Names the variables and the new path, never a
 * value: a variable may carry a secret.
 */
export function renamedVariableMessage(
	rename: RenamedVariable & { readonly newVariable: RenamedVariableProblem },
): string {
	return goneKeyMessage(
		rename.from,
		`was renamed ${rename.to}, the variable ${rename.path} is bound to`,
		rename.newVariable === "unset"
			? `Set ${rename.to} instead and unset ${rename.from}.`
			: `${rename.to} is set to a different value: keep the one you mean in ${rename.to} and unset ${rename.from}.`,
	);
}
