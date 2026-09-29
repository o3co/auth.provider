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
 * The one way a removed config key dies (#366).
 *
 * Zod's default object behavior strips unknown keys before `superRefine`
 * sees the data, so without a raw-input check an operator's stale config
 * line (`legacyTokenCompat = true`) is silently ignored on upgrade — the
 * config sits in the file looking load-bearing while doing nothing. Every
 * key removal therefore detects on the raw input, via `z.preprocess`, and
 * fails boot naming the key, the release that removed it, and what to do.
 *
 * Before #366 that detection existed as two copy-pasted table+wrapper
 * blocks (`oauth.refreshToken`, `oauth.authorize`), and the next removal
 * would have copied whichever the author saw last. This helper is the one
 * spelling; `docs/release-policy.md` §"Retiring a config key" carries the
 * fail-vs-warn decision rule for choosing between it and the warn-and-
 * ignore treatment (`INERT_PKCE_KEYS` in `@o3co/auth-provider-oauth`).
 *
 * A path that moved (#728 B10) dies the same way, in the same words: a
 * module declares where its section moved from (`section.relocatedFrom`),
 * and boot refuses a configuration still setting a key there
 * (`config-path-relocated`), naming the new path and the environment variable
 * that binds it. The detection (`findRelocatedKeys`) and the message
 * (`relocatedKeyMessage`) live here beside `withRemovedKeys`, sharing its
 * message shape; boot reads the rows off the loaded modules' manifests, since
 * an old path may sit in no section any of them still parses. The refusal is
 * removed at the first major release — `relocatedPaths.drift.test.mts` fails
 * the cut that forgets.
 *
 * ## The coercion-walk caveat
 *
 * `z.preprocess` compiles to a pipe the `@o3co/ts.hocon` zod bridge does
 * not descend into, so any leaf wrapped by this helper loses the bridge's
 * free string coercion (#288's root cause). That is survivable because the
 * repo no longer relies on the bridge for coercion: every env-overridable
 * boolean goes through `coerceBooleanFromEnv` and every number through
 * `z.coerce.number()` **on the field itself** — a property owned by the
 * field, not by what happens to be wrapped around it, and pinned by the
 * standalone template's documented-env-overrides suite. Keep it that way
 * when adding fields under a wrapped section.
 *
 * Related mechanisms, deliberately NOT this helper:
 *
 * - **Enum shrink** (`legacyRtPolicy: z.enum(["reject"])`): removing a
 *   VALUE from a still-live key. Zod's `invalid_enum_value` already names
 *   the accepted values; a tombstone table would only restate it.
 * - **Keys reshaped in place** (`LEGACY_JWT_FIELDS`): the key still exists under a new
 *   shape, so the message is a migration pointer ("migrate to
 *   `oauth.jwt.signingKey.local.<field>`"), not a removal notice. Folding
 *   it here would either water the removal message down or teach this
 *   helper a second dialect.
 * - **Warn-and-ignore** (`INERT_PKCE_KEYS`): for keys whose ignored value
 *   leaves behavior strictly stronger — see the release-policy rule.
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
	 * The release that removed it, plus internal phase marker where the tag
	 * is not cut yet (`v0.6.0 (Phase G / M4)`). Per docs/release-policy.md
	 * R5, the released-tag portion is filled in at release-cut time.
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
 * One configuration path that moved (#728 B10): the keys an operator wrote it
 * at, and the keys it is written at now — or `null` for a key removed rather
 * than moved. A subtree moves with everything under it — `oauth.dpop` to
 * `dpop` takes `oauth.dpop.nonce.lifetime` to `dpop.nonce.lifetime` — unless
 * a more specific relocation says otherwise (`oauth.dpop.iat-window-seconds`
 * to `dpop.iatWindowSeconds`).
 *
 * Unlike a removed key, which a section's own schema detects
 * (`withRemovedKeys`), a moved path is declared by the module that now owns it
 * (its manifest's `section.relocatedFrom`) and refused by boot before the
 * configuration is parsed, since the old path may be in no section any loaded
 * module reads.
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
 * A key a configuration still sets at or under a relocated path: the dot path
 * it was written at, the dot path it moved to (`null` when it was removed),
 * and the environment variable bound to the new path (#728 B9's rule,
 * `environmentVariableFor`, a list of objects' elements indexed per #728 R4)
 * — absent when the key was removed, or nothing binds the new path yet.
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
 * Every key `config` sets at or under a relocated path, each once, in the
 * order the relocations are given and the configuration lists its keys. A
 * value is one key; so is a list of values (an environment variable carries
 * it whole, comma-separated), and a value that is not plain data (a Date, a
 * URL). A subtree is walked, and so is a list of objects, each index a key
 * (#728 R4); an empty one sets nothing — HOCON leaves `{}` where an unset
 * `${?VARIABLE}` was an object's only binding. Each key is mapped by the most
 * specific relocation that covers it — the longest `from`, the first given
 * on a tie — its keys below that relocation's `from` carried over unchanged,
 * or to nothing when that relocation's `to` is `null`. Keys are read as own
 * properties.
 *
 * Each result carries the relocation that mapped it.
 */
export function findRelocatedKeys<R extends RelocatedPath>(
	config: unknown,
	relocations: readonly R[],
): (RelocatedKey & { readonly relocation: R })[] {
	const found = new Map<string, RelocatedKey & { readonly relocation: R }>();
	const add = (path: readonly string[]): void => {
		let mapping: R | undefined;
		for (const relocation of relocations) {
			if (!startsWith(path, relocation.from)) continue;
			if (mapping === undefined || relocation.from.length > mapping.from.length) {
				mapping = relocation;
			}
		}
		if (mapping === undefined) return;
		const from = path.join(".");
		if (mapping.to === null) {
			found.set(from, { from, to: null, relocation: mapping });
			return;
		}
		const to = [...mapping.to, ...path.slice(mapping.from.length)];
		found.set(from, {
			from,
			to: to.join("."),
			...(mapping.unbound === true ? {} : { environmentVariable: environmentVariableFor(to) }),
			relocation: mapping,
		});
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
