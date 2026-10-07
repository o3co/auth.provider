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
 * The one precedence every bundled limiter takes a key's budget by, so one
 * configuration is one budget whichever limiter is mounted.
 */

import type { RateLimitSpec } from "./types.mjs";
import { assertUsableRateLimitSpecs } from "./usableSpec.mjs";

export interface RateLimitBudgetLookupOptions {
	/** What an operator declared on this limiter, by prefix. */
	readonly limits?: Readonly<Record<string, RateLimitSpec>>;
	/** What a key under a prefix `limits` does not name is limited by. */
	readonly defaultLimit: RateLimitSpec;
}

/** The prefix a key is limited under, and the budget in force for it. */
export interface RateLimitBudget {
	/** The key up to its first `:`, or the whole key when it has none. */
	readonly prefix: string;
	readonly spec: RateLimitSpec;
}

/** A key's budget, and the default it falls to. */
export interface RateLimitBudgetLookup {
	(key: string): RateLimitBudget;
	/** `defaultLimit` as it was checked, frozen. */
	readonly defaultLimit: RateLimitSpec;
}

const prefixOf = (key: string): string => {
	const colon = key.indexOf(":");
	return colon === -1 ? key : key.slice(0, colon);
};

/** An object spec's two fields, read once, frozen; anything else as given. */
const snapshotSpec = (spec: unknown): unknown =>
	typeof spec === "object" && spec !== null
		? Object.freeze({
				limit: (spec as { readonly limit?: unknown }).limit,
				windowSeconds: (spec as { readonly windowSeconds?: unknown }).windowSeconds,
			})
		: spec;

/**
 * A key's budget: the limiter's own `limits` entry for its prefix, else
 * `defaultLimit` (never no limit). `limits` and `defaultLimit` are each read
 * once into a frozen copy, refused, naming `who`, unless usable, and held as
 * checked, so no spec a lookup hands out can change.
 */
export function createRateLimitBudgetLookup(
	who: string,
	options: RateLimitBudgetLookupOptions,
): RateLimitBudgetLookup {
	// Each spec is read once into the frozen copy that is checked and held.
	const readLimits: unknown =
		typeof options.limits === "object" && options.limits !== null && !Array.isArray(options.limits)
			? Object.fromEntries(
					Object.entries(options.limits).map(([prefix, spec]) => [prefix, snapshotSpec(spec)]),
				)
			: options.limits;
	const readDefault = snapshotSpec(options.defaultLimit);
	assertUsableRateLimitSpecs(who, { limits: readLimits, defaultLimit: readDefault });
	// A Map: a prefix finds only an entry declared under it, never a member a
	// plain object inherits (`constructor`, `__proto__`).
	const limits: ReadonlyMap<string, RateLimitSpec> = new Map(
		Object.entries((readLimits ?? {}) as Readonly<Record<string, RateLimitSpec>>),
	);
	const defaultLimit = readDefault as RateLimitSpec;
	const lookup = (key: string): RateLimitBudget => {
		const prefix = prefixOf(key);
		return { prefix, spec: limits.get(prefix) ?? defaultLimit };
	};
	return Object.assign(lookup, { defaultLimit });
}
