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

import type { RateLimitBudgetResolver } from "../modules/manifest/synthetic-keys.mjs";
import type { RateLimitSpec } from "./types.mjs";
import { assertUsableRateLimitSpecs } from "./usableSpec.mjs";

export interface RateLimitBudgetLookupOptions {
	/** What an operator declared on this limiter, by prefix; wins over a contributed budget. */
	readonly limits?: Readonly<Record<string, RateLimitSpec>>;
	/** What a key under a prefix nothing budgets is limited by. */
	readonly defaultLimit: RateLimitSpec;
	/**
	 * The owners' contributed budgets (`rateLimitBudgetResolver`), read at each
	 * lookup: they register after the limiter is built.
	 */
	readonly budgets?: RateLimitBudgetResolver;
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

/**
 * A key's budget: the limiter's own `limits` entry for its prefix, else the
 * contributed budget, else `defaultLimit` (never no limit). `limits` and
 * `defaultLimit` are refused, naming `who`, unless usable as written, and held
 * as checked.
 */
export function createRateLimitBudgetLookup(
	who: string,
	options: RateLimitBudgetLookupOptions,
): RateLimitBudgetLookup {
	assertUsableRateLimitSpecs(who, options);
	const limits: Readonly<Record<string, RateLimitSpec>> = Object.fromEntries(
		Object.entries(options.limits ?? {}).map(([prefix, spec]) => [
			prefix,
			{ limit: spec.limit, windowSeconds: spec.windowSeconds },
		]),
	);
	const defaultLimit: RateLimitSpec = Object.freeze({
		limit: options.defaultLimit.limit,
		windowSeconds: options.defaultLimit.windowSeconds,
	});
	const { budgets } = options;
	const lookup = (key: string): RateLimitBudget => {
		const prefix = prefixOf(key);
		return { prefix, spec: limits[prefix] ?? budgets?.get(prefix) ?? defaultLimit };
	};
	return Object.assign(lookup, { defaultLimit });
}
