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
 * The budget a limiter applies to a key, for every bundled limiter: one
 * precedence, so one configuration is one budget whichever limiter a
 * composition mounts.
 */

import type { RateLimitBudgetResolver } from "../modules/manifest/synthetic-keys.mjs";
import type { RateLimitSpec } from "./types.mjs";
import { assertUsableRateLimitSpecs } from "./usableSpec.mjs";

export interface RateLimitBudgetLookupOptions {
	/**
	 * What an operator declared on this limiter, by prefix. An entry wins over
	 * the budget the prefix's owner contributed: it is an explicit statement
	 * about this limiter.
	 */
	readonly limits?: Readonly<Record<string, RateLimitSpec>>;
	/** What a key under a prefix nothing budgets is limited by. */
	readonly defaultLimit: RateLimitSpec;
	/**
	 * The budgets the prefixes' owners contributed (`rateLimitBudgetResolver`),
	 * read at each lookup: they register after the limiter is built. Each was
	 * held to `isUsableRateLimitSpec` when it registered.
	 */
	readonly budgets?: RateLimitBudgetResolver;
}

/** The prefix a key is limited under, and the budget in force for it. */
export interface RateLimitBudget {
	/** The key up to its first `:`, or the whole key when it has none. */
	readonly prefix: string;
	readonly spec: RateLimitSpec;
}

export type RateLimitBudgetLookup = (key: string) => RateLimitBudget;

const prefixOf = (key: string): string => {
	const colon = key.indexOf(":");
	return colon === -1 ? key : key.slice(0, colon);
};

/**
 * The lookup a limiter takes each key's budget from: its own `limits` entry
 * for the key's prefix, else the budget the prefix's owner contributed, else
 * `defaultLimit`. A budget switched off by its owner is absent from the
 * resolver, so its prefix falls to `defaultLimit`, never to no limit.
 *
 * `limits` and `defaultLimit` are refused here, with `who` in the message,
 * when a limiter cannot apply them as written, and held as they were checked:
 * a later change to the caller's objects reaches no lookup.
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
	const defaultLimit: RateLimitSpec = {
		limit: options.defaultLimit.limit,
		windowSeconds: options.defaultLimit.windowSeconds,
	};
	const { budgets } = options;
	return (key) => {
		const prefix = prefixOf(key);
		return { prefix, spec: limits[prefix] ?? budgets?.get(prefix) ?? defaultLimit };
	};
}
