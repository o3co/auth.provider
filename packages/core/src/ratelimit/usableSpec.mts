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

import { isStorableLifetime } from "../adapters/expiry.mjs";
import type { RateLimitSpec } from "./types.mjs";

const isPositiveInteger = (value: unknown): value is number =>
	typeof value === "number" && Number.isInteger(value) && value > 0;

/**
 * Whether a value is a spec a limiter can apply as written: a positive whole
 * `limit`, and a positive whole `windowSeconds` that ends within ECMAScript's
 * Date range (core's `isStorableLifetime`).
 *
 * Each refusal is a budget that is not the one written. A zero window is an
 * `EXPIRE key 0`, which deletes the counter, and an in-process bucket that
 * resets on every check: it never limits anything. A limit of zero or less
 * denies everything. NaN and fractions are not budgets. A window past the Date
 * range has no end any clock reaches: Redis refuses the `EXPIRE` after its
 * `INCR` has run (#269's shape), and an in-process bucket would reset at an
 * Invalid Date.
 */
export const isUsableRateLimitSpec = (value: unknown): value is RateLimitSpec => {
	if (typeof value !== "object" || value === null) return false;
	const { limit, windowSeconds } = value as { limit?: unknown; windowSeconds?: unknown };
	return (
		isPositiveInteger(limit) &&
		isPositiveInteger(windowSeconds) &&
		isStorableLifetime(windowSeconds * 1000)
	);
};

const described = (spec: unknown): string => {
	if (typeof spec !== "object" || spec === null) return String(spec);
	const { limit, windowSeconds } = spec as { limit?: unknown; windowSeconds?: unknown };
	return `limit ${String(limit)}, windowSeconds ${String(windowSeconds)}`;
};

/**
 * Refuses, when a limiter is built, every spec it was given that
 * {@link isUsableRateLimitSpec} does not accept: each entry of `limits`, and
 * `defaultLimit`. `undefined` is "not given", and nothing else is.
 *
 * Refused, never dropped. A dropped spec let the adapter's default budget
 * apply in its place, a looser one than the operator wrote. On the device
 * verification route that is the budget RFC 8628 §5.1 sizes the user code
 * against. Every adapter calls this, so one configuration is one budget,
 * whichever adapter is mounted. The zod schemas refuse the same values at the
 * config boundary; this is for the builder paths and the hand-built configs
 * that never pass them.
 */
export function assertUsableRateLimitSpecs(
	who: string,
	specs: { readonly limits?: unknown; readonly defaultLimit?: unknown },
): void {
	const refuse = (name: string, spec: unknown): never => {
		throw new RangeError(
			`${who}: ${name} must be { limit, windowSeconds } as positive whole numbers, with a window that ends within the Date range (got ${described(spec)})`,
		);
	};
	const { limits, defaultLimit } = specs;
	if (limits !== undefined) {
		if (typeof limits !== "object" || limits === null || Array.isArray(limits)) {
			throw new RangeError(
				`${who}: limits must be an object of { limit, windowSeconds } specs, keyed by prefix (got ${Array.isArray(limits) ? "an array" : String(limits)})`,
			);
		}
		for (const [prefix, spec] of Object.entries(limits as Record<string, unknown>)) {
			if (!isUsableRateLimitSpec(spec)) refuse(`limits.${prefix}`, spec);
		}
	}
	if (defaultLimit !== undefined && !isUsableRateLimitSpec(defaultLimit)) {
		refuse("defaultLimit", defaultLimit);
	}
}
