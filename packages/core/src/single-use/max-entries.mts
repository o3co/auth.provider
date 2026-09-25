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

/*
 * An in-process store's cap: what it may be, and how a module or an adapter
 * factory reads it from config (`replaySeenSet.memory.maxEntries`,
 * `challengeStore.memory.maxEntries`, an adapter config's `maxEntries`).
 *
 * A cap is a positive whole number no greater than
 * {@link MAX_MEMORY_STORE_ENTRIES}: a V8 `Map` refuses an entry past 2^24,
 * so a larger cap is one the store could never reach, and `Map.set` would
 * throw at the Map's own limit instead of the store refusing at its cap.
 * Read from config, absent means the store's own default; a number is the
 * cap, and so is a string of digits — what HOCON's `${?VAR}` substitution
 * delivers. Anything else that is given — zero, a negative or fractional
 * number, one past the limit, other text, a boolean — is refused with a
 * RangeError naming the key, rather than replaced by the default.
 */

/** The most entries a V8 `Map` holds, and so the largest cap an in-process store takes. */
export const MAX_MEMORY_STORE_ENTRIES = 2 ** 24;

/**
 * Refuse a cap `owner` (a store's factory) cannot use: `${owner}: maxEntries
 * must be …`. Answers the cap.
 */
export function usableMaxEntries(maxEntries: number, owner: string): number {
	if (!Number.isInteger(maxEntries) || maxEntries <= 0) {
		throw new RangeError(
			`${owner}: maxEntries must be a positive whole number (got ${String(maxEntries)})`,
		);
	}
	if (maxEntries > MAX_MEMORY_STORE_ENTRIES) {
		throw new RangeError(
			`${owner}: maxEntries must be at most ${MAX_MEMORY_STORE_ENTRIES}, the most entries a Map holds (got ${String(maxEntries)})`,
		);
	}
	return maxEntries;
}

/** The store's options for the value at `key`: `{}` when absent, `{ maxEntries }` when usable. */
export function configuredMaxEntries(
	value: unknown,
	key: string,
): { readonly maxEntries?: number } {
	if (value === undefined || value === null) return {};
	const count =
		typeof value === "number"
			? value
			: typeof value === "string" && /^\s*\d+\s*$/.test(value)
				? Number(value)
				: Number.NaN;
	if (!Number.isInteger(count) || count <= 0) {
		throw new RangeError(`${key} must be a positive whole number (got ${JSON.stringify(value)})`);
	}
	if (count > MAX_MEMORY_STORE_ENTRIES) {
		throw new RangeError(
			`${key} must be at most ${MAX_MEMORY_STORE_ENTRIES}, the most entries a Map holds (got ${JSON.stringify(value)})`,
		);
	}
	return { maxEntries: count };
}
