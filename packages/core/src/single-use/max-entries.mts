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
 * `configuredMaxEntries`: an in-process store's cap as its module reads it
 * from config (`replaySeenSet.memory.maxEntries`,
 * `challengeStore.memory.maxEntries`). Absent, the store's own default
 * applies. A number is the cap, and so is a string of digits — what HOCON's
 * `${?VAR}` substitution delivers. Anything else that is given — zero, a
 * negative or fractional number, other text, a boolean — is refused with a
 * RangeError naming the key, at boot, rather than replaced by the default.
 */

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
	return { maxEntries: count };
}
