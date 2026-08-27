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
 * Reject a page/batch size that is not a positive integer, at construction.
 *
 * Shared rather than inlined per helper because the three sid-keyed structures
 * take the same kind of knob and the failure mode is not uniform — which makes
 * it easy to guard the one that hangs and forget the two that do not:
 *
 *   - `createRedisSidSortedSet`'s `pageSize` is a **loop step**. A value that
 *     does not advance the cursor makes `list()` repeat one command forever, on
 *     the logout path. `0` is the sharpest case: `ZRANGE key 0 -1` returns the
 *     whole set, so the short-page test that ends the walk never fires.
 *   - `createRedisSidHash`'s and `createRedisSidSet`'s `scanCount` are `HSCAN` /
 *     `SSCAN` `COUNT` hints. Those cannot hang, but Redis refuses a
 *     non-positive `COUNT`, and finding that out during a logout is no better.
 *
 * `Number.isSafeInteger` covers `NaN`, both infinities and fractional values in
 * one test; a fractional step would also drift the rank arithmetic into
 * non-integer `ZRANGE` bounds, which Redis rejects.
 */
export function assertPositiveInteger(value: number, label: string): void {
	if (!Number.isSafeInteger(value) || value <= 0) {
		throw new Error(`${label} must be a positive integer (received ${String(value)})`);
	}
}
