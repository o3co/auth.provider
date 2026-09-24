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

/**
 * Refuses, when a limiter is built, a spec whose window ends past
 * ECMAScript's Date range (core's `isStorableLifetime`).
 *
 * No clock reaches the end of such a window. The in-process limiter's bucket
 * would reset at an Invalid Date, and Redis refuses the `EXPIRE` after its
 * `INCR` has run, which leaves a counter with no TTL (#269's shape).
 *
 * It is refused rather than dropped: a dropped spec let the default budget
 * apply, a looser one than the operator wrote, and on the device verification
 * route the budget RFC 8628 §5.1 sizes the user code against. Every adapter
 * calls this, so they give one answer. A window that is not a positive finite
 * number is each adapter's own business, as it was.
 */
export function assertRateLimitWindowsInRange(
	who: string,
	specs: { readonly limits?: unknown; readonly defaultLimit?: unknown },
): void {
	const check = (name: string, spec: unknown): void => {
		const windowSeconds =
			typeof spec === "object" && spec !== null
				? (spec as { windowSeconds?: unknown }).windowSeconds
				: undefined;
		if (
			typeof windowSeconds === "number" &&
			Number.isFinite(windowSeconds) &&
			windowSeconds > 0 &&
			!isStorableLifetime(windowSeconds * 1000)
		) {
			throw new RangeError(
				`${who}: ${name}.windowSeconds must end within the Date range (got ${windowSeconds})`,
			);
		}
	};
	if (typeof specs.limits === "object" && specs.limits !== null) {
		for (const [prefix, spec] of Object.entries(specs.limits as Record<string, unknown>)) {
			check(`limits.${prefix}`, spec);
		}
	}
	check("defaultLimit", specs.defaultLimit);
}
