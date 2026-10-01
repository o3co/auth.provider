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
 * The one check of a boundary a `SubjectRevocation` store is asked to
 * record: a date, and — on the store's clock — never later than it by more
 * than `DEFAULT_CLOCK_SKEW_MS`. A boundary behind the store's clock is not
 * refused: a revocation must not fail because the revoking replica runs
 * behind, and the stores keep the later boundary anyway.
 */

import { DEFAULT_CLOCK_SKEW_MS } from "../jwt/verify.mjs";

/**
 * `before` as epoch milliseconds, or a `RangeError` naming what is wrong: not
 * a valid `Date`, or, given `storeNowMs`, the store's clock, later than it
 * plus `DEFAULT_CLOCK_SKEW_MS`. Every adapter runs it before it writes; one
 * whose store judges the clock in a script runs the shape first and the bound
 * on the clock that script answers.
 */
export function checkSubjectRevocationBoundary(before: unknown, storeNowMs?: number): number {
	const ms = (before as Date | null | undefined)?.getTime?.();
	if (typeof ms !== "number" || Number.isNaN(ms)) {
		throw new RangeError("SubjectRevocation: before must be a date");
	}
	if (storeNowMs !== undefined && !(ms <= storeNowMs + DEFAULT_CLOCK_SKEW_MS)) {
		throw new RangeError(
			"SubjectRevocation: before must be no further ahead of the store's clock than DEFAULT_CLOCK_SKEW_MS",
		);
	}
	return ms;
}
