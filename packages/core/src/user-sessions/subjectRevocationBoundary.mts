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
 * How a `SubjectRevocation` store reads what it is asked to record: an
 * instant only as a `Date` with a finite time, and a boundary never later
 * than the store's clock plus `DEFAULT_CLOCK_SKEW_MS`, clamped to it rather
 * than refused. A refusal would leave every token already issued alive; the
 * clamp still revokes all a replica within the skew minted, and holds a
 * lockout to the skew.
 */

import { DEFAULT_CLOCK_SKEW_MS } from "../jwt/verify.mjs";

/**
 * `value`'s epoch milliseconds when it is a `Date` (of any realm) with a
 * finite time; else a `RangeError` naming `name`. An object that only answers
 * `getTime` is not a date: its time could read back as no instant at all.
 */
export function checkSubjectRevocationInstant(value: unknown, name: string): number {
	let ms: number;
	try {
		ms = Date.prototype.getTime.call(value);
	} catch {
		ms = Number.NaN;
	}
	if (!Number.isFinite(ms)) throw new RangeError(`SubjectRevocation: ${name} must be a date`);
	return ms;
}

/**
 * The boundary a store records for `before` on `storeNowMs`, its clock read
 * in the same step as the write: `before` when it is no later than
 * `storeNowMs + DEFAULT_CLOCK_SKEW_MS`, else exactly that, with `clamped`
 * saying which. A `RangeError` for a `before` that is no date, or a clock
 * that is not a finite instant: the bound is never skipped.
 */
export function clampSubjectRevocationBoundary(
	before: unknown,
	storeNowMs: number,
): { readonly boundary: Date; readonly clamped: boolean } {
	const beforeMs = checkSubjectRevocationInstant(before, "before");
	if (typeof storeNowMs !== "number" || !Number.isFinite(storeNowMs)) {
		throw new RangeError("SubjectRevocation: the store's clock must be a finite instant");
	}
	const latestMs = storeNowMs + DEFAULT_CLOCK_SKEW_MS;
	return beforeMs > latestMs
		? { boundary: new Date(latestMs), clamped: true }
		: { boundary: new Date(beforeMs), clamped: false };
}
