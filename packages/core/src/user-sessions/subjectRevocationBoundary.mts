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

import {
	claimCoveredByRevocationBoundary,
	DEFAULT_CLOCK_SKEW_MS,
	DEFAULT_SUBJECT_REVOCATION_SKEW_MS,
	readSubjectRevocationBoundary,
} from "../jwt/verify.mjs";
import type { SubjectRevocation } from "./types.mjs";

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

/** The furthest a `Date` reaches either side of the epoch, in milliseconds (ECMA-262). */
const MAX_DATE_MS = 8_640_000_000_000_000;

/** Whether `ms` is an instant a `Date` can hold: anything else reads back as an Invalid Date. */
const holdsAsDate = (ms: unknown): ms is number =>
	typeof ms === "number" && Number.isFinite(ms) && Math.abs(ms) <= MAX_DATE_MS;

/**
 * `storeNowMs` when it is an instant a `Date` can hold; else a `RangeError`.
 * A store whose clock is read in-process reads it through this before it
 * compares or drops a record, so a reading of no instant fails the operation
 * and lapses nothing.
 */
export function checkSubjectRevocationClock(storeNowMs: unknown): number {
	if (!holdsAsDate(storeNowMs)) {
		throw new RangeError("SubjectRevocation: the store's clock must be an instant a Date can hold");
	}
	return storeNowMs;
}

/**
 * The rule every store bounds a boundary by: `before` when it is no later
 * than `storeNowMs + DEFAULT_CLOCK_SKEW_MS`, else exactly that, with `clamped`
 * saying which. A `RangeError` for a `before` that is no date, or a clock
 * whose reading or bound a `Date` cannot hold: the bound is never skipped,
 * and never answers an Invalid Date. A store whose
 * clock is read in-process calls it in the step that writes; a store whose
 * clock is a server's clamps in its own atomic step there, and may call it
 * with the `now` that server answers to tell whether it clamped.
 */
export function clampSubjectRevocationBoundary(
	before: unknown,
	storeNowMs: number,
): { readonly boundary: Date; readonly clamped: boolean } {
	const beforeMs = checkSubjectRevocationInstant(before, "before");
	const latestMs = checkSubjectRevocationClock(storeNowMs) + DEFAULT_CLOCK_SKEW_MS;
	checkSubjectRevocationClock(latestMs);
	return beforeMs > latestMs
		? { boundary: new Date(latestMs), clamped: true }
		: { boundary: new Date(beforeMs), clamped: false };
}

/**
 * What {@link subjectBoundaryCovers} found: the subject's boundary covers the
 * claim (refuse), does not (go on), or could not be read or compared
 * (`cause`; answer it as an outage, never as either verdict).
 */
export type SubjectBoundaryAnswer =
	| { readonly answer: "covered" }
	| { readonly answer: "clear" }
	| { readonly answer: "unavailable"; readonly cause: unknown };

const COVERED: SubjectBoundaryAnswer = Object.freeze({ answer: "covered" });
const CLEAR: SubjectBoundaryAnswer = Object.freeze({ answer: "clear" });

/**
 * Whether `subject`'s sessions boundary covers a claim in NumericDate seconds
 * (an assertion's or a proof's issue time), for a grant that compares before
 * it signs. One read of the boundary, compared by the rule and allowance
 * `verifyJwt` applies to `iat` (`claimCoveredByRevocationBoundary`,
 * `DEFAULT_SUBJECT_REVOCATION_SKEW_MS`).
 *
 * - No boundary in force: `clear`, whatever the claim.
 * - A boundary in force and a claim that is absent or not a finite number:
 *   `covered`, as `verifyJwt` refuses a token without `iat`: it cannot show
 *   it postdates the boundary.
 * - A read that throws, or a boundary that is not a `Date` with a finite
 *   time: `unavailable`, whatever the claim.
 *
 * Call it as the last read before signing, after the issuance instant is
 * fixed, so a revocation stamped while earlier steps ran is seen.
 */
export async function subjectBoundaryCovers(
	subjectRevocation: Pick<SubjectRevocation, "revokedBefore">,
	subject: string,
	claimSeconds: number | undefined,
): Promise<SubjectBoundaryAnswer> {
	let boundary: Date | null;
	try {
		boundary = await readSubjectRevocationBoundary(subjectRevocation, subject);
		if (boundary === null) return CLEAR;
		checkSubjectRevocationInstant(boundary, "the sessions boundary");
	} catch (cause) {
		return { answer: "unavailable", cause };
	}
	if (typeof claimSeconds !== "number" || !Number.isFinite(claimSeconds)) return COVERED;
	try {
		return claimCoveredByRevocationBoundary(
			claimSeconds,
			boundary,
			DEFAULT_SUBJECT_REVOCATION_SKEW_MS,
		)
			? COVERED
			: CLEAR;
	} catch (cause) {
		return { answer: "unavailable", cause };
	}
}
