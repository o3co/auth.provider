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
 * What a JWT's `exp`, `iat` and `nbf` must be before anything computes an
 * expiry, age or window from them: a NumericDate (RFC 7519 §2), a finite
 * number of seconds a Date can hold.
 *
 * jose checks only that such a claim is a number. `1e400` parses to Infinity,
 * so an `exp` of `1e400` never expires and reaches a store that cannot hold
 * "forever" (the seen-set's `RangeError`, a `503` for the client's malformed
 * input); `1e300`, past the Date range, fails the same way a step later. A
 * verifier refuses both as malformed before any arithmetic runs. A fraction
 * is valid (RFC 7519 §2), and every consumer here accepts one.
 */

/**
 * The largest NumericDate, in seconds: ECMAScript's Date range, ±8.64e15
 * milliseconds from the epoch (ECMA-262 §21.4.1.22, "Time Values and Time
 * Range"). Every value within it is a valid Date and a lifetime a store can
 * write; one past it is not a date at all.
 */
export const MAX_NUMERIC_DATE_SECONDS = 8_640_000_000_000;

/** Whether `value` is a NumericDate this server can reason about. */
export function isNumericDate(value: unknown): value is number {
	return (
		typeof value === "number" &&
		Number.isFinite(value) &&
		Math.abs(value) <= MAX_NUMERIC_DATE_SECONDS
	);
}

/** The NumericDate claims RFC 7519 §4.1 defines. */
export type NumericDateClaim = "exp" | "iat" | "nbf";

const NUMERIC_DATE_CLAIMS: readonly NumericDateClaim[] = ["exp", "iat", "nbf"];

/**
 * The first of `exp`, `iat`, `nbf` that `claims` carries and that is not a
 * NumericDate, or `undefined` when every one present is. An absent claim is
 * not malformed: whether it is required is the caller's rule.
 */
export function malformedNumericDateClaim(
	claims: Readonly<Record<string, unknown>>,
): NumericDateClaim | undefined {
	return NUMERIC_DATE_CLAIMS.find(
		(claim) => Object.hasOwn(claims, claim) && !isNumericDate(claims[claim]),
	);
}
