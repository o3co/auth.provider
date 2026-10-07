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
 * expiry, an age or a window from them: a NumericDate (RFC 7519 §2) — a
 * finite number of seconds that a Date can hold.
 *
 * jose checks only that such a claim is a number. JSON has no Infinity, but
 * `1e400` parses to it, so an assertion whose `exp` is `1e400` is never
 * expired, reaches whatever records it until it expires, and meets a store
 * that cannot hold "forever" — the seen-set's `RangeError`, answered `503`,
 * the server's fault for the client's malformed input. A finite value past
 * the Date range (`1e300`) is the same thing one step later: a lifetime no
 * store can write. Both are a malformed claim, and a verifier refuses them as
 * one, before any of that arithmetic runs.
 *
 * A fraction is not malformed: RFC 7519 §2 says a NumericDate may be
 * non-integer, and every consumer here accepts one — the seen-set records a
 * fractional expiry, the Redis adapters round it up.
 */
/**
 * The largest NumericDate, in seconds: ECMAScript's Date range, ±8.64e15
 * milliseconds from the epoch (ECMA-262 §21.4.1.22, "Time Values and Time
 * Range"). Every value within it is a valid Date and a lifetime a store can
 * write; one past it is not a date at all.
 */
export const MAX_NUMERIC_DATE_SECONDS = 8_640_000_000_000;
/** Whether `value` is a NumericDate this server can reason about. */
export function isNumericDate(value) {
    return (typeof value === "number" &&
        Number.isFinite(value) &&
        Math.abs(value) <= MAX_NUMERIC_DATE_SECONDS);
}
const NUMERIC_DATE_CLAIMS = ["exp", "iat", "nbf"];
/**
 * The first of `exp`, `iat`, `nbf` that `claims` carries and that is not a
 * NumericDate, or `undefined` when every one present is. An absent claim is
 * not malformed: whether it is required is the caller's rule.
 */
export function malformedNumericDateClaim(claims) {
    return NUMERIC_DATE_CLAIMS.find((claim) => Object.hasOwn(claims, claim) && !isNumericDate(claims[claim]));
}
