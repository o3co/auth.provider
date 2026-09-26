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
export declare const MAX_NUMERIC_DATE_SECONDS = 8640000000000;
/** Whether `value` is a NumericDate this server can reason about. */
export declare function isNumericDate(value: unknown): value is number;
/** The NumericDate claims RFC 7519 §4.1 defines. */
export type NumericDateClaim = "exp" | "iat" | "nbf";
/**
 * The first of `exp`, `iat`, `nbf` that `claims` carries and that is not a
 * NumericDate, or `undefined` when every one present is. An absent claim is
 * not malformed: whether it is required is the caller's rule.
 */
export declare function malformedNumericDateClaim(claims: Readonly<Record<string, unknown>>): NumericDateClaim | undefined;
//# sourceMappingURL=numericDate.d.mts.map