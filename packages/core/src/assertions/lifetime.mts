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
 * How long a single-use assertion may live: the one ceiling this server
 * holds every assertion whose `jti` it records to.
 *
 * A single-use assertion (a `private_key_jwt` client assertion, an ID-JAG) is
 * remembered in the replay seen-set until its `exp`, so an unbounded `exp` is
 * an unbounded replay record. RFC 7523 §3 lets an authorization server reject
 * an `exp` "unreasonably far in the future"; the ID-JAG draft (RFC 7521 §5.2
 * processing) names no number. This is the number, for `exp − now` and for
 * `iat` age alike, plus the verifier's clock tolerance. Both verifiers (the
 * ID-JAG registry verifier and `private_key_jwt`) compare `exp` through
 * {@link assertionLifetime} so they cannot drift. Client libraries mint
 * assertions that live one to ten minutes; an hour leaves room for a clock
 * running ahead while keeping each record small.
 *
 * A plain RFC 7523 jwt-bearer assertion is not held to it: nothing of it is
 * recorded, and RFC 7523 gives its lifetime to the issuing authority.
 */
export const MAX_ASSERTION_LIFETIME_SECONDS = 3600;

/**
 * The largest clock tolerance an assertion verifier may be given, in seconds:
 * an issuer entry's `clockToleranceSeconds`, `private_key_jwt`'s
 * `clockToleranceSeconds`. Five minutes — the tolerance `verifyJwt` gives this
 * server's own tokens (`DEFAULT_CLOCK_SKEW_MS`). No peer's clock needs more
 * slack than that, and the tolerance is added to the lifetime ceiling and to
 * every `exp` check, so an unbounded one would switch both off.
 */
export const MAX_ASSERTION_CLOCK_TOLERANCE_SECONDS = 300;

/**
 * Whether `value` is a usable assertion clock tolerance: a finite number of
 * seconds from 0 to {@link MAX_ASSERTION_CLOCK_TOLERANCE_SECONDS}. `NaN`,
 * `Infinity` and a string are not — the first two switch every time check
 * off, and a string concatenates onto the ceiling.
 */
export function isValidAssertionClockTolerance(value: unknown): value is number {
	return (
		typeof value === "number" &&
		Number.isFinite(value) &&
		value >= 0 &&
		value <= MAX_ASSERTION_CLOCK_TOLERANCE_SECONDS
	);
}

/** The refusal {@link isValidAssertionClockTolerance} is reported with. */
export function describeInvalidAssertionClockTolerance(value: unknown): string {
	const got = typeof value === "number" ? String(value) : `a ${typeof value}`;
	return (
		`clockToleranceSeconds must be a finite number of seconds from 0 to ` +
		`${MAX_ASSERTION_CLOCK_TOLERANCE_SECONDS} (got ${got}): it is added to the lifetime ceiling ` +
		"and to every exp check, and a value outside that range switches them off"
	);
}

/** How far past now an assertion's `exp` runs, against the most it may. */
export interface AssertionLifetime {
	/** `exp − now`, in seconds. */
	readonly lifetimeSeconds: number;
	/** {@link MAX_ASSERTION_LIFETIME_SECONDS} plus the clock tolerance. */
	readonly maxLifetimeSeconds: number;
	/**
	 * Whether `lifetimeSeconds` is past `maxLifetimeSeconds` — refuse it. Also
	 * true when the two cannot be compared (a tolerance of `NaN`, `Infinity`
	 * or a string): the ceiling fails closed.
	 */
	readonly exceeded: boolean;
}

/**
 * The `exp` ceiling every recorded assertion is held to: `exp − now` may be
 * at most {@link MAX_ASSERTION_LIFETIME_SECONDS} plus the verifier's clock
 * tolerance, as in every other time check, so an hour-long assertion from a
 * peer whose clock runs slightly ahead is not refused. Both numbers are
 * returned so a refusal can log them.
 *
 * `expSeconds` must already be a NumericDate (`malformedNumericDateClaim`).
 */
export function assertionLifetime(
	expSeconds: number,
	nowSeconds: number,
	clockToleranceSeconds: number,
): AssertionLifetime {
	const lifetimeSeconds = expSeconds - nowSeconds;
	const maxLifetimeSeconds = MAX_ASSERTION_LIFETIME_SECONDS + clockToleranceSeconds;
	// Written as "not within" so that anything uncomparable — NaN on either
	// side, an infinite ceiling, a string that concatenated — is exceeded.
	const within = Number.isFinite(maxLifetimeSeconds) && lifetimeSeconds <= maxLifetimeSeconds;
	return { lifetimeSeconds, maxLifetimeSeconds, exceeded: !within };
}
