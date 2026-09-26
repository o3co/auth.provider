/**
 * How long a single-use assertion may live: the one ceiling this server
 * holds every assertion whose `jti` it records to.
 *
 * An assertion recorded for single use — a `private_key_jwt` client
 * assertion, an ID-JAG — is remembered in the replay seen-set until its
 * `exp`, which is exactly how long it could be replayed. An `exp` with no
 * upper bound is therefore a replay record with none either. RFC 7523 §3
 * lets an authorization server reject an `exp` "unreasonably far in the
 * future"; the ID-JAG draft applies RFC 7521 §5.2's processing and names no
 * number of its own. This is the number: an assertion may run at most this
 * long past now (`exp − now`), and — the same hour the other way — may have
 * been issued at most this long ago (`iat` age). Both verifiers that hold an
 * assertion to it — the ID-JAG registry verifier and `private_key_jwt` —
 * allow their clock tolerance on top of both, as they do for every other
 * time check, and compare `exp` through {@link assertionLifetime} so the two
 * cannot drift. Client libraries mint
 * assertions that live a minute or ten; an hour leaves room for a client
 * whose clock runs ahead while keeping each record small.
 *
 * A plain RFC 7523 jwt-bearer assertion is not held to it: nothing of it is
 * recorded, and RFC 7523 gives its lifetime to the issuing authority.
 */
export declare const MAX_ASSERTION_LIFETIME_SECONDS = 3600;
/**
 * The largest clock tolerance an assertion verifier may be given, in seconds:
 * an issuer entry's `clockToleranceSeconds`, `private_key_jwt`'s
 * `clockToleranceSeconds`. Five minutes — the tolerance `verifyJwt` gives this
 * server's own tokens (`DEFAULT_CLOCK_SKEW_MS`). No peer's clock needs more
 * slack than that, and the tolerance is added to the lifetime ceiling and to
 * every `exp` check, so an unbounded one would switch both off.
 */
export declare const MAX_ASSERTION_CLOCK_TOLERANCE_SECONDS = 300;
/**
 * Whether `value` is a usable assertion clock tolerance: a finite number of
 * seconds from 0 to {@link MAX_ASSERTION_CLOCK_TOLERANCE_SECONDS}. `NaN`,
 * `Infinity` and a string are not — the first two switch every time check
 * off, and a string concatenates onto the ceiling.
 */
export declare function isValidAssertionClockTolerance(value: unknown): value is number;
/** The refusal {@link isValidAssertionClockTolerance} is reported with. */
export declare function describeInvalidAssertionClockTolerance(value: unknown): string;
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
 * tolerance. The tolerance is allowed here as in every other time check — a
 * client or an IdP whose clock runs a little ahead mints an hour-long
 * assertion whose `exp` is a little past an hour from this server's now, and
 * refusing it would make the answer depend on how the two clocks sat that
 * second. Both numbers are returned so a refusal can log them.
 *
 * `expSeconds` must already be a NumericDate (`malformedNumericDateClaim`).
 */
export declare function assertionLifetime(expSeconds: number, nowSeconds: number, clockToleranceSeconds: number): AssertionLifetime;
//# sourceMappingURL=lifetime.d.mts.map