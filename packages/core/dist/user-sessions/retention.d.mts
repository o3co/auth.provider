/**
 * One minute more than the longest grant the code will ever allow.
 *
 * A grant's `expiresAt` is at most `consent.at` plus the ceiling (D3, enforced
 * by `activate`), and a boundary is stamped no earlier than the consent it
 * covers, give or take the comparison's second and the rounding to whole
 * seconds. Both are far inside the minute. So a boundary retained this long
 * outlives every grant it covers, whatever the operator does to the
 * configuration and whether or not the caller passed a grant store.
 *
 * The cost is one small key per revoked subject, for a year.
 */
export declare const SUBJECT_REVOCATION_MIN_RETENTION_MS: number;
/**
 * How long a **sessions-only** boundary must be retained, from the lifetimes
 * this deployment is configured with.
 *
 * Three inputs, not two. D13 named the refresh token and the session; the
 * access token belongs here as well, because nothing in the configuration says
 * an access token must be shorter than a refresh token — a deployment is free
 * to invert them, and `verifyJwt` consults the watermark for both.
 *
 * And each is extended by the tolerance with which it is actually accepted,
 * not by its nominal expiry: `verifyJwt` passes `clockTolerance`, so a token is
 * acceptable for `DEFAULT_CLOCK_SKEW_MS` past its `exp`. A boundary sized to
 * the nominal expiry leaves exactly that window with nothing behind it. The
 * revocation comparison's own allowance and a whole second of rounding go on
 * top; neither is the five-minute tolerance, which is a different number for a
 * different comparison.
 *
 * What this cannot know is what was issued *before* an operator lowered these
 * settings. Lowering a lifetime shortens the horizon immediately while the
 * artifacts issued under the old one are still live, so a deployment that
 * lowers one keeps the previous horizon until they have expired. The grants
 * boundary has no such hole, because its floor comes from a ceiling the code
 * enforces rather than from configuration.
 */
export declare function resolveSubjectRevocationHorizonMs(config: unknown): number;
//# sourceMappingURL=retention.d.mts.map