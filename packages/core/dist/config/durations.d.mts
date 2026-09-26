/**
 * Sanity ceiling for a duration expressed in whole seconds: one year.
 *
 * Not a policy — a deployment wanting a 400-day refresh token is a different
 * conversation — but a typo guard. The pairing with `.positive()` is what
 * actually matters (see `readinessTimeoutMs` for the same reasoning): HOCON
 * substitutes an exported-but-empty environment variable as `""`, and
 * `z.coerce.number()` turns `""` into `0`. A zero token lifetime mints tokens
 * that are already expired.
 *
 * Exported so a package's own config schema holds its durations to the same
 * ceiling as core's: a rate-limit window, a federation grant's tombstone
 * retention or listing allowance. Past the Date range, such a value is a
 * deadline no store can keep (`isStorableLifetime`), and the store's refusal
 * at construction is the second line behind this one.
 */
export declare const MAX_DURATION_SECONDS = 31536000;
/** The same one-year ceiling for the settings expressed in milliseconds. */
export declare const MAX_DURATION_MS = 31536000000;
//# sourceMappingURL=durations.d.mts.map