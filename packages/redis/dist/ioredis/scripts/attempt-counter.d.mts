/**
 * `KEYS[1]` = the window's hash (`count`, `resetAt`); `ARGV` = the caller's clock, the limit,
 * the end of a window this attempt opens, the clock allowance. A window opens with its end
 * (`ARGV[3]`) and a relative TTL, the window's length on the caller's clock plus the allowance.
 * It is running while its end is after the caller's clock, or while its TTL is above the
 * allowance: the server's countdown, which no caller's clock moves, so a caller whose clock runs
 * ahead never reopens a window the server still runs, and is answered its end. Running, below the
 * limit the attempt is counted; at it the attempt is refused and nothing is written. Replies
 * `{allowed (0|1), count, resetAt}`.
 */
export declare const ATTEMPT_COUNTER_CONSUME: import("./define.mjs").CachedScript;
//# sourceMappingURL=attempt-counter.d.mts.map