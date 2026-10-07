/** The limit one consume is counted against: at most `limit` attempts in a window of `windowSeconds`, at most a day. */
export interface AttemptSpec {
    readonly limit: number;
    readonly windowSeconds: number;
}
/** A counter's answer to one attempt. */
export interface AttemptCount {
    /** This attempt is one of the first `limit` counted under its key in its window. */
    readonly allowed: boolean;
    /** Attempts the key has left in the window after this one: below `limit` when allowed, 0 when refused. */
    readonly remaining: number;
    /** When the window this attempt fell in ends. */
    readonly resetAt: Date;
}
/**
 * A fixed-window attempt counter.
 *
 * `consume` counts one attempt under `key`, atomically: of the attempts made
 * under one key in one window, by any number of callers or replicas, exactly
 * the first `spec.limit` are allowed, each against the spec handed in with
 * it, and a refused attempt counts nothing. A window starts at the first
 * attempt counted under a key with no window running, and ends
 * `spec.windowSeconds` later; a window keeps its end when a later spec
 * changes the window. Keys are counted apart.
 *
 * It rejects, counting nothing, a key `isAttemptKey` refuses or a spec
 * `isAttemptSpec` refuses. A backend that cannot count rejects: an outage is
 * never answered as a count.
 */
export interface AttemptCounter {
    consume(key: string, spec: AttemptSpec): Promise<AttemptCount>;
}
/**
 * The longest window a counter takes. Verifier windows are minutes; the cap
 * lets a reader bound a window's end without knowing the spec it started under.
 */
export declare const MAX_ATTEMPT_WINDOW_SECONDS = 86400;
/** A spec a counter takes: a positive whole `limit` and a positive whole `windowSeconds` of at most {@link MAX_ATTEMPT_WINDOW_SECONDS}. */
export declare const isAttemptSpec: (value: unknown) => value is AttemptSpec;
/** The longest key a counter takes. */
export declare const MAX_ATTEMPT_KEY_LENGTH = 512;
/** A key a counter takes: a non-empty string of at most {@link MAX_ATTEMPT_KEY_LENGTH} characters. */
export declare const isAttemptKey: (value: unknown) => value is string;
/** How far a counter's clock may stand from the reader's when its window's end is judged. */
export declare const ATTEMPT_COUNT_CLOCK_ALLOWANCE_MS = 5000;
/**
 * A counter's answer, read at `nowMs`, as a fresh, frozen count, each field
 * read once, or `undefined` when it is not one under `spec`: `allowed` not a
 * boolean, `remaining` not a whole number below `spec.limit` on an allowed
 * attempt or 0 on a refused one, `resetAt` not a valid `Date` within
 * {@link ATTEMPT_COUNT_CLOCK_ALLOWANCE_MS} of `[nowMs, nowMs + MAX_ATTEMPT_WINDOW_SECONDS]`,
 * or a read that throws. The bound is the longest window any spec allows, not
 * the current spec's, so a window started under an earlier, longer spec is
 * still a count.
 */
export declare function readAttemptCount(answer: unknown, spec: AttemptSpec, nowMs: number): AttemptCount | undefined;
declare module "@o3co/auth-provider-core" {
    interface ComponentMap {
        readonly attemptCounter?: AttemptCounter;
    }
}
//# sourceMappingURL=attempts.d.mts.map