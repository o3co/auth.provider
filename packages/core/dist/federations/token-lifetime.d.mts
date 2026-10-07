/** The lifetime fields of an adapter's answer, each as the consumer read it once. */
export interface UpstreamLifetimeFields {
    readonly expiresIn: unknown;
    readonly expiresAt: unknown;
}
export interface UpstreamLifetimeClock {
    /** Epoch ms, taken just before the adapter was asked: an `expiresIn` counts from it. */
    readonly calledAt: number;
    /** Epoch ms, when the answer is read. */
    readonly now: number;
    /** A token with less than this left (ms), or none, is `spent`. The value is the consumer's policy. */
    readonly floorMs: number;
}
export type UpstreamTokenLifetime = 
/** Neither field names a lifetime: each is absent or `null`. */
{
    readonly verdict: "unstated";
}
/** A field is present but names no lifetime, or the instant it derives lies outside the Date range. */
 | {
    readonly verdict: "malformed";
}
/** One field is `null` (no finite lifetime) and the other names one. */
 | {
    readonly verdict: "contradictory";
}
/** The derived instant leaves less than `floorMs` after `now`, or nothing. */
 | {
    readonly verdict: "spent";
} | {
    readonly verdict: "finite";
    /** `expiresIn` named it, alone or beside `expiresAt`. */
    readonly stated: "both" | "expiresIn";
    /** When the token was obtained: `calledAt`. */
    readonly obtainedAt: Date;
    /** When the token ends: the earlier instant the fields name, to the ms, after `obtainedAt`. */
    readonly expiresAt: Date;
    /** Seconds, the `expiresIn` as issued: what a maximum is judged against. */
    readonly issuedLifetime: number;
} | {
    readonly verdict: "finite";
    /** `expiresAt` alone named it: no lifetime was issued. */
    readonly stated: "expiresAt";
    /** When the token was obtained: `calledAt`. */
    readonly obtainedAt: Date;
    /** When the token ends: the instant `expiresAt` names, after `obtainedAt`. */
    readonly expiresAt: Date;
};
/** A token already held: when it was obtained and when it ends. */
export interface HeldUpstreamToken {
    readonly obtainedAt: Date;
    readonly expiresAt: Date;
}
export interface HeldUpstreamTokenAge {
    /** `obtainedAt` is a valid instant, before `expiresAt`, and not more than `allowanceMs` ahead of `now`. */
    readonly believed: boolean;
    /** `min(obtainedAt, now)` + lifetime − `now`: no token has more left than its own life (`expiresAt − obtainedAt`). 0 when not believed. */
    readonly remainingMs: number;
    /** At least half its lifetime has passed, or it is not believed: before then it is never refreshed. */
    readonly halfSpent: boolean;
}
/** The epoch ms of a real `Date` holding an instant, read by its own value, never through a method it may override. Never throws. */
export declare const instantOf: (value: unknown) => number | undefined;
/**
 * Read an adapter's `expiresIn` / `expiresAt`. A finite lifetime is dated
 * from `calledAt`, so time the upstream took is not counted as life left:
 * the derived instant is `min(expiresAt, calledAt + expiresIn)`, and
 * `obtainedAt` is `calledAt`. Throws a
 * `RangeError` only for a clock that is not a finite instant, or a floor
 * that is not a finite duration ≥ 0. Each clock field is read once.
 */
export declare function readUpstreamTokenLifetime(fields: UpstreamLifetimeFields, clock: UpstreamLifetimeClock): UpstreamTokenLifetime;
/**
 * The age of a token held since `obtainedAt`. One dated ahead of `now` by
 * up to `allowanceMs` (a refresh buffer, or replicas' clock skew) is
 * believed; one dated further ahead, or not before its own end, is not, and
 * reads as ended. Throws a `RangeError` only for a clock that is not a
 * finite instant, or an allowance that is not a finite duration ≥ 0. Each
 * clock field is read once.
 */
export declare function judgeHeldUpstreamToken(token: HeldUpstreamToken, at: {
    readonly now: number;
    readonly allowanceMs: number;
}): HeldUpstreamTokenAge;
//# sourceMappingURL=token-lifetime.d.mts.map