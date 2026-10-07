/** The HMACs a factor's codes may be computed with, in the order the ADR names them. */
export declare const TOTP_ALGORITHMS: readonly ["SHA1", "SHA256", "SHA512"];
/** The HMAC a factor's codes are computed with. */
export type TotpAlgorithm = (typeof TOTP_ALGORITHMS)[number];
/**
 * A secret of the algorithm's output length, as RFC 6238's reference seeds
 * are: a shorter one wastes the hash, and a longer one is hashed down to
 * this length by HMAC anyway.
 */
export declare const TOTP_SECRET_BYTES: Readonly<Record<TotpAlgorithm, number>>;
/** How long a code may be: RFC 4226 asks for at least 6; 8 is what Appendix B's vectors use. */
export declare const TOTP_DIGITS: Readonly<{
    min: 6;
    max: 8;
}>;
/** What a code is computed with, beside the secret and the counter. */
export interface HotpParameters {
    readonly algorithm: TotpAlgorithm;
    readonly digits: number;
}
/**
 * The RFC 4226 value of `secret` at `counter`, `digits` long with leading
 * zeros. A `RangeError` for an input it cannot compute over — an algorithm it
 * does not know, a length outside {@link TOTP_DIGITS}, a counter that is not a
 * safe non-negative integer, an empty secret: each a caller's fault, and none
 * quoted, since the secret is one of them.
 */
export declare function hotp(secret: Buffer, counter: number, { algorithm, digits }: HotpParameters): string;
/**
 * The RFC 6238 time step `nowMs` falls in: `floor(seconds / period)` from the
 * epoch. A `RangeError` for a time that is not a finite non-negative number,
 * or a period that is not a positive whole number of seconds.
 */
export declare function totpStep(nowMs: number, period: number): number;
/** What a code is matched with: the factor's parameters, the window, the time and the step last used. */
export interface TotpMatchParameters extends HotpParameters {
    readonly secret: Buffer;
    /** Seconds per step. */
    readonly period: number;
    /** Steps accepted either side of now. */
    readonly window: number;
    readonly nowMs: number;
    /** The step the factor's last accepted code was at; absent for a factor that has none (an enrollment's proof). */
    readonly lastUsedStep?: number;
}
/**
 * What matching found. `matched`: the code is the one for `step`, the latest
 * such step in the window after `lastUsedStep`. `replayed`: it is a code of
 * the window, but only for a step at or before `lastUsedStep`. `invalid`: no
 * step in the window has it.
 */
export type TotpMatch = {
    readonly outcome: "matched";
    readonly step: number;
} | {
    readonly outcome: "replayed";
} | {
    readonly outcome: "invalid";
};
/**
 * Looks for `code` at each step from `T - window` to `T + window` (none
 * before the epoch). A `RangeError` for a window that is not a non-negative
 * whole number, or a `lastUsedStep` that is not a safe integer, beside
 * {@link hotp}'s and {@link totpStep}'s.
 */
export declare function matchTotpCode(code: string, params: TotpMatchParameters): TotpMatch;
//# sourceMappingURL=rfc6238.d.mts.map