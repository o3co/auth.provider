/**
 * Length-independent constant-time string comparison, for the CSRF token: its
 * signature against the one expected, and the cookie's copy against the one
 * echoed back.
 *
 * `timingSafeEqual` throws on differing lengths, and guarding that with a
 * length check leaks the length. Comparing fixed-width digests of the inputs
 * sidesteps both.
 */
export declare const constantTimeEquals: (a: string, b: string) => boolean;
//# sourceMappingURL=constantTimeEquals.d.mts.map