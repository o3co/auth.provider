/**
 * A value as a refusal shows it, with its type: a string quoted (so `"20"`
 * does not read as a usable number), a number as it prints (`NaN` included),
 * a BigInt with its `n`, a function as `[function]` (never its source),
 * anything else as JSON, or `String()` where JSON cannot write it (a circular
 * object, a `toJSON` that answers nothing, a Symbol).
 */
export declare const shownConfigValue: (value: unknown) => string;
/**
 * A configured number as core's schemas read one ({@link wholeNumberFromEnv}),
 * for a key read where its owning schema did not run: a number as it is, and
 * a string of decimal digits (whitespace around allowed) as its number. HOCON
 * substitutes an environment variable as a string, so a key filled from one
 * arrives as one. Anything else — a blank string, a hex, exponent, sign or
 * fraction, a boolean, an array, an object — is `undefined`, never a number
 * the operator did not write. The caller judges the range.
 */
export declare const configuredNumber: (value: unknown) => number | undefined;
//# sourceMappingURL=configuredValue.d.mts.map