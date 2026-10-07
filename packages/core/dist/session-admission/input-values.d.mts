/**
 * The two readings every admission stage takes of a value a caller or a
 * requirement handed in: an object is anything of type `object` but `null`,
 * and a string counts only when it is non-empty.
 */
export declare const nonEmptyString: (value: unknown) => string | undefined;
export declare const isObject: (value: unknown) => value is Record<string, unknown>;
//# sourceMappingURL=input-values.d.mts.map