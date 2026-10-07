/**
 * What `value` is, for a refusal that names a value it cannot trust, never
 * rendered and never throwing: `the string "…"`, `the number 5`,
 * `the bigint 1`, `null`, `undefined`, `a function`, `a Set`, `an Object`,
 * or `an object` when its prototype names no constructor or cannot be read.
 * A primitive is named by its kind and value; an object by its kind alone,
 * so nothing it holds — a secret, a cycle, a getter that throws — is read.
 * Internal to core: not exported from the package.
 */
export declare const describeValue: (value: unknown) => string;
//# sourceMappingURL=describe-value.d.mts.map