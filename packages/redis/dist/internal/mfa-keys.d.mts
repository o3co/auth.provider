/**
 * How the two MFA stores spell a caller's value inside a key or a hash field,
 * and the rule their key prefixes are held to. A subject, factor id or
 * transaction id is base64url of its JSON, as in the federation grant store,
 * so no brace a value carries can move a key's hash tag, and two values that
 * differ only in a lone surrogate (which UTF-8 turns into the same replacement
 * character) never share a key or a field.
 */
/** `value` as it appears inside a key or a field: base64url of its JSON. */
export declare const mfaKeyPart: (value: string) => string;
/**
 * Refuses, with a `RangeError` naming `store`, a key prefix that carries a
 * brace: it would open a hash tag of its own ahead of the subject's, and
 * every subject would land on the one Cluster slot the prefix names.
 */
export declare function checkMfaKeyPrefix(keyPrefix: string, store: string): string;
//# sourceMappingURL=mfa-keys.d.mts.map