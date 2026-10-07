/**
 * The longest `jti`, in UTF-16 code units, a single-use check records.
 *
 * A recorded `jti` is a seen-set key, held for as long as the credential it
 * names could be replayed, and the presenter chooses it: a DPoP proof reaches
 * the token endpoint before the client is authenticated, so without a bound
 * an anonymous caller decides how large each record is.
 *
 * 256 because a `jti` only has to be unique. RFC 9449 §4.2 suggests 96 bits
 * of randomness (16 base64url characters) or a UUID (36); RFC 7519 §4.1.7
 * asks for no more than a negligible chance of collision. 256 leaves room for
 * a prefixed identifier, a hex SHA-512 (128) or a signed nonce, and still
 * caps every record's key. Counted in code units because that is the unit
 * the seen-set's canonical key is measured in (`single-use/canonical-key.mts`),
 * so the bound is the same number an adapter stores; in UTF-8 it is at most
 * 768 bytes.
 */
export declare const MAX_JTI_LENGTH = 256;
/**
 * Whether a claimed `jti` may be recorded: a non-empty string of at most
 * {@link MAX_JTI_LENGTH} code units. A consumer refuses anything else as a
 * malformed credential, before `markSeen`, so an over-long value never
 * reaches the store.
 */
export declare function isRecordableJti(value: unknown): value is string;
//# sourceMappingURL=jti.d.mts.map