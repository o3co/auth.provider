/**
 * RFC 6749 §5.2 error response envelope. Used across `/oauth/*` and the
 * session router so consumer code can parse error responses with a single
 * shape regardless of which surface produced them.
 */
export interface ErrorEnvelope {
    readonly error: string;
    readonly error_description?: string;
    readonly error_uri?: string;
}
/**
 * Construct an RFC 6749 §5.2 error envelope. Optional fields are omitted
 * (rather than serialized as `undefined`) so JSON consumers see a clean
 * shape — `JSON.stringify({ x: undefined })` does drop the key, but having
 * the helper pre-omit keeps the in-memory object consistent for tests
 * that snapshot the structure with `toEqual`.
 *
 * Empty-string `description` / `uri` are treated as omissions: RFC 6749
 * §5.2 specifies these as optional human-readable / URI fields, and an
 * empty string conveys no information while still serializing as a
 * present-but-empty value. Callers that need an explicit empty string
 * should construct the envelope literal directly.
 *
 * Contract scope: the three RFC 6749 §5.2 stock fields only (`error`,
 * `error_description`, `error_uri`). Extension fields (e.g. namespaced
 * sub-codes, rate-limit details) are not added here — pass through a
 * separate helper or a literal envelope object.
 *
 * @param error       Machine-readable error code (snake_case, e.g. `invalid_grant`).
 * @param description Optional human-readable detail. Empty string is dropped.
 * @param uri         Optional reference URL. Empty string is dropped.
 */
export declare function errorEnvelope(error: string, description?: string, uri?: string): ErrorEnvelope;
//# sourceMappingURL=envelope.d.mts.map