/**
 * Normalise an `htu` URI per RFC 9449 §6 / RFC 3986 §6.2.2.
 *
 * Rules applied (in order):
 *   1. Parse via WHATWG URL — handles scheme/host lowercase + IDN ASCII.
 *   2. Strip query (`?`) and fragment (`#`).
 *   3. Remove default port (443 for https, 80 for http).
 *   4. Decode unreserved percent-encoded sequences in the path.
 *   5. Remove dot segments from the path (RFC 3986 §5.2.4).
 *   6. Normalise empty path to `/`.
 *
 * WHATWG URL (used internally) already performs:
 *   - Scheme + host lowercasing.
 *   - IDN (internationalized domain) → ASCII-compatible (Punycode) form.
 *
 * It does NOT perform:
 *   - Unreserved character decoding in the path (rule 4).
 *   - Dot-segment removal for already-parsed inputs (rule 5).
 *
 * Returns the canonical `htu` string ready for equality comparison.
 *
 * Per Wave 2 Phase 2 spec §7.
 */
export declare const normalizeHtu: (raw: string) => string;
//# sourceMappingURL=htu-normalize.d.mts.map