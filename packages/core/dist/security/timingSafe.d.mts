/**
 * Constant-time string equality — for inputs whose **byte length is public
 * information** (e.g. PKCE code_verifier, OAuth `code_challenge`).
 *
 * `===`/`!==` short-circuit on the first mismatched byte, leaking timing
 * information about how many bytes of the candidate matched the secret.
 * For PKCE `code_verifier` comparison (RFC 7636 §4.1) and OAuth 2.1 BCP
 * §4.5 this is a security defect — a network-positioned attacker can
 * iteratively recover a stored `code_challenge` byte-by-byte.
 *
 * ## Contract — read this BEFORE reusing the helper
 *
 * The early-return on byte-length mismatch (`bufA.length !== bufB.length →
 * return false`) is structurally NOT constant-time across length-distinct
 * inputs: an attacker can distinguish "lengths differ" (returns ~immediately)
 * from "lengths equal but bytes differ" (returns after `timingSafeEqual`'s
 * fixed-time loop). For the use cases this helper currently serves —
 * PKCE `code_verifier` (RFC 7636: 43–128 chars) and the SHA-256 base64url
 * `code_challenge` (always 43 chars) — input lengths are bounded by the
 * protocol and are not secrets, so the length-mismatch branch is NOT a
 * usable oracle.
 *
 * **DO NOT** reuse this helper for secrets whose byte length is itself
 * sensitive (variable-length tokens, password hashes of variable cost,
 * etc.) without first auditing whether a length oracle is acceptable.
 * For the secret-length-is-secret case, compare fixed-size digests
 * (e.g. HMAC) instead, or use a dedicated constant-time-irrespective-
 * of-length primitive. Per Copilot review on PR #126: the helper is
 * named/documented as suitable for public-length inputs only; widening
 * its contract is out of scope for v0.5.1.
 *
 * ## Implementation note
 *
 * Codex Delta 3 of SF-3 spec: the buffers are encoded BEFORE the length
 * check. `timingSafeEqual` requires equal-length inputs, and JS string
 * length does not equal UTF-8 byte length for multi-byte code points
 * (`"😀".length === 2` but `Buffer.byteLength("😀") === 4`). Comparing
 * byte-lengths after encoding makes the helper safe for arbitrary
 * Unicode strings and avoids a thrown `RangeError` on the rare non-ASCII
 * input.
 *
 * Per SF-3 + MIN-4 (v0.5.1).
 */
export declare function constantTimeStringEqual(a: string, b: string): boolean;
//# sourceMappingURL=timingSafe.d.mts.map