/**
 * What an {@link AssertionVerifier} concluded about a presented assertion.
 *
 * `subjectHandle` is the value handed to `UserRepository.authenticateByToken`.
 * It is an **opaque handle**, not an identity: the verifier proves the caller
 * possesses the credential, and the Store decides who that is. Splitting the
 * two is the whole point — possession is cryptography and belongs here;
 * resolution is identity data and belongs to the Store (#301).
 *
 * Namespacing the handle (`device:<id>`, `agent:<id>`) is the deployment's
 * choice and its Store's contract, not this library's.
 */
export interface AssertionVerificationResult {
    /** Opaque handle for `UserRepository.authenticateByToken`. */
    readonly subjectHandle: string;
    /**
     * Scopes the assertion itself authorizes, if it says.
     *
     * A ceiling, never a grant: the issued token's scope is the intersection of
     * this, the request, and the client's allowlist. An assertion that names no
     * scope constrains nothing by itself and leaves the other two in charge.
     */
    readonly scope?: readonly string[];
}
/**
 * Proves that whoever presented an assertion possesses the credential behind
 * it (#301).
 *
 * ## Why this is a slot rather than a fixed implementation
 *
 * "Assertion" covers a signed device JWT, an Apple DeviceCheck token, a Play
 * Integrity verdict, a TPM quote — each verified against a different authority
 * by a different protocol, several of them requiring a network call to a
 * vendor. Fixing one here would bundle that vendor into every deployment; this
 * library ships the seam and one vendor-neutral JWT implementation, the same
 * split #303 made for remote signing.
 *
 * ## The rule this exists to enforce
 *
 * **A bare identifier is not authentication.** The failure this guards against
 * is a deployment accepting `{"assertion": "device-1234"}` as a login because
 * the string looked like a credential. A verifier MUST establish possession —
 * a signature, an attestation, something the holder could not have fabricated
 * — before returning a handle. Returning `null` refuses the login; the grant
 * never falls back to trusting the input.
 *
 * ## Failure vocabulary
 *
 * `null` means "not verified", and is answered as `invalid_grant`. **Throwing**
 * means the verifier could not reach a conclusion — a vendor attestation
 * service being down — and is answered as `503`, not as a refusal, for the same
 * reason #408 separated a revocation-store outage from a revocation: telling a
 * caller their credential is bad when the truth is that a backend is unreachable
 * sends them to re-enrol a device that was fine.
 */
export interface AssertionVerifier {
    /** Adapter kind, for logs and boot diagnostics. */
    readonly kind: string;
    /**
     * Verify possession. Resolves to the handle to look up, or `null` when the
     * assertion does not prove possession. Throws when verification could not
     * be attempted.
     */
    verify(assertion: string): Promise<AssertionVerificationResult | null>;
}
declare module "@o3co/auth-provider-core" {
    interface ComponentMap {
        readonly assertionVerifier?: AssertionVerifier;
    }
}
//# sourceMappingURL=types.d.mts.map