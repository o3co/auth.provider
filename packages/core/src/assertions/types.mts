/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * What an {@link AssertionVerifier} concluded about a presented assertion.
 *
 * `subjectHandle` is the value handed to `UserRepository.authenticateByToken`:
 * an opaque handle, not an identity. The verifier proves possession
 * (cryptography); the Store decides who that is (identity data). Namespacing
 * the handle (`device:<id>`, `agent:<id>`) is the deployment's choice and its
 * Store's contract, not this library's.
 */
export interface AssertionVerificationResult {
	/** Opaque handle for `UserRepository.authenticateByToken`. */
	readonly subjectHandle: string;
	/**
	 * The issuer the assertion verified against, when the verifier knows one.
	 * For logs, and for anything that scopes state per issuer.
	 */
	readonly issuer?: string;
	/**
	 * Scopes the assertion itself authorizes, if it says.
	 *
	 * A ceiling, never a grant: the issued token's scope is the intersection of
	 * this, the request, and the client's allowlist. An assertion that names no
	 * scope constrains nothing by itself and leaves the other two in charge.
	 */
	readonly scope?: readonly string[];
	/**
	 * Audiences a token minted from this assertion may name, if the issuer's
	 * terms say. A ceiling on the issued `aud` whatever chose it (a policy, a
	 * `resource` parameter, the client registration), and, with no
	 * authenticated client, the stand-in for the registration's
	 * `allowedAudiences`. Absent, the other parties stay in charge.
	 */
	readonly audience?: readonly string[];
	/**
	 * When the verified assertion was issued (its `iat`), in epoch seconds, as
	 * the assertion claims it. Present, it is a finite number.
	 *
	 * Absent: the verifier did not establish an issue time.
	 */
	readonly issuedAt?: number;
	/**
	 * When the verified assertion expires (its `exp`), in epoch seconds.
	 *
	 * A ceiling on the issued token's lifetime: the jwt-bearer grant mints
	 * `min(oauth.accessToken.defaultExpiresIn, expiresAt − now)` and refuses an
	 * assertion with no whole second left (`invalid_grant`). Report the claim
	 * as it is: clamping one inside the clock tolerance forward would mint a
	 * token the issuing authority never backed.
	 *
	 * Omitting it is a statement, not a default: it asserts a credential with
	 * **no expiry**, and the configured lifetime stands uncapped. A verifier
	 * whose credential expires (a signed JWT, an attestation with a validity
	 * window) reports it; the bundled registry verifier always does. Present,
	 * it must be a finite number; anything else (a numeric string, `null`,
	 * `NaN`, `Infinity`) is refused as `invalid_grant`.
	 */
	readonly expiresAt?: number;
}

/**
 * What the grant knows about the presentation, handed to the verifier so
 * trust can depend on it.
 */
export interface AssertionVerificationContext {
	/**
	 * The authenticated client presenting the assertion. Absent for an
	 * unauthenticated presenter — RFC 7523 §3 makes client authentication
	 * optional — which a verifier may admit or refuse on its own terms.
	 */
	readonly clientId?: string;
}

/**
 * Proves that whoever presented an assertion possesses the credential behind
 * it.
 *
 * A slot rather than a fixed implementation: "assertion" covers a signed
 * device JWT, an Apple DeviceCheck token, a Play Integrity verdict, a TPM
 * quote, each verified against a different authority, several by a network
 * call to a vendor. This library ships the seam and one vendor-neutral JWT
 * implementation instead of bundling a vendor into every deployment.
 *
 * **A bare identifier is not authentication.** A verifier MUST establish
 * possession (a signature, an attestation, something the holder could not
 * have fabricated) before returning a handle, so `{"assertion": "device-1234"}`
 * is never a login. Returning `null` refuses; the grant never falls back to
 * trusting the input.
 *
 * `null` means "not verified" and is answered as `invalid_grant`. Throwing
 * means no conclusion was reached (a vendor attestation service down) and is
 * answered as `503`: calling a credential bad when a backend is unreachable
 * sends the caller to re-enrol a device that was fine.
 */
export interface AssertionVerifier {
	/** Adapter kind, for logs and boot diagnostics. */
	readonly kind: string;
	/**
	 * Verify possession. Resolves to the handle to look up, or `null` when the
	 * assertion does not prove possession. Throws when verification could not
	 * be attempted.
	 *
	 * `context` says who is presenting. A verifier that does not care ignores
	 * it; the registry verifier refuses a presenter an issuer's entry does not
	 * admit.
	 */
	verify(
		assertion: string,
		context?: AssertionVerificationContext,
	): Promise<AssertionVerificationResult | null>;
}

// ---------------------------------------------------------------------------
// ComponentMap slot
//
// Optional to wire: only the jwt-bearer grant uses it, and declares it in
// `requires`, so enabling the grant without a verifier fails boot. There is
// deliberately no default: the only possible default would accept things.
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly assertionVerifier?: AssertionVerifier;
	}
}
