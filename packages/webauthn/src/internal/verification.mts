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
 * Internal WebAuthn verification helpers (spec §2.5).
 *
 * These are thin wrappers around `@simplewebauthn/server` that:
 *   1. Map SimpleWebAuthn's thrown errors to a typed `reason` discriminant
 *      so callers never need to parse error strings.
 *   2. Reshape the registration material to drop fields that belong to the
 *      endpoint layer (userId, createdAt, nickname).
 *   3. Enforce the §2.4 sign-count corner case: when both stored counter and
 *      new counter are 0 (authenticators that always report 0), skip the
 *      strict-increase check — SimpleWebAuthn natively skips its throw for
 *      this case, so the post-verification guard handles the remaining check.
 *
 * NOT exported from the package barrel — internal use only.
 *
 * Error-reason regex mapping (validated against SimpleWebAuthn v13.1.1 source):
 *   /origin/i   → "origin_mismatch"
 *   /challenge/i → "challenge_mismatch"
 *   /rp.?id/i   → "rp_id_mismatch"  (matches "RP ID" from UnexpectedRPIDHash)
 *   /counter/i  → "sign_count_regression"
 *
 * Cross-refs: Plan T25 / spec §2.5 / §2.4 sign-count
 */

import type { AuthenticatorTransport, WebAuthnCredential } from "@o3co/auth-provider-core";
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/server";
import { verifyAuthenticationResponse, verifyRegistrationResponse } from "@simplewebauthn/server";

// ---------------------------------------------------------------------------
// Attestation (registration)
// ---------------------------------------------------------------------------

export interface AttestationVerificationInput {
	readonly response: RegistrationResponseJSON;
	readonly expectedChallenge: string;
	readonly expectedRpId: string;
	readonly expectedOrigins: readonly string[];
}

export type AttestationVerificationResult =
	| {
			readonly ok: true;
			readonly material: {
				readonly credentialId: string;
				readonly publicKey: Uint8Array;
				readonly signCount: number;
				readonly transports?: ReadonlyArray<AuthenticatorTransport>;
				readonly backedUp: boolean;
			};
	  }
	| {
			readonly ok: false;
			readonly reason:
				| "origin_mismatch"
				| "challenge_mismatch"
				| "attestation_invalid"
				| "rp_id_mismatch"
				| "unknown";
	  };

export async function verifyWebAuthnAttestation(
	input: AttestationVerificationInput,
): Promise<AttestationVerificationResult> {
	try {
		const verification = await verifyRegistrationResponse({
			response: input.response,
			expectedChallenge: input.expectedChallenge,
			expectedOrigin: [...input.expectedOrigins], // S7: multi-origin support
			expectedRPID: input.expectedRpId,
			requireUserVerification: false, // policy decided per-endpoint
		});

		if (!verification.verified || !verification.registrationInfo) {
			return { ok: false, reason: "attestation_invalid" };
		}

		const info = verification.registrationInfo;
		return {
			ok: true,
			material: {
				credentialId: info.credential.id,
				publicKey: new Uint8Array(info.credential.publicKey),
				signCount: info.credential.counter,
				// SimpleWebAuthn's AuthenticatorTransportFuture is a superset of our
				// AuthenticatorTransport (adds "cable" and "smart-card"). Cast to
				// unknown first to avoid the direct-super-type assignment error.
				transports: info.credential.transports as unknown as
					| ReadonlyArray<AuthenticatorTransport>
					| undefined,
				backedUp: info.credentialBackedUp,
			},
		};
	} catch (err) {
		return mapRegistrationError(err);
	}
}

function mapRegistrationError(err: unknown): AttestationVerificationResult {
	if (err instanceof Error) {
		if (/origin/i.test(err.message)) return { ok: false, reason: "origin_mismatch" };
		if (/challenge/i.test(err.message)) return { ok: false, reason: "challenge_mismatch" };
		if (/rp.?id/i.test(err.message)) return { ok: false, reason: "rp_id_mismatch" };
	}
	return { ok: false, reason: "unknown" };
}

// ---------------------------------------------------------------------------
// Assertion (authentication)
// ---------------------------------------------------------------------------

export interface AssertionVerificationInput {
	readonly credential: WebAuthnCredential;
	readonly response: AuthenticationResponseJSON;
	readonly expectedChallenge: string;
	readonly expectedRpId: string;
	readonly expectedOrigins: readonly string[];
}

export type AssertionVerificationResult =
	| { readonly ok: true; readonly newSignCount: number }
	| {
			readonly ok: false;
			readonly reason:
				| "origin_mismatch"
				| "challenge_mismatch"
				| "rp_id_mismatch"
				| "signature_invalid"
				| "sign_count_regression"
				| "unknown";
	  };

export async function verifyWebAuthnAssertion(
	input: AssertionVerificationInput,
): Promise<AssertionVerificationResult> {
	try {
		const verification = await verifyAuthenticationResponse({
			response: input.response,
			expectedChallenge: input.expectedChallenge,
			expectedOrigin: [...input.expectedOrigins], // S7: multi-origin support
			expectedRPID: input.expectedRpId,
			credential: {
				id: input.credential.credentialId,
				publicKey: input.credential.publicKey,
				counter: input.credential.signCount,
				// Cast: SimpleWebAuthn expects AuthenticatorTransportFuture[]
				// (superset of our AuthenticatorTransport — adds "cable" and
				// "smart-card"). Our stored values are a strict subset; the cast
				// is safe since the common values round-trip without loss.
				// biome-ignore lint/suspicious/noExplicitAny: transport superset cast — see comment
				transports: input.credential.transports as any,
			},
			requireUserVerification: false, // policy decided per-endpoint
		});

		if (!verification.verified) {
			return { ok: false, reason: "signature_invalid" };
		}

		const newCounter = verification.authenticationInfo.newCounter;
		const stored = input.credential.signCount;

		// §2.4 sign-count corner case: if both stored AND new counters are 0,
		// allow (some authenticators always report 0).
		// SimpleWebAuthn already skips its own counter throw for the 0/0 case
		// (condition: (counter > 0 || credential.counter > 0) && counter <= credential.counter).
		// We still guard here so the return type is explicit.
		if (newCounter === 0 && stored === 0) {
			return { ok: true, newSignCount: 0 };
		}

		// For all other cases: SimpleWebAuthn already throws a counter error
		// when newCounter <= stored (and at least one is > 0), so this guard
		// only fires in edge cases where SimpleWebAuthn returns verified=true
		// but the counter did not increase (should not happen in practice).
		if (newCounter <= stored) {
			return { ok: false, reason: "sign_count_regression" };
		}

		return { ok: true, newSignCount: newCounter };
	} catch (err) {
		return mapAuthenticationError(err);
	}
}

function mapAuthenticationError(err: unknown): AssertionVerificationResult {
	if (err instanceof Error) {
		if (/origin/i.test(err.message)) return { ok: false, reason: "origin_mismatch" };
		if (/challenge/i.test(err.message)) return { ok: false, reason: "challenge_mismatch" };
		if (/rp.?id/i.test(err.message)) return { ok: false, reason: "rp_id_mismatch" };
		if (/counter/i.test(err.message)) return { ok: false, reason: "sign_count_regression" };
	}
	return { ok: false, reason: "unknown" };
}
