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
 * Internal wrappers around `@simplewebauthn/server` verification; not exported from the package
 * barrel. They map the library's thrown errors to a typed `reason` by matching message text
 * (recheck the patterns against the library's messages whenever it is bumped), reshape
 * registration material for the endpoint layer, allow the sign-count 0/0 case of
 * authenticators that always report 0, and answer a verified assertion's backup state (BS) to
 * the caller that asks for it.
 *
 * Attestation chain failures ("x5c could not be chained to any specified trust anchor") match no
 * pattern and read as "unknown"; there is no dedicated reason for them.
 */

import type { AuthenticatorTransport, WebAuthnCredential } from "@o3co/auth-provider-core";
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/server";
import { verifyAuthenticationResponse, verifyRegistrationResponse } from "@simplewebauthn/server";
import { WEBAUTHN_ALGORITHM_IDS } from "./options.mjs";

// ---------------------------------------------------------------------------
// Attestation (registration)
// ---------------------------------------------------------------------------

export interface AttestationVerificationInput {
	readonly response: RegistrationResponseJSON;
	readonly expectedChallenge: string;
	readonly expectedRpId: string;
	readonly expectedOrigins: readonly string[];
	/**
	 * UserVerificationRequirement (W3C WebAuthn §5.8.6); defaults to "preferred". Only "required"
	 * is enforced here (the UV flag must be set); "preferred" and "discouraged" are hints the
	 * options carry. UV is a cryptographic property of the response, so it is checked here, not
	 * by grant policy.
	 */
	readonly userVerification?: "required" | "preferred" | "discouraged";
}

export type AttestationVerificationResult =
	| {
			readonly ok: true;
			readonly material: {
				readonly credentialId: string;
				/**
				 * COSE public key. Typed `Uint8Array<ArrayBuffer>` because it is always freshly
				 * allocated below (never SharedArrayBuffer-backed), so it passes to
				 * `@simplewebauthn/server`'s byte inputs without another copy.
				 */
				readonly publicKey: Uint8Array<ArrayBuffer>;
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
				// The credential's key uses an algorithm outside
				// `WEBAUTHN_ALGORITHM_IDS` — a refusal this package chose, named as one.
				| "algorithm_not_allowed"
				| "unknown";
	  };

export async function verifyWebAuthnAttestation(
	input: AttestationVerificationInput,
): Promise<AttestationVerificationResult> {
	try {
		const verification = await verifyRegistrationResponse({
			response: input.response,
			expectedChallenge: input.expectedChallenge,
			expectedOrigin: [...input.expectedOrigins],
			expectedRPID: input.expectedRpId,
			// Only "required" is enforced; the other values are hints.
			requireUserVerification: (input.userVerification ?? "preferred") === "required",
			// The same set `generateRegistrationOptionsForUser` offered: what is
			// accepted here and what is advertised there cannot drift apart, and
			// the library's default moves with the runtime.
			supportedAlgorithmIDs: [...WEBAUTHN_ALGORITHM_IDS],
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
		// `Unexpected public key alg "-48", expected one of "-8,-7,-257"`: a credential outside
		// `WEBAUTHN_ALGORITHM_IDS`.
		if (/public key alg/i.test(err.message)) return { ok: false, reason: "algorithm_not_allowed" };
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
	/** The stored credential: its id, its COSE public key, its sign count and its transports. */
	readonly credential: Pick<
		WebAuthnCredential,
		"credentialId" | "publicKey" | "signCount" | "transports"
	>;
	readonly response: AuthenticationResponseJSON;
	readonly expectedChallenge: string;
	readonly expectedRpId: string;
	readonly expectedOrigins: readonly string[];
	/** As {@link AttestationVerificationInput.userVerification}; defaults to "preferred". */
	readonly userVerification?: "required" | "preferred" | "discouraged";
	/**
	 * Origins this RP may be framed by: the `topOrigin` a browser reports for a cross-origin
	 * (iframe) ceremony. Absent, a reported cross-origin response is refused (the library's
	 * default).
	 */
	readonly expectedTopOrigins?: readonly string[];
}

export type AssertionVerificationResult =
	| { readonly ok: true; readonly newSignCount: number }
	| {
			readonly ok: false;
			readonly reason:
				| "origin_mismatch"
				| "top_origin_mismatch"
				| "challenge_mismatch"
				| "rp_id_mismatch"
				| "signature_invalid"
				| "sign_count_regression"
				| "unknown";
	  };

/**
 * {@link AssertionVerificationResult}, with the backup state (BS) the verified authenticator data
 * carries: whether the credential is backed up, a synced passkey, at this assertion.
 */
export type AssertionVerificationWithBackupState =
	| { readonly ok: true; readonly newSignCount: number; readonly backedUp: boolean }
	| Extract<AssertionVerificationResult, { ok: false }>;

export async function verifyWebAuthnAssertion(
	input: AssertionVerificationInput,
): Promise<AssertionVerificationResult> {
	const verified = await verifyWebAuthnAssertionWithBackupState(input);
	return verified.ok ? { ok: true, newSignCount: verified.newSignCount } : verified;
}

/**
 * Verifies an assertion as {@link verifyWebAuthnAssertion} does, and answers the backup state its
 * authenticator data carries beside the new count.
 */
export async function verifyWebAuthnAssertionWithBackupState(
	input: AssertionVerificationInput,
): Promise<AssertionVerificationWithBackupState> {
	try {
		const verification = await verifyAuthenticationResponse({
			response: input.response,
			expectedChallenge: input.expectedChallenge,
			expectedOrigin: [...input.expectedOrigins],
			// Omitted rather than `undefined` when unset (the library treats both alike): the
			// absence states that this RP does not expect to be framed.
			...(input.expectedTopOrigins === undefined
				? {}
				: { expectedTopOrigin: [...input.expectedTopOrigins] }),
			expectedRPID: input.expectedRpId,
			credential: {
				id: input.credential.credentialId,
				// A copy, for two reasons. The store's bare `Uint8Array` (so a driver's `Buffer`
				// satisfies it) must become the `Uint8Array<ArrayBuffer>` the library requires, and
				// `new Uint8Array(view)` converts even a SharedArrayBuffer-backed view, which no
				// cast could make safe. And the in-process adapter returns its own stored array,
				// which a third-party library must not hold a live alias of.
				publicKey: new Uint8Array(input.credential.publicKey),
				counter: input.credential.signCount,
				// SimpleWebAuthn's AuthenticatorTransportFuture is a superset of ours (adds "cable"
				// and "smart-card"); stored values are a subset, so the cast is safe.
				// biome-ignore lint/suspicious/noExplicitAny: transport superset cast — see comment
				transports: input.credential.transports as any,
			},
			// Only "required" is enforced; the other values are hints.
			requireUserVerification: (input.userVerification ?? "preferred") === "required",
		});

		if (!verification.verified) {
			return { ok: false, reason: "signature_invalid" };
		}

		const { newCounter, credentialBackedUp } = verification.authenticationInfo;
		const stored = input.credential.signCount;

		// Both counters 0 is allowed: some authenticators always report 0 (the library skips its
		// own counter check in that case too).
		if (newCounter === 0 && stored === 0) {
			return { ok: true, newSignCount: 0, backedUp: credentialBackedUp };
		}

		// The library already throws when the counter did not increase; this guard keeps the
		// invariant local rather than trusting that.
		if (newCounter <= stored) {
			return { ok: false, reason: "sign_count_regression" };
		}

		return { ok: true, newSignCount: newCounter, backedUp: credentialBackedUp };
	} catch (err) {
		return mapAuthenticationError(err);
	}
}

function mapAuthenticationError(err: unknown): Extract<AssertionVerificationResult, { ok: false }> {
	if (err instanceof Error) {
		// Before the plain-origin arm: the library's cross-origin messages contain "origin" and
		// would otherwise point an operator at `webauthn.origin`, which cannot fix an embedding.
		if (/top.?origin/i.test(err.message)) return { ok: false, reason: "top_origin_mismatch" };
		if (/origin/i.test(err.message)) return { ok: false, reason: "origin_mismatch" };
		if (/challenge/i.test(err.message)) return { ok: false, reason: "challenge_mismatch" };
		if (/rp.?id/i.test(err.message)) return { ok: false, reason: "rp_id_mismatch" };
		if (/counter/i.test(err.message)) return { ok: false, reason: "sign_count_regression" };
	}
	return { ok: false, reason: "unknown" };
}
