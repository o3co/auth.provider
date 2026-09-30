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
 * barrel. They map the library's thrown errors to a typed `reason` by the prefixes of the
 * library's own messages, never by text a client can write into one (the client data's `type`,
 * `challenge` and `origin` are quoted inside them) — recheck the prefixes whenever the library is
 * bumped. They reshape registration material for the endpoint layer, and answer the backup
 * eligibility (BE) and backup state (BS) of a verified credential to the caller that asks.
 *
 * A registration's top origin is held to the rule the library holds an assertion's to, which it
 * does not apply to a registration: a top origin the client data reports must be one of the
 * expected top origins, and belong to a cross-origin ceremony. None reported passes, as it does
 * for an assertion (Safari reports none). The client data is read with the library's own decoder,
 * so the text judged is the text it verified.
 * - `topOriginAccepted` mirrors `verifyAuthenticationResponse`'s `crossOrigin` branch: recheck it
 *   at every `@simplewebauthn/server` bump.
 * - Once `verifyRegistrationResponse` takes an expected top origin, pass it through and delete
 *   `topOriginAccepted`.
 *
 * The sign count is judged here, only once the signature verified: the library, which compares
 * the count before it checks the signature, is handed a stored count of 0 and so never judges
 * it. A count that did not increase over the stored one is a regression, but for 0 against a
 * stored 0 — an authenticator that keeps no counter (WebAuthn §6.1.1).
 *
 * Attestation chain failures ("x5c could not be chained to any specified trust anchor") match no
 * prefix and read as "unknown"; there is no dedicated reason for them.
 */

import type { AuthenticatorTransport, WebAuthnCredential } from "@o3co/auth-provider-core";
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/server";
import { verifyAuthenticationResponse, verifyRegistrationResponse } from "@simplewebauthn/server";
import { decodeClientDataJSON } from "@simplewebauthn/server/helpers";
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
	/**
	 * Origins this RP may be framed by, as {@link AssertionVerificationInput.expectedTopOrigins}.
	 * Absent, a reported top origin is refused.
	 */
	readonly expectedTopOrigins?: readonly string[];
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
				| "top_origin_mismatch"
				| "challenge_mismatch"
				| "attestation_invalid"
				| "rp_id_mismatch"
				// The credential's key uses an algorithm outside
				// `WEBAUTHN_ALGORITHM_IDS` — a refusal this package chose, named as one.
				| "algorithm_not_allowed"
				| "unknown";
	  };

/**
 * {@link AttestationVerificationResult}, the material also carrying the credential's backup
 * eligibility (BE): whether it may be backed up — a multi-device credential — as the
 * authenticator reports it.
 */
export type AttestationVerificationWithBackupState =
	| {
			readonly ok: true;
			readonly material: Extract<AttestationVerificationResult, { ok: true }>["material"] & {
				readonly backupEligible: boolean;
			};
	  }
	| Extract<AttestationVerificationResult, { ok: false }>;

export async function verifyWebAuthnAttestation(
	input: AttestationVerificationInput,
): Promise<AttestationVerificationResult> {
	const verified = await verifyWebAuthnAttestationWithBackupState(input);
	if (!verified.ok) return verified;
	const { backupEligible: _backupEligible, ...material } = verified.material;
	return { ok: true, material };
}

/**
 * Verifies an attestation as {@link verifyWebAuthnAttestation} does, and answers the credential's
 * backup eligibility beside its material.
 */
export async function verifyWebAuthnAttestationWithBackupState(
	input: AttestationVerificationInput,
): Promise<AttestationVerificationWithBackupState> {
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
		if (!topOriginAccepted(input.response.response.clientDataJSON, input.expectedTopOrigins)) {
			return { ok: false, reason: "top_origin_mismatch" };
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
				// The library reads BE into the device type: `multiDevice` when it is set.
				backupEligible: info.credentialDeviceType === "multiDevice",
			},
		};
	} catch (err) {
		return mapRegistrationError(err);
	}
}

/**
 * Whether the top origin `clientDataJSON` reports, decoded as the library decodes it, is one a
 * ceremony may come from: none reported, or one of `expected` for a cross-origin ceremony. Client
 * data that is not a JSON object fails.
 */
function topOriginAccepted(
	clientDataJSON: string,
	expected: readonly string[] | undefined,
): boolean {
	const clientData: unknown = decodeClientDataJSON(clientDataJSON);
	if (typeof clientData !== "object" || clientData === null) return false;
	const { crossOrigin, topOrigin } = clientData as { crossOrigin?: unknown; topOrigin?: unknown };
	if (topOrigin === undefined) return true;
	return crossOrigin === true && typeof topOrigin === "string" && !!expected?.includes(topOrigin);
}

/** The library's own message prefixes for a refused registration, each with its reason. */
const REGISTRATION_REFUSALS: readonly (readonly [
	string,
	Extract<AttestationVerificationResult, { ok: false }>["reason"],
])[] = [
	// A credential outside `WEBAUTHN_ALGORITHM_IDS`.
	["Unexpected public key alg ", "algorithm_not_allowed"],
	["Unexpected registration response origin ", "origin_mismatch"],
	["Unexpected registration response challenge ", "challenge_mismatch"],
	["Unexpected RP ID hash", "rp_id_mismatch"],
];

/** The library's own message prefixes for a refused assertion, each with its reason. */
const AUTHENTICATION_REFUSALS: readonly (readonly [
	string,
	Extract<AssertionVerificationResult, { ok: false }>["reason"],
])[] = [
	// A cross-origin (framed) ceremony: `webauthn.origin` cannot fix it, `webauthn.topOrigin` can.
	["Detected cross-origin authentication response from top origin ", "top_origin_mismatch"],
	["Unexpected cross-origin authentication response top origin ", "top_origin_mismatch"],
	["Unexpected top origin ", "top_origin_mismatch"],
	["Unexpected authentication response origin ", "origin_mismatch"],
	["Unexpected authentication response challenge ", "challenge_mismatch"],
	["Unexpected RP ID hash", "rp_id_mismatch"],
];

/**
 * The reason whose prefix begins `err`'s message; `unknown` for any other
 * refusal. The message is read to classify the refusal alone, never logged.
 */
function refusalOf<R extends string>(
	err: unknown,
	refusals: readonly (readonly [string, R])[],
): R | "unknown" {
	if (!(err instanceof Error)) return "unknown";
	const { message } = err;
	return refusals.find(([prefix]) => message.startsWith(prefix))?.[1] ?? "unknown";
}

function mapRegistrationError(err: unknown): Extract<AttestationVerificationResult, { ok: false }> {
	return { ok: false, reason: refusalOf(err, REGISTRATION_REFUSALS) };
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
 * {@link AssertionVerificationResult}, with the backup flags the verified authenticator data
 * carries: the backup eligibility (BE) — whether the credential may be backed up, a
 * multi-device credential — and the backup state (BS) — whether it is backed up at this
 * assertion.
 */
export type AssertionVerificationWithBackupState =
	| {
			readonly ok: true;
			readonly newSignCount: number;
			readonly backupEligible: boolean;
			readonly backedUp: boolean;
	  }
	| Extract<AssertionVerificationResult, { ok: false }>;

export async function verifyWebAuthnAssertion(
	input: AssertionVerificationInput,
): Promise<AssertionVerificationResult> {
	const verified = await verifyWebAuthnAssertionWithBackupState(input);
	return verified.ok ? { ok: true, newSignCount: verified.newSignCount } : verified;
}

/**
 * Verifies an assertion as {@link verifyWebAuthnAssertion} does, and answers the backup flags its
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
				// 0, so the library never judges the count: it compares it before the signature,
				// and the count is judged below, once the signature verified.
				counter: 0,
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

		const { newCounter, credentialBackedUp, credentialDeviceType } =
			verification.authenticationInfo;
		const stored = input.credential.signCount;
		const flags = {
			// The library reads BE into the device type: `multiDevice` when it is set.
			backupEligible: credentialDeviceType === "multiDevice",
			backedUp: credentialBackedUp,
		};

		// Both counters 0: an authenticator that keeps no counter (WebAuthn §6.1.1).
		if (newCounter === 0 && stored === 0) {
			return { ok: true, newSignCount: 0, ...flags };
		}

		if (newCounter <= stored) {
			return { ok: false, reason: "sign_count_regression" };
		}

		return { ok: true, newSignCount: newCounter, ...flags };
	} catch (err) {
		return mapAuthenticationError(err);
	}
}

function mapAuthenticationError(err: unknown): Extract<AssertionVerificationResult, { ok: false }> {
	return { ok: false, reason: refusalOf(err, AUTHENTICATION_REFUSALS) };
}
