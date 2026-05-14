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
 * Tests for verifyWebAuthnAttestation + verifyWebAuthnAssertion (spec §2.5).
 *
 * Fixture strategy: Option D — vi.mock(@simplewebauthn/server).
 *
 * Rationale: SimpleWebAuthn v13.1.1 ships no test fixtures or ceremony-builder
 * helpers. Constructing a valid attestation object requires raw CBOR + COSE key
 * encoding + WebAuthn authenticatorData + a real EC/RSA signature, which is
 * brittle and duplicates SimpleWebAuthn's own test surface.
 *
 * The helpers under test are *thin wrappers* whose value-add is:
 *   1. Typed error-reason mapping (origin/challenge/rp_id/counter error strings
 *      → typed reason union)
 *   2. Material reshaping (drop SimpleWebAuthn-internal fields; expose only
 *      credentialId / publicKey / signCount / transports / backedUp)
 *   3. §2.4 sign-count corner case (stored=0 && new=0 → allow)
 *
 * All three are fully exercisable via mocked SimpleWebAuthn responses/throws.
 * The real cryptographic path is covered by SimpleWebAuthn's own test suite and
 * by the integration tests (T31) that exercise a real ceremony.
 */

import type { WebAuthnCredential } from "@o3co/auth-provider-core";
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

// ---------------------------------------------------------------------------
// Mock @simplewebauthn/server before importing the module under test
// ---------------------------------------------------------------------------
vi.mock("@simplewebauthn/server", () => ({
	verifyRegistrationResponse: vi.fn(),
	verifyAuthenticationResponse: vi.fn(),
}));

import { verifyAuthenticationResponse, verifyRegistrationResponse } from "@simplewebauthn/server";
import { verifyWebAuthnAssertion, verifyWebAuthnAttestation } from "../internal/verification.mjs";

const mockVerifyRegistration = vi.mocked(verifyRegistrationResponse);
const mockVerifyAuthentication = vi.mocked(verifyAuthenticationResponse);

// ---------------------------------------------------------------------------
// Shared test stubs
// ---------------------------------------------------------------------------

/** Minimal RegistrationResponseJSON stub — the wrapped function receives this but
 *  passes it straight to SimpleWebAuthn. Its shape doesn't matter for unit tests
 *  since SimpleWebAuthn is mocked. */
const STUB_REGISTRATION_RESPONSE: RegistrationResponseJSON = {
	id: "dGVzdC1jcmVkZW50aWFsLWlk",
	rawId: "dGVzdC1jcmVkZW50aWFsLWlk",
	response: {
		clientDataJSON: "stub",
		attestationObject: "stub",
	},
	clientExtensionResults: {},
	type: "public-key",
};

/** Minimal AuthenticationResponseJSON stub */
const STUB_AUTHENTICATION_RESPONSE: AuthenticationResponseJSON = {
	id: "dGVzdC1jcmVkZW50aWFsLWlk",
	rawId: "dGVzdC1jcmVkZW50aWFsLWlk",
	response: {
		clientDataJSON: "stub",
		authenticatorData: "stub",
		signature: "stub",
	},
	clientExtensionResults: {},
	type: "public-key",
};

const STUB_PUBLIC_KEY = new Uint8Array([1, 2, 3, 4]);

/** A minimal WebAuthnCredential for assertion inputs */
function makeStoredCredential(signCount: number): WebAuthnCredential {
	return {
		userId: "user-1",
		credentialId: "dGVzdC1jcmVkZW50aWFsLWlk",
		publicKey: STUB_PUBLIC_KEY,
		signCount,
		backedUp: false,
		createdAt: new Date("2026-01-01T00:00:00Z"),
	};
}

beforeEach(() => {
	vi.clearAllMocks();
});

// ---------------------------------------------------------------------------
// verifyWebAuthnAttestation (spec §2.5)
// ---------------------------------------------------------------------------

describe("verifyWebAuthnAttestation (spec §2.5)", () => {
	it("returns origin_mismatch when SimpleWebAuthn throws an origin error", async () => {
		mockVerifyRegistration.mockRejectedValueOnce(
			new Error(
				'Unexpected registration response origin "https://evil.example", expected one of: https://example.com',
			),
		);

		const result = await verifyWebAuthnAttestation({
			response: STUB_REGISTRATION_RESPONSE,
			expectedChallenge: "some-challenge",
			expectedRpId: "example.com",
			expectedOrigins: ["https://example.com"],
		});

		expect(result).toEqual({ ok: false, reason: "origin_mismatch" });
	});

	it("returns challenge_mismatch when SimpleWebAuthn throws a challenge error", async () => {
		mockVerifyRegistration.mockRejectedValueOnce(
			new Error(
				'Unexpected registration response challenge "wrong-challenge", expected "some-challenge"',
			),
		);

		const result = await verifyWebAuthnAttestation({
			response: STUB_REGISTRATION_RESPONSE,
			expectedChallenge: "some-challenge",
			expectedRpId: "example.com",
			expectedOrigins: ["https://example.com"],
		});

		expect(result).toEqual({ ok: false, reason: "challenge_mismatch" });
	});

	it("returns rp_id_mismatch when SimpleWebAuthn throws an RP ID hash error", async () => {
		mockVerifyRegistration.mockRejectedValueOnce(new Error("Unexpected RP ID hash"));

		const result = await verifyWebAuthnAttestation({
			response: STUB_REGISTRATION_RESPONSE,
			expectedChallenge: "some-challenge",
			expectedRpId: "example.com",
			expectedOrigins: ["https://example.com"],
		});

		expect(result).toEqual({ ok: false, reason: "rp_id_mismatch" });
	});

	it("returns attestation_invalid when verified=false", async () => {
		mockVerifyRegistration.mockResolvedValueOnce({ verified: false });

		const result = await verifyWebAuthnAttestation({
			response: STUB_REGISTRATION_RESPONSE,
			expectedChallenge: "some-challenge",
			expectedRpId: "example.com",
			expectedOrigins: ["https://example.com"],
		});

		expect(result).toEqual({ ok: false, reason: "attestation_invalid" });
	});

	it("returns material on success — no userId, no createdAt, no nickname", async () => {
		mockVerifyRegistration.mockResolvedValueOnce({
			verified: true,
			registrationInfo: {
				fmt: "none",
				aaguid: "00000000-0000-0000-0000-000000000000",
				credential: {
					id: "dGVzdC1jcmVkZW50aWFsLWlk",
					publicKey: STUB_PUBLIC_KEY,
					counter: 0,
					transports: ["internal"],
				},
				credentialType: "public-key",
				attestationObject: new Uint8Array([]),
				userVerified: false,
				credentialDeviceType: "singleDevice",
				credentialBackedUp: false,
				origin: "https://example.com",
				rpID: "example.com",
			},
		});

		const result = await verifyWebAuthnAttestation({
			response: STUB_REGISTRATION_RESPONSE,
			expectedChallenge: "some-challenge",
			expectedRpId: "example.com",
			expectedOrigins: ["https://example.com"],
		});

		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error("expected ok=true");

		expect(result.material.credentialId).toBe("dGVzdC1jcmVkZW50aWFsLWlk");
		expect(result.material.publicKey).toBeInstanceOf(Uint8Array);
		expect(result.material.signCount).toBe(0);
		expect(result.material.backedUp).toBe(false);
		// Material MUST NOT include userId, createdAt, or nickname —
		// those are composed by the endpoint, not the helper.
		expect("userId" in result.material).toBe(false);
		expect("createdAt" in result.material).toBe(false);
		expect("nickname" in result.material).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// verifyWebAuthnAssertion (spec §2.5 + §2.4 sign-count)
// ---------------------------------------------------------------------------

describe("verifyWebAuthnAssertion (spec §2.5 + §2.4 sign-count)", () => {
	it("returns origin_mismatch when SimpleWebAuthn throws an origin error", async () => {
		mockVerifyAuthentication.mockRejectedValueOnce(
			new Error(
				'Unexpected authentication response origin "https://evil.example", expected one of: https://example.com',
			),
		);

		const result = await verifyWebAuthnAssertion({
			credential: makeStoredCredential(5),
			response: STUB_AUTHENTICATION_RESPONSE,
			expectedChallenge: "some-challenge",
			expectedRpId: "example.com",
			expectedOrigins: ["https://example.com"],
		});

		expect(result).toEqual({ ok: false, reason: "origin_mismatch" });
	});

	it("returns challenge_mismatch when SimpleWebAuthn throws a challenge error", async () => {
		mockVerifyAuthentication.mockRejectedValueOnce(
			new Error('Unexpected authentication response challenge "wrong", expected "some-challenge"'),
		);

		const result = await verifyWebAuthnAssertion({
			credential: makeStoredCredential(5),
			response: STUB_AUTHENTICATION_RESPONSE,
			expectedChallenge: "some-challenge",
			expectedRpId: "example.com",
			expectedOrigins: ["https://example.com"],
		});

		expect(result).toEqual({ ok: false, reason: "challenge_mismatch" });
	});

	it("returns sign_count_regression when SimpleWebAuthn throws a counter error (stored=5, new=4)", async () => {
		// SimpleWebAuthn throws when (counter > 0 || credential.counter > 0) && counter <= credential.counter
		mockVerifyAuthentication.mockRejectedValueOnce(
			new Error("Response counter value 4 was lower than expected 5"),
		);

		const result = await verifyWebAuthnAssertion({
			credential: makeStoredCredential(5),
			response: STUB_AUTHENTICATION_RESPONSE,
			expectedChallenge: "some-challenge",
			expectedRpId: "example.com",
			expectedOrigins: ["https://example.com"],
		});

		expect(result).toEqual({ ok: false, reason: "sign_count_regression" });
	});

	it("§2.4 corner case: stored=0 and new=0 → ok=true (authenticator always reports 0)", async () => {
		// SimpleWebAuthn does NOT throw when both counters are 0:
		//   (0 > 0 || 0 > 0) === false → no counter throw
		// We still need verified=true from signature check.
		mockVerifyAuthentication.mockResolvedValueOnce({
			verified: true,
			authenticationInfo: {
				newCounter: 0,
				credentialID: "dGVzdC1jcmVkZW50aWFsLWlk",
				userVerified: false,
				credentialDeviceType: "singleDevice",
				credentialBackedUp: false,
				authenticatorExtensionResults: undefined,
				origin: "https://example.com",
				rpID: "example.com",
			},
		});

		const result = await verifyWebAuthnAssertion({
			credential: makeStoredCredential(0),
			response: STUB_AUTHENTICATION_RESPONSE,
			expectedChallenge: "some-challenge",
			expectedRpId: "example.com",
			expectedOrigins: ["https://example.com"],
		});

		expect(result).toEqual({ ok: true, newSignCount: 0 });
	});

	it("success with strict counter increase (stored=5, new=10) → ok=true, newSignCount=10", async () => {
		mockVerifyAuthentication.mockResolvedValueOnce({
			verified: true,
			authenticationInfo: {
				newCounter: 10,
				credentialID: "dGVzdC1jcmVkZW50aWFsLWlk",
				userVerified: false,
				credentialDeviceType: "singleDevice",
				credentialBackedUp: false,
				authenticatorExtensionResults: undefined,
				origin: "https://example.com",
				rpID: "example.com",
			},
		});

		const result = await verifyWebAuthnAssertion({
			credential: makeStoredCredential(5),
			response: STUB_AUTHENTICATION_RESPONSE,
			expectedChallenge: "some-challenge",
			expectedRpId: "example.com",
			expectedOrigins: ["https://example.com"],
		});

		expect(result).toEqual({ ok: true, newSignCount: 10 });
	});

	it("returns signature_invalid when verified=false", async () => {
		mockVerifyAuthentication.mockResolvedValueOnce({
			verified: false,
			authenticationInfo: {
				newCounter: 6,
				credentialID: "dGVzdC1jcmVkZW50aWFsLWlk",
				userVerified: false,
				credentialDeviceType: "singleDevice",
				credentialBackedUp: false,
				authenticatorExtensionResults: undefined,
				origin: "https://example.com",
				rpID: "example.com",
			},
		});

		const result = await verifyWebAuthnAssertion({
			credential: makeStoredCredential(5),
			response: STUB_AUTHENTICATION_RESPONSE,
			expectedChallenge: "some-challenge",
			expectedRpId: "example.com",
			expectedOrigins: ["https://example.com"],
		});

		expect(result).toEqual({ ok: false, reason: "signature_invalid" });
	});
});

// ---------------------------------------------------------------------------
// S7 multi-origin pass-through + rejection (spec §spec S7)
// ---------------------------------------------------------------------------

describe("S7 multi-origin: expectedOrigins array forwarding", () => {
	it("verifyWebAuthnAttestation forwards multi-element expectedOrigins to SimpleWebAuthn intact", async () => {
		// Verify the helper passes the full array — the mock captures args so we
		// can assert every element arrived.
		mockVerifyRegistration.mockResolvedValueOnce({
			verified: true,
			registrationInfo: {
				fmt: "none",
				aaguid: "00000000-0000-0000-0000-000000000000",
				credential: {
					id: "dGVzdC1jcmVkZW50aWFsLWlk",
					publicKey: STUB_PUBLIC_KEY,
					counter: 0,
					transports: [],
				},
				credentialType: "public-key",
				attestationObject: new Uint8Array([]),
				userVerified: false,
				credentialDeviceType: "singleDevice",
				credentialBackedUp: false,
				origin: "https://a.example",
				rpID: "example",
			},
		});

		const origins = ["https://a.example", "https://b.example"];
		await verifyWebAuthnAttestation({
			response: STUB_REGISTRATION_RESPONSE,
			expectedChallenge: "some-challenge",
			expectedRpId: "example",
			expectedOrigins: origins,
		});

		expect(mockVerifyRegistration).toHaveBeenCalledOnce();
		const [callArgs] = mockVerifyRegistration.mock.calls[0];
		// The helper must forward ALL elements of the array — not just [0].
		expect((callArgs as { expectedOrigin: string[] }).expectedOrigin).toEqual(origins);
	});

	it("verifyWebAuthnAttestation returns origin_mismatch when origin is not in multi-element expectedOrigins", async () => {
		mockVerifyRegistration.mockRejectedValueOnce(
			new Error(
				'Unexpected registration response origin "https://evil.example", expected one of: https://a.example, https://b.example',
			),
		);

		const result = await verifyWebAuthnAttestation({
			response: STUB_REGISTRATION_RESPONSE,
			expectedChallenge: "some-challenge",
			expectedRpId: "example",
			expectedOrigins: ["https://a.example", "https://b.example"],
		});

		expect(result).toEqual({ ok: false, reason: "origin_mismatch" });
	});

	it("verifyWebAuthnAssertion forwards multi-element expectedOrigins to SimpleWebAuthn intact", async () => {
		mockVerifyAuthentication.mockResolvedValueOnce({
			verified: true,
			authenticationInfo: {
				newCounter: 6,
				credentialID: "dGVzdC1jcmVkZW50aWFsLWlk",
				userVerified: false,
				credentialDeviceType: "singleDevice",
				credentialBackedUp: false,
				authenticatorExtensionResults: undefined,
				origin: "https://a.example",
				rpID: "example",
			},
		});

		const origins = ["https://a.example", "https://b.example"];
		await verifyWebAuthnAssertion({
			credential: makeStoredCredential(5),
			response: STUB_AUTHENTICATION_RESPONSE,
			expectedChallenge: "some-challenge",
			expectedRpId: "example",
			expectedOrigins: origins,
		});

		expect(mockVerifyAuthentication).toHaveBeenCalledOnce();
		const [callArgs] = mockVerifyAuthentication.mock.calls[0];
		expect((callArgs as { expectedOrigin: string[] }).expectedOrigin).toEqual(origins);
	});

	it("verifyWebAuthnAssertion returns origin_mismatch when origin is not in multi-element expectedOrigins", async () => {
		mockVerifyAuthentication.mockRejectedValueOnce(
			new Error(
				'Unexpected authentication response origin "https://evil.example", expected one of: https://a.example, https://b.example',
			),
		);

		const result = await verifyWebAuthnAssertion({
			credential: makeStoredCredential(5),
			response: STUB_AUTHENTICATION_RESPONSE,
			expectedChallenge: "some-challenge",
			expectedRpId: "example",
			expectedOrigins: ["https://a.example", "https://b.example"],
		});

		expect(result).toEqual({ ok: false, reason: "origin_mismatch" });
	});
});
