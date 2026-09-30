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
 * Tests for verifyWebAuthnAttestation + verifyWebAuthnAssertion, with
 * @simplewebauthn/server mocked: the library ships no fixtures, and a valid
 * attestation needs raw CBOR, COSE key encoding, authenticatorData and a real
 * signature.
 *
 * The helpers are thin wrappers, and all they add runs against mocked
 * responses and throws:
 *   1. the library's own messages (algorithm/top-origin/origin/challenge/rp_id)
 *      mapped to the typed reason union by their prefixes, never by text the
 *      client wrote into them
 *   2. material reshaped to credentialId / publicKey / signCount / transports /
 *      backedUp, and the backup flags beside it for the caller that asks
 *   3. the sign count, judged here after the signature verified — the library
 *      is handed a stored count of 0 — with the corner case stored=0 && new=0
 *      allowed
 *   4. the user handle a response carries, held to the one the caller
 *      expects, once the signature verified
 *
 * The real cryptographic path is covered by the library's own suite and by the
 * integration tests that run a real ceremony.
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
import {
	verifyWebAuthnAssertion,
	verifyWebAuthnAssertionWithBackupState,
	verifyWebAuthnAttestation,
	verifyWebAuthnAttestationWithBackupState,
} from "../internal/verification.mjs";

const mockVerifyRegistration = vi.mocked(verifyRegistrationResponse);
const mockVerifyAuthentication = vi.mocked(verifyAuthenticationResponse);

// ---------------------------------------------------------------------------
// Shared test stubs
// ---------------------------------------------------------------------------

/** Minimal RegistrationResponseJSON stub — the wrapped function passes it to SimpleWebAuthn,
 *  mocked here, and reads its client data's top origin; that is a same-origin browser's. */
const STUB_REGISTRATION_RESPONSE: RegistrationResponseJSON = {
	id: "dGVzdC1jcmVkZW50aWFsLWlk",
	rawId: "dGVzdC1jcmVkZW50aWFsLWlk",
	response: {
		clientDataJSON: Buffer.from(
			JSON.stringify({
				type: "webauthn.create",
				challenge: "some-challenge",
				origin: "https://example.com",
				crossOrigin: false,
			}),
		).toString("base64url"),
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
// verifyWebAuthnAttestation
// ---------------------------------------------------------------------------

describe("verifyWebAuthnAttestation", () => {
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

	it("returns algorithm_not_allowed, rather than unknown, when the credential's algorithm is outside the pin", async () => {
		// `WEBAUTHN_ALGORITHM_IDS` refuses e.g. ML-DSA-44 (-48). The refusal is
		// this package's choice, so it gets its own reason, not `unknown`.
		mockVerifyRegistration.mockRejectedValueOnce(
			new Error('Unexpected public key alg "-48", expected one of "-8,-7,-257"'),
		);
		const result = await verifyWebAuthnAttestation({
			response: STUB_REGISTRATION_RESPONSE,
			expectedChallenge: "some-challenge",
			expectedRpId: "example.com",
			expectedOrigins: ["https://example.com"],
		});
		expect(result).toEqual({ ok: false, reason: "algorithm_not_allowed" });
	});

	it.each([
		'Unexpected registration response type "origin", expected "webauthn.create"',
		'Unexpected registration response type "challenge", expected "webauthn.create"',
		'Unexpected registration response type "public key alg", expected "webauthn.create"',
		'Unexpected registration response type "rp id", expected "webauthn.create"',
	])(
		"maps a refusal by the library's own message, never by text the client wrote into it: %s",
		async (message) => {
			mockVerifyRegistration.mockRejectedValueOnce(new Error(message));

			const result = await verifyWebAuthnAttestation({
				response: STUB_REGISTRATION_RESPONSE,
				expectedChallenge: "some-challenge",
				expectedRpId: "example.com",
				expectedOrigins: ["https://example.com"],
			});

			expect(result).toEqual({ ok: false, reason: "unknown" });
		},
	);

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

	it("passes SimpleWebAuthn only the pinned algorithms, -8, -7 and -257", async () => {
		// The options test pins what is advertised; this pins what is accepted.
		// Without both, dropping this argument would let SimpleWebAuthn's
		// runtime-dependent default accept an ML-DSA credential the offer never
		// made — which is the drift the explicit set exists to prevent.
		mockVerifyRegistration.mockResolvedValueOnce({ verified: false });

		await verifyWebAuthnAttestation({
			response: STUB_REGISTRATION_RESPONSE,
			expectedChallenge: "some-challenge",
			expectedRpId: "example.com",
			expectedOrigins: ["https://example.com"],
		});

		expect(mockVerifyRegistration).toHaveBeenCalledWith(
			expect.objectContaining({ supportedAlgorithmIDs: [-8, -7, -257] }),
		);
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
// verifyWebAuthnAssertion (incl. the sign-count rule)
// ---------------------------------------------------------------------------

describe("verifyWebAuthnAssertion", () => {
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

	it("hands the library a stored count of 0, so the library never judges the count", async () => {
		// The library compares the count before it checks the signature: judged
		// there, an unsigned assertion could report a regression.
		mockVerifyAuthentication.mockResolvedValueOnce({
			verified: true,
			authenticationInfo: { newCounter: 6, credentialBackedUp: false } as never,
		} as never);

		await verifyWebAuthnAssertion({
			credential: makeStoredCredential(5),
			response: STUB_AUTHENTICATION_RESPONSE,
			expectedChallenge: "some-challenge",
			expectedRpId: "example.com",
			expectedOrigins: ["https://example.com"],
		});

		expect(mockVerifyAuthentication.mock.calls[0]?.[0].credential.counter).toBe(0);
	});

	it("reads a counter refusal thrown by the library as unknown, never as a regression", async () => {
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

		expect(result).toEqual({ ok: false, reason: "unknown" });
	});

	it("refuses a count that did not increase over the stored one, once the signature verified, as sign_count_regression", async () => {
		mockVerifyAuthentication.mockResolvedValueOnce({
			verified: true,
			authenticationInfo: { newCounter: 4, credentialBackedUp: false } as never,
		} as never);

		const result = await verifyWebAuthnAssertion({
			credential: makeStoredCredential(5),
			response: STUB_AUTHENTICATION_RESPONSE,
			expectedChallenge: "some-challenge",
			expectedRpId: "example.com",
			expectedOrigins: ["https://example.com"],
		});

		expect(result).toEqual({ ok: false, reason: "sign_count_regression" });
	});

	it("does not judge the count of an assertion whose signature did not verify", async () => {
		mockVerifyAuthentication.mockResolvedValueOnce({
			verified: false,
			authenticationInfo: { newCounter: 0, credentialBackedUp: false } as never,
		} as never);

		const result = await verifyWebAuthnAssertion({
			credential: makeStoredCredential(5),
			response: STUB_AUTHENTICATION_RESPONSE,
			expectedChallenge: "some-challenge",
			expectedRpId: "example.com",
			expectedOrigins: ["https://example.com"],
		});

		expect(result).toEqual({ ok: false, reason: "signature_invalid" });
	});

	it.each([
		'Unexpected authentication response type "counter", expected "webauthn.get"',
		'Unexpected authentication response type "origin", expected "webauthn.get"',
		'Unexpected authentication response type "challenge", expected "webauthn.get"',
		'Unexpected authentication response type "rp id", expected "webauthn.get"',
		'Unexpected authentication response type "top origin", expected "webauthn.get"',
	])(
		"maps a refusal by the library's own message, never by text the client wrote into it: %s",
		async (message) => {
			mockVerifyAuthentication.mockRejectedValueOnce(new Error(message));

			const result = await verifyWebAuthnAssertion({
				credential: makeStoredCredential(5),
				response: STUB_AUTHENTICATION_RESPONSE,
				expectedChallenge: "some-challenge",
				expectedRpId: "example.com",
				expectedOrigins: ["https://example.com"],
			});

			expect(result).toEqual({ ok: false, reason: "unknown" });
		},
	);

	it("maps the library's RP ID refusal", async () => {
		mockVerifyAuthentication.mockRejectedValueOnce(new Error("Unexpected RP ID hash"));

		const result = await verifyWebAuthnAssertion({
			credential: makeStoredCredential(5),
			response: STUB_AUTHENTICATION_RESPONSE,
			expectedChallenge: "some-challenge",
			expectedRpId: "example.com",
			expectedOrigins: ["https://example.com"],
		});

		expect(result).toEqual({ ok: false, reason: "rp_id_mismatch" });
	});

	it("sign-count corner case: stored=0 and new=0 → ok=true (an authenticator that always reports 0)", async () => {
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
// The response's user handle (WebAuthn §7.2 step 6)
// ---------------------------------------------------------------------------

describe("the user handle an assertion carries", () => {
	beforeEach(() => vi.clearAllMocks());

	/** The owner's user handle: bytes whose base64url is not a multiple of four characters. */
	const OWNER = new TextEncoder().encode("user-alice");
	const OWNER_JSON = Buffer.from(OWNER).toString("base64url");
	/** Another account's user handle, as the JSON form writes it. */
	const OTHER_JSON = Buffer.from("user-mallory").toString("base64url");

	/** An owner's user handle whose base64url uses both characters the base64 alphabet writes otherwise. */
	const URL_SAFE_OWNER = new Uint8Array(Buffer.from("u-_owner", "base64url"));

	/** A verified assertion as the library answers one, its counter `newCounter` (increased unless given). */
	const verified = (newCounter = 6) =>
		mockVerifyAuthentication.mockResolvedValueOnce({
			verified: true,
			authenticationInfo: {
				newCounter,
				credentialID: "dGVzdC1jcmVkZW50aWFsLWlk",
				userVerified: true,
				credentialDeviceType: "singleDevice",
				credentialBackedUp: false,
				authenticatorExtensionResults: undefined,
				origin: "https://example.com",
				rpID: "example.com",
			},
		});

	/**
	 * An input whose response carries `userHandle` as given (a `null` included), expecting the
	 * owner's handle unless told otherwise; `null` expects none.
	 */
	const input = (
		userHandle: unknown,
		expectedUserHandle: Uint8Array | null = OWNER,
	): Parameters<typeof verifyWebAuthnAssertion>[0] => ({
		credential: makeStoredCredential(5),
		response: {
			...STUB_AUTHENTICATION_RESPONSE,
			response: {
				...STUB_AUTHENTICATION_RESPONSE.response,
				...(userHandle === undefined ? {} : { userHandle: userHandle as string }),
			},
		},
		expectedChallenge: "some-challenge",
		expectedRpId: "example.com",
		expectedOrigins: ["https://example.com"],
		...(expectedUserHandle === null ? {} : { expectedUserHandle }),
	});

	it.each([
		["another account's", OTHER_JSON],
		["an empty one", ""],
		["the owner's, padded", `${OWNER_JSON}==`],
		[
			"the owner's as raw text, as a client before @simplewebauthn/browser v10 answers it",
			"user-alice",
		],
	])("refuses %s as user_handle_mismatch", async (_what, userHandle) => {
		verified();
		expect(await verifyWebAuthnAssertion(input(userHandle))).toEqual({
			ok: false,
			reason: "user_handle_mismatch",
		});
	});

	it.each([
		["the owner's", OWNER_JSON],
		["none", undefined],
		["null, which is none", null],
	])("accepts %s", async (_what, userHandle) => {
		verified();
		expect(await verifyWebAuthnAssertion(input(userHandle))).toEqual({
			ok: true,
			newSignCount: 6,
		});
	});

	it("refuses another's with the backup flags asked for too", async () => {
		verified();
		expect(await verifyWebAuthnAssertionWithBackupState(input(OTHER_JSON))).toEqual({
			ok: false,
			reason: "user_handle_mismatch",
		});
	});

	it("refuses the owner's written in the standard base64 alphabet, and accepts it in the URL-safe one", async () => {
		const standard = Buffer.from(URL_SAFE_OWNER).toString("base64");
		expect(standard).toBe("u+/owner");
		verified();
		expect(await verifyWebAuthnAssertion(input(standard, URL_SAFE_OWNER))).toEqual({
			ok: false,
			reason: "user_handle_mismatch",
		});
		verified();
		expect(await verifyWebAuthnAssertion(input("u-_owner", URL_SAFE_OWNER))).toEqual({
			ok: true,
			newSignCount: 6,
		});
	});

	it("judges it before the count: another's with a counter that did not increase is user_handle_mismatch", async () => {
		verified(5);
		expect(await verifyWebAuthnAssertion(input(OTHER_JSON))).toEqual({
			ok: false,
			reason: "user_handle_mismatch",
		});
	});

	it("does not read it when the caller expects none", async () => {
		verified();
		expect(await verifyWebAuthnAssertion(input(OTHER_JSON, null))).toEqual({
			ok: true,
			newSignCount: 6,
		});
	});

	it("judges it only once the signature verified: an unsigned assertion carrying another's is signature_invalid", async () => {
		mockVerifyAuthentication.mockResolvedValueOnce({ verified: false } as never);
		expect(await verifyWebAuthnAssertion(input(OTHER_JSON))).toEqual({
			ok: false,
			reason: "signature_invalid",
		});
	});
});

// ---------------------------------------------------------------------------
// Multi-origin pass-through + rejection
// ---------------------------------------------------------------------------

describe("multi-origin: expectedOrigins array forwarding", () => {
	it("verifyWebAuthnAttestation forwards multi-element expectedOrigins to SimpleWebAuthn intact", async () => {
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

// ---------------------------------------------------------------------------
// userVerification enforcement
// ---------------------------------------------------------------------------

describe("userVerification enforcement", () => {
	beforeEach(() => {
		vi.clearAllMocks();
	});

	it("passes requireUserVerification=true to SimpleWebAuthn when userVerification='required' (attestation)", async () => {
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
				userVerified: true,
				credentialDeviceType: "singleDevice",
				credentialBackedUp: false,
				origin: "https://example.com",
				rpID: "example.com",
			},
		});

		await verifyWebAuthnAttestation({
			response: STUB_REGISTRATION_RESPONSE,
			expectedChallenge: "c",
			expectedRpId: "example.com",
			expectedOrigins: ["https://example.com"],
			userVerification: "required",
		});

		expect(mockVerifyRegistration).toHaveBeenCalledOnce();
		const [callArgs] = mockVerifyRegistration.mock.calls[0];
		expect((callArgs as Record<string, unknown>).requireUserVerification).toBe(true);
	});

	it("passes requireUserVerification=false to SimpleWebAuthn when userVerification='preferred' (attestation)", async () => {
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
				origin: "https://example.com",
				rpID: "example.com",
			},
		});

		await verifyWebAuthnAttestation({
			response: STUB_REGISTRATION_RESPONSE,
			expectedChallenge: "c",
			expectedRpId: "example.com",
			expectedOrigins: ["https://example.com"],
			userVerification: "preferred",
		});

		expect(mockVerifyRegistration).toHaveBeenCalledOnce();
		const [callArgs] = mockVerifyRegistration.mock.calls[0];
		expect((callArgs as Record<string, unknown>).requireUserVerification).toBe(false);
	});

	it("passes requireUserVerification=true to SimpleWebAuthn when userVerification='required' (assertion)", async () => {
		mockVerifyAuthentication.mockResolvedValueOnce({
			verified: true,
			authenticationInfo: {
				newCounter: 6,
				credentialID: "dGVzdC1jcmVkZW50aWFsLWlk",
				userVerified: true,
				credentialDeviceType: "singleDevice",
				credentialBackedUp: false,
				authenticatorExtensionResults: undefined,
				origin: "https://example.com",
				rpID: "example.com",
			},
		});

		await verifyWebAuthnAssertion({
			credential: makeStoredCredential(5),
			response: STUB_AUTHENTICATION_RESPONSE,
			expectedChallenge: "c",
			expectedRpId: "example.com",
			expectedOrigins: ["https://example.com"],
			userVerification: "required",
		});

		expect(mockVerifyAuthentication).toHaveBeenCalledOnce();
		const [callArgs] = mockVerifyAuthentication.mock.calls[0];
		expect((callArgs as Record<string, unknown>).requireUserVerification).toBe(true);
	});

	it("passes requireUserVerification=false to SimpleWebAuthn when userVerification='preferred' (assertion)", async () => {
		mockVerifyAuthentication.mockResolvedValueOnce({
			verified: true,
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

		await verifyWebAuthnAssertion({
			credential: makeStoredCredential(5),
			response: STUB_AUTHENTICATION_RESPONSE,
			expectedChallenge: "c",
			expectedRpId: "example.com",
			expectedOrigins: ["https://example.com"],
			userVerification: "preferred",
		});

		expect(mockVerifyAuthentication).toHaveBeenCalledOnce();
		const [callArgs] = mockVerifyAuthentication.mock.calls[0];
		expect((callArgs as Record<string, unknown>).requireUserVerification).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// Stored public key is copied at the SimpleWebAuthn boundary
// ---------------------------------------------------------------------------

describe("stored publicKey is copied before it reaches SimpleWebAuthn", () => {
	/**
	 * Builds a credential whose publicKey is a fresh array owned by this test,
	 * so a missing copy shows up here rather than as cross-test pollution of
	 * the shared STUB_PUBLIC_KEY.
	 */
	function makeOwnedCredential(): WebAuthnCredential {
		return { ...makeStoredCredential(5), publicKey: new Uint8Array([1, 2, 3, 4]) };
	}

	function mockVerifiedOnce(): void {
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
	}

	it("forwards equal bytes on a plain-ArrayBuffer-backed copy, not the stored array", async () => {
		mockVerifiedOnce();
		const stored = makeOwnedCredential();

		await verifyWebAuthnAssertion({
			credential: stored,
			response: STUB_AUTHENTICATION_RESPONSE,
			expectedChallenge: "some-challenge",
			expectedRpId: "example.com",
			expectedOrigins: ["https://example.com"],
		});

		expect(mockVerifyAuthentication).toHaveBeenCalledOnce();
		const [callArgs] = mockVerifyAuthentication.mock.calls[0];
		const forwarded = callArgs.credential.publicKey;

		// Same bytes...
		expect(Array.from(forwarded)).toEqual([1, 2, 3, 4]);
		// ...on a different array, over a different, non-shared buffer.
		// `@simplewebauthn/server` >= 13.3.2 requires a plain ArrayBuffer backing.
		expect(forwarded).not.toBe(stored.publicKey);
		expect(forwarded.buffer).not.toBe(stored.publicKey.buffer);
		expect(forwarded.buffer).toBeInstanceOf(ArrayBuffer);
	});

	it("mutation of the forwarded array cannot corrupt the stored credential", async () => {
		mockVerifiedOnce();
		const stored = makeOwnedCredential();

		await verifyWebAuthnAssertion({
			credential: stored,
			response: STUB_AUTHENTICATION_RESPONSE,
			expectedChallenge: "some-challenge",
			expectedRpId: "example.com",
			expectedOrigins: ["https://example.com"],
		});

		const [callArgs] = mockVerifyAuthentication.mock.calls[0];
		// Stand-in for a third party writing through the reference it was handed.
		// The store contract documents these bytes as logically immutable, and the
		// in-process adapter returns its own stored array by reference.
		callArgs.credential.publicKey[0] = 99;

		expect(Array.from(stored.publicKey)).toEqual([1, 2, 3, 4]);
	});
});

describe("cross-origin authentication is the deployment's decision", () => {
	const baseAssertionInput = () => ({
		credential: makeStoredCredential(5),
		response: STUB_AUTHENTICATION_RESPONSE,
		expectedChallenge: "some-challenge",
		expectedRpId: "example.com",
		expectedOrigins: ["https://example.com"],
	});

	it("passes the configured top origins to the library", async () => {
		// SimpleWebAuthn 14 refuses a cross-origin (iframe) authentication
		// whose `topOrigin` the browser reports unless `expectedTopOrigin` is
		// given. The configured top origins are how an operator allows one.
		mockVerifyAuthentication.mockResolvedValueOnce({
			verified: true,
			authenticationInfo: { newCounter: 1 },
		} as never);

		await verifyWebAuthnAssertion({
			...baseAssertionInput(),
			expectedTopOrigins: ["https://embedder.example"],
		});

		expect(mockVerifyAuthentication).toHaveBeenCalledWith(
			expect.objectContaining({ expectedTopOrigin: ["https://embedder.example"] }),
		);
	});

	it("passes none when the deployment configured none", async () => {
		// Absent, the library keeps its own default — refusing a reported
		// cross-origin response — which is the right default for a deployment
		// that never meant to be framed.
		mockVerifyAuthentication.mockResolvedValueOnce({
			verified: true,
			authenticationInfo: { newCounter: 1 },
		} as never);

		await verifyWebAuthnAssertion(baseAssertionInput());

		expect(mockVerifyAuthentication).toHaveBeenCalledWith(
			expect.not.objectContaining({ expectedTopOrigin: expect.anything() }),
		);
	});

	it("reports a refused cross-origin response as its own reason, not an origin mismatch", async () => {
		// The library's message carries the word "origin", but `origin_mismatch`
		// would send the operator to their `webauthn.origin` allowlist, which
		// cannot fix it.
		mockVerifyAuthentication.mockRejectedValueOnce(
			new Error(
				'Detected cross-origin authentication response from top origin of "https://embedder.example", but a value for `expectedTopOrigin` was not specified when calling `verifyAuthenticationResponse()`',
			),
		);
		expect(await verifyWebAuthnAssertion(baseAssertionInput())).toEqual({
			ok: false,
			reason: "top_origin_mismatch",
		});

		mockVerifyAuthentication.mockRejectedValueOnce(
			new Error(
				'Unexpected cross-origin authentication response top origin of "https://elsewhere.example", expected: https://embedder.example',
			),
		);
		expect(
			await verifyWebAuthnAssertion({
				...baseAssertionInput(),
				expectedTopOrigins: ["https://embedder.example"],
			}),
		).toEqual({ ok: false, reason: "top_origin_mismatch" });
	});

	it("still reports a plain origin mismatch as one", async () => {
		mockVerifyAuthentication.mockRejectedValueOnce(
			new Error('Unexpected authentication response origin "https://evil.example"'),
		);
		expect(await verifyWebAuthnAssertion(baseAssertionInput())).toEqual({
			ok: false,
			reason: "origin_mismatch",
		});
	});
});

describe("verifyWebAuthnAssertionWithBackupState", () => {
	/**
	 * A verified assertion as the library answers one: its counter, and its
	 * backup eligibility (BE, as the device type) and backup state (BS).
	 */
	const verified = (
		newCounter: number,
		credentialBackedUp: boolean,
		backupEligible: boolean = credentialBackedUp,
	) =>
		mockVerifyAuthentication.mockResolvedValueOnce({
			verified: true,
			authenticationInfo: {
				newCounter,
				credentialID: "dGVzdC1jcmVkZW50aWFsLWlk",
				userVerified: true,
				credentialDeviceType: backupEligible ? "multiDevice" : "singleDevice",
				credentialBackedUp,
				authenticatorExtensionResults: undefined,
				origin: "https://example.com",
				rpID: "example.com",
			},
		});

	/** An input whose credential carries its id, key, count and transports alone. */
	const input = (signCount: number) => ({
		credential: {
			credentialId: "dGVzdC1jcmVkZW50aWFsLWlk",
			publicKey: STUB_PUBLIC_KEY,
			signCount,
			transports: ["usb"] as const,
		},
		response: STUB_AUTHENTICATION_RESPONSE,
		expectedChallenge: "some-challenge",
		expectedRpId: "example.com",
		expectedOrigins: ["https://example.com"],
	});

	it.each([
		[false, false],
		[true, false],
		[true, true],
	])(
		"answers the new count, and the backup eligibility (%s) and backup state (%s) the verified authenticator data carries",
		async (backupEligible, backedUp) => {
			verified(8, backedUp, backupEligible);
			expect(await verifyWebAuthnAssertionWithBackupState(input(5))).toEqual({
				ok: true,
				newSignCount: 8,
				backupEligible,
				backedUp,
			});
		},
	);

	it("accepts a count of 0 against a stored 0, the authenticator that keeps no counter", async () => {
		verified(0, false);
		expect(await verifyWebAuthnAssertionWithBackupState(input(0))).toEqual({
			ok: true,
			newSignCount: 0,
			backupEligible: false,
			backedUp: false,
		});
	});

	it("refuses a count that did not increase over the stored one, once the signature verified, as sign_count_regression", async () => {
		verified(5, false);
		expect(await verifyWebAuthnAssertionWithBackupState(input(5))).toEqual({
			ok: false,
			reason: "sign_count_regression",
		});
		expect(mockVerifyAuthentication.mock.calls[0]?.[0].credential.counter).toBe(0);
	});

	it("maps the library's refusals as verifyWebAuthnAssertion does", async () => {
		mockVerifyAuthentication.mockRejectedValueOnce(
			new Error('Unexpected authentication response challenge "x", expected "y"'),
		);
		expect(await verifyWebAuthnAssertionWithBackupState(input(0))).toEqual({
			ok: false,
			reason: "challenge_mismatch",
		});
	});

	it("leaves verifyWebAuthnAssertion's answer as it is: the new count alone", async () => {
		verified(9, true);
		expect(await verifyWebAuthnAssertion(makeStoredCredentialInput(3))).toEqual({
			ok: true,
			newSignCount: 9,
		});
	});
});

/** verifyWebAuthnAssertion's input over a stored credential at `signCount`. */
function makeStoredCredentialInput(signCount: number) {
	return {
		credential: makeStoredCredential(signCount),
		response: STUB_AUTHENTICATION_RESPONSE,
		expectedChallenge: "some-challenge",
		expectedRpId: "example.com",
		expectedOrigins: ["https://example.com"],
	};
}

describe("verifyWebAuthnAttestationWithBackupState", () => {
	const registered = (credentialDeviceType: "singleDevice" | "multiDevice", backedUp: boolean) =>
		mockVerifyRegistration.mockResolvedValueOnce({
			verified: true,
			registrationInfo: {
				fmt: "none",
				aaguid: "00000000-0000-0000-0000-000000000000",
				credential: {
					id: "dGVzdC1jcmVkZW50aWFsLWlk",
					publicKey: STUB_PUBLIC_KEY,
					counter: 0,
					transports: ["usb"],
				},
				credentialType: "public-key",
				attestationObject: new Uint8Array([]),
				userVerified: true,
				credentialDeviceType,
				credentialBackedUp: backedUp,
				origin: "https://example.com",
				rpID: "example.com",
			},
		} as never);

	const input = {
		response: STUB_REGISTRATION_RESPONSE,
		expectedChallenge: "some-challenge",
		expectedRpId: "example.com",
		expectedOrigins: ["https://example.com"],
	};

	it.each([
		["singleDevice", false, false],
		["multiDevice", true, false],
		["multiDevice", true, true],
	] as const)(
		"answers the material with the backup eligibility the device type says (%s: %s) and the backup state (%s)",
		async (deviceType, backupEligible, backedUp) => {
			registered(deviceType, backedUp);
			const result = await verifyWebAuthnAttestationWithBackupState(input);
			expect(result).toMatchObject({ ok: true, material: { backedUp, backupEligible } });
		},
	);

	it("leaves verifyWebAuthnAttestation's material as it is", async () => {
		registered("multiDevice", true);
		const result = await verifyWebAuthnAttestation(input);
		expect(result.ok && Object.keys(result.material).sort()).toEqual([
			"backedUp",
			"credentialId",
			"publicKey",
			"signCount",
			"transports",
		]);
	});

	it("maps the library's refusals as verifyWebAuthnAttestation does", async () => {
		mockVerifyRegistration.mockRejectedValueOnce(new Error("Unexpected RP ID hash"));
		expect(await verifyWebAuthnAttestationWithBackupState(input)).toEqual({
			ok: false,
			reason: "rp_id_mismatch",
		});
	});
});
