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
 * The `webauthn` second factor, as core's `MfaFactor` contract states it,
 * with verification mocked at `#/internal/verification.mjs`, as the grant's
 * tests mock it. See the MFA ADR's D4, D14, D21 and F7.
 *
 * Registration asks for a credential under the subject's WebAuthn user
 * handle, excluding the credentials the subject holds, with a resident key
 * discouraged; completion verifies the attestation and keeps what an
 * assertion needs. An assertion's challenge lists every WebAuthn factor of
 * the subject; a verification finds the credential by its id among them and
 * answers its new sign count and backup state as the factor's next data.
 */

import {
	HARDWARE_KEY_AMR,
	type MfaCeremonyContext,
	type MfaEnrolledFactor,
	type MfaFactor,
	type MfaFactorData,
	SOFTWARE_KEY_AMR,
} from "@o3co/auth-provider-core";
import { createTestMfaDigests } from "@o3co/auth-provider-core/testing";
import { mfaFactorContract } from "@o3co/auth-provider-test-kit";
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("#/internal/verification.mjs", () => ({
	verifyWebAuthnAttestation: vi.fn(),
	verifyWebAuthnAssertion: vi.fn(),
	verifyWebAuthnAssertionWithBackupState: vi.fn(),
}));

import { WEBAUTHN_ALGORITHM_IDS } from "#/internal/options.mjs";
import {
	verifyWebAuthnAssertionWithBackupState,
	verifyWebAuthnAttestation,
} from "#/internal/verification.mjs";
import { createWebAuthnMfaFactor, WEBAUTHN_MFA_FACTOR_KIND } from "#/mfaFactor/factor.mjs";
import { createTestWebAuthnConfig } from "#/testing/index.mjs";

const mockAttestation = vi.mocked(verifyWebAuthnAttestation);
const mockAssertion = vi.mocked(verifyWebAuthnAssertionWithBackupState);

beforeEach(() => {
	vi.clearAllMocks();
});

const RELYING_PARTY = createTestWebAuthnConfig({
	topOrigin: ["https://embedder.test.example"],
	// Not the factor's: the factor asks for no attestation and its own user verification.
	attestationPreference: "direct",
	userVerification: "discouraged",
});

const factorWith = (userVerification: "required" | "preferred" | "discouraged" = "required") =>
	createWebAuthnMfaFactor({ relyingParty: RELYING_PARTY, userVerification });

const NOW_MS = Date.UTC(2026, 8, 30, 12);
const USER = { id: "u-alice", username: "alice", email: "alice@example.com" };

const ceremony = (overrides: Partial<MfaCeremonyContext> = {}): MfaCeremonyContext => ({
	subject: USER.id,
	transactionId: "tx-1",
	nowMs: NOW_MS,
	request: { ip: "192.0.2.1", userAgent: "test" },
	digests: createTestMfaDigests(WEBAUTHN_MFA_FACTOR_KIND),
	...overrides,
});

const b64url = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64url");

const HANDLE = b64url(new Uint8Array(32).fill(7));
const PUBLIC_KEY = new Uint8Array([165, 1, 2, 3, 38]);

/** A WebAuthn factor's data, as an enrollment leaves it. */
const dataOf = (overrides: Record<string, unknown> = {}): MfaFactorData => ({
	credentialId: "Y3JlZC1h",
	publicKey: b64url(PUBLIC_KEY),
	signCount: 5,
	transports: ["usb"],
	backedUp: false,
	userHandle: HANDLE,
	...overrides,
});

const enrolled = (id: string, data: MfaFactorData): MfaEnrolledFactor => ({
	id,
	label: undefined,
	createdAt: new Date(NOW_MS - 86_400_000),
	lastUsedAt: undefined,
	data,
});

const A = enrolled("factor-a", dataOf());
const B = enrolled(
	"factor-b",
	dataOf({ credentialId: "Y3JlZC1i", transports: ["internal", "hybrid"], signCount: 0 }),
);

/** What `factor`'s challenge answers for `named` among `factors`. */
function challengeOf(factor: MfaFactor, named: MfaEnrolledFactor, factors: MfaEnrolledFactor[]) {
	if (factor.challenge === undefined) throw new Error("the factor has no challenge");
	return factor.challenge({ ...ceremony(), factor: named, factors });
}

/** A registration response as a client sends it; its shape alone matters here. */
const registration = (overrides: Record<string, unknown> = {}): RegistrationResponseJSON =>
	({
		id: "bmV3LWNyZWQ",
		rawId: "bmV3LWNyZWQ",
		type: "public-key",
		response: { clientDataJSON: "Y2Q", attestationObject: "YW8", transports: ["usb"] },
		clientExtensionResults: {},
		...overrides,
	}) as RegistrationResponseJSON;

/** An assertion as a client sends it, by the credential `id`; its shape alone matters here. */
const assertion = (
	id: string,
	overrides: Record<string, unknown> = {},
): AuthenticationResponseJSON =>
	({
		id,
		rawId: id,
		type: "public-key",
		response: { clientDataJSON: "Y2Q", authenticatorData: "YWQ", signature: "c2ln" },
		clientExtensionResults: {},
		...overrides,
	}) as AuthenticationResponseJSON;

/** An attestation the library verified, of `credentialId`. */
const attested = (credentialId = "bmV3LWNyZWQ", backedUp = false) =>
	mockAttestation.mockResolvedValueOnce({
		ok: true,
		material: {
			credentialId,
			publicKey: new Uint8Array(PUBLIC_KEY),
			signCount: 0,
			transports: ["usb", "nfc"],
			backedUp,
		},
	});

describe("the webauthn factor's contract values", () => {
	it("is kind webauthn: counting, adding mfa, not guessable, its challenge taken by a verification", () => {
		const factor = factorWith();
		expect(factor.kind).toBe("webauthn");
		expect(factor.counting).toBe(true);
		expect(factor.addsMfa).toBe(true);
		expect(factor.guessable).toBe(false);
		expect(factor.reusableChallenge).toBeUndefined();
		expect(factor.enrollable).toBeUndefined();
	});

	it("may add hwk or swk", () => {
		expect(factorWith().amrValues).toEqual([HARDWARE_KEY_AMR, SOFTWARE_KEY_AMR]);
	});

	it("adds hwk for a credential whose backup state is clear, and swk for one backed up", () => {
		const factor = factorWith();
		expect(factor.amrFor(dataOf({ backedUp: false }))).toEqual([HARDWARE_KEY_AMR]);
		expect(factor.amrFor(dataOf({ backedUp: true }))).toEqual([SOFTWARE_KEY_AMR]);
	});

	it("describes a factor with no hint", () => {
		expect(factorWith().describe(dataOf())).toEqual({});
	});

	it("throws for data that is not a WebAuthn factor's, naming the field and quoting nothing", () => {
		const factor = factorWith();
		for (const [data, field] of [
			[dataOf({ backedUp: "no" }), "backedUp"],
			[dataOf({ signCount: -1 }), "signCount"],
			[dataOf({ credentialId: "" }), "credentialId"],
			[dataOf({ publicKey: "not base64url!" }), "publicKey"],
			[dataOf({ userHandle: undefined }), "userHandle"],
			[dataOf({ transports: "usb" }), "transports"],
		] as const) {
			expect(() => factor.amrFor(data), field).toThrow(new RegExp(field));
		}
		try {
			factor.amrFor(dataOf({ credentialId: "", publicKey: "secret-looking" }));
		} catch (err) {
			expect(String(err)).not.toContain("secret-looking");
		}
	});
});

describe("registration", () => {
	it("asks for a credential under a new 32-byte user handle, named by the account's email, with a resident key discouraged, no attestation, the package's algorithms and the section's user verification", async () => {
		const begun = await factorWith("required").beginEnrollment({
			...ceremony(),
			user: USER,
			factors: [],
		});
		const options = begun.response as {
			rp: { id: string; name: string };
			user: { id: string; name: string; displayName: string };
			challenge: string;
			attestation: string;
			pubKeyCredParams: { alg: number }[];
			excludeCredentials: unknown[];
			authenticatorSelection: Record<string, unknown>;
		};
		expect(options.rp).toEqual({ id: "test.example", name: "Test" });
		expect(Buffer.from(options.user.id, "base64url")).toHaveLength(32);
		expect(options.user.name).toBe(USER.email);
		expect(options.user.displayName).toBe(USER.email);
		expect(options.attestation).toBe("none");
		expect(options.pubKeyCredParams.map((param) => param.alg)).toEqual([...WEBAUTHN_ALGORITHM_IDS]);
		expect(options.excludeCredentials).toEqual([]);
		expect(options.authenticatorSelection).toMatchObject({
			residentKey: "discouraged",
			requireResidentKey: false,
			userVerification: "required",
		});
		expect(Buffer.from(options.challenge, "base64url")).toHaveLength(32);
		expect(begun.state).toEqual({
			challenge: options.challenge,
			userHandle: options.user.id,
			expiresAtMs: NOW_MS + RELYING_PARTY.challengeTtlMs,
		});
	});

	it("makes a new user handle and challenge at every first enrollment", async () => {
		const factor = factorWith();
		const handles = new Set<unknown>();
		const challenges = new Set<unknown>();
		for (let i = 0; i < 3; i++) {
			const { state } = await factor.beginEnrollment({ ...ceremony(), user: USER, factors: [] });
			handles.add(state.userHandle);
			challenges.add(state.challenge);
		}
		expect(handles.size).toBe(3);
		expect(challenges.size).toBe(3);
	});

	it("names the account by its username when it has no email", async () => {
		const { response } = await factorWith().beginEnrollment({
			...ceremony(),
			user: { id: USER.id, username: "alice" },
			factors: [],
		});
		expect((response as { user: { name: string } }).user.name).toBe("alice");
	});

	it("refuses an account with neither an email nor a username, quoting nothing", async () => {
		await expect(
			factorWith().beginEnrollment({ ...ceremony(), user: { id: USER.id }, factors: [] }),
		).rejects.toThrow(RangeError);
	});

	it("keeps the subject's user handle for a further credential, and excludes every WebAuthn credential the subject holds", async () => {
		const { response, state } = await factorWith().beginEnrollment({
			...ceremony(),
			user: USER,
			factors: [A, B, enrolled("unreadable", { credentialId: 1 })],
		});
		const options = response as {
			user: { id: string };
			excludeCredentials: { id: string; transports?: string[] }[];
		};
		expect(options.user.id).toBe(HANDLE);
		expect(state.userHandle).toBe(HANDLE);
		expect(options.excludeCredentials).toEqual([
			{ id: "Y3JlZC1h", type: "public-key", transports: ["usb"] },
			{ id: "Y3JlZC1i", type: "public-key", transports: ["internal", "hybrid"] },
		]);
	});

	it("completes with the verified attestation's credential, kept with the subject's user handle", async () => {
		attested("bmV3LWNyZWQ", true);
		const factor = factorWith("required");
		const state = { challenge: "Y2hhbGxlbmdl", userHandle: HANDLE, expiresAtMs: NOW_MS + 1 };
		const done = await factor.completeEnrollment({
			...ceremony(),
			user: USER,
			factors: [A],
			state,
			proof: registration(),
		});
		expect(done).toEqual({
			ok: true,
			data: {
				credentialId: "bmV3LWNyZWQ",
				publicKey: b64url(PUBLIC_KEY),
				signCount: 0,
				transports: ["usb", "nfc"],
				backedUp: true,
				userHandle: HANDLE,
			},
		});
		expect(mockAttestation).toHaveBeenCalledWith({
			response: registration(),
			expectedChallenge: "Y2hhbGxlbmdl",
			expectedRpId: "test.example",
			expectedOrigins: ["https://test.example"],
			userVerification: "required",
		});
	});

	it("keeps only the transports WebAuthn defines that the provider knows", async () => {
		mockAttestation.mockResolvedValueOnce({
			ok: true,
			material: {
				credentialId: "bmV3LWNyZWQ",
				publicKey: new Uint8Array(PUBLIC_KEY),
				signCount: 0,
				transports: ["cable", "internal"] as never,
				backedUp: false,
			},
		});
		const done = await factorWith().completeEnrollment({
			...ceremony(),
			user: USER,
			factors: [],
			state: { challenge: "Y2g", userHandle: HANDLE, expiresAtMs: NOW_MS + 1 },
			proof: registration(),
		});
		expect(done.ok && done.data.transports).toEqual(["internal"]);
	});

	it("refuses as duplicate a credential the subject already holds", async () => {
		attested("Y3JlZC1i");
		const done = await factorWith().completeEnrollment({
			...ceremony(),
			user: USER,
			factors: [A, B],
			state: { challenge: "Y2g", userHandle: HANDLE, expiresAtMs: NOW_MS + 1 },
			proof: registration({ id: "Y3JlZC1i", rawId: "Y3JlZC1i" }),
		});
		expect(done).toEqual({ ok: false, reason: "duplicate" });
	});

	it("refuses as invalid an attestation the library refuses", async () => {
		mockAttestation.mockResolvedValueOnce({ ok: false, reason: "challenge_mismatch" });
		const done = await factorWith().completeEnrollment({
			...ceremony(),
			user: USER,
			factors: [],
			state: { challenge: "Y2g", userHandle: HANDLE, expiresAtMs: NOW_MS + 1 },
			proof: registration(),
		});
		expect(done).toEqual({ ok: false, reason: "invalid" });
	});

	it("refuses as expired a registration past its challenge's time, checking nothing", async () => {
		const done = await factorWith().completeEnrollment({
			...ceremony(),
			user: USER,
			factors: [],
			state: { challenge: "Y2g", userHandle: HANDLE, expiresAtMs: NOW_MS },
			proof: registration(),
		});
		expect(done).toEqual({ ok: false, reason: "expired" });
		expect(mockAttestation).not.toHaveBeenCalled();
	});

	it("answers malformed for a proof that is not a registration response, checking nothing", async () => {
		const factor = factorWith();
		for (const proof of [
			undefined,
			"a string",
			registration({ type: "other" }),
			registration({ id: "" }),
			registration({ response: { clientDataJSON: "Y2Q" } }),
			registration({ response: { clientDataJSON: 1, attestationObject: "YW8" } }),
		]) {
			expect(
				await factor.completeEnrollment({
					...ceremony(),
					user: USER,
					factors: [],
					state: { challenge: "Y2g", userHandle: HANDLE, expiresAtMs: NOW_MS + 1 },
					proof,
				}),
			).toEqual({ ok: false, reason: "malformed" });
		}
		expect(mockAttestation).not.toHaveBeenCalled();
	});

	it("throws for a pending state that is not a WebAuthn enrollment's", async () => {
		for (const state of [
			{},
			{ challenge: "Y2g", userHandle: HANDLE },
			{ challenge: 1, userHandle: HANDLE, expiresAtMs: 1 },
		]) {
			await expect(
				factorWith().completeEnrollment({
					...ceremony(),
					user: USER,
					factors: [],
					state,
					proof: registration(),
				}),
			).rejects.toThrow(/pending enrollment/);
		}
	});
});

describe("an assertion's challenge", () => {
	it("lists every WebAuthn factor of the subject, asks for the section's user verification, and keeps the challenge until the relying party's challenge lifetime", async () => {
		const { state, response } = await challengeOf(factorWith("preferred"), A, [A, B]);
		const options = response as {
			rpId: string;
			challenge: string;
			userVerification: string;
			allowCredentials: unknown[];
		};
		expect(options.rpId).toBe("test.example");
		expect(options.userVerification).toBe("preferred");
		expect(options.allowCredentials).toEqual([
			{ id: "Y3JlZC1h", type: "public-key", transports: ["usb"] },
			{ id: "Y3JlZC1i", type: "public-key", transports: ["internal", "hybrid"] },
		]);
		expect(Buffer.from(options.challenge, "base64url")).toHaveLength(32);
		expect(state).toEqual({
			challenge: options.challenge,
			expiresAtMs: NOW_MS + RELYING_PARTY.challengeTtlMs,
		});
	});

	it("leaves out another factor whose data is not a WebAuthn factor's, and throws for the named one's", async () => {
		const factor = factorWith();
		const broken = enrolled("broken", { credentialId: 1 });
		const sent = await challengeOf(factor, A, [A, broken]);
		expect((sent.response as { allowCredentials: unknown[] }).allowCredentials).toHaveLength(1);
		await expect(challengeOf(factor, broken, [A, broken])).rejects.toThrow(/credentialId/);
	});
});

describe("an assertion's verification", () => {
	const STATE = { challenge: "Y2hhbGxlbmdl", expiresAtMs: NOW_MS + 60_000 };

	const verify = (factor: MfaFactor, proof: unknown, overrides: Record<string, unknown> = {}) =>
		factor.verify({
			...ceremony(),
			factor: A,
			factors: [A, B],
			state: STATE,
			proof,
			...overrides,
		});

	it("verifies the credential named by the assertion against the challenge taken, and answers its new count and backup state as its next data", async () => {
		mockAssertion.mockResolvedValueOnce({ ok: true, newSignCount: 6, backedUp: false });
		const factor = factorWith("required");
		expect(await verify(factor, assertion("Y3JlZC1h"))).toEqual({
			ok: true,
			factorId: "factor-a",
			next: { ...dataOf(), signCount: 6, backedUp: false },
		});
		expect(mockAssertion).toHaveBeenCalledWith({
			credential: {
				credentialId: "Y3JlZC1h",
				publicKey: PUBLIC_KEY,
				signCount: 5,
				transports: ["usb"],
			},
			response: assertion("Y3JlZC1h"),
			expectedChallenge: "Y2hhbGxlbmdl",
			expectedRpId: "test.example",
			expectedOrigins: ["https://test.example"],
			expectedTopOrigins: ["https://embedder.test.example"],
			userVerification: "required",
		});
	});

	it("finds the credential among the subject's: an assertion by another of its WebAuthn factors verifies that one", async () => {
		mockAssertion.mockResolvedValueOnce({ ok: true, newSignCount: 0, backedUp: true });
		const verdict = await verify(factorWith(), assertion("Y3JlZC1i"));
		expect(verdict).toEqual({
			ok: true,
			factorId: "factor-b",
			next: { ...B.data, signCount: 0, backedUp: true },
		});
	});

	it("records the backup state the assertion reports, so a credential since synced adds swk", async () => {
		mockAssertion.mockResolvedValueOnce({ ok: true, newSignCount: 6, backedUp: true });
		const factor = factorWith();
		const verdict = await verify(factor, assertion("Y3JlZC1h"));
		if (!verdict.ok || verdict.next === undefined) throw new Error("not verified");
		expect(factor.amrFor(verdict.next)).toEqual([SOFTWARE_KEY_AMR]);
	});

	it("refuses as sign_count_regression a counter that did not increase over the stored one", async () => {
		mockAssertion.mockResolvedValueOnce({ ok: false, reason: "sign_count_regression" });
		expect(await verify(factorWith(), assertion("Y3JlZC1h"))).toEqual({
			ok: false,
			reason: "sign_count_regression",
		});
	});

	it.each([
		"signature_invalid",
		"challenge_mismatch",
		"origin_mismatch",
		"top_origin_mismatch",
		"rp_id_mismatch",
		"unknown",
	] as const)("refuses as invalid an assertion the library refuses: %s", async (reason) => {
		mockAssertion.mockResolvedValueOnce({ ok: false, reason });
		expect(await verify(factorWith(), assertion("Y3JlZC1h"))).toEqual({
			ok: false,
			reason: "invalid",
		});
	});

	it("refuses as invalid a credential the subject does not hold, checking nothing", async () => {
		expect(await verify(factorWith(), assertion("b3RoZXI"))).toEqual({
			ok: false,
			reason: "invalid",
		});
		expect(mockAssertion).not.toHaveBeenCalled();
	});

	it("refuses as invalid an assertion whose user handle is not the credential's, checking nothing", async () => {
		const proof = assertion("Y3JlZC1h", {
			response: {
				clientDataJSON: "Y2Q",
				authenticatorData: "YWQ",
				signature: "c2ln",
				userHandle: b64url(new Uint8Array(32).fill(9)),
			},
		});
		expect(await verify(factorWith(), proof)).toEqual({ ok: false, reason: "invalid" });
		expect(mockAssertion).not.toHaveBeenCalled();
	});

	it("verifies an assertion carrying the credential's user handle", async () => {
		mockAssertion.mockResolvedValueOnce({ ok: true, newSignCount: 6, backedUp: false });
		const proof = assertion("Y3JlZC1h", {
			response: {
				clientDataJSON: "Y2Q",
				authenticatorData: "YWQ",
				signature: "c2ln",
				userHandle: HANDLE,
			},
		});
		expect((await verify(factorWith(), proof)).ok).toBe(true);
	});

	it("refuses as expired an assertion with no challenge to answer, or one past its time, checking nothing", async () => {
		const factor = factorWith();
		expect(await verify(factor, assertion("Y3JlZC1h"), { state: undefined })).toEqual({
			ok: false,
			reason: "expired",
		});
		expect(
			await verify(factor, assertion("Y3JlZC1h"), {
				state: { ...STATE, expiresAtMs: NOW_MS },
			}),
		).toEqual({ ok: false, reason: "expired" });
		expect(mockAssertion).not.toHaveBeenCalled();
	});

	it("answers malformed for a proof that is not an assertion, checking nothing", async () => {
		const factor = factorWith();
		for (const proof of [
			undefined,
			null,
			"Y3JlZC1h",
			assertion("Y3JlZC1h", { type: "other" }),
			assertion(""),
			assertion("Y3JlZC1h", { response: { clientDataJSON: "Y2Q", authenticatorData: "YWQ" } }),
			assertion("Y3JlZC1h", {
				response: {
					clientDataJSON: "Y2Q",
					authenticatorData: "YWQ",
					signature: "c2ln",
					userHandle: 7,
				},
			}),
		]) {
			expect(await verify(factor, proof)).toEqual({ ok: false, reason: "malformed" });
		}
		expect(mockAssertion).not.toHaveBeenCalled();
	});

	it("hands the library only the assertion's own fields", async () => {
		mockAssertion.mockResolvedValueOnce({ ok: true, newSignCount: 6, backedUp: false });
		await verify(factorWith(), { ...assertion("Y3JlZC1h"), extra: "dropped" });
		expect(mockAssertion.mock.calls[0]?.[0].response).toEqual(assertion("Y3JlZC1h"));
	});

	it("throws for a challenge state that is not a WebAuthn challenge's, and for the named factor's data that is not a WebAuthn factor's", async () => {
		const factor = factorWith();
		await expect(
			verify(factor, assertion("Y3JlZC1h"), { state: { challenge: 1, expiresAtMs: 1 } }),
		).rejects.toThrow(/challenge/);
		const broken = enrolled("broken", { credentialId: 1 });
		await expect(
			verify(factor, assertion("Y3JlZC1h"), { factor: broken, factors: [A, broken] }),
		).rejects.toThrow(/credentialId/);
	});
});

describe("the factor contract (@o3co/auth-provider-test-kit)", () => {
	/** Every mocked verification succeeds for the credential the suite enrolled. */
	beforeEach(() => {
		mockAttestation.mockImplementation(async (input) => ({
			ok: true,
			material: {
				credentialId: input.response.id,
				publicKey: new Uint8Array(PUBLIC_KEY),
				signCount: 0,
				transports: ["internal"],
				backedUp: false,
			},
		}));
		mockAssertion.mockImplementation(async (input) => ({
			ok: true,
			newSignCount: input.credential.signCount + 1,
			backedUp: false,
		}));
	});

	for (const { name, run } of mfaFactorContract({
		build: () => factorWith(),
		user: USER,
		enrollmentProof: () => registration(),
		verificationProof: (enrolledFactor) =>
			assertion(String((enrolledFactor.data as { credentialId: unknown }).credentialId)),
	})) {
		it(name, run);
	}
});
