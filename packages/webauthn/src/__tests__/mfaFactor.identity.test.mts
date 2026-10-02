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
 * The identity a WebAuthn second factor answers for its data: the credential id the record
 * holds, over `@simplewebauthn/server`'s real verification of software authenticators. Data the
 * factor cannot read answers none, and the identity never throws. The factor contract, given two
 * software authenticators, holds them to two identities.
 */

import type { MfaEnrolledFactor, MfaFactor, MfaFactorData } from "@o3co/auth-provider-core";
import { createTestMfaDigests } from "@o3co/auth-provider-core/testing";
import { mfaFactorContract } from "@o3co/auth-provider-test-kit";
import { describe, expect, it } from "vitest";
import { createWebAuthnMfaFactor, WEBAUTHN_MFA_FACTOR_KIND } from "#/mfaFactor/factor.mjs";
import { createTestWebAuthnConfig } from "#/testing/index.mjs";
import {
	type SoftwareAuthenticator,
	softwareAuthenticator,
} from "./softwareAuthenticator.fixture.mjs";

const NOW_MS = Date.now();
const USER = { id: "u-alice", username: "alice" };
const RELYING_PARTY = { rpId: "test.example", origin: "https://test.example" };
const BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const ceremony = {
	subject: USER.id,
	transactionId: "tx-1",
	nowMs: NOW_MS,
	request: {},
	digests: createTestMfaDigests(WEBAUTHN_MFA_FACTOR_KIND),
};

const newFactor = (): MfaFactor =>
	createWebAuthnMfaFactor({
		relyingParty: createTestWebAuthnConfig(),
		userVerification: "preferred",
	});

/** `factor`'s identity of `data`; a throw when the factor answers no identity at all. */
function identityOf(factor: MfaFactor, data: unknown): string | undefined {
	if (factor.identity === undefined) throw new Error("the factor answers no identity");
	return factor.identity(data as MfaFactorData);
}

const reopened = (data: MfaFactorData): MfaFactorData => JSON.parse(JSON.stringify(data));

const recordOf = (id: string, data: MfaFactorData): MfaEnrolledFactor => ({
	id,
	label: undefined,
	createdAt: new Date(NOW_MS),
	lastUsedAt: undefined,
	data,
});

/** `passkey` enrolled by `factor` beside the subject's `held` records, as the record it completes with. */
async function enroll(
	factor: MfaFactor,
	passkey: SoftwareAuthenticator,
	held: readonly MfaEnrolledFactor[] = [],
): Promise<MfaEnrolledFactor> {
	const begun = await factor.beginEnrollment({ ...ceremony, user: USER, factors: held });
	const { challenge } = begun.state as { readonly challenge: string };
	const completed = await factor.completeEnrollment({
		...ceremony,
		user: USER,
		factors: held,
		state: begun.state,
		proof: passkey.register(challenge),
	});
	if (!completed.ok) throw new Error(`not enrolled: ${JSON.stringify(completed)}`);
	return recordOf(`factor-${held.length + 1}`, completed.data);
}

/** The next data `factor` answers for an assertion by `passkey` of its `record`. */
async function nextAfterVerifying(
	factor: MfaFactor,
	passkey: SoftwareAuthenticator,
	record: MfaEnrolledFactor,
): Promise<MfaFactorData> {
	if (factor.challenge === undefined) throw new Error("the factor has no challenge");
	const challenged = await factor.challenge({ ...ceremony, factor: record, factors: [record] });
	const { challenge } = challenged.state as { readonly challenge: string };
	const verdict = await factor.verify({
		...ceremony,
		factor: record,
		factors: [record],
		state: challenged.state,
		proof: passkey.assert(challenge),
	});
	if (!verdict.ok || verdict.next === undefined) {
		throw new Error(`not verified: ${JSON.stringify(verdict)}`);
	}
	return verdict.next;
}

describe("the identity of a WebAuthn second factor's data", () => {
	it("is the credential id the enrolled data holds, the same after a JSON round trip and for a verification's next data", async () => {
		const factor = newFactor();
		const passkey = softwareAuthenticator(RELYING_PARTY);
		const record = await enroll(factor, passkey);

		expect(identityOf(factor, record.data)).toBe(passkey.credentialId);
		expect(identityOf(factor, reopened(record.data))).toBe(passkey.credentialId);
		const next = await nextAfterVerifying(factor, passkey, record);
		expect(next).not.toEqual(record.data);
		expect(identityOf(factor, reopened(next))).toBe(passkey.credentialId);
	});

	it("answers two identities for two credentials of two authenticators enrolled by one subject", async () => {
		const factor = newFactor();
		const first = await enroll(factor, softwareAuthenticator(RELYING_PARTY));
		const second = await enroll(factor, softwareAuthenticator(RELYING_PARTY), [first]);

		const identities = [identityOf(factor, first.data), identityOf(factor, second.data)];

		expect(identities.every((identity) => typeof identity === "string")).toBe(true);
		expect(identities[0]).not.toBe(identities[1]);
	});

	it.each<[string, Record<string, unknown>]>([
		["a sign count it moved to", { signCount: 7 }],
		["no transports", { transports: [] }],
		["a transport it does not know", { transports: ["smoke-signal"] }],
		["another backup state", { backedUp: true }],
	])("stays the credential id over valid data with %s", async (_what, change) => {
		const factor = newFactor();
		const passkey = softwareAuthenticator(RELYING_PARTY);
		const { data } = await enroll(factor, passkey);

		expect(identityOf(factor, { ...data, ...change })).toBe(passkey.credentialId);
	});

	it("answers none, and does not throw, for data the factor cannot read", async () => {
		const factor = newFactor();
		const { data } = await enroll(factor, softwareAuthenticator(RELYING_PARTY));
		const { userHandle } = data as { readonly userHandle: string };
		const handleBytes = Buffer.from(userHandle, "base64url");
		// The last character of 32 bytes' base64url carries 2 bits no byte holds: setting one
		// writes the same bytes non-canonically.
		const last = BASE64URL_ALPHABET.indexOf(userHandle.slice(-1));
		const nonCanonical = `${userHandle.slice(0, -1)}${BASE64URL_ALPHABET[last | 1]}`;
		expect(Buffer.from(nonCanonical, "base64url")).toEqual(handleBytes);
		expect(nonCanonical).not.toBe(userHandle);

		const unreadable: [string, unknown][] = [
			["null", null],
			["an array", [data]],
			["no credentialId", { ...data, credentialId: undefined }],
			["a credentialId that is not base64url", { ...data, credentialId: "Y3J+ZC/h" }],
			["an empty credentialId", { ...data, credentialId: "" }],
			["a credentialId that is not a string", { ...data, credentialId: 7 }],
			["a publicKey that is not base64url", { ...data, publicKey: "k e y" }],
			["a negative signCount", { ...data, signCount: -1 }],
			["a signCount that is not an integer", { ...data, signCount: 1.5 }],
			["transports that are not a list", { ...data, transports: "usb" }],
			["a backupEligible that is not a boolean", { ...data, backupEligible: "false" }],
			["a backedUp that is not a boolean", { ...data, backedUp: 0 }],
			["a padded userHandle", { ...data, userHandle: `${userHandle}=` }],
			["a userHandle written non-canonically", { ...data, userHandle: nonCanonical }],
			["an empty userHandle", { ...data, userHandle: "" }],
			[
				"a userHandle over 64 bytes",
				{ ...data, userHandle: Buffer.alloc(65, 1).toString("base64url") },
			],
		];
		for (const [what, damaged] of unreadable) {
			let answered: string | undefined;
			expect(() => {
				answered = identityOf(factor, damaged);
			}, what).not.toThrow();
			expect(answered, what).toBeUndefined();
		}
	});
});

describe("the WebAuthn second factor keeps the MFA factor contract with two software authenticators", () => {
	const first = softwareAuthenticator(RELYING_PARTY);
	const second = softwareAuthenticator(RELYING_PARTY);
	const challengeOf = (state: unknown): string =>
		(state as { readonly challenge: string }).challenge;

	for (const { name, run } of mfaFactorContract({
		build: newFactor,
		user: { ...USER, email: "alice@example.com" },
		enrollmentProof: (start) => first.register(challengeOf(start.state)),
		secondEnrollmentProof: (start) => second.register(challengeOf(start.state)),
		verificationProof: (enrolled, challenge) => {
			const { credentialId } = enrolled.data as { readonly credentialId: unknown };
			const passkey = credentialId === second.credentialId ? second : first;
			return passkey.assert(challengeOf(challenge?.state));
		},
	})) {
		it(name, run);
	}
});
