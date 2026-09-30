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
 * The user handle a WebAuthn second factor's assertion carries (WebAuthn §7.2 step 6), over
 * `@simplewebauthn/server`'s real verification of a software authenticator: the factor enrolls
 * the credential under the subject's user handle, and a verification holds a handle the
 * response carries to it, whatever the signature.
 */

import { randomBytes } from "node:crypto";
import type { MfaEnrolledFactor } from "@o3co/auth-provider-core";
import { createTestMfaDigests } from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import { createWebAuthnMfaFactor, WEBAUTHN_MFA_FACTOR_KIND } from "#/mfaFactor/factor.mjs";
import { createTestWebAuthnConfig } from "#/testing/index.mjs";
import { softwareAuthenticator } from "./softwareAuthenticator.fixture.mjs";

const NOW_MS = Date.now();

/**
 * A factor with a credential enrolled for alice, and one signed assertion of that credential
 * answering a challenge the factor made: what the factor's verification answers for it carrying
 * a user handle as given (none for `undefined`), and the subject's user handle.
 */
async function enrolledFactor() {
	const factor = createWebAuthnMfaFactor({
		relyingParty: createTestWebAuthnConfig(),
		userVerification: "preferred",
	});
	const passkey = softwareAuthenticator({ rpId: "test.example", origin: "https://test.example" });
	const ceremony = {
		subject: "u-alice",
		transactionId: "tx-1",
		nowMs: NOW_MS,
		request: {},
		digests: createTestMfaDigests(WEBAUTHN_MFA_FACTOR_KIND),
	};
	const begun = await factor.beginEnrollment({
		...ceremony,
		user: { id: "u-alice", username: "alice" },
		factors: [],
	});
	const { challenge: enrollmentChallenge, userHandle } = begun.state as {
		readonly challenge: string;
		readonly userHandle: string;
	};
	const completed = await factor.completeEnrollment({
		...ceremony,
		user: { id: "u-alice", username: "alice" },
		factors: [],
		state: begun.state,
		proof: passkey.register(enrollmentChallenge),
	});
	if (!completed.ok) throw new Error(`not enrolled: ${JSON.stringify(completed)}`);
	const enrolled: MfaEnrolledFactor = {
		id: "factor-1",
		label: undefined,
		createdAt: new Date(NOW_MS),
		lastUsedAt: undefined,
		data: completed.data,
	};
	if (factor.challenge === undefined) throw new Error("the factor has no challenge");
	const challenged = await factor.challenge({ ...ceremony, factor: enrolled, factors: [enrolled] });
	const { challenge } = challenged.state as { readonly challenge: string };

	const asserted = passkey.assert(challenge);
	const verify = (presented: string | undefined) =>
		factor.verify({
			...ceremony,
			factor: enrolled,
			factors: [enrolled],
			state: challenged.state,
			proof: {
				...asserted,
				response: {
					...asserted.response,
					...(presented === undefined ? {} : { userHandle: presented }),
				},
			},
		});
	return { verify, userHandle };
}

describe("the user handle a WebAuthn second factor's assertion carries", () => {
	it.each([
		["another account's", () => randomBytes(32).toString("base64url")],
		["the subject's, padded", (handle: string) => `${handle}=`],
	])(
		"refuses as invalid a signed assertion that verifies with the subject's user handle, when it carries %s",
		async (_what, presented) => {
			const { verify, userHandle } = await enrolledFactor();

			expect((await verify(userHandle)).ok).toBe(true);
			expect(await verify(presented(userHandle))).toEqual({ ok: false, reason: "invalid" });
		},
	);

	it.each([
		["the subject's", (handle: string) => handle],
		["none", () => undefined],
	])("verifies an assertion whose user handle is %s", async (_what, presented) => {
		const { verify, userHandle } = await enrolledFactor();

		const verdict = await verify(presented(userHandle));

		expect(verdict.ok, JSON.stringify(verdict)).toBe(true);
	});
});
