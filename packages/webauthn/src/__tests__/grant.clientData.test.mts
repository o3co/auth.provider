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
 * The challenge the WebAuthn grant consumes is the one the assertion's client data carries as
 * `@simplewebauthn/server` decodes it, over the library's real verification of a software
 * authenticator's signed assertion: base64url that is not canonical is read as the library reads
 * it, and client data the library cannot read is refused before the challenge is consumed.
 */

import {
	createChallengeCeremony,
	createMemoryChallengeStore,
	createMemoryReplaySeenSet,
	createMemoryWebAuthnCredentialStore,
	createSymmetricKeyStore,
	type GrantContext,
} from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import { createWebAuthnGrant, WEBAUTHN_GRANT_TYPE } from "#/grant.mjs";
import { createTestWebAuthnConfig } from "#/testing/index.mjs";
import { makeAppConfig } from "./appConfig.fixture.mjs";
import {
	type CeremonyOptions,
	nonCanonicalBase64url,
	softwareAuthenticator,
} from "./softwareAuthenticator.fixture.mjs";

/** Fixed, so the client data, and how each encoding below decodes, is the same at every run. */
const CHALLENGE = "Y2hhbGxlbmdlLWZvci1hbGljZS1hdXRoZW50aWNhdGlvbg";
/** Client data whose canonical base64url holds an `A`, which `"@@@"` guarantees. */
const WITH_A_ZERO_SEXTET = { extension: "@@@" };

/** The grant, with alice's passkey registered and {@link CHALLENGE} issued: one sign-in's result per call. */
async function grant() {
	const challengeStore = createMemoryChallengeStore();
	const credentialStore = createMemoryWebAuthnCredentialStore();
	const passkey = softwareAuthenticator({ rpId: "test.example", origin: "https://test.example" });
	await credentialStore.registerCredential({
		userId: "alice",
		credentialId: passkey.credentialId,
		publicKey: passkey.publicKey,
		signCount: 0,
		backedUp: false,
		createdAt: new Date(),
	});
	const handler = createWebAuthnGrant({
		config: makeAppConfig() as never,
		keyStore: createSymmetricKeyStore("client-data-test-secret-32-bytes!!"),
		webauthnCredentialStore: credentialStore,
		challengeCeremony: createChallengeCeremony({
			challengeStore,
			replaySeenSet: createMemoryReplaySeenSet(),
		}),
		webauthnConfig: createTestWebAuthnConfig(),
	});
	await challengeStore.issue("webauthn:authentication", CHALLENGE, Date.now() + 120_000);
	const signIn = async (options: CeremonyOptions = {}) => {
		const ctx: GrantContext = {
			body: { grant_type: WEBAUTHN_GRANT_TYPE, assertion: passkey.assert(CHALLENGE, options) },
			session: {},
			issuer: "https://test.example",
			metadata: {},
			authenticatedClient: null,
		};
		return (await handler.handle(ctx)).result;
	};
	return { signIn };
}

describe("the challenge the WebAuthn grant consumes", () => {
	it.each([
		["a space", " "],
		["an =", "="],
		["a character outside the alphabet", "!"],
	])(
		"is read as the library reads it, from base64url that is not canonical: %s where an A was, and the sign-in succeeds",
		async (_what, replacement) => {
			const { signIn } = await grant();

			const result = await signIn({
				clientData: WITH_A_ZERO_SEXTET,
				encode: nonCanonicalBase64url(replacement),
			});

			expect(result.status, JSON.stringify(result)).toBe(200);
		},
	);

	it("is not consumed for client data the library cannot read: 400 invalid_grant, and the challenge still completes a sign-in", async () => {
		const { signIn } = await grant();

		// Node's decoder skips a leading space; the library reads it as a sextet of 0.
		const refused = await signIn({ encode: (bytes) => ` ${bytes.toString("base64url")}` });

		expect(refused).toMatchObject({ status: 400, error: "invalid_grant" });

		const signedIn = await signIn();

		expect(signedIn.status, JSON.stringify(signedIn)).toBe(200);
	});

	it.each([
		[
			"an object whose challenge is a number",
			{ clientData: { challenge: 7 } },
			"assertion.response.clientDataJSON has no valid challenge",
		],
		[
			"an object whose challenge is empty",
			{ clientData: { challenge: "" } },
			"assertion.response.clientDataJSON has no valid challenge",
		],
		[
			"JSON that is not an object",
			{ encode: () => Buffer.from("[]").toString("base64url") },
			"assertion.response.clientDataJSON is not a base64url JSON object",
		],
	] as const)(
		"is not consumed for client data the library reads as %s: 400 invalid_grant, and the challenge still completes a sign-in",
		async (_what, options: CeremonyOptions, errorDescription) => {
			const { signIn } = await grant();

			const refused = await signIn(options);

			expect(refused).toEqual({ status: 400, error: "invalid_grant", errorDescription });

			const signedIn = await signIn();

			expect(signedIn.status, JSON.stringify(signedIn)).toBe(200);
		},
	);
});
