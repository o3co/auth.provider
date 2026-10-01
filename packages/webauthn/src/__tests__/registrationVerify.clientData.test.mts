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
 * The challenge `POST /oauth/webauthn/registration/verify` consumes is the one the client data
 * carries as `@simplewebauthn/server` decodes it, over the library's real verification of a
 * software authenticator's `none` attestation: base64url that is not canonical is read as the
 * library reads it, and client data the library cannot read is refused before the challenge is
 * consumed.
 */

import {
	createChallengeCeremony,
	createMemoryChallengeStore,
	createMemoryReplaySeenSet,
	createMemoryWebAuthnCredentialStore,
} from "@o3co/auth-provider-core";
import express from "express";
import supertest from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createRegistrationVerifyHandler } from "#/routes/registrationVerify.mjs";
import { createTestWebAuthnConfig } from "#/testing/index.mjs";
import {
	type CeremonyOptions,
	nonCanonicalBase64url,
	softwareAuthenticator,
} from "./softwareAuthenticator.fixture.mjs";

const PATH = "/oauth/webauthn/registration/verify";
/** Fixed, so the client data, and how each encoding below decodes, is the same at every run. */
const CHALLENGE = "Y2hhbGxlbmdlLWZvci1hbGljZS1yZWdpc3RyYXRpb24";
/** Client data whose canonical base64url holds an `A`, which `"@@@"` guarantees. */
const WITH_A_ZERO_SEXTET = { extension: "@@@" };

/** The grant's verify route for alice, with {@link CHALLENGE} issued: what a test posts to it, and the store. */
async function registration() {
	const challengeStore = createMemoryChallengeStore();
	const credentialStore = createMemoryWebAuthnCredentialStore();
	const app = express();
	app.use(express.json());
	app.use((req, _res, next) => {
		req.webauthnSubject = { userId: "alice" };
		next();
	});
	app.post(
		PATH,
		createRegistrationVerifyHandler({
			config: createTestWebAuthnConfig(),
			challengeCeremony: createChallengeCeremony({
				challengeStore,
				replaySeenSet: createMemoryReplaySeenSet(),
			}),
			credentialStore,
			logger: { error: vi.fn() },
		}),
	);
	await challengeStore.issue("webauthn:registration:alice", CHALLENGE, Date.now() + 120_000);
	const passkey = softwareAuthenticator({ rpId: "test.example", origin: "https://test.example" });
	const post = (options: CeremonyOptions = {}) =>
		supertest(app)
			.post(PATH)
			.send({ response: passkey.register(CHALLENGE, options) });
	return { post, credentialStore };
}

describe("the challenge the grant's registration consumes", () => {
	it.each([
		["a space", " "],
		["an =", "="],
		["a character outside the alphabet", "!"],
	])(
		"is read as the library reads it, from base64url that is not canonical: %s where an A was, and the registration is stored",
		async (_what, replacement) => {
			const { post, credentialStore } = await registration();

			const res = await post({
				clientData: WITH_A_ZERO_SEXTET,
				encode: nonCanonicalBase64url(replacement),
			});

			expect(res.status, JSON.stringify(res.body)).toBe(200);
			expect(await credentialStore.listByUserId("alice")).toHaveLength(1);
		},
	);

	it("is not consumed for client data the library cannot read: 400 invalid_request, and the challenge still completes a registration", async () => {
		const { post, credentialStore } = await registration();

		// Node's decoder skips a leading space; the library reads it as a sextet of 0.
		const refused = await post({ encode: (bytes) => ` ${bytes.toString("base64url")}` });

		expect(refused.status).toBe(400);
		expect(refused.body).toMatchObject({ error: "invalid_request" });
		expect(await credentialStore.listByUserId("alice")).toEqual([]);

		const stored = await post();

		expect(stored.status, JSON.stringify(stored.body)).toBe(200);
		expect(await credentialStore.listByUserId("alice")).toHaveLength(1);
	});

	it("is not consumed for client data the library reads as an object with no string challenge: 400 invalid_request, and the challenge still completes a registration", async () => {
		const { post, credentialStore } = await registration();

		const refused = await post({ clientData: { challenge: 7 } });

		expect(refused.status).toBe(400);
		expect(refused.body).toMatchObject({ error: "invalid_request" });
		expect(await credentialStore.listByUserId("alice")).toEqual([]);

		const stored = await post();

		expect(stored.status, JSON.stringify(stored.body)).toBe(200);
		expect(await credentialStore.listByUserId("alice")).toHaveLength(1);
	});
});
