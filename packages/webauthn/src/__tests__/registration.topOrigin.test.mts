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
 * A registration's top origin, on both registration paths — the grant's
 * `POST /oauth/webauthn/registration/verify` and the WebAuthn second
 * factor's enrollment — over `@simplewebauthn/server`'s real verification of
 * a software authenticator's `none` attestation. A registration is held to
 * the rule an assertion is: a top origin the browser reports must be one
 * `webauthn.topOrigin` lists, and belong to a cross-origin ceremony. On the
 * client data a browser sends, the two wrappers answer alike; client data
 * no browser sends is refused at registration. The client data is read as
 * the library decodes it, canonical base64url or not.
 */

import { randomBytes } from "node:crypto";
import {
	createChallengeCeremony,
	createMemoryChallengeStore,
	createMemoryReplaySeenSet,
	createMemoryWebAuthnCredentialStore,
} from "@o3co/auth-provider-core";
import { createTestMfaDigests } from "@o3co/auth-provider-core/testing";
import express from "express";
import supertest from "supertest";
import { describe, expect, it, vi } from "vitest";
import { verifyWebAuthnAssertion, verifyWebAuthnAttestation } from "#/internal/verification.mjs";
import { createWebAuthnMfaFactor, WEBAUTHN_MFA_FACTOR_KIND } from "#/mfaFactor/factor.mjs";
import { createRegistrationVerifyHandler } from "#/routes/registrationVerify.mjs";
import { createTestWebAuthnConfig } from "#/testing/index.mjs";
import { nonCanonicalBase64url, softwareAuthenticator } from "./softwareAuthenticator.fixture.mjs";

const RP_ID = "test.example";
const ORIGIN = "https://test.example";
const PARTNER = "https://partner.example";
const FRAMER = "https://framer.example";

/** A case: the top origins the deployment lists, and what the browser reports beside `origin`. */
type Case = readonly [
	what: string,
	topOrigin: readonly string[] | undefined,
	clientData: Readonly<Record<string, unknown>>,
];

/** Refused, on client data a browser sends. */
const REFUSED_AS_AN_ASSERTION_IS: readonly Case[] = [
	[
		"reporting a top origin for a cross-origin ceremony, with no webauthn.topOrigin",
		undefined,
		{ crossOrigin: true, topOrigin: FRAMER },
	],
	[
		"reporting a top origin webauthn.topOrigin does not list",
		[PARTNER],
		{ crossOrigin: true, topOrigin: FRAMER },
	],
	[
		"reporting a listed top origin for a ceremony that is not cross-origin",
		[PARTNER],
		{ crossOrigin: false, topOrigin: PARTNER },
	],
];

const REFUSED: readonly Case[] = [
	...REFUSED_AS_AN_ASSERTION_IS,
	// Client data no browser sends.
	[
		"reporting a top origin that is not a string",
		[PARTNER],
		{ crossOrigin: true, topOrigin: null },
	],
	[
		"reporting a listed top origin with a crossOrigin that is not the boolean true",
		[PARTNER],
		{ crossOrigin: "true", topOrigin: PARTNER },
	],
];

const ACCEPTED: readonly Case[] = [
	["of a same-origin ceremony", undefined, {}],
	[
		"of a cross-origin ceremony from a top origin webauthn.topOrigin lists",
		[PARTNER],
		{ crossOrigin: true, topOrigin: PARTNER },
	],
	[
		"of a cross-origin ceremony whose browser reports no top origin, as an assertion is",
		undefined,
		{ crossOrigin: true },
	],
];

const relyingParty = (topOrigin: readonly string[] | undefined) =>
	createTestWebAuthnConfig(topOrigin === undefined ? {} : { topOrigin: [...topOrigin] });

const authenticator = () => softwareAuthenticator({ rpId: RP_ID, origin: ORIGIN });

// ---------------------------------------------------------------------------
// The grant's registration
// ---------------------------------------------------------------------------

/** The grant's verify route for alice under `topOrigin`, with a challenge issued: what a test posts to it, and the store. */
async function grantRegistration(topOrigin: readonly string[] | undefined) {
	const challengeStore = createMemoryChallengeStore();
	const credentialStore = createMemoryWebAuthnCredentialStore();
	const app = express();
	app.use(express.json());
	app.use((req, _res, next) => {
		req.webauthnSubject = { userId: "alice" };
		next();
	});
	app.post(
		"/oauth/webauthn/registration/verify",
		createRegistrationVerifyHandler({
			config: relyingParty(topOrigin),
			challengeCeremony: createChallengeCeremony({
				challengeStore,
				replaySeenSet: createMemoryReplaySeenSet(),
			}),
			credentialStore,
			logger: { error: vi.fn() },
		}),
	);
	const challenge = randomBytes(32).toString("base64url");
	await challengeStore.issue("webauthn:registration:alice", challenge, Date.now() + 120_000);
	const post = (clientData: Readonly<Record<string, unknown>>) =>
		supertest(app)
			.post("/oauth/webauthn/registration/verify")
			.send({ response: authenticator().register(challenge, { clientData }) });
	return { post, credentialStore };
}

describe("the grant's registration", () => {
	it.each(REFUSED)(
		"refuses a registration %s: 400 top_origin_mismatch, nothing stored",
		async (_what, topOrigin, clientData) => {
			const { post, credentialStore } = await grantRegistration(topOrigin);

			const res = await post(clientData);

			expect(res.status).toBe(400);
			expect(res.body).toEqual({ error: "top_origin_mismatch" });
			expect(await credentialStore.listByUserId("alice")).toEqual([]);
		},
	);

	it.each(ACCEPTED)("stores a registration %s", async (_what, topOrigin, clientData) => {
		const { post, credentialStore } = await grantRegistration(topOrigin);

		const res = await post(clientData);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(await credentialStore.listByUserId("alice")).toHaveLength(1);
	});
});

// ---------------------------------------------------------------------------
// The second factor's enrollment
// ---------------------------------------------------------------------------

/** The second factor under `topOrigin`, an enrollment begun for alice: what completes it. */
async function factorEnrollment(topOrigin: readonly string[] | undefined) {
	const factor = createWebAuthnMfaFactor({
		relyingParty: relyingParty(topOrigin),
		userVerification: "preferred",
	});
	const nowMs = Date.now();
	const context = {
		subject: "u-alice",
		transactionId: "tx-1",
		nowMs,
		request: {},
		digests: createTestMfaDigests(WEBAUTHN_MFA_FACTOR_KIND),
		user: { id: "u-alice", username: "alice" },
		factors: [],
	};
	const started = await factor.beginEnrollment(context);
	const { challenge } = started.state as { readonly challenge: string };
	return (clientData: Readonly<Record<string, unknown>>) =>
		factor.completeEnrollment({
			...context,
			state: started.state,
			proof: authenticator().register(challenge, { clientData }),
		});
}

describe("the second factor's enrollment", () => {
	it.each(REFUSED)("refuses as invalid a registration %s", async (_what, topOrigin, clientData) => {
		const complete = await factorEnrollment(topOrigin);

		expect(await complete(clientData)).toEqual({ ok: false, reason: "invalid" });
	});

	it.each(ACCEPTED)("completes a registration %s", async (_what, topOrigin, clientData) => {
		const complete = await factorEnrollment(topOrigin);

		const done = await complete(clientData);

		expect(done.ok, JSON.stringify(done)).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// The wrappers
// ---------------------------------------------------------------------------

const CHALLENGE = randomBytes(32).toString("base64url");

/** The expected values both wrappers are handed, under `topOrigin`. */
const expected = (topOrigin: readonly string[] | undefined) => ({
	expectedChallenge: CHALLENGE,
	expectedRpId: RP_ID,
	expectedOrigins: [ORIGIN],
	...(topOrigin === undefined ? {} : { expectedTopOrigins: topOrigin }),
});

/** A verdict as the two wrappers can both answer it: accepted, or the reason refused. */
const verdictOf = (result: { readonly ok: boolean; readonly reason?: string }): string =>
	result.ok ? "accepted" : (result.reason ?? "refused");

describe("the registration and assertion wrappers, on the client data a browser sends", () => {
	it.each([
		...REFUSED_AS_AN_ASSERTION_IS.map((c) => [...c, "top_origin_mismatch"] as const),
		...ACCEPTED.map((c) => [...c, "accepted"] as const),
	])("answer alike for a ceremony %s", async (_what, topOrigin, clientData, verdict) => {
		const passkey = authenticator();

		const registered = await verifyWebAuthnAttestation({
			response: passkey.register(CHALLENGE, { clientData }),
			...expected(topOrigin),
		});
		const asserted = await verifyWebAuthnAssertion({
			credential: {
				credentialId: passkey.credentialId,
				publicKey: passkey.publicKey,
				signCount: 0,
				transports: ["internal"],
			},
			response: passkey.assert(CHALLENGE, { clientData }),
			...expected(topOrigin),
		});

		expect(verdictOf(registered)).toBe(verdict);
		expect(verdictOf(asserted)).toBe(verdict);
	});
});

describe("the client data a registration is judged on", () => {
	/** Client data whose canonical base64url holds an `A`, which `"@@@"` guarantees. */
	const WITH_A_ZERO_SEXTET = { extension: "@@@" };

	it.each([
		["a space", " "],
		["an =", "="],
	])(
		"is the text the library verified, when its base64url is not canonical: %s where an A was",
		async (_what, replacement) => {
			const encode = nonCanonicalBase64url(replacement);
			const verdict = async (
				topOrigin: readonly string[] | undefined,
				clientData: Readonly<Record<string, unknown>>,
			) =>
				verdictOf(
					await verifyWebAuthnAttestation({
						response: authenticator().register(CHALLENGE, {
							clientData: { ...WITH_A_ZERO_SEXTET, ...clientData },
							encode,
						}),
						...expected(topOrigin),
					}),
				);

			expect(await verdict(undefined, {})).toBe("accepted");
			expect(await verdict([PARTNER], { crossOrigin: true, topOrigin: PARTNER })).toBe("accepted");
			expect(await verdict([PARTNER], { crossOrigin: true, topOrigin: FRAMER })).toBe(
				"top_origin_mismatch",
			);
			expect(await verdict(undefined, { crossOrigin: true, topOrigin: FRAMER })).toBe(
				"top_origin_mismatch",
			);
		},
	);
});
