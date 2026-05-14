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
 * Tests for POST /oauth/webauthn/registration/verify endpoint (spec §2.4).
 *
 * Uses supertest + express for HTTP-level testing. Memory adapters from
 * @o3co/auth-provider-core are used for ChallengeStore, ReplaySeenSet, and
 * WebAuthnCredentialStore — no hand-rolled stubs for adapters.
 *
 * verifyWebAuthnAttestation is mocked via vi.mock (same strategy as T25
 * internal.verification.test.mts) to exercise the endpoint's error-mapping
 * logic without requiring real WebAuthn ceremony fixtures.
 *
 * Cross-refs: Plan T28 / spec §2.4 / S7 multi-origin
 */

import {
	createChallengeCeremony,
	createMemoryChallengeStore,
	createMemoryReplaySeenSet,
	createMemoryWebAuthnCredentialStore,
} from "@o3co/auth-provider-core";
import express from "express";
import supertest from "supertest";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { WebAuthnConfig } from "../config.mjs";
import type { WebAuthnSubject } from "../routes/registrationOptions.mjs";

// ---------------------------------------------------------------------------
// Mock verifyWebAuthnAttestation before importing the module under test
// ---------------------------------------------------------------------------
vi.mock("../internal/verification.mjs", () => ({
	verifyWebAuthnAttestation: vi.fn(),
	// verifyWebAuthnAssertion not needed by this endpoint
	verifyWebAuthnAssertion: vi.fn(),
}));

import { verifyWebAuthnAttestation } from "../internal/verification.mjs";
import { createRegistrationVerifyHandler } from "../routes/registrationVerify.mjs";

const mockVerifyAttestation = vi.mocked(verifyWebAuthnAttestation);

// ---------------------------------------------------------------------------
// Shared test fixtures
// ---------------------------------------------------------------------------

const BASE_CONFIG: WebAuthnConfig = {
	rpId: "test.example",
	rpName: "Test App",
	origin: ["https://test.example"],
	challengeTtlMs: 120_000,
	attestationPreference: "none",
	userVerification: "preferred",
};

const STUB_MATERIAL = {
	credentialId: "dGVzdC1jcmVkZW50aWFsLWlk",
	publicKey: new Uint8Array([1, 2, 3, 4]),
	signCount: 0,
	transports: ["internal" as const],
	backedUp: false,
};

/**
 * Build a minimal RegistrationResponseJSON stub whose clientDataJSON
 * encodes a valid base64url JSON containing the given challenge string.
 * The handler extracts the challenge from clientDataJSON to pass to
 * ChallengeCeremony.consume — stubs must carry the same value that
 * was issued to the ChallengeStore.
 */
function makeStubResponse(challenge: string) {
	const clientDataJSON = Buffer.from(
		JSON.stringify({ type: "webauthn.create", challenge, origin: "https://test.example" }),
	).toString("base64url");
	return {
		id: "dGVzdC1jcmVkZW50aWFsLWlk",
		rawId: "dGVzdC1jcmVkZW50aWFsLWlk",
		response: {
			clientDataJSON,
			attestationObject: "stub",
		},
		clientExtensionResults: {},
		type: "public-key" as const,
	};
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeDeps(challengeStore = createMemoryChallengeStore()) {
	const replaySeenSet = createMemoryReplaySeenSet();
	const challengeCeremony = createChallengeCeremony({ challengeStore, replaySeenSet });
	const credentialStore = createMemoryWebAuthnCredentialStore();
	return { challengeStore, challengeCeremony, credentialStore };
}

function buildApp(subject: WebAuthnSubject | undefined, deps = makeDeps()) {
	const app = express();
	app.use(express.json());

	// Simulate upstream auth middleware: attach (or omit) the authenticated subject
	app.use((req, _res, next) => {
		if (subject !== undefined) {
			req.webauthnSubject = subject;
		}
		next();
	});

	const handler = createRegistrationVerifyHandler({
		config: BASE_CONFIG,
		challengeCeremony: deps.challengeCeremony,
		credentialStore: deps.credentialStore,
	});

	app.post("/oauth/webauthn/registration/verify", handler);
	return { app, ...deps };
}

/** Issue a challenge for userId under the registration scope. */
async function issueChallenge(
	challengeStore: ReturnType<typeof createMemoryChallengeStore>,
	userId: string,
	value = "test-challenge-value",
) {
	await challengeStore.issue(`webauthn:registration:${userId}`, value, Date.now() + 120_000);
	return value;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

beforeEach(() => {
	vi.clearAllMocks();
});

describe("POST /oauth/webauthn/registration/verify (spec §2.4)", () => {
	// -------------------------------------------------------------------------
	// Test 1: 401 when no authenticated subject
	// -------------------------------------------------------------------------
	it("401 when no authenticated subject", async () => {
		const { app } = buildApp(undefined);

		// response shape irrelevant — 401 fires before clientDataJSON decode
		const res = await supertest(app)
			.post("/oauth/webauthn/registration/verify")
			.send({ response: makeStubResponse("any-challenge") });

		expect(res.status).toBe(401);
		expect(res.body).toMatchObject({ error: "unauthorized" });
	});

	// -------------------------------------------------------------------------
	// Test 2: Success path — 200 with credentialId/transports/backedUp
	// -------------------------------------------------------------------------
	it("200 on success: credentialStore.put called with full credential; response has credentialId/transports/backedUp", async () => {
		mockVerifyAttestation.mockResolvedValueOnce({ ok: true, material: STUB_MATERIAL });

		const deps = makeDeps();
		const challengeValue = await issueChallenge(deps.challengeStore, "alice");
		const putSpy = vi.spyOn(deps.credentialStore, "put");

		const { app } = buildApp({ userId: "alice" }, deps);

		const before = Date.now();
		const res = await supertest(app)
			.post("/oauth/webauthn/registration/verify")
			.send({ response: makeStubResponse(challengeValue) });
		const after = Date.now();

		expect(res.status).toBe(200);
		expect(res.body).toMatchObject({
			credentialId: STUB_MATERIAL.credentialId,
			transports: STUB_MATERIAL.transports,
			backedUp: STUB_MATERIAL.backedUp,
		});

		// credentialStore.put called once with full WebAuthnCredential
		expect(putSpy).toHaveBeenCalledOnce();
		const [stored] = putSpy.mock.calls[0] ?? [];
		expect(stored).toMatchObject({
			userId: "alice",
			credentialId: STUB_MATERIAL.credentialId,
			publicKey: STUB_MATERIAL.publicKey,
			signCount: STUB_MATERIAL.signCount,
			transports: STUB_MATERIAL.transports,
			backedUp: STUB_MATERIAL.backedUp,
		});
		// createdAt is a server-set Date, not from the request
		expect(stored?.createdAt).toBeInstanceOf(Date);
		expect(stored?.createdAt.getTime()).toBeGreaterThanOrEqual(before);
		expect(stored?.createdAt.getTime()).toBeLessThanOrEqual(after + 50);

		// verifyWebAuthnAttestation called with expectedChallenge = issued value
		expect(mockVerifyAttestation).toHaveBeenCalledOnce();
		const verifyArgs = mockVerifyAttestation.mock.calls[0]?.[0];
		expect(verifyArgs?.expectedChallenge).toBe(challengeValue);
		expect(verifyArgs?.expectedRpId).toBe(BASE_CONFIG.rpId);
		expect(verifyArgs?.expectedOrigins).toEqual(BASE_CONFIG.origin);
	});

	// -------------------------------------------------------------------------
	// Test 3: Challenge consumed (replay rejection)
	// -------------------------------------------------------------------------
	it("400 challenge_invalid on second call with the same challenge (replay)", async () => {
		mockVerifyAttestation.mockResolvedValue({ ok: true, material: STUB_MATERIAL });

		const deps = makeDeps();
		await issueChallenge(deps.challengeStore, "alice");

		const { app } = buildApp({ userId: "alice" }, deps);

		// First call — should consume the challenge
		const res1 = await supertest(app)
			.post("/oauth/webauthn/registration/verify")
			.send({ response: makeStubResponse("test-challenge-value") });
		expect(res1.status).toBe(200);

		// Second call — same challenge, already consumed; ceremony returns "replayed"
		const res2 = await supertest(app)
			.post("/oauth/webauthn/registration/verify")
			.send({ response: makeStubResponse("test-challenge-value") });
		expect(res2.status).toBe(400);
		expect(res2.body).toMatchObject({ error: "challenge_invalid" });
	});

	// -------------------------------------------------------------------------
	// Test 4: 400 challenge_invalid when no challenge exists (unknown)
	// -------------------------------------------------------------------------
	it("400 challenge_invalid when no challenge was issued (unknown outcome)", async () => {
		const { app } = buildApp({ userId: "alice" });
		// No challenge issued — ceremony returns "unknown"

		const res = await supertest(app)
			.post("/oauth/webauthn/registration/verify")
			.send({ response: makeStubResponse("never-issued-value") });

		expect(res.status).toBe(400);
		expect(res.body).toMatchObject({ error: "challenge_invalid" });
	});

	// -------------------------------------------------------------------------
	// Test 5: Attestation failure → 400 with reason
	// -------------------------------------------------------------------------
	it("400 with reason when verifyWebAuthnAttestation returns ok=false", async () => {
		mockVerifyAttestation.mockResolvedValueOnce({ ok: false, reason: "origin_mismatch" });

		const deps = makeDeps();
		const challengeValue = await issueChallenge(deps.challengeStore, "alice");

		const { app } = buildApp({ userId: "alice" }, deps);
		const res = await supertest(app)
			.post("/oauth/webauthn/registration/verify")
			.send({ response: makeStubResponse(challengeValue) });

		expect(res.status).toBe(400);
		expect(res.body).toMatchObject({ error: "origin_mismatch" });
	});

	// -------------------------------------------------------------------------
	// Test 6: Nickname too long → 400 invalid_request
	// -------------------------------------------------------------------------
	it("400 invalid_request when nickname exceeds 64 characters", async () => {
		const { app } = buildApp({ userId: "alice" });

		const longNickname = "a".repeat(65); // 65 chars — exceeds limit of 64
		// nickname validation fires before clientDataJSON decode
		const res = await supertest(app)
			.post("/oauth/webauthn/registration/verify")
			.send({ response: makeStubResponse("any"), nickname: longNickname });

		expect(res.status).toBe(400);
		expect(res.body).toMatchObject({ error: "invalid_request" });
	});

	// -------------------------------------------------------------------------
	// Test 7: Nickname empty string → 400 invalid_request
	// -------------------------------------------------------------------------
	it("400 invalid_request when nickname is an empty string", async () => {
		const { app } = buildApp({ userId: "alice" });

		// nickname validation fires before clientDataJSON decode
		const res = await supertest(app)
			.post("/oauth/webauthn/registration/verify")
			.send({ response: makeStubResponse("any"), nickname: "" });

		expect(res.status).toBe(400);
		expect(res.body).toMatchObject({ error: "invalid_request" });
	});

	// -------------------------------------------------------------------------
	// Test 8: Nickname at exactly 64 chars → accepted
	// -------------------------------------------------------------------------
	it("200 when nickname is exactly 64 characters (upper bound inclusive)", async () => {
		mockVerifyAttestation.mockResolvedValueOnce({ ok: true, material: STUB_MATERIAL });

		const deps = makeDeps();
		const challengeValue = await issueChallenge(deps.challengeStore, "alice");
		const putSpy = vi.spyOn(deps.credentialStore, "put");

		const { app } = buildApp({ userId: "alice" }, deps);

		const maxNickname = "a".repeat(64);
		const res = await supertest(app)
			.post("/oauth/webauthn/registration/verify")
			.send({ response: makeStubResponse(challengeValue), nickname: maxNickname });

		expect(res.status).toBe(200);
		// Nickname stored in the credential record
		const [stored] = putSpy.mock.calls[0] ?? [];
		expect(stored?.nickname).toBe(maxNickname);
	});

	// -------------------------------------------------------------------------
	// Test 9: userId in body ignored — session userId wins
	// -------------------------------------------------------------------------
	it("userId taken from authenticated session (req.webauthnSubject), NOT request body", async () => {
		mockVerifyAttestation.mockResolvedValueOnce({ ok: true, material: STUB_MATERIAL });

		const deps = makeDeps();
		// Challenge issued for "alice" (the session user)
		const challengeValue = await issueChallenge(deps.challengeStore, "alice");
		const putSpy = vi.spyOn(deps.credentialStore, "put");

		// Authenticated as "alice"
		const { app } = buildApp({ userId: "alice" }, deps);

		// Body contains userId: "victim" — must be ignored
		const res = await supertest(app)
			.post("/oauth/webauthn/registration/verify")
			.send({ response: makeStubResponse(challengeValue), userId: "victim" });

		expect(res.status).toBe(200);
		// Credential stored with userId from session, not body
		const [stored] = putSpy.mock.calls[0] ?? [];
		expect(stored?.userId).toBe("alice");
		expect(stored?.userId).not.toBe("victim");
	});
});
