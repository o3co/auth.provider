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
 * Tests for generateRegistrationOptionsForUser + generateAuthenticationOptionsForUser (spec §2.4).
 *
 * No mocks — uses real @simplewebauthn/server invocation. These helpers are pure
 * functions returning deterministic JSON shapes; the real library call exercises
 * the mapping layer (rpId, challenge encoding, excludeCredentials, attestationType,
 * userVerification, discoverable-credential flow).
 *
 * Cross-refs: Plan T26 / spec §2.4
 */

import type { WebAuthnCredential } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import type { WebAuthnConfig } from "../config.mjs";
import {
	generateAuthenticationOptionsForUser,
	generateRegistrationOptionsForUser,
} from "../internal/options.mjs";

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

function makeChallenge(): Uint8Array<ArrayBuffer> {
	return crypto.getRandomValues(new Uint8Array(32));
}

function makeCredential(overrides?: Partial<WebAuthnCredential>): WebAuthnCredential {
	return {
		credentialId: "dGVzdC1jcmVkZW50aWFsLWlk", // base64url of "test-credential-id"
		publicKey: new Uint8Array(64),
		signCount: 0,
		transports: ["internal"],
		backedUp: false,
		userId: "user-1",
		...overrides,
	};
}

// ---------------------------------------------------------------------------
// generateRegistrationOptionsForUser
// ---------------------------------------------------------------------------

describe("generateRegistrationOptionsForUser (spec §2.4)", () => {
	it("sets rpId and rpName from config", async () => {
		const result = await generateRegistrationOptionsForUser({
			config: BASE_CONFIG,
			userId: "user-1",
			userName: "alice@example.com",
			userDisplayName: "Alice",
			excludeCredentials: [],
			challenge: makeChallenge(),
		});

		expect(result.rp.id).toBe("test.example");
		expect(result.rp.name).toBe("Test App");
	});

	it("encodes userId as base64url Uint8Array", async () => {
		const userId = "user-abc-123";
		const result = await generateRegistrationOptionsForUser({
			config: BASE_CONFIG,
			userId,
			userName: "alice@example.com",
			userDisplayName: "Alice",
			excludeCredentials: [],
			challenge: makeChallenge(),
		});

		// SimpleWebAuthn encodes userID as base64url in the returned JSON.
		// TextEncoder produces UTF-8 bytes; Buffer.from encodes those to base64url.
		const expectedId = Buffer.from(new TextEncoder().encode(userId)).toString("base64url");
		expect(result.user.id).toBe(expectedId);
	});

	it("honours excludeCredentials — passes 2 fake credentials", async () => {
		const cred1 = makeCredential({ credentialId: "Y3JlZC0x" });
		const cred2 = makeCredential({ credentialId: "Y3JlZC0y" });

		const result = await generateRegistrationOptionsForUser({
			config: BASE_CONFIG,
			userId: "user-1",
			userName: "alice@example.com",
			userDisplayName: "Alice",
			excludeCredentials: [cred1, cred2],
			challenge: makeChallenge(),
		});

		expect(result.excludeCredentials).toHaveLength(2);
		const ids = result.excludeCredentials?.map((c) => c.id);
		expect(ids).toContain("Y3JlZC0x");
		expect(ids).toContain("Y3JlZC0y");
	});

	it("passes attestationPreference='none' through to returned attestation", async () => {
		const result = await generateRegistrationOptionsForUser({
			config: { ...BASE_CONFIG, attestationPreference: "none" },
			userId: "user-1",
			userName: "alice@example.com",
			userDisplayName: "Alice",
			excludeCredentials: [],
			challenge: makeChallenge(),
		});

		expect(result.attestation).toBe("none");
	});

	it("passes attestationPreference='direct' through to returned attestation", async () => {
		const result = await generateRegistrationOptionsForUser({
			config: { ...BASE_CONFIG, attestationPreference: "direct" },
			userId: "user-1",
			userName: "alice@example.com",
			userDisplayName: "Alice",
			excludeCredentials: [],
			challenge: makeChallenge(),
		});

		expect(result.attestation).toBe("direct");
	});

	it("maps attestationPreference='indirect' to 'none' (SimpleWebAuthn v13 dropped indirect)", async () => {
		const result = await generateRegistrationOptionsForUser({
			config: { ...BASE_CONFIG, attestationPreference: "indirect" },
			userId: "user-1",
			userName: "alice@example.com",
			userDisplayName: "Alice",
			excludeCredentials: [],
			challenge: makeChallenge(),
		});

		// SimpleWebAuthn v13.1.1 does not accept "indirect" in its server API;
		// the helper maps it to "none".
		expect(result.attestation).toBe("none");
	});

	it("challenge bytes round-trip via base64url", async () => {
		const challengeBytes = makeChallenge();
		const result = await generateRegistrationOptionsForUser({
			config: BASE_CONFIG,
			userId: "user-1",
			userName: "alice@example.com",
			userDisplayName: "Alice",
			excludeCredentials: [],
			challenge: challengeBytes,
		});

		// SimpleWebAuthn encodes the challenge as base64url in the JSON response.
		const expectedChallenge = Buffer.from(challengeBytes).toString("base64url");
		expect(result.challenge).toBe(expectedChallenge);
	});
});

// ---------------------------------------------------------------------------
// generateAuthenticationOptionsForUser
// ---------------------------------------------------------------------------

describe("generateAuthenticationOptionsForUser (spec §2.4)", () => {
	it("sets rpId from config", async () => {
		const result = await generateAuthenticationOptionsForUser({
			config: BASE_CONFIG,
			allowCredentials: [],
			challenge: makeChallenge(),
		});

		expect(result.rpId).toBe("test.example");
	});

	it("empty allowCredentials → discoverable flow (allowCredentials absent or undefined)", async () => {
		const result = await generateAuthenticationOptionsForUser({
			config: BASE_CONFIG,
			allowCredentials: [],
			challenge: makeChallenge(),
		});

		// Discoverable credentials: no allowCredentials in the JSON.
		expect(result.allowCredentials == null || result.allowCredentials?.length === 0).toBe(true);
	});

	it("non-empty allowCredentials → honoured in returned JSON", async () => {
		const cred = makeCredential({ credentialId: "Y3JlZC0x" });

		const result = await generateAuthenticationOptionsForUser({
			config: BASE_CONFIG,
			allowCredentials: [cred],
			challenge: makeChallenge(),
		});

		expect(result.allowCredentials).toHaveLength(1);
		expect(result.allowCredentials?.[0].id).toBe("Y3JlZC0x");
	});

	it("passes userVerification='required' from config", async () => {
		const result = await generateAuthenticationOptionsForUser({
			config: { ...BASE_CONFIG, userVerification: "required" },
			allowCredentials: [],
			challenge: makeChallenge(),
		});

		expect(result.userVerification).toBe("required");
	});

	it("challenge bytes round-trip via base64url", async () => {
		const challengeBytes = makeChallenge();
		const result = await generateAuthenticationOptionsForUser({
			config: BASE_CONFIG,
			allowCredentials: [],
			challenge: challengeBytes,
		});

		const expectedChallenge = Buffer.from(challengeBytes).toString("base64url");
		expect(result.challenge).toBe(expectedChallenge);
	});
});
