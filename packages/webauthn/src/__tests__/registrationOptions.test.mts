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
 * Tests for POST /oauth/webauthn/registration/options endpoint (spec §2.4).
 *
 * Uses supertest + express for HTTP-level testing. Memory adapters from
 * @o3co/auth-provider-core are used for ChallengeStore and
 * WebAuthnCredentialStore — no hand-rolled stubs.
 *
 * Cross-refs: Plan T27 / spec §2.4
 */

import {
	createMemoryChallengeStore,
	createMemoryWebAuthnCredentialStore,
	type WebAuthnCredential,
} from "@o3co/auth-provider-core";
import express from "express";
import supertest from "supertest";
import { describe, expect, it, vi } from "vitest";
import type { WebAuthnConfig } from "../config.mjs";
import {
	createRegistrationOptionsHandler,
	type WebAuthnSubject,
} from "../routes/registrationOptions.mjs";

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

function makeCredential(overrides?: Partial<WebAuthnCredential>): WebAuthnCredential {
	return {
		credentialId: "dGVzdC1jcmVkZW50aWFsLWlk",
		publicKey: new Uint8Array(64),
		signCount: 0,
		transports: ["internal"],
		backedUp: false,
		userId: "alice",
		...overrides,
	};
}

// ---------------------------------------------------------------------------
// Test setup helpers
// ---------------------------------------------------------------------------

function buildApp(
	subject: WebAuthnSubject | undefined,
	challengeStore = createMemoryChallengeStore(),
	credentialStore = createMemoryWebAuthnCredentialStore(),
) {
	const app = express();
	app.use(express.json());

	// Simulate upstream auth middleware: attach (or omit) the authenticated subject
	app.use((req, _res, next) => {
		if (subject !== undefined) {
			req.webauthnSubject = subject;
		}
		next();
	});

	const handler = createRegistrationOptionsHandler({
		config: BASE_CONFIG,
		challengeStore,
		credentialStore,
	});

	app.post("/oauth/webauthn/registration/options", handler);
	return { app, challengeStore, credentialStore };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("POST /oauth/webauthn/registration/options (spec §2.4)", () => {
	it("401 when no authenticated subject", async () => {
		const { app } = buildApp(undefined);

		const res = await supertest(app).post("/oauth/webauthn/registration/options").send({});

		expect(res.status).toBe(401);
		expect(res.body).toMatchObject({ error: "unauthorized" });
	});

	it("200 returns PublicKeyCredentialCreationOptions; challenge stored under webauthn:registration:<userId>", async () => {
		const challengeStore = createMemoryChallengeStore();
		const issueSpy = vi.spyOn(challengeStore, "issue");

		const { app } = buildApp(
			{ userId: "alice", userName: "alice@example.com", userDisplayName: "Alice" },
			challengeStore,
		);

		const res = await supertest(app).post("/oauth/webauthn/registration/options").send({});

		expect(res.status).toBe(200);
		// Verify PublicKeyCredentialCreationOptions structure
		expect(res.body).toMatchObject({
			rp: { id: "test.example", name: "Test App" },
			user: expect.objectContaining({ name: "alice@example.com", displayName: "Alice" }),
			challenge: expect.any(String),
			pubKeyCredParams: expect.any(Array),
		});
		expect(res.body.pubKeyCredParams.length).toBeGreaterThan(0);

		// Verify challengeStore.issue was called with correct scope and challenge value
		expect(issueSpy).toHaveBeenCalledOnce();
		const firstCall = issueSpy.mock.calls[0];
		expect(firstCall).toBeDefined();
		const [scope, value, expiresAtMs] = firstCall ?? [];
		expect(scope).toBe("webauthn:registration:alice");
		expect(typeof value).toBe("string");
		expect((value as string).length).toBeGreaterThan(0);
		// The challenge in the response should match what was stored
		expect(res.body.challenge).toBe(value);
		// expiresAtMs should be approximately now + challengeTtlMs
		expect(expiresAtMs).toBeGreaterThan(Date.now());
		expect(expiresAtMs).toBeLessThanOrEqual(Date.now() + BASE_CONFIG.challengeTtlMs + 100);
	});

	it("excludeCredentials populated from credentialStore.listByUserId", async () => {
		const credentialStore = createMemoryWebAuthnCredentialStore();
		const cred1 = makeCredential({ credentialId: "Y3JlZC0x", userId: "alice" });
		const cred2 = makeCredential({ credentialId: "Y3JlZC0y", userId: "alice" });
		await credentialStore.put(cred1);
		await credentialStore.put(cred2);

		const { app } = buildApp(
			{ userId: "alice", userName: "alice@example.com", userDisplayName: "Alice" },
			createMemoryChallengeStore(),
			credentialStore,
		);

		const res = await supertest(app).post("/oauth/webauthn/registration/options").send({});

		expect(res.status).toBe(200);
		expect(res.body.excludeCredentials).toHaveLength(2);
		const ids = (res.body.excludeCredentials as Array<{ id: string }>).map((c) => c.id);
		expect(ids).toContain("Y3JlZC0x");
		expect(ids).toContain("Y3JlZC0y");
	});

	it("userId taken from authenticated session, NOT request body", async () => {
		const challengeStore = createMemoryChallengeStore();
		const issueSpy = vi.spyOn(challengeStore, "issue");

		const { app } = buildApp(
			// Authenticated session says "alice"
			{ userId: "alice", userName: "alice@example.com", userDisplayName: "Alice" },
			challengeStore,
		);

		// Request body tries to inject "victim"
		const res = await supertest(app)
			.post("/oauth/webauthn/registration/options")
			.send({ userId: "victim" }); // intentional chain-split: send payload differs from empty

		expect(res.status).toBe(200);
		// Challenge must be scoped to "alice", NOT "victim"
		expect(issueSpy).toHaveBeenCalledOnce();
		const firstCall = issueSpy.mock.calls[0];
		expect(firstCall).toBeDefined();
		const [scope] = firstCall ?? [];
		expect(scope).toBe("webauthn:registration:alice");
		expect(scope).not.toContain("victim");
	});
});
