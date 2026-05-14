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
 * Tests for POST /oauth/webauthn/authentication/options endpoint (spec §2.4).
 *
 * Uses supertest + express for HTTP-level testing. Memory adapters from
 * @o3co/auth-provider-core are used for ChallengeStore and
 * WebAuthnCredentialStore — no hand-rolled stubs.
 *
 * Uses real generateAuthenticationOptionsForUser (T26) — it is a pure
 * function and requires no mocking.
 *
 * Cross-refs: Plan T29 / spec §2.4
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
import { createAuthenticationOptionsHandler } from "../routes/authenticationOptions.mjs";

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
// Test setup helper
// ---------------------------------------------------------------------------

function buildApp(
	challengeStore = createMemoryChallengeStore(),
	credentialStore = createMemoryWebAuthnCredentialStore(),
) {
	const app = express();
	app.use(express.json());

	const handler = createAuthenticationOptionsHandler({
		config: BASE_CONFIG,
		challengeStore,
		credentialStore,
	});

	app.post("/oauth/webauthn/authentication/options", handler);
	return { app, challengeStore, credentialStore };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("POST /oauth/webauthn/authentication/options (spec §2.4)", () => {
	it("no userId in body → discoverable flow: empty/absent allowCredentials, challenge stored under webauthn:authentication", async () => {
		const challengeStore = createMemoryChallengeStore();
		const issueSpy = vi.spyOn(challengeStore, "issue");
		const { app } = buildApp(challengeStore);

		const res = await supertest(app).post("/oauth/webauthn/authentication/options").send({});

		expect(res.status).toBe(200);
		// Discoverable flow: allowCredentials should be absent or empty
		const body = res.body as Record<string, unknown>;
		if ("allowCredentials" in body) {
			expect(body.allowCredentials).toEqual([]);
		}
		// challenge is a base64url string
		expect(typeof body.challenge).toBe("string");
		expect((body.challenge as string).length).toBeGreaterThan(0);

		// Challenge must be stored under the non-user-scoped namespace
		expect(issueSpy).toHaveBeenCalledOnce();
		const [scope, , expiresAtMs] = issueSpy.mock.calls[0] ?? [];
		expect(scope).toBe("webauthn:authentication");
		expect(expiresAtMs).toBeGreaterThan(Date.now());
		expect(expiresAtMs).toBeLessThanOrEqual(Date.now() + BASE_CONFIG.challengeTtlMs + 200);
	});

	it("userId in body → allowCredentials populated with user's credentials", async () => {
		const credentialStore = createMemoryWebAuthnCredentialStore();
		const cred1 = makeCredential({ credentialId: "Y3JlZC0x", userId: "alice" });
		const cred2 = makeCredential({ credentialId: "Y3JlZC0y", userId: "alice" });
		await credentialStore.put(cred1);
		await credentialStore.put(cred2);

		const { app } = buildApp(createMemoryChallengeStore(), credentialStore);

		const res = await supertest(app)
			.post("/oauth/webauthn/authentication/options")
			.send({ userId: "alice" });

		expect(res.status).toBe(200);
		const body = res.body as { allowCredentials?: Array<{ id: string }> };
		expect(body.allowCredentials).toBeDefined();
		expect(body.allowCredentials).toHaveLength(2);
		const ids = (body.allowCredentials ?? []).map((c) => c.id);
		expect(ids).toContain("Y3JlZC0x");
		expect(ids).toContain("Y3JlZC0y");
	});

	it("userId in body but no credentials → empty allowCredentials (existence-leak mitigation, no 404)", async () => {
		const { app } = buildApp();

		const res = await supertest(app)
			.post("/oauth/webauthn/authentication/options")
			.send({ userId: "unknown-user" });

		// MUST succeed with 200 — no existence leak via 404 or error body
		expect(res.status).toBe(200);
		const body = res.body as Record<string, unknown>;
		// allowCredentials must be absent or empty — never an error response
		if ("allowCredentials" in body) {
			expect(body.allowCredentials).toEqual([]);
		}
		expect(body).not.toMatchObject({ error: expect.anything() });
	});

	it("challenge stored under scope 'webauthn:authentication' (not user-scoped) regardless of userId", async () => {
		const challengeStore = createMemoryChallengeStore();
		const issueSpy = vi.spyOn(challengeStore, "issue");
		const { app } = buildApp(challengeStore);

		await supertest(app).post("/oauth/webauthn/authentication/options").send({ userId: "alice" });

		expect(issueSpy).toHaveBeenCalledOnce();
		const [scope] = issueSpy.mock.calls[0] ?? [];
		// Must be the fixed, non-user-scoped namespace — userId resolved post-assertion
		expect(scope).toBe("webauthn:authentication");
		expect(scope).not.toContain("alice");
	});

	it("invalid userId type (number) → 400 invalid_request", async () => {
		const { app } = buildApp();

		const res = await supertest(app)
			.post("/oauth/webauthn/authentication/options")
			.send({ userId: 123 });

		expect(res.status).toBe(400);
		expect(res.body).toMatchObject({ error: "invalid_request" });
	});
});
