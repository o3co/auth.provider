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
 * Cross-refs: Plan T29 / spec §2.4 / issue #281
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
	// #281: enumeration-resistant default — the endpoint never derives
	// allowCredentials from a body-supplied user id.
	allowCredentialsForKnownUser: false,
	rateLimit: {
		authenticationOptions: { limit: 30, windowSeconds: 60 },
	},
};

/** Config with the #281 escape hatch turned on (non-discoverable deployments). */
const OPT_IN_CONFIG: WebAuthnConfig = {
	...BASE_CONFIG,
	allowCredentialsForKnownUser: true,
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
	config: WebAuthnConfig = BASE_CONFIG,
) {
	const app = express();
	app.use(express.json());

	const handler = createAuthenticationOptionsHandler({
		config,
		challengeStore,
		credentialStore,
	});

	app.post("/oauth/webauthn/authentication/options", handler);
	return { app, challengeStore, credentialStore };
}

/** The challenge is fresh per request; everything else must be identical. */
function withoutChallenge(body: Record<string, unknown>): Record<string, unknown> {
	const { challenge: _challenge, ...rest } = body;
	return rest;
}

/** A credential store pre-seeded with two credentials for "alice". */
async function seededCredentialStore() {
	const credentialStore = createMemoryWebAuthnCredentialStore();
	await credentialStore.registerCredential(
		makeCredential({ credentialId: "Y3JlZC0x", userId: "alice" }),
	);
	await credentialStore.registerCredential(
		makeCredential({ credentialId: "Y3JlZC0y", userId: "alice" }),
	);
	return credentialStore;
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
});

// ---------------------------------------------------------------------------
// #281 — account enumeration via allowCredentials
// ---------------------------------------------------------------------------

describe("POST /oauth/webauthn/authentication/options — enumeration resistance (#281)", () => {
	it("never derives allowCredentials from a body-supplied userId by default", async () => {
		const credentialStore = await seededCredentialStore();
		const { app } = buildApp(createMemoryChallengeStore(), credentialStore);

		const res = await supertest(app)
			.post("/oauth/webauthn/authentication/options")
			.send({ userId: "alice" });

		expect(res.status).toBe(200);
		expect(res.body).not.toHaveProperty("allowCredentials");
	});

	it("returns a byte-identical body (modulo challenge) for a known user, an unknown user, and no userId", async () => {
		const credentialStore = await seededCredentialStore();
		const { app } = buildApp(createMemoryChallengeStore(), credentialStore);

		const post = (body: Record<string, unknown>) =>
			supertest(app).post("/oauth/webauthn/authentication/options").send(body);

		const known = await post({ userId: "alice" });
		const unknown = await post({ userId: "nobody-at-all" });
		const anonymous = await post({});

		for (const res of [known, unknown, anonymous]) {
			expect(res.status).toBe(200);
		}
		const knownBody = withoutChallenge(known.body);
		expect(withoutChallenge(unknown.body)).toEqual(knownBody);
		expect(withoutChallenge(anonymous.body)).toEqual(knownBody);
		// Shape uniformity is not enough on its own — the key set must match too.
		expect(Object.keys(unknown.body).sort()).toEqual(Object.keys(known.body).sort());
		expect(Object.keys(anonymous.body).sort()).toEqual(Object.keys(known.body).sort());
	});

	it("does not touch the credential store at all when the opt-in is off (no existence-dependent timing)", async () => {
		const credentialStore = await seededCredentialStore();
		const listSpy = vi.spyOn(credentialStore, "listByUserId");
		const { app } = buildApp(createMemoryChallengeStore(), credentialStore);

		await supertest(app).post("/oauth/webauthn/authentication/options").send({ userId: "alice" });
		await supertest(app).post("/oauth/webauthn/authentication/options").send({ userId: "nobody" });
		await supertest(app).post("/oauth/webauthn/authentication/options").send({});

		expect(listSpy).not.toHaveBeenCalled();
	});

	it("allowCredentialsForKnownUser: true → restores the allow-list flow for non-discoverable authenticators", async () => {
		const credentialStore = await seededCredentialStore();
		const { app } = buildApp(createMemoryChallengeStore(), credentialStore, OPT_IN_CONFIG);

		const res = await supertest(app)
			.post("/oauth/webauthn/authentication/options")
			.send({ userId: "alice" });

		expect(res.status).toBe(200);
		const body = res.body as { allowCredentials?: Array<{ id: string }> };
		expect(body.allowCredentials).toBeDefined();
		expect(body.allowCredentials).toHaveLength(2);
		expect((body.allowCredentials ?? []).map((c) => c.id).sort()).toEqual(["Y3JlZC0x", "Y3JlZC0y"]);
	});

	it("allowCredentialsForKnownUser: true + unknown user → still 200 with no error-shape leak", async () => {
		const { app } = buildApp(
			createMemoryChallengeStore(),
			createMemoryWebAuthnCredentialStore(),
			OPT_IN_CONFIG,
		);

		const res = await supertest(app)
			.post("/oauth/webauthn/authentication/options")
			.send({ userId: "unknown-user" });

		expect(res.status).toBe(200);
		const body = res.body as Record<string, unknown>;
		if ("allowCredentials" in body) {
			expect(body.allowCredentials).toEqual([]);
		}
		expect(body).not.toMatchObject({ error: expect.anything() });
	});

	it("allowCredentialsForKnownUser: true but no userId → discoverable flow (no store lookup)", async () => {
		const credentialStore = await seededCredentialStore();
		const listSpy = vi.spyOn(credentialStore, "listByUserId");
		const { app } = buildApp(createMemoryChallengeStore(), credentialStore, OPT_IN_CONFIG);

		const res = await supertest(app).post("/oauth/webauthn/authentication/options").send({});

		expect(res.status).toBe(200);
		expect(res.body).not.toHaveProperty("allowCredentials");
		expect(listSpy).not.toHaveBeenCalled();
	});
});

// ---------------------------------------------------------------------------
// #281 — unbounded user IDs
// ---------------------------------------------------------------------------

describe("POST /oauth/webauthn/authentication/options — userId bounds (#281)", () => {
	const post = (app: express.Express, body: unknown) =>
		supertest(app)
			.post("/oauth/webauthn/authentication/options")
			.send(body as object);

	it("invalid userId type (number) → 400 invalid_request", async () => {
		const { app } = buildApp();

		const res = await post(app, { userId: 123 });

		expect(res.status).toBe(400);
		expect(res.body).toMatchObject({ error: "invalid_request" });
	});

	it("rejects an over-long userId with 400 before any credential lookup", async () => {
		const credentialStore = await seededCredentialStore();
		const listSpy = vi.spyOn(credentialStore, "listByUserId");
		const { app } = buildApp(createMemoryChallengeStore(), credentialStore, OPT_IN_CONFIG);

		const res = await post(app, { userId: "a".repeat(65) });

		expect(res.status).toBe(400);
		expect(res.body).toMatchObject({ error: "invalid_request" });
		expect(listSpy).not.toHaveBeenCalled();
	});

	it("rejects a 100kb userId with 400 (the DoS shape the endpoint used to accept)", async () => {
		const challengeStore = createMemoryChallengeStore();
		const issueSpy = vi.spyOn(challengeStore, "issue");
		const { app } = buildApp(challengeStore);

		const res = await post(app, { userId: "x".repeat(100_000) });

		expect(res.status).toBe(400);
		// No challenge is minted for a rejected request.
		expect(issueSpy).not.toHaveBeenCalled();
	});

	it("accepts a userId of exactly 64 bytes", async () => {
		const { app } = buildApp();

		const res = await post(app, { userId: "b".repeat(64) });

		expect(res.status).toBe(200);
	});

	it("bounds by UTF-8 bytes, not by code units (WebAuthn §5.4.3)", async () => {
		const { app } = buildApp();

		// 32 × 2-byte characters = 64 bytes → accepted.
		const ok = await post(app, { userId: "é".repeat(32) });
		expect(ok.status).toBe(200);

		// 33 × 2-byte characters = 66 bytes → rejected, even though the string
		// is only 33 code units long.
		const tooLong = await post(app, { userId: "é".repeat(33) });
		expect(tooLong.status).toBe(400);
	});

	it("rejects an empty userId", async () => {
		const { app } = buildApp();

		const res = await post(app, { userId: "" });

		expect(res.status).toBe(400);
		expect(res.body).toMatchObject({ error: "invalid_request" });
	});

	it("rejects a userId carrying control characters", async () => {
		const { app } = buildApp();

		const res = await post(app, { userId: "alice\u0000admin" });

		expect(res.status).toBe(400);
		expect(res.body).toMatchObject({ error: "invalid_request" });
	});

	it("the rejection description does not depend on whether the account exists", async () => {
		const credentialStore = await seededCredentialStore();
		const { app } = buildApp(createMemoryChallengeStore(), credentialStore, OPT_IN_CONFIG);

		const knownButTooLong = await post(app, { userId: `alice${"!".repeat(64)}` });
		const unknownAndTooLong = await post(app, { userId: `zzzzz${"!".repeat(64)}` });

		expect(knownButTooLong.body).toEqual(unknownAndTooLong.body);
	});
});
