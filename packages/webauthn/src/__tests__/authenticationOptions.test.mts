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
 * Tests for the POST /oauth/webauthn/authentication/options endpoint, over
 * HTTP with supertest + express. The ChallengeStore is core's memory adapter,
 * not a hand-rolled stub, and generateAuthenticationOptionsForUser is the real
 * one: a pure function.
 */

import { createMemoryChallengeStore } from "@o3co/auth-provider-core";
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

// ---------------------------------------------------------------------------
// Test setup helper
// ---------------------------------------------------------------------------

function buildApp(challengeStore = createMemoryChallengeStore()) {
	const app = express();
	app.use(express.json());

	const handler = createAuthenticationOptionsHandler({
		config: BASE_CONFIG,
		challengeStore,
		logger: { error: vi.fn() },
	});

	app.post("/oauth/webauthn/authentication/options", handler);
	return { app, challengeStore };
}

/** The challenge is fresh per request; everything else must be identical. */
function withoutChallenge(body: Record<string, unknown>): Record<string, unknown> {
	const { challenge: _challenge, ...rest } = body;
	return rest;
}

const post = (app: express.Express, body: unknown) =>
	supertest(app)
		.post("/oauth/webauthn/authentication/options")
		.send(body as object);

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("POST /oauth/webauthn/authentication/options", () => {
	it("answers the discoverable flow: no allowCredentials, challenge stored under webauthn:authentication", async () => {
		const challengeStore = createMemoryChallengeStore();
		const issueSpy = vi.spyOn(challengeStore, "issue");
		const { app } = buildApp(challengeStore);

		const res = await post(app, {});

		expect(res.status).toBe(200);
		const body = res.body as Record<string, unknown>;
		expect(body).not.toHaveProperty("allowCredentials");
		expect(typeof body.challenge).toBe("string");
		expect((body.challenge as string).length).toBeGreaterThan(0);

		// Stored under the non-user-scoped namespace.
		expect(issueSpy).toHaveBeenCalledOnce();
		const [scope, , expiresAtMs] = issueSpy.mock.calls[0] ?? [];
		expect(scope).toBe("webauthn:authentication");
		expect(expiresAtMs).toBeGreaterThan(Date.now());
		expect(expiresAtMs).toBeLessThanOrEqual(Date.now() + BASE_CONFIG.challengeTtlMs + 200);
	});

	it("records when it issued the challenge: the instant its expiry is one challenge lifetime after", async () => {
		const challengeStore = createMemoryChallengeStore();
		const issueSpy = vi.spyOn(challengeStore, "issue");
		const { app } = buildApp(challengeStore);
		const before = Date.now();

		await post(app, {});

		const [, challenge, expiresAtMs, issuedAtMs] = issueSpy.mock.calls[0] ?? [];
		expect(typeof issuedAtMs).toBe("number");
		expect(issuedAtMs).toBeGreaterThanOrEqual(before);
		expect(issuedAtMs).toBeLessThanOrEqual(Date.now());
		expect(expiresAtMs).toBe((issuedAtMs as number) + BASE_CONFIG.challengeTtlMs);
		expect(
			(await challengeStore.find("webauthn:authentication", challenge as string))?.issuedAtMs,
		).toBe(issuedAtMs);
	});

	it("stores the challenge under 'webauthn:authentication' whatever the body names", async () => {
		const challengeStore = createMemoryChallengeStore();
		const issueSpy = vi.spyOn(challengeStore, "issue");
		const { app } = buildApp(challengeStore);

		await post(app, { userId: "alice" });

		expect(issueSpy).toHaveBeenCalledOnce();
		const [scope] = issueSpy.mock.calls[0] ?? [];
		expect(scope).toBe("webauthn:authentication");
		expect(scope).not.toContain("alice");
	});
});

// ---------------------------------------------------------------------------
// Account enumeration via allowCredentials
// ---------------------------------------------------------------------------

describe("POST /oauth/webauthn/authentication/options — enumeration resistance", () => {
	it("answers an identical body (modulo challenge) whatever the body names, the body unread", async () => {
		const { app } = buildApp();

		const answers = await Promise.all(
			[{ userId: "alice" }, { userId: "nobody-at-all" }, {}, { userId: 123 }, { userId: "" }].map(
				(body) => post(app, body),
			),
		);

		const first = answers[0];
		if (first === undefined) throw new Error("no answer");
		for (const res of answers) {
			expect(res.status).toBe(200);
			expect(withoutChallenge(res.body)).toEqual(withoutChallenge(first.body));
			expect(Object.keys(res.body).sort()).toEqual(Object.keys(first.body).sort());
		}
	});
});
