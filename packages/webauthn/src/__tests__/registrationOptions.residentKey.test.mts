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
 * What the grant's registration route asks an authenticator for: a
 * discoverable credential, preferred — the passkey its passwordless grant
 * signs in with (WebAuthn Level 3 §5.4.6).
 */

import {
	createMemoryChallengeStore,
	createMemoryWebAuthnCredentialStore,
} from "@o3co/auth-provider-core";
import express from "express";
import supertest from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createRegistrationOptionsHandler } from "#/routes/registrationOptions.mjs";
import { createTestWebAuthnConfig } from "#/testing/index.mjs";

describe("POST /oauth/webauthn/registration/options — the resident key", () => {
	it("asks for a discoverable credential, preferred", async () => {
		const app = express();
		app.use(express.json());
		app.use((req, _res, next) => {
			req.webauthnSubject = { userId: "u-alice" };
			next();
		});
		app.post(
			"/options",
			createRegistrationOptionsHandler({
				config: createTestWebAuthnConfig(),
				challengeStore: createMemoryChallengeStore(),
				credentialStore: createMemoryWebAuthnCredentialStore(),
				logger: { error: vi.fn() },
			}),
		);

		const res = await supertest(app).post("/options").send({});

		expect(res.status).toBe(200);
		expect(res.body.authenticatorSelection).toMatchObject({
			residentKey: "preferred",
			requireResidentKey: false,
		});
	});
});
