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

// A code exchange that throws after its refresh-token family is registered
// revokes that family before the throw leaves the grant, so no family whose
// tokens were never served is left live outside the session's index. The
// throw reaches the terminal handler, which answers without its message.

import crypto from "node:crypto";
import {
	type AppConfig,
	type CodeRepository,
	createInMemorySessionFamilyIndex,
	createInMemorySessionRPRegistry,
	createInMemoryUserSessionStore,
	createMemoryRefreshTokenFamilyStore,
	createRefreshTokenFamilyRotation,
	createSymmetricKeyStore,
	type PublicClient,
	passwordSessionAuthentication,
	type RefreshTokenFamilyRevocation,
	terminalErrorHandler,
} from "@o3co/auth-provider-core";
import { makeValidAppConfig, resolverForTests } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createAuthorizationGrant } from "#/grants/authorization.mjs";
import { joinSession } from "#/logout/sessionEnd.mjs";
import { createTokenHandler } from "#/routes/token.mjs";
import { oauthConfigForTests } from "#/testing/index.mjs";
import { OAUTH_ADMISSION_ACTIONS } from "./_helpers/admissionActions.mjs";
import { codeRecord } from "./_helpers/codeRecord.mjs";
import { createMockLogger } from "./_helpers/mockLogger.mjs";

vi.mock("#/logout/sessionEnd.mjs", async (importOriginal) => {
	const original = await importOriginal<typeof import("#/logout/sessionEnd.mjs")>();
	return { ...original, joinSession: vi.fn(original.joinSession) };
});

const CLIENT_ID = "client1";
const REDIRECT_URI = "https://rp.example/cb";
const SID = "session-xyz";
const SUBJECT = "u1";
const VERIFIER = "pkce-verifier".padEnd(43, "x");
const CHALLENGE = crypto.createHash("sha256").update(VERIFIER).digest("base64url");
const INTERNAL = "internal detail: redis://user:secret@10.0.0.7";

const config = { ...makeValidAppConfig(), ...oauthConfigForTests() } as AppConfig;

const client: PublicClient = {
	clientId: CLIENT_ID,
	tokenEndpointAuthMethod: "client_secret_basic",
	allowedRedirectUris: [REDIRECT_URI],
	allowedScopes: ["read"],
	allowedGrantTypes: ["authorization_code"],
};

describe("createAuthorizationGrant — a throw after the family is registered", () => {
	it("revokes the registered family, and the token endpoint answers 500 without the throw's message", async () => {
		vi.mocked(joinSession).mockRejectedValueOnce(new Error(INTERNAL));
		const logger = createMockLogger();
		const userSessionStore = createInMemoryUserSessionStore();
		await userSessionStore.create({
			sid: SID,
			sub: SUBJECT,
			authTime: new Date(Date.now() - 60_000),
			expiresAt: new Date(Date.now() + 3_600_000),
			claims: {},
			...passwordSessionAuthentication(),
		});
		const rotation = createRefreshTokenFamilyRotation({
			refreshTokenFamilyStore: createMemoryRefreshTokenFamilyStore(),
			accessTokenHorizonMs: 3_600_000,
		});
		const register = vi.fn(rotation.register);
		const revokeFamily = vi.fn(async () => {});
		const handler = createAuthorizationGrant({
			sessionRequirementResolver: resolverForTests([], { actions: OAUTH_ADMISSION_ACTIONS }),
			config,
			keyStore: createSymmetricKeyStore("test-secret"),
			codeRepository: {
				consumeByCode: vi.fn(async () =>
					codeRecord({
						code: "abc",
						sid: SID,
						client_id: CLIENT_ID,
						redirect_uri: REDIRECT_URI,
						code_challenge: CHALLENGE,
						code_challenge_method: "S256",
					}),
				),
				createCode: vi.fn(),
				findByCode: vi.fn(),
				removeByCode: vi.fn(),
			} as unknown as CodeRepository,
			clientRepository: { findById: async () => client, authenticate: async () => null },
			userSessionStore,
			sessionFamilyIndex: createInMemorySessionFamilyIndex(),
			sessionRPRegistry: createInMemorySessionRPRegistry(),
			refreshTokenFamilyRotation: { ...rotation, register },
			refreshTokenFamilyRevocation: { revokeFamily } as unknown as RefreshTokenFamilyRevocation,
			logger,
		});

		const app = express();
		app.use(express.urlencoded({ extended: true }));
		app.use((req, _res, next) => {
			(req as unknown as { session: Record<string, unknown> }).session = {};
			(req as unknown as { oauthClient: PublicClient }).oauthClient = client;
			next();
		});
		app.post(
			"/token",
			createTokenHandler({
				registry: { get: () => handler },
				options: { requireGrantTypeAllowlist: false },
				canonicalIssuer: "https://issuer.test",
				auditSink: undefined,
				logger,
			}),
		);
		app.use(terminalErrorHandler(logger));

		const res = await request(app).post("/token").type("form").send({
			grant_type: "authorization_code",
			code: "abc",
			redirect_uri: REDIRECT_URI,
			code_verifier: VERIFIER,
		});

		expect(res.status).toBe(500);
		expect(res.body).toEqual({ error: "server_error", error_description: "unexpected_error" });
		expect(res.text).not.toContain("secret");
		expect(register).toHaveBeenCalledTimes(1);
		const familyId = register.mock.calls[0]?.[1];
		expect(revokeFamily).toHaveBeenCalledTimes(1);
		expect(revokeFamily).toHaveBeenCalledWith(familyId);
	});
});
