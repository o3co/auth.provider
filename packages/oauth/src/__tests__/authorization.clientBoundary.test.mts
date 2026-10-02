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

// The code exchange reads the client's logout metadata through core's
// client-record boundary: a record the registration schema refuses puts no
// logout URI in the session RP registry, as an unknown client does, and a
// read that throws is still an outage.

import crypto from "node:crypto";
import {
	type AppConfig,
	type ClientRepository,
	type CodeRepository,
	createInMemorySessionFamilyIndex,
	createInMemorySessionRPRegistry,
	createInMemoryUserSessionStore,
	createSymmetricKeyStore,
	type PublicClient,
	type RegisteredRP,
} from "@o3co/auth-provider-core";
import { makeValidAppConfig, resolverForTests } from "@o3co/auth-provider-core/testing";
import { describe, expect, it, vi } from "vitest";
import { createAuthorizationGrant } from "#/grants/authorization.mjs";
import { oauthConfigForTests } from "#/testing/index.mjs";
import { OAUTH_ADMISSION_ACTIONS } from "./_helpers/admissionActions.mjs";
import { createMockLogger } from "./_helpers/mockLogger.mjs";
import { expectUriNotLogged } from "./_helpers/projectedLog.mjs";

const CLIENT_ID = "client1";
const REDIRECT_URI = "https://rp.example/cb";
const SID = "session-xyz";
const SUBJECT = "u1";
const FRONT = "https://rp.example/front";
const BACK = "https://rp.example/back";
const VERIFIER = "pkce-verifier".padEnd(43, "x");
const CHALLENGE = crypto.createHash("sha256").update(VERIFIER).digest("base64url");

const config = { ...makeValidAppConfig(), ...oauthConfigForTests() } as AppConfig;

/** A record the registration schema accepts, carrying both logout URIs. */
const validRecord: PublicClient = {
	clientId: CLIENT_ID,
	tokenEndpointAuthMethod: "client_secret_basic",
	allowedRedirectUris: [REDIRECT_URI],
	allowedScopes: ["read"],
	backchannelLogoutUri: BACK,
	backchannelLogoutSessionRequired: false,
	frontchannelLogoutUri: FRONT,
	frontchannelLogoutSessionRequired: false,
};

/**
 * One code exchange whose `findById` is `findById`; what the session RP
 * registry holds for the session afterwards, the result and the logger.
 */
const exchangeWith = async (findById: ClientRepository["findById"]) => {
	const logger = createMockLogger();
	const userSessionStore = createInMemoryUserSessionStore();
	await userSessionStore.create({
		sid: SID,
		sub: SUBJECT,
		authTime: new Date(Date.now() - 60_000),
		expiresAt: new Date(Date.now() + 3_600_000),
		claims: {},
	});
	const sessionRPRegistry = createInMemorySessionRPRegistry();
	const codeRepository = {
		consumeByCode: vi.fn().mockResolvedValue({
			code: "abc",
			sid: SID,
			client_id: CLIENT_ID,
			redirect_uri: REDIRECT_URI,
			code_challenge: CHALLENGE,
			code_challenge_method: "S256",
		}),
		createCode: vi.fn(),
		findByCode: vi.fn(),
		removeByCode: vi.fn(),
	} as unknown as CodeRepository;
	const handler = createAuthorizationGrant({
		sessionRequirementResolver: resolverForTests([], { actions: OAUTH_ADMISSION_ACTIONS }),
		config,
		keyStore: createSymmetricKeyStore("test-secret"),
		codeRepository,
		clientRepository: { findById, authenticate: vi.fn().mockResolvedValue(null) },
		userSessionStore,
		sessionFamilyIndex: createInMemorySessionFamilyIndex(),
		sessionRPRegistry,
		logger,
	});
	const { result } = await handler.handle({
		body: { code: "abc", client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, code_verifier: VERIFIER },
		session: { code: "abc", user: { id: SUBJECT } },
		issuer: "localhost",
		metadata: { ip: "127.0.0.1" },
		authenticatedClient: { clientId: CLIENT_ID, tokenEndpointAuthMethod: "client_secret_basic" },
	});
	const rps = await sessionRPRegistry.listRPs(SID);
	return { result, rps, logger };
};

/** An RP entry without the instant it was registered at. */
const withoutRegisteredAt = ({ registeredAt: _at, ...rp }: RegisteredRP) => rp;

describe("createAuthorizationGrant — the client's logout metadata is read through core's boundary", () => {
	it("registers the logout URIs of a record the registration schema accepts", async () => {
		const { result, rps, logger } = await exchangeWith(async () => validRecord);

		expect(result.status).toBe(200);
		expect(rps.map(withoutRegisteredAt)).toEqual([
			{
				clientId: CLIENT_ID,
				backchannelLogoutUri: BACK,
				backchannelLogoutSessionRequired: false,
				frontchannelLogoutUri: FRONT,
				frontchannelLogoutSessionRequired: false,
			},
		]);
		expect(logger.warn).not.toHaveBeenCalled();
	});

	it.each([
		["a back-channel logout URI that is not http(s)", { backchannelLogoutUri: "javascript:alert(1)" }],
		["a registered redirect URI with a fragment", { allowedRedirectUris: [`${REDIRECT_URI}#f`] }],
		["a clientId that is not the id looked up", { clientId: "another-client" }],
		["no token endpoint auth method", { tokenEndpointAuthMethod: undefined }],
	])(
		"registers the RP as for an unknown client, and warns client_record_refused, for a record with %s",
		async (_label, change) => {
			const refused = await exchangeWith(async () => ({ ...validRecord, ...change }) as PublicClient);
			const absent = await exchangeWith(async () => null);

			expect(refused.result.status).toBe(200);
			expect(refused.rps.map(withoutRegisteredAt)).toEqual(absent.rps.map(withoutRegisteredAt));
			expect(refused.rps[0]?.frontchannelLogoutUri).toBeUndefined();
			expect(refused.rps[0]?.backchannelLogoutUri).toBeUndefined();
			const warned = refused.logger.warn.mock.calls.filter(
				([, event]) => event === "client_record_refused",
			);
			expect(warned).toHaveLength(1);
			expect(warned[0]?.[0]).toMatchObject({ step: "find", clientId: CLIENT_ID });
			expectUriNotLogged(refused.logger, FRONT);
			expectUriNotLogged(refused.logger, BACK);
		},
	);

	it("answers a repository that throws 503 temporarily_unavailable and registers no RP", async () => {
		const { result, rps, logger } = await exchangeWith(async () => {
			throw new Error("db down");
		});

		expect(result).toMatchObject({
			status: 503,
			error: "temporarily_unavailable",
			errorDescription: "session linking unavailable",
		});
		expect(rps).toEqual([]);
		expect(logger.error.mock.calls.map(([, event]) => event)).toContain(
			"client_repository_unavailable",
		);
	});
});
