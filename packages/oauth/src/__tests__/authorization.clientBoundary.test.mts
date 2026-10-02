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
// logout URI in the session RP registry, and is answered as the store's
// outage is, with the refusal named as the cause.

import crypto from "node:crypto";
import {
	type AppConfig,
	type ClientRepository,
	type Code,
	type CodeRepository,
	createInMemorySessionFamilyIndex,
	createInMemorySessionRPRegistry,
	createInMemoryUserSessionStore,
	createMemoryRefreshTokenFamilyStore,
	createRefreshTokenFamilyRotation,
	createSymmetricKeyStore,
	type PublicClient,
	passwordSessionAuthentication,
	type RegisteredRP,
} from "@o3co/auth-provider-core";
import { makeValidAppConfig, resolverForTests } from "@o3co/auth-provider-core/testing";
import { describe, expect, it, vi } from "vitest";
import { createAuthorizationGrant } from "#/grants/authorization.mjs";
import { oauthConfigForTests } from "#/testing/index.mjs";
import { OAUTH_ADMISSION_ACTIONS } from "./_helpers/admissionActions.mjs";
import { codeRecord } from "./_helpers/codeRecord.mjs";
import { createMockLogger } from "./_helpers/mockLogger.mjs";
import { serialisedCalls } from "./_helpers/projectedLog.mjs";

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
 * A code exchange handler whose client lookup is `findById`, over a
 * single-use code store holding one code, with a refresh-token family
 * rotation whose `register` is a spy.
 */
const exchangeSetup = async (findById: ClientRepository["findById"]) => {
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
	const sessionRPRegistry = createInMemorySessionRPRegistry();
	let stored: Code | null = codeRecord({
		code: "abc",
		sid: SID,
		client_id: CLIENT_ID,
		redirect_uri: REDIRECT_URI,
		code_challenge: CHALLENGE,
		code_challenge_method: "S256",
	});
	const consumeByCode = vi.fn(async (code: string) => {
		if (stored === null || code !== stored.code) return null;
		const consumed = stored;
		stored = null;
		return consumed;
	});
	const codeRepository = {
		consumeByCode,
		createCode: vi.fn(),
		findByCode: vi.fn(),
		removeByCode: vi.fn(),
	} as unknown as CodeRepository;
	const rotation = createRefreshTokenFamilyRotation({
		refreshTokenFamilyStore: createMemoryRefreshTokenFamilyStore(),
		accessTokenHorizonMs: 3_600_000,
	});
	const register = vi.fn(rotation.register);
	const handler = createAuthorizationGrant({
		sessionRequirementResolver: resolverForTests([], { actions: OAUTH_ADMISSION_ACTIONS }),
		config,
		keyStore: createSymmetricKeyStore("test-secret"),
		codeRepository,
		clientRepository: { findById, authenticate: vi.fn().mockResolvedValue(null) },
		userSessionStore,
		sessionFamilyIndex: createInMemorySessionFamilyIndex(),
		sessionRPRegistry,
		refreshTokenFamilyRotation: { ...rotation, register },
		logger,
	});
	const exchange = async () => {
		const { result } = await handler.handle({
			body: {
				code: "abc",
				client_id: CLIENT_ID,
				redirect_uri: REDIRECT_URI,
				code_verifier: VERIFIER,
			},
			session: { code: "abc", user: { id: SUBJECT } },
			issuer: "localhost",
			metadata: { ip: "127.0.0.1" },
			authenticatedClient: { clientId: CLIENT_ID, tokenEndpointAuthMethod: "client_secret_basic" },
		});
		return result;
	};
	return { exchange, consumeByCode, register, sessionRPRegistry, logger };
};

/**
 * One code exchange whose `findById` is `findById`; what the session RP
 * registry holds for the session afterwards, the result and the logger.
 */
const exchangeWith = async (findById: ClientRepository["findById"]) => {
	const { exchange, sessionRPRegistry, logger } = await exchangeSetup(findById);
	const result = await exchange();
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
		[
			"a back-channel logout URI that is not http(s)",
			{ backchannelLogoutUri: "javascript:alert(1)" },
		],
		["a registered redirect URI with a fragment", { allowedRedirectUris: [`${REDIRECT_URI}#f`] }],
		["a clientId that is not the id looked up", { clientId: "another-client" }],
		["no token endpoint auth method", { tokenEndpointAuthMethod: undefined }],
	])(
		"answers 503 temporarily_unavailable and registers no RP, warning client_record_refused, for a record with %s",
		async (_label, change) => {
			const refused = await exchangeWith(
				async () => ({ ...validRecord, ...change }) as PublicClient,
			);

			// The refusal is the lookup's rejection, so the exchange answers it as
			// it answers a repository that throws, never as a client it does not
			// hold.
			expect(refused.result).toMatchObject({
				status: 503,
				error: "temporarily_unavailable",
				errorDescription: "session linking unavailable",
			});
			expect(refused.rps).toEqual([]);
			const warned = refused.logger.warn.mock.calls.filter(
				([, event]) => event === "client_record_refused",
			);
			expect(warned).toHaveLength(1);
			expect(warned[0]?.[0]).toMatchObject({ step: "find", clientId: CLIENT_ID });
			expect(refused.logger.error.mock.calls).toEqual([
				[
					expect.objectContaining({
						site: "authorization_code",
						step: "find",
						clientId: CLIENT_ID,
						err: expect.objectContaining({ reason: "client_record_refused" }),
					}),
					"client_repository_unavailable",
				],
			]);
			const logged = serialisedCalls(refused.logger);
			for (const uri of [FRONT, BACK, "javascript:alert(1)", REDIRECT_URI]) {
				expect(logged).not.toContain(uri);
			}
		},
	);

	it("registers an absent client's RP with no logout metadata, and issues tokens", async () => {
		const { result, rps, logger } = await exchangeWith(async () => null);

		expect(result.status).toBe(200);
		expect(rps.map(withoutRegisteredAt)).toEqual([{ clientId: CLIENT_ID }]);
		expect(logger.warn).not.toHaveBeenCalled();
	});

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

describe("createAuthorizationGrant — the client is looked up before the code is spent", () => {
	const refusedRecord = async () =>
		({ ...validRecord, backchannelLogoutUri: "javascript:alert(1)" }) as PublicClient;
	const outage = async (): Promise<PublicClient | null> => {
		throw new Error("db down");
	};

	it.each([
		["a record the boundary refuses", refusedRecord],
		["a repository that throws", outage],
	])(
		"leaves the code unspent and registers no refresh-token family for %s",
		async (_label, findById) => {
			const { exchange, consumeByCode, register } = await exchangeSetup(findById);

			const result = await exchange();

			expect(result).toMatchObject({
				status: 503,
				error: "temporarily_unavailable",
				errorDescription: "session linking unavailable",
			});
			expect(consumeByCode).not.toHaveBeenCalled();
			expect(register).not.toHaveBeenCalled();
		},
	);

	it("redeems the same code once the client's record is answered again", async () => {
		let lookup: ClientRepository["findById"] = refusedRecord;
		const { exchange, consumeByCode, register } = await exchangeSetup((id) => lookup(id));

		expect((await exchange()).status).toBe(503);
		lookup = async () => validRecord;
		const redeemed = await exchange();

		expect(redeemed.status).toBe(200);
		expect(consumeByCode).toHaveBeenCalledTimes(1);
		expect(register).toHaveBeenCalledTimes(1);
		// Single use: a second redemption after the success is refused.
		expect(await exchange()).toMatchObject({ status: 400, error: "invalid_grant" });
	});
});
