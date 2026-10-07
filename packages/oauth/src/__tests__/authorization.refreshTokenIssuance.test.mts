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
 * The code exchange issues a refresh token only where the client can redeem
 * one: the `refresh_token` grant is registered in the composition, and
 * `/oauth/token`'s dispatch would let this client use it. Otherwise the
 * response carries no `refresh_token`, no family is registered, the access
 * token carries no `family_id`, and the session is joined by the client
 * alone.
 *
 * Driven through the token endpoint's dispatch, with the grant's real family
 * rotation; the session lifecycle records each join.
 */

import crypto from "node:crypto";
import {
	type AppConfig,
	type CodeRepository,
	createInMemoryUserSessionStore,
	createMemoryRefreshTokenFamilyStore,
	createRefreshTokenFamilyRotation,
	createSymmetricKeyStore,
	type GrantHandler,
	type PublicClient,
	passwordSessionAuthentication,
	type RefreshTokenFamilyRevocation,
	terminalErrorHandler,
} from "@o3co/auth-provider-core";
import {
	GrantRegistry,
	makeValidAppConfig,
	resolverForTests,
} from "@o3co/auth-provider-core/testing";
import express from "express";
import { decodeJwt } from "jose";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createAuthorizationGrant } from "#/grants/authorization.mjs";
import { createTokenHandler } from "#/routes/token.mjs";
import { oauthConfigForTests } from "#/testing/index.mjs";
import { OAUTH_ADMISSION_ACTIONS } from "./_helpers/admissionActions.mjs";
import { codeRecord } from "./_helpers/codeRecord.mjs";
import { grantSettingsFrom } from "./_helpers/grantSettings.mjs";
import { createMockLogger } from "./_helpers/mockLogger.mjs";
import { joiningLifecycle, openingLifecycleStore } from "./_helpers/sessionLifecycle.mjs";

const CLIENT_ID = "client1";
const REDIRECT_URI = "https://rp.example/cb";
const SID = "session-xyz";
const SUBJECT = "u1";
const VERIFIER = "pkce-verifier".padEnd(43, "x");
const CHALLENGE = crypto.createHash("sha256").update(VERIFIER).digest("base64url");

const config = { ...makeValidAppConfig(), ...oauthConfigForTests() } as AppConfig;

/** A `refresh_token` grant that is only ever looked up, never run. */
const refreshGrant = (options: { readonly strict?: boolean } = {}): GrantHandler => ({
	...(options.strict ? { requiresExplicitGrantAllowlist: true } : {}),
	async handle() {
		throw new Error("this test never redeems a refresh token");
	},
});

interface Exchange {
	/** The client's `allowedGrantTypes`; absent when the key is. */
	readonly allowedGrantTypes?: readonly string[];
	/** The `refresh_token` grant the composition registers, or none. */
	readonly refreshTokenGrant: GrantHandler | null;
	readonly requireGrantTypeAllowlist?: boolean;
}

async function exchangeCode(exchange: Exchange) {
	const client: PublicClient = {
		clientId: CLIENT_ID,
		tokenEndpointAuthMethod: "client_secret_basic",
		allowedRedirectUris: [REDIRECT_URI],
		allowedScopes: ["read"],
		...(exchange.allowedGrantTypes ? { allowedGrantTypes: exchange.allowedGrantTypes } : {}),
	};
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
	const { lifecycle, join } = joiningLifecycle();
	const refreshTokenFamilyStore = createMemoryRefreshTokenFamilyStore();
	const rotation = createRefreshTokenFamilyRotation({
		refreshTokenFamilyStore,
		accessTokenHorizonMs: 3_600_000,
	});
	const register = vi.fn(rotation.register);
	const registry = new GrantRegistry();
	const handler = createAuthorizationGrant({
		sessionRequirementResolver: resolverForTests([], { actions: OAUTH_ADMISSION_ACTIONS }),
		grantHandlerResolver: registry,
		...grantSettingsFrom(config),
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
					grantedScope: ["read"],
				}),
			),
			createCode: vi.fn(),
			findByCode: vi.fn(),
			removeByCode: vi.fn(),
		} as unknown as CodeRepository,
		clientRepository: { findById: async () => client, authenticate: async () => null },
		userSessionStore,
		sessionLifecycle: lifecycle,
		sessionLifecycleStore: openingLifecycleStore(SUBJECT),
		refreshTokenFamilyRotation: { ...rotation, register },
		refreshTokenFamilyRevocation: {
			revokeFamily: vi.fn(async () => {}),
		} as unknown as RefreshTokenFamilyRevocation,
		logger,
	});
	registry.register("authorization_code", handler);
	registry.register("refresh_token", exchange.refreshTokenGrant);
	registry.freeze();

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
			registry,
			options: { requireGrantTypeAllowlist: exchange.requireGrantTypeAllowlist === true },
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
	return { res, register, join, refreshTokenFamilyStore };
}

/** Asserts a 200 that serves no refresh token and opens no family. */
function expectNoRefreshToken({ res, register, join }: Awaited<ReturnType<typeof exchangeCode>>) {
	expect(res.status).toBe(200);
	expect(res.body.access_token).toEqual(expect.any(String));
	expect(res.body).not.toHaveProperty("refresh_token");
	expect(decodeJwt(res.body.access_token)).not.toHaveProperty("family_id");
	expect(register).not.toHaveBeenCalled();
	// The client still joins the session, for logout to reach it; no family does.
	expect(join).toHaveBeenCalledTimes(1);
	const [sid, joined] = join.mock.calls[0] ?? [];
	expect(sid).toBe(SID);
	expect(joined).toHaveProperty("rp.clientId", CLIENT_ID);
	expect(joined).not.toHaveProperty("familyId");
}

describe("authorization_code — a refresh token only where the client can redeem one", () => {
	it("serves no refresh token and opens no family for a client whose allowedGrantTypes omits refresh_token", async () => {
		expectNoRefreshToken(
			await exchangeCode({
				allowedGrantTypes: ["authorization_code"],
				refreshTokenGrant: refreshGrant(),
			}),
		);
	});

	it("serves no refresh token and opens no family when the refresh_token grant is not registered", async () => {
		expectNoRefreshToken(await exchangeCode({ refreshTokenGrant: null }));
		expectNoRefreshToken(
			await exchangeCode({
				allowedGrantTypes: ["authorization_code", "refresh_token"],
				refreshTokenGrant: null,
			}),
		);
	});

	it("serves no refresh token to a client without a list when the refresh_token grant denies by absence", async () => {
		expectNoRefreshToken(await exchangeCode({ refreshTokenGrant: refreshGrant({ strict: true }) }));
	});

	it("serves nothing, and opens no family, under requireGrantTypeAllowlist for a client without a list", async () => {
		const { res, register, join } = await exchangeCode({
			refreshTokenGrant: refreshGrant(),
			requireGrantTypeAllowlist: true,
		});
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("unauthorized_client");
		expect(res.body).not.toHaveProperty("refresh_token");
		expect(register).not.toHaveBeenCalled();
		expect(join).not.toHaveBeenCalled();
	});

	it.each([
		["a client without a list", undefined],
		["a client that lists refresh_token", ["authorization_code", "refresh_token"]],
	])(
		"serves a refresh token whose family is registered and joined, for %s",
		async (_label, allowedGrantTypes) => {
			const { res, register, join, refreshTokenFamilyStore } = await exchangeCode({
				...(allowedGrantTypes ? { allowedGrantTypes } : {}),
				refreshTokenGrant: refreshGrant(),
				requireGrantTypeAllowlist: allowedGrantTypes !== undefined,
			});
			expect(res.status).toBe(200);
			const refreshToken = decodeJwt(res.body.refresh_token as string);
			const accessToken = decodeJwt(res.body.access_token as string);
			expect(accessToken.family_id).toBe(refreshToken.family_id);
			expect(register).toHaveBeenCalledTimes(1);
			expect(register).toHaveBeenCalledWith(
				refreshToken.jti,
				refreshToken.family_id,
				(refreshToken.exp as number) * 1000,
			);
			expect(
				await refreshTokenFamilyStore.findFamily(refreshToken.family_id as string),
			).toMatchObject({ activeJti: refreshToken.jti, revoked: false });
			expect(join).toHaveBeenCalledTimes(1);
			expect(join.mock.calls[0]?.[1]).toMatchObject({
				rp: { clientId: CLIENT_ID },
				familyId: refreshToken.family_id,
			});
		},
	);
});

describe("createAuthorizationGrant — the grant registry", () => {
	it("refuses a factory built without the grantHandlerResolver", () => {
		expect(() =>
			createAuthorizationGrant({
				sessionRequirementResolver: resolverForTests([], { actions: OAUTH_ADMISSION_ACTIONS }),
				...grantSettingsFrom(config),
				keyStore: createSymmetricKeyStore("test-secret"),
				codeRepository: {} as CodeRepository,
				clientRepository: { findById: async () => null, authenticate: async () => null },
			} as unknown as Parameters<typeof createAuthorizationGrant>[0]),
		).toThrow(/grantHandlerResolver/);
	});
});
