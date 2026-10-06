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
 * The `amr` an authorization code's tokens carry is the one `/authorize`
 * vouched for when it minted the code. A second factor recorded on the
 * session afterwards reaches neither those tokens nor what their refresh
 * token mints. Over the router, with core's memory user-session store and
 * code repository.
 */

import crypto from "node:crypto";
import {
	type AppConfig,
	type ClientRepository,
	createInMemorySessionLifecycleStore,
	createInMemoryUserSessionStore,
	createMemoryAccessTokenDenylist,
	createMemoryRefreshTokenFamilyStore,
	createRefreshTokenFamilyRevocation,
	createSessionLifecycle,
	createSymmetricKeyStore,
	type FederationTokenStore,
	InMemoryCodeRepository,
	passwordSessionAuthentication,
	type SessionRequirement,
} from "@o3co/auth-provider-core";
import {
	createTestLoginEntry,
	GrantRegistry,
	makeValidAppConfig,
	resolverForTests,
} from "@o3co/auth-provider-core/testing";
import express from "express";
import { decodeJwt } from "jose";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createAuthorizationGrant } from "#/grants/authorization.mjs";
import { createRefreshTokenGrant } from "#/grants/refreshToken.mjs";
import { createOAuthRouter } from "#/routes.mjs";
import { oauthConfigForTests } from "#/testing/index.mjs";
import { OAUTH_ADMISSION_ACTIONS } from "./_helpers/admissionActions.mjs";
import { grantSettingsFrom } from "./_helpers/grantSettings.mjs";
import { routerInputsOf } from "./_helpers/sections.mjs";

const ISSUER = "https://issuer.test";
const SECRET = "code-amr-test-secret-32-bytes-long!!";
const CLIENT_ID = "app";
const REDIRECT_URI = "https://app.example/cb";
const SID = "sid-1";
const SUBJECT = "user-1";
const VERIFIER = "pkce-verifier".padEnd(43, "x");
const CHALLENGE = crypto.createHash("sha256").update(VERIFIER).digest("base64url");

const config = { ...makeValidAppConfig(), ...oauthConfigForTests({ issuer: ISSUER }) } as AppConfig;

const codes: InMemoryCodeRepository[] = [];
afterEach(() => {
	for (const repo of codes.splice(0)) repo.dispose();
});

/** A signed-in browser's session record, as a login writes it, with the `amr` and `authentication` given. */
const world = async (
	recorded: Pick<
		Parameters<ReturnType<typeof createInMemoryUserSessionStore>["create"]>[0],
		"amr" | "authentication"
	> = passwordSessionAuthentication(),
	/** When given, the `amr` the repository answers each code with, in place of the one it holds. */
	answered?: { readonly amr: unknown },
	/** The session requirements every consumer here admits through. */
	registered: readonly SessionRequirement[] = [],
) => {
	const userSessionStore = createInMemoryUserSessionStore();
	const expiresAt = new Date(Date.now() + 3_600_000);
	await userSessionStore.create({
		sid: SID,
		sub: SUBJECT,
		authTime: new Date(Date.now() - 60_000),
		expiresAt,
		claims: {},
		...recorded,
	});
	const codeRepository = new InMemoryCodeRepository();
	codes.push(codeRepository);
	const createCode = vi.spyOn(codeRepository, "createCode");
	if (answered !== undefined) {
		const consume = codeRepository.consumeByCode.bind(codeRepository);
		vi.spyOn(codeRepository, "consumeByCode").mockImplementation(async (code) => {
			const held = await consume(code);
			return held === null ? null : ({ ...held, amr: answered.amr } as typeof held);
		});
	}
	const keyStore = createSymmetricKeyStore(SECRET);
	const requirements = resolverForTests(registered, {
		issuer: ISSUER,
		actions: OAUTH_ADMISSION_ACTIONS,
	});
	const client = {
		clientId: CLIENT_ID,
		tokenEndpointAuthMethod: "none" as const,
		allowedRedirectUris: [REDIRECT_URI],
		allowedScopes: ["openid", "read"],
		defaultScopes: ["read"],
		allowedGrantTypes: ["authorization_code", "refresh_token"],
		firstParty: true,
	};
	const clientRepository: ClientRepository = {
		findById: async (id) => (id === CLIENT_ID ? client : null),
		authenticate: async () => null,
	};
	// Core's own lifecycle over the same stores, the session opened in it as
	// a login opens it: the grant joins the session through it, and the
	// router reads and ends sessions through it.
	const sessionLifecycleStore = createInMemorySessionLifecycleStore();
	const sessionLifecycle = createSessionLifecycle({
		store: sessionLifecycleStore,
		userSessionStore,
		refreshTokenFamilyRevocation: createRefreshTokenFamilyRevocation({
			refreshTokenFamilyStore: createMemoryRefreshTokenFamilyStore(),
			accessTokenHorizonMs: 3_600_000,
		}),
		federationTokenStore: {
			removeBySid: vi.fn(),
			delete: vi.fn(),
		} as unknown as FederationTokenStore,
		retainMs: 0,
		logger: { warn: () => undefined, error: () => undefined },
	});
	expect(await sessionLifecycle.open(SID, { sub: SUBJECT, expiresAt })).toEqual({
		outcome: "opened",
	});
	const registry = new GrantRegistry();
	registry.register(
		"authorization_code",
		createAuthorizationGrant({
			sessionRequirementResolver: requirements,
			...grantSettingsFrom(config),
			keyStore,
			clientRepository,
			codeRepository,
			userSessionStore,
			sessionLifecycle,
			sessionLifecycleStore,
		}),
	);
	registry.register(
		"refresh_token",
		createRefreshTokenGrant({
			...grantSettingsFrom(config),
			keyStore,
			userSessionStore,
			sessionLifecycleStore,
			sessionRequirementResolver: requirements,
		}),
	);
	const { router } = await createOAuthRouter(express, {
		loginEntry: createTestLoginEntry(),
		registry,
		...routerInputsOf(config),
		clientRepository,
		codeRepository,
		keyStore,
		userSessionStore,
		sessionLifecycle,
		sessionLifecycleStore,
		accessTokenDenylist: createMemoryAccessTokenDenylist(),
		requirements,
	});
	const app = express();
	app.use((req, _res, next) => {
		// The cookie session of the browser the record belongs to.
		(req as unknown as { session: unknown }).session = {
			isAuthenticated: true,
			sid: SID,
			user: { id: SUBJECT },
		};
		next();
	});
	app.use("/oauth", router);

	/** `/authorize` for `openid read`, answered with a code. */
	const authorize = async (): Promise<string> => {
		const res = await request(app).get("/oauth/authorize").query({
			response_type: "code",
			client_id: CLIENT_ID,
			redirect_uri: REDIRECT_URI,
			scope: "openid read",
			state: "xyz",
			nonce: "n-1",
			code_challenge: CHALLENGE,
			code_challenge_method: "S256",
		});
		expect(res.status, JSON.stringify(res.body)).toBe(302);
		const code = new URL(res.headers.location as string).searchParams.get("code");
		if (code === null) throw new Error(`no code in ${String(res.headers.location)}`);
		return code;
	};

	const exchange = (code: string) =>
		request(app).post("/oauth/token").type("form").send({
			grant_type: "authorization_code",
			client_id: CLIENT_ID,
			redirect_uri: REDIRECT_URI,
			code,
			code_verifier: VERIFIER,
		});

	const refresh = (refreshToken: string) =>
		request(app).post("/oauth/token").type("form").send({
			grant_type: "refresh_token",
			client_id: CLIENT_ID,
			refresh_token: refreshToken,
		});

	/** The verified second factor the MFA finish records: a TOTP, with `mfa`. */
	const stepUp = async () => {
		const stepped = await userSessionStore.recordSecondFactor(SID, {
			amr: ["otp", "mfa"],
			at: new Date(),
		});
		expect(stepped?.amr).toEqual(["pwd", "otp", "mfa"]);
	};

	return { authorize, exchange, refresh, stepUp, createCode, userSessionStore };
};

/** The `amr` of each token a successful exchange answered. */
const amrOf = (body: Record<string, unknown>) => ({
	access: decodeJwt(body.access_token as string).amr,
	refresh: decodeJwt(body.refresh_token as string).amr,
	id: decodeJwt(body.id_token as string).amr,
});

describe("an authorization code carries the amr /authorize vouched for", () => {
	it("a code minted before a step-up is exchanged for tokens that carry the amr before it", async () => {
		const w = await world();
		const code = await w.authorize();
		await w.stepUp();

		const res = await w.exchange(code);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(amrOf(res.body)).toEqual({ access: ["pwd"], refresh: ["pwd"], id: ["pwd"] });
	});

	it("a code minted after the step-up carries the step-up's amr", async () => {
		const w = await world();
		await w.stepUp();
		const code = await w.authorize();

		const res = await w.exchange(code);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		const escalated = ["pwd", "otp", "mfa"];
		expect(amrOf(res.body)).toEqual({ access: escalated, refresh: escalated, id: escalated });
	});

	it("the refresh token of such a code mints tokens that carry the amr before the step-up", async () => {
		const w = await world();
		const code = await w.authorize();
		await w.stepUp();
		const exchanged = await w.exchange(code);
		expect(exchanged.status, JSON.stringify(exchanged.body)).toBe(200);

		const res = await w.refresh(exchanged.body.refresh_token as string);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(decodeJwt(res.body.access_token as string).amr).toEqual(["pwd"]);
		expect(decodeJwt(res.body.refresh_token as string).amr).toEqual(["pwd"]);
	});

	it.each([
		[
			"a federated session from before the upstream split: fed alone, its upstream IdP's values left off",
			{ amr: ["hwk", "fed"], authentication: undefined },
			["fed"],
		],
		[
			"a trusted federation's session: its IdP's values beside fed",
			{
				amr: ["hwk", "fed"],
				authentication: {
					primary: "fed",
					federation: "google",
					upstreamAmr: undefined,
					mfaAt: undefined,
				},
			},
			["hwk", "fed"],
		],
		[
			"an untrusted federation's session: fed, never what was kept apart",
			{
				amr: ["fed"],
				authentication: {
					primary: "fed",
					federation: "google",
					upstreamAmr: ["hwk"],
					mfaAt: undefined,
				},
			},
			["fed"],
		],
	] as const)(
		"records on the code, and stamps, what the session vouches for — %s",
		async (_, recorded, vouched) => {
			const w = await world(recorded);

			const code = await w.authorize();
			const res = await w.exchange(code);

			expect(w.createCode).toHaveBeenCalledTimes(1);
			expect(w.createCode.mock.calls[0]?.[0]).toMatchObject({ amr: vouched });
			expect(res.status, JSON.stringify(res.body)).toBe(200);
			expect(amrOf(res.body)).toEqual({ access: vouched, refresh: vouched, id: vouched });
		},
	);

	it.each([
		["that carries none (one minted before codes carried it)", undefined],
		["with an empty amr", []],
		["with an amr that is not a list", "pwd"],
	])(
		"a code %s is exchanged for tokens that carry no amr, whatever the session holds",
		async (_, amr) => {
			const w = await world(passwordSessionAuthentication(), { amr });
			const code = await w.authorize();
			await w.stepUp();

			const res = await w.exchange(code);

			expect(res.status, JSON.stringify(res.body)).toBe(200);
			expect(amrOf(res.body)).toEqual({ access: undefined, refresh: undefined, id: undefined });
		},
	);

	it("a code whose session ended before the exchange is refused, its amr notwithstanding", async () => {
		const w = await world();
		const code = await w.authorize();
		await w.userSessionStore.delete(SID);

		const res = await w.exchange(code);

		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_grant");
		expect(res.body).not.toHaveProperty("access_token");
	});
});

describe("an authorization code carries how its session had authenticated at /authorize, and is judged on it", () => {
	it("/authorize records the admitted session's primary and second factor on the code, beside its amr", async () => {
		const w = await world();
		await w.authorize();
		expect(w.createCode).toHaveBeenLastCalledWith(
			expect.objectContaining({
				amr: ["pwd"],
				authentication: { primary: "pwd", mfaAt: undefined },
			}),
		);
		await w.stepUp();
		await w.authorize();
		expect(w.createCode).toHaveBeenLastCalledWith(
			expect.objectContaining({
				amr: ["pwd", "otp", "mfa"],
				authentication: { primary: "pwd", mfaAt: expect.any(Date) },
			}),
		);
	});

	it("records what admission read, not the record as it is when the code is minted: a step-up landing between the two does not reach the code", async () => {
		const w = await world();
		const mint = InMemoryCodeRepository.prototype.createCode;
		w.createCode.mockImplementationOnce(async function (
			this: InMemoryCodeRepository,
			params: Parameters<InMemoryCodeRepository["createCode"]>[0],
		) {
			await w.stepUp();
			return mint.call(this, params);
		});
		await w.authorize();
		expect(w.createCode).toHaveBeenLastCalledWith(
			expect.objectContaining({
				amr: ["pwd"],
				authentication: { primary: "pwd", mfaAt: undefined },
			}),
		);
	});

	/** A requirement that holds the exchange, not `/authorize`, to a second factor. */
	const exchangeNeedsSecondFactor: SessionRequirement = {
		name: "exchange-mfa",
		reach: new Set(),
		stepUpPage: undefined,
		remediations: [],
		hintKeys: [],
		admit: async ({ action, authentication }) =>
			action.name === "oauth.code_exchange" && authentication?.authentication?.mfaAt === undefined
				? { outcome: "unmet" }
				: { outcome: "met" },
	};

	it("a code minted before a step-up is refused by a requirement that holds the exchange to a second factor, though the session has one now", async () => {
		const w = await world(passwordSessionAuthentication(), undefined, [exchangeNeedsSecondFactor]);
		const code = await w.authorize();
		await w.stepUp();

		const res = await w.exchange(code);

		expect(res.status, JSON.stringify(res.body)).toBe(400);
		expect(res.body).toMatchObject({
			error: "invalid_grant",
			error_description: "the session does not meet the exchange-mfa requirement",
		});
		expect(res.body).not.toHaveProperty("access_token");
	});

	it("a code minted after the step-up meets it", async () => {
		const w = await world(passwordSessionAuthentication(), undefined, [exchangeNeedsSecondFactor]);
		await w.stepUp();
		const code = await w.authorize();

		const res = await w.exchange(code);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
	});
});
