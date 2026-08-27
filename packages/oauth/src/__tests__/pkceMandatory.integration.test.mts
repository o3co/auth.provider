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
 * Issue #273 — PKCE is mandatory, S256-only, and decided by ONE resolved
 * policy object that `/authorize` and `/token` both read.
 *
 * Pre-#273 the two endpoints disagreed: `/authorize` mandated PKCE/S256 for
 * public clients but let a confidential client omit PKCE entirely or pick
 * `plain` (the default `supportedMethods` was `["S256","plain"]`), while
 * `/token` applied a *different* rule derived from the legacy `requireS256`
 * boolean. A code could therefore be minted at `/authorize` and be
 * unredeemable at `/token`.
 *
 * This suite drives both endpoints over HTTP against the same router so the
 * agreement is pinned end-to-end rather than per-unit.
 */

import crypto from "node:crypto";
import {
	type AppConfig,
	type ClientRepository,
	type Code,
	type CodeRepository,
	createSymmetricKeyStore,
	type PublicClient,
} from "@o3co/auth-provider-core";
import { GrantRegistry } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createAuthorizationGrant } from "#/grants/authorization.mjs";
import { createOAuthRouter } from "#/routes.mjs";
import { createMockLogger } from "./_helpers/mockLogger.mjs";

const CLIENT_ID = "conf-client";
const CLIENT_SECRET = "conf-secret";
const BASIC = `Basic ${Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64")}`;
const REDIRECT_URI = "https://app.example/cb";

/** RFC 7636 §4.1 — 43-128 unreserved characters. */
const VERIFIER = "pkce-verifier".padEnd(43, "x");
const S256_CHALLENGE = crypto.createHash("sha256").update(VERIFIER).digest("base64url");

const makeConfig = (oauthOverrides: Record<string, unknown> = {}): AppConfig =>
	({
		oauth: {
			jwt: { issuer: "https://issuer.example" },
			accessToken: { expiresIn: 300 },
			refreshToken: { expiresIn: 3600 },
			// `dual` so a request without `openid` reaches the PKCE gate instead
			// of tripping the IH-6 scope gate first.
			oidcMode: "dual",
			grants: { authorization_code: { enabled: true } },
			...oauthOverrides,
		},
		rateLimit: { failMode: "open" as const },
		endpoints: { login: { url: "/login" } },
	}) as unknown as AppConfig;

const makeApp = async (
	opts: {
		/** Merged into the client registration. */
		client?: Record<string, unknown>;
		/** Merged into `config.oauth`. */
		oauth?: Record<string, unknown>;
		/** The code record `/token` consumes. */
		storedCode?: Record<string, unknown> | null;
	} = {},
) => {
	const record = {
		clientId: CLIENT_ID,
		tokenEndpointAuthMethod: "client_secret_basic" as const,
		allowedRedirectUris: [REDIRECT_URI],
		allowedScopes: ["read"],
		firstParty: true,
		...(opts.client ?? {}),
	} as unknown as PublicClient;

	const clientRepository: ClientRepository = {
		findById: async (id) => (id === CLIENT_ID ? record : null),
		authenticate: async (id, secret) =>
			id === CLIENT_ID && secret === CLIENT_SECRET ? record : null,
	};

	const createCode = vi.fn(
		async (params: Parameters<CodeRepository["createCode"]>[0]) =>
			({ code: "code-x", ...params }) as unknown as Code,
	);
	const codeRepository: CodeRepository = {
		createCode: (params) => createCode(params),
		findByCode: async () => null,
		consumeByCode: async () =>
			opts.storedCode === undefined || opts.storedCode === null
				? null
				: ({ code: "code-x", ...opts.storedCode } as unknown as Code),
		removeByCode: async () => {},
	};

	const config = makeConfig(opts.oauth ?? {});
	const logger = createMockLogger();
	const registry = new GrantRegistry();
	registry.register(
		"authorization_code",
		createAuthorizationGrant({
			config,
			keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
			codeRepository,
			clientRepository,
			logger,
		} as unknown as Parameters<typeof createAuthorizationGrant>[0]),
	);

	const { router } = await createOAuthRouter(express, {
		registry,
		config,
		clientRepository,
		codeRepository,
		keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
		logger,
	});

	const app = express();
	app.use((req, _res, next) => {
		(req as unknown as { session: Record<string, unknown> }).session = {
			isAuthenticated: true,
			user: { id: "user-1" },
		};
		next();
	});
	app.use("/oauth", router);
	return { app, createCode, logger };
};

type Query = Record<string, string>;

const baseQuery: Query = {
	response_type: "code",
	client_id: CLIENT_ID,
	redirect_uri: REDIRECT_URI,
	state: "xyz",
};

const authorize = (app: express.Express, query: Query) =>
	request(app).get("/oauth/authorize").query(query);

const redirectParams = (res: request.Response): URLSearchParams => {
	expect(res.status).toBe(302);
	return new URL(res.headers.location as string).searchParams;
};

const redeem = (app: express.Express, body: Record<string, unknown>) =>
	request(app)
		.post("/oauth/token")
		.set("Authorization", BASIC)
		.type("form")
		.send({
			grant_type: "authorization_code",
			redirect_uri: REDIRECT_URI,
			code: "code-x",
			...body,
		});

describe("#273 /authorize — PKCE is mandatory for CONFIDENTIAL clients too", () => {
	it("refuses a confidential-client request that omits code_challenge", async () => {
		// Pre-#273: accepted, because `pkce.required` defaulted to false and
		// the S256 mandate only covered `tokenEndpointAuthMethod: "none"`.
		const { app } = await makeApp();
		const params = redirectParams(await authorize(app, baseQuery));
		expect(params.get("error")).toBe("invalid_request");
		expect(params.get("error_description")).toBe("code_challenge is required");
		expect(params.get("code")).toBeNull();
	});

	it("refuses an empty-string code_challenge the same way", async () => {
		const { app } = await makeApp();
		const params = redirectParams(await authorize(app, { ...baseQuery, code_challenge: "" }));
		expect(params.get("error")).toBe("invalid_request");
		expect(params.get("error_description")).toBe("code_challenge is required");
	});

	it("cannot be disabled by the legacy requireS256 = false config", async () => {
		const { app } = await makeApp({
			oauth: { grants: { authorization_code: { pkce: { requireS256: false } } } },
		});
		const params = redirectParams(await authorize(app, baseQuery));
		expect(params.get("error")).toBe("invalid_request");
	});

	it("cannot be disabled by pkce.required = false", async () => {
		const { app } = await makeApp({
			oauth: { grants: { authorization_code: { pkce: { required: false } } } },
		});
		const params = redirectParams(await authorize(app, baseQuery));
		expect(params.get("error")).toBe("invalid_request");
	});

	it("mints a code for a confidential client presenting S256", async () => {
		const { app, createCode } = await makeApp();
		const params = redirectParams(
			await authorize(app, {
				...baseQuery,
				code_challenge: S256_CHALLENGE,
				code_challenge_method: "S256",
			}),
		);
		expect(params.get("error")).toBeNull();
		expect(params.get("code")).toBe("code-x");
		expect(createCode).toHaveBeenCalledWith(
			expect.objectContaining({
				code_challenge: S256_CHALLENGE,
				code_challenge_method: "S256",
			}),
		);
	});
});

describe("#273 /authorize — S256 only, plain behind a per-client opt-in", () => {
	it("refuses code_challenge_method=plain for a client with no opt-in", async () => {
		const { app } = await makeApp();
		const params = redirectParams(
			await authorize(app, {
				...baseQuery,
				code_challenge: VERIFIER,
				code_challenge_method: "plain",
			}),
		);
		expect(params.get("error")).toBe("invalid_request");
		expect(params.get("error_description")).toBe('code_challenge_method "plain" is not supported');
	});

	it("refuses an OMITTED method — RFC 7636 §4.3 makes that `plain`", async () => {
		const { app } = await makeApp();
		const params = redirectParams(
			await authorize(app, { ...baseQuery, code_challenge: S256_CHALLENGE }),
		);
		expect(params.get("error")).toBe("invalid_request");
		expect(params.get("error_description")).toBe(
			'code_challenge_method is required and must be "S256"',
		);
	});

	it("cannot re-admit plain through a global supportedMethods allowlist", async () => {
		// The whole point of #273: `plain` must not be reachable from any
		// server-wide knob, only from a named client registration.
		const { app } = await makeApp({
			oauth: {
				grants: {
					authorization_code: {
						pkce: { supportedMethods: ["S256", "plain"], defaultMethod: "plain" },
					},
				},
			},
		});
		const params = redirectParams(
			await authorize(app, {
				...baseQuery,
				code_challenge: VERIFIER,
				code_challenge_method: "plain",
			}),
		);
		expect(params.get("error")).toBe("invalid_request");
	});

	it("admits plain for a client registered with allowPlainPkce: true", async () => {
		const { app, createCode } = await makeApp({ client: { allowPlainPkce: true } });
		const params = redirectParams(
			await authorize(app, {
				...baseQuery,
				code_challenge: VERIFIER,
				code_challenge_method: "plain",
			}),
		);
		expect(params.get("code")).toBe("code-x");
		expect(createCode).toHaveBeenCalledWith(
			expect.objectContaining({ code_challenge_method: "plain" }),
		);
	});

	it("still requires a challenge from an allowPlainPkce client", async () => {
		const { app } = await makeApp({ client: { allowPlainPkce: true } });
		const params = redirectParams(await authorize(app, baseQuery));
		expect(params.get("error_description")).toBe("code_challenge is required");
	});

	it("still refuses plain for a public client even with the opt-in absent", async () => {
		const { app } = await makeApp({
			client: { tokenEndpointAuthMethod: "none", clientSecret: undefined },
		});
		const params = redirectParams(
			await authorize(app, {
				...baseQuery,
				code_challenge: VERIFIER,
				code_challenge_method: "plain",
			}),
		);
		expect(params.get("error")).toBe("invalid_request");
	});
});

describe("#273 /token — the same policy object decides redemption", () => {
	it("refuses a code that carries no code_challenge_method", async () => {
		// Pre-#273 this depended on `pkce.required`, which defaulted to false,
		// so a PKCE-less code was redeemable by a confidential client.
		const { app } = await makeApp({
			storedCode: { client_id: CLIENT_ID, redirect_uri: REDIRECT_URI },
		});
		const res = await redeem(app, {});
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_request");
		expect(res.body.error_description).toBe(
			"PKCE is required but code was issued without code_challenge",
		);
	});

	it("refuses a PKCE-less code even when the legacy requireS256 = false is configured", async () => {
		const { app } = await makeApp({
			oauth: { grants: { authorization_code: { pkce: { requireS256: false } } } },
			storedCode: { client_id: CLIENT_ID, redirect_uri: REDIRECT_URI },
		});
		expect((await redeem(app, {})).status).toBe(400);
	});

	it("refuses a plain code for a client with no opt-in", async () => {
		// The divergence #273 closes: `/authorize` would not mint this today,
		// but a code minted before the upgrade — or by a custom CodeRepository
		// — must not be honoured either.
		const { app } = await makeApp({
			storedCode: {
				client_id: CLIENT_ID,
				redirect_uri: REDIRECT_URI,
				code_challenge: VERIFIER,
				code_challenge_method: "plain",
			},
		});
		const res = await redeem(app, { code_verifier: VERIFIER });
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_request");
		expect(res.body.error_description).toBe('code_challenge_method "plain" is not supported');
	});

	it("honours a plain code for a client registered with allowPlainPkce: true", async () => {
		const { app } = await makeApp({
			client: { allowPlainPkce: true },
			storedCode: {
				client_id: CLIENT_ID,
				redirect_uri: REDIRECT_URI,
				code_challenge: VERIFIER,
				code_challenge_method: "plain",
			},
		});
		const res = await redeem(app, { code_verifier: VERIFIER });
		expect(res.status).toBe(200);
		expect(res.body.access_token).toBeTruthy();
	});

	it("redeems an S256 code minted by /authorize — the endpoints agree end to end", async () => {
		const { app } = await makeApp({
			storedCode: {
				client_id: CLIENT_ID,
				redirect_uri: REDIRECT_URI,
				code_challenge: S256_CHALLENGE,
				code_challenge_method: "S256",
			},
		});
		const res = await redeem(app, { code_verifier: VERIFIER });
		expect(res.status).toBe(200);
		expect(res.body.access_token).toBeTruthy();
	});

	it("still rejects a wrong verifier against an S256 code", async () => {
		const { app } = await makeApp({
			storedCode: {
				client_id: CLIENT_ID,
				redirect_uri: REDIRECT_URI,
				code_challenge: S256_CHALLENGE,
				code_challenge_method: "S256",
			},
		});
		const res = await redeem(app, { code_verifier: "wrong-verifier".padEnd(43, "y") });
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_grant");
	});
});

describe("#273 — operator signal for the now-inert pkce knobs", () => {
	it("warns at composition when a config still carries them", async () => {
		const { logger } = await makeApp({
			oauth: {
				grants: { authorization_code: { pkce: { requireS256: false, defaultMethod: "plain" } } },
			},
		});
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({ ignoredKeys: ["requireS256", "defaultMethod"] }),
			"pkce_config_ignored_s256_is_mandatory",
		);
	});
});
