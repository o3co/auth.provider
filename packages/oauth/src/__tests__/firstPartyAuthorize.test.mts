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
 * Issue #267 — `GET /authorize` minted a code for any registered client the
 * moment `req.session.isAuthenticated` was true. That is defensible in a pure
 * first-party OP where every registered client is trusted, and only there —
 * but nothing said so and nothing enforced it, so registering one
 * semi-trusted client silently turned the endpoint into an account-linking
 * vector.
 *
 * These tests pin the invariant: a client reaching `/authorize` must be
 * marked `firstParty: true`, unless the deployment has explicitly declared it
 * is still migrating.
 *
 * They do NOT pin "forced navigation is impossible" — it is not. A client
 * genuinely marked first-party still mints a code on a forced top-level
 * navigation. That is the accepted model here, and the user-interaction step
 * that changes it is consent (#284).
 */

import {
	type AppConfig,
	type ClientRepository,
	type CodeRepository,
	createSymmetricKeyStore,
	type GrantHandler,
	type PublicClient,
} from "@o3co/auth-provider-core";
import { GrantRegistry } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createOAuthRouter } from "#/routes.mjs";

const CLIENT_ID = "client-a";
const REDIRECT_URI = "https://app.example/cb";

const makeConfig = (allowUnmarkedClients: boolean): AppConfig =>
	({
		oauth: {
			jwt: { issuer: "https://issuer.example" },
			accessToken: { expiresIn: 300 },
			authorize: { allowUnmarkedClients },
			grants: { authorization_code: { pkce: { requireS256: false } } },
		},
		rateLimit: { failMode: "open" as const },
		endpoints: { login: { url: "/login" } },
	}) as unknown as AppConfig;

const alwaysGrant = (): GrantHandler => ({
	async handle() {
		return {
			result: { status: 200, tokens: { access_token: "at", token_type: "Bearer" } },
		};
	},
});

const makeApp = async (opts: {
	firstParty?: boolean;
	allowUnmarkedClients?: boolean;
	warn?: ReturnType<typeof vi.fn>;
}) => {
	const record = {
		clientId: CLIENT_ID,
		tokenEndpointAuthMethod: "none" as const,
		allowedRedirectUris: [REDIRECT_URI],
		allowedScopes: ["read"],
		...(opts.firstParty === undefined ? {} : { firstParty: opts.firstParty }),
	} as unknown as PublicClient;

	const clientRepository: ClientRepository = {
		findById: async (id) => (id === CLIENT_ID ? record : null),
		authenticate: async () => null,
	};
	const codeRepository: CodeRepository = {
		createCode: async () => ({ code: "code-x", client_id: CLIENT_ID, redirect_uri: REDIRECT_URI }),
		findByCode: async () => null,
		consumeByCode: async () => null,
		removeByCode: async () => {},
	};

	const registry = new GrantRegistry();
	registry.register("authorization_code", alwaysGrant());

	const { router } = await createOAuthRouter(express, {
		registry,
		config: makeConfig(opts.allowUnmarkedClients ?? false),
		clientRepository,
		codeRepository,
		keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
		...(opts.warn
			? {
					logger: {
						warn: opts.warn,
						info: vi.fn(),
						error: vi.fn(),
						debug: vi.fn(),
					} as never,
				}
			: {}),
	});

	const app = express();
	app.use(express.json());
	app.use((req, _res, next) => {
		(req as unknown as { session: Record<string, unknown> }).session = {
			isAuthenticated: true,
			user: { id: "user-1" },
		};
		next();
	});
	app.use("/oauth", router);
	return app;
};

const authorize = (app: express.Express) =>
	request(app).get("/oauth/authorize").query({
		response_type: "code",
		client_id: CLIENT_ID,
		redirect_uri: REDIRECT_URI,
		state: "xyz",
		code_challenge: "abc",
		code_challenge_method: "plain",
	});

/** The `error` a response carries, wherever it carries it. */
const errorOf = (res: request.Response): string | null => {
	const location = res.headers.location as string | undefined;
	if (location !== undefined) {
		try {
			return new URL(location).searchParams.get("error");
		} catch {
			return null;
		}
	}
	return typeof res.body?.error === "string" ? res.body.error : null;
};

describe("/authorize first-party invariant (#267)", () => {
	it("refuses a client that is not marked first-party", async () => {
		const app = await makeApp({ firstParty: undefined });
		expect(errorOf(await authorize(app))).toBe("unauthorized_client");
	});

	it("refuses a client explicitly marked not first-party", async () => {
		const app = await makeApp({ firstParty: false });
		expect(errorOf(await authorize(app))).toBe("unauthorized_client");
	});

	it("admits a client marked first-party", async () => {
		const app = await makeApp({ firstParty: true });
		expect(errorOf(await authorize(app))).not.toBe("unauthorized_client");
	});

	it("delivers the refusal as a redirect to the registered redirect_uri", async () => {
		// `redirect_uri` is validated against the client's allowlist before this
		// check, so the error goes to the real client and no code is minted.
		// RFC 6749 §4.1.2.1 puts errors after that validation in the redirect.
		const app = await makeApp({ firstParty: false });
		const res = await authorize(app);
		expect(res.status).toBe(302);
		const location = new URL(res.headers.location as string);
		expect(location.origin + location.pathname).toBe(REDIRECT_URI);
		expect(location.searchParams.get("state")).toBe("xyz");
		expect(location.searchParams.get("code")).toBeNull();
	});
});

describe("/authorize first-party invariant — migration opt-in (#267)", () => {
	it("admits an unmarked client when the deployment declared it is migrating", async () => {
		const app = await makeApp({ firstParty: undefined, allowUnmarkedClients: true });
		expect(errorOf(await authorize(app))).not.toBe("unauthorized_client");
	});

	it("warns when it admits an unmarked client, naming it", async () => {
		const warn = vi.fn();
		const app = await makeApp({
			firstParty: undefined,
			allowUnmarkedClients: true,
			warn,
		});
		await authorize(app);
		expect(warn).toHaveBeenCalledWith(
			expect.objectContaining({ clientId: CLIENT_ID }),
			"authorize_client_not_marked_first_party",
		);
	});

	it("still admits a marked client without warning under the opt-in", async () => {
		const warn = vi.fn();
		const app = await makeApp({ firstParty: true, allowUnmarkedClients: true, warn });
		await authorize(app);
		expect(warn).not.toHaveBeenCalledWith(
			expect.anything(),
			"authorize_client_not_marked_first_party",
		);
	});
});
