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
 * Issue #268 — `allowedGrantTypes` was consulted only by `client_credentials`
 * and the WebAuthn grant, so a client registered for one grant could exercise
 * every other one and the registration's restriction was silently void.
 *
 * These tests pin the central enforcement: once at `/oauth/token` dispatch, so
 * every grant — including one registered later through `GrantFactory` — inherits
 * it, and once at `/authorize`.
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
import { describe, expect, it } from "vitest";
import { createOAuthRouter } from "#/routes.mjs";

const CLIENT_ID = "client-a";
const CLIENT_SECRET = "secret-a";
const REDIRECT_URI = "https://app.example/cb";
const BASIC = `Basic ${Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64")}`;

const config = {
	oauth: { jwt: { issuer: "https://issuer.example" }, accessToken: { expiresIn: 300 } },
	rateLimit: { failMode: "open" as const },
	endpoints: { login: { url: "/login" } },
} as unknown as AppConfig;

/**
 * A grant that always succeeds. The point of these tests is which requests
 * reach a handler at all, so the handler's own semantics are noise — a stub
 * makes "reached it" and "was turned away" unambiguous.
 */
const alwaysGrant = (): GrantHandler => ({
	async handle() {
		return {
			result: {
				status: 200,
				tokens: { access_token: "at", token_type: "Bearer", expires_in: 300 },
			},
		};
	},
});

const makeApp = async (allowedGrantTypes: readonly string[] | undefined) => {
	const record = {
		clientId: CLIENT_ID,
		tokenEndpointAuthMethod: "client_secret_basic" as const,
		allowedRedirectUris: [REDIRECT_URI],
		allowedScopes: ["read"],
		...(allowedGrantTypes === undefined ? {} : { allowedGrantTypes }),
	} as unknown as PublicClient;

	const clientRepository: ClientRepository = {
		findById: async (id) => (id === CLIENT_ID ? record : null),
		authenticate: async (id, secret) =>
			id === CLIENT_ID && secret === CLIENT_SECRET ? record : null,
	};
	const codeRepository: CodeRepository = {
		createCode: async () => ({ code: "code-x", client_id: CLIENT_ID, redirect_uri: REDIRECT_URI }),
		findByCode: async () => null,
		consumeByCode: async () => null,
		removeByCode: async () => {},
	};

	const registry = new GrantRegistry();
	registry.register("refresh_token", alwaysGrant());
	registry.register("authorization_code", alwaysGrant());

	const { router } = await createOAuthRouter(express, {
		registry,
		config,
		clientRepository,
		codeRepository,
		keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
	});

	const app = express();
	app.use(express.json());
	app.use(express.urlencoded({ extended: true }));
	// `/authorize` redirects to login unless the session says otherwise; stub a
	// session so the tests reach the allowlist gate rather than the redirect.
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

const tokenRequest = (app: express.Express, grantType: string) =>
	request(app)
		.post("/oauth/token")
		.set("Authorization", BASIC)
		.type("form")
		.send({ grant_type: grantType, refresh_token: "rt", code: "code-x" });

describe("allowedGrantTypes — central /oauth/token enforcement (#268)", () => {
	it("refuses a grant the client did not register for", async () => {
		// The bug: a client provisioned for client_credentials only could still
		// redeem refresh tokens and authorization codes.
		const app = await makeApp(["client_credentials"]);
		const res = await tokenRequest(app, "refresh_token");
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("unauthorized_client");
	});

	it("refuses every grant when the allowlist is empty", async () => {
		const app = await makeApp([]);
		const res = await tokenRequest(app, "refresh_token");
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("unauthorized_client");
	});

	it("admits a grant the client did register for", async () => {
		const app = await makeApp(["refresh_token"]);
		const res = await tokenRequest(app, "refresh_token");
		expect(res.status).toBe(200);
	});

	it("does not restrict a client that declared no allowlist", async () => {
		// Absence is "no policy declared". Denying here would revoke every grant
		// from every registration written before the field existed.
		const app = await makeApp(undefined);
		const res = await tokenRequest(app, "refresh_token");
		expect(res.status).toBe(200);
	});

	it("gates every grant, not a hard-coded list of them", async () => {
		// The check sits at dispatch, so a grant registered through GrantFactory
		// inherits it without opting in.
		const app = await makeApp(["refresh_token"]);
		const res = await tokenRequest(app, "authorization_code");
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("unauthorized_client");
	});
});

describe("allowedGrantTypes — /authorize enforcement (#268)", () => {
	const authorize = (app: express.Express) =>
		request(app).get("/oauth/authorize").query({
			response_type: "code",
			client_id: CLIENT_ID,
			redirect_uri: REDIRECT_URI,
			state: "xyz",
		});

	it("refuses to start a code flow for a client not allowed authorization_code", async () => {
		const app = await makeApp(["client_credentials"]);
		const res = await authorize(app);
		// RFC 6749 §4.1.2.1: once redirect_uri is validated, errors redirect.
		expect(res.status).toBe(302);
		const location = new URL(res.headers.location as string);
		expect(location.origin + location.pathname).toBe(REDIRECT_URI);
		expect(location.searchParams.get("error")).toBe("unauthorized_client");
		expect(location.searchParams.get("state")).toBe("xyz");
	});

	/**
	 * The `error` this response carries, wherever it carries it — a redirect
	 * query parameter or a JSON body — or `null` when it carries none.
	 *
	 * Asserting through one accessor keeps the negative cases unconditional. An
	 * `if (redirected) expect(...)` would pass vacuously the day the gate starts
	 * rejecting these requests some other way, which is exactly the regression
	 * these two tests exist to catch.
	 */
	const errorOf = (res: request.Response): string | null => {
		const location = res.headers.location as string | undefined;
		if (location !== undefined) {
			try {
				return new URL(location).searchParams.get("error");
			} catch {
				return null; // relative redirect (the login bounce) carries no error
			}
		}
		return typeof res.body?.error === "string" ? res.body.error : null;
	};

	it("starts the flow for a client allowed authorization_code", async () => {
		const app = await makeApp(["authorization_code"]);
		expect(errorOf(await authorize(app))).not.toBe("unauthorized_client");
	});

	it("does not restrict a client that declared no allowlist", async () => {
		const app = await makeApp(undefined);
		expect(errorOf(await authorize(app))).not.toBe("unauthorized_client");
	});
});
