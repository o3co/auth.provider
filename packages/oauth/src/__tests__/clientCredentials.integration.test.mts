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
 * End-to-end coverage for the route → ctx.authenticatedClient propagation
 * path of the `client_credentials` grant.
 *
 * The unit tests in `clientCredentials.test.mts` construct
 * `AuthenticatedClient` directly and therefore cannot detect a regression in
 * `routes.mts` ctx construction (e.g. a typo in the 3-line spread that maps
 * `req.oauthClient.*` into the handler input). This file exercises the full
 * HTTP path via supertest so per-client gating is verified end-to-end.
 */

import {
	type AppConfig,
	type ClientRepository,
	type CodeRepository,
	createSymmetricKeyStore,
} from "@o3co/auth-provider-core";
import { GrantRegistry } from "@o3co/auth-provider-core/testing";
import express from "express";
import { decodeJwt } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createClientCredentialsGrant } from "#/grants/clientCredentials.mjs";
import { createOAuthRouter } from "#/routes.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const ISSUER = "https://auth.example";
const TEST_CLIENT_ID = "cc-client";
const TEST_CLIENT_SECRET = "cc-secret";
const TEST_BASIC_AUTH = `Basic ${Buffer.from(`${TEST_CLIENT_ID}:${TEST_CLIENT_SECRET}`).toString("base64")}`;

const fullConfig = {
	oauth: {
		jwt: { issuer: ISSUER },
		accessToken: { expiresIn: 3600 },
	},
	rateLimit: { failMode: "open" as const },
	endpoints: { login: { url: "/login" } },
} as unknown as AppConfig;

const codeRepoStub: CodeRepository = {
	createCode: async () => ({
		code: "code-x",
		client_id: TEST_CLIENT_ID,
		redirect_uri: "",
	}),
	findByCode: async () => null,
	consumeByCode: async () => null,
	removeByCode: async () => {},
};

function clientRepoWith(opts: {
	allowedGrantTypes: readonly string[] | undefined;
	allowedScopes?: readonly string[];
	allowedAudiences?: readonly string[];
}): ClientRepository {
	const baseClient = {
		clientId: TEST_CLIENT_ID,
		tokenEndpointAuthMethod: "client_secret_basic" as const,
		allowedRedirectUris: [],
		allowedScopes: opts.allowedScopes ?? ["read", "write"],
		allowedAudiences: opts.allowedAudiences ?? ["https://api.example"],
		...(opts.allowedGrantTypes !== undefined && { allowedGrantTypes: opts.allowedGrantTypes }),
	};
	return {
		findById: async (id) => (id === TEST_CLIENT_ID ? baseClient : null),
		authenticate: async (id, secret) =>
			id === TEST_CLIENT_ID && secret === TEST_CLIENT_SECRET ? baseClient : null,
	};
}

async function buildApp(clientRepo: ClientRepository): Promise<express.Express> {
	const app = express();
	app.set("trust proxy", 1);
	app.use(express.json());
	app.use(express.urlencoded({ extended: false }));
	const keyStore = createSymmetricKeyStore(SECRET);
	const registry = new GrantRegistry();
	registry.register(
		"client_credentials",
		createClientCredentialsGrant({ config: fullConfig, keyStore }),
	);
	const { router } = await createOAuthRouter(express, {
		registry,
		config: fullConfig,
		clientRepository: clientRepo,
		codeRepository: codeRepoStub,
		keyStore,
	});
	app.use("/oauth", router);
	return app;
}

describe("client_credentials — /oauth/token integration (route → ctx propagation)", () => {
	it("issues 200 + access_token when the client record surfaces allowedGrantTypes: ['client_credentials']", async () => {
		// Confirms routes.mts copies allowedGrantTypes from req.oauthClient
		// into ctx.authenticatedClient. A typo in the spread would silently
		// reject this request with 400 unauthorized_client.
		const app = await buildApp(clientRepoWith({ allowedGrantTypes: ["client_credentials"] }));
		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", TEST_BASIC_AUTH)
			.type("form")
			.send({ grant_type: "client_credentials" });

		expect(res.status).toBe(200);
		expect(res.body.access_token).toBeTruthy();
		expect(res.body.refresh_token).toBeUndefined();
		const payload = decodeJwt(res.body.access_token);
		expect(payload.sub).toBe(TEST_CLIENT_ID);
		expect(payload.client_id).toBe(TEST_CLIENT_ID);
		expect(payload.aud).toBe("https://api.example");
	});

	it("returns 400 unauthorized_client when the client record omits allowedGrantTypes (deny-by-absence)", async () => {
		// Confirms the field's absence is propagated as undefined (not coerced
		// to [] or some allow-all default) so §3.4.1 deny-by-absence holds.
		const app = await buildApp(clientRepoWith({ allowedGrantTypes: undefined }));
		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", TEST_BASIC_AUTH)
			.type("form")
			.send({ grant_type: "client_credentials" });

		expect(res.status).toBe(400);
		expect(res.body.error).toBe("unauthorized_client");
	});

	it("keeps the pre-#326 denial wire format for deny-by-absence", async () => {
		// #326 moved the deny-by-absence check from the handler onto dispatch
		// (`requiresExplicitGrantAllowlist`). Pure refactor: the response the
		// handler used to emit — code AND description — must survive the move.
		const app = await buildApp(clientRepoWith({ allowedGrantTypes: undefined }));
		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", TEST_BASIC_AUTH)
			.type("form")
			.send({ grant_type: "client_credentials" });

		expect(res.status).toBe(400);
		expect(res.body.error).toBe("unauthorized_client");
		expect(res.body.error_description).toBe("client is not authorized for client_credentials");
	});

	it("denies a public client with no allowlist through the allowlist rule (#326 precedence)", async () => {
		// The one composed-order change #326 makes, pinned so it stays
		// deliberate: this doubly-ineligible request (public client AND absent
		// allowlist) used to reach the handler and fail its confidential-client
		// rule first (`invalid_client`); the dispatch-level deny-by-absence now
		// runs before any handler code, so the allowlist denial wins
		// (`unauthorized_client`). Still a 400 denial either way — keeping the
		// old precedence would mean teaching dispatch cc's confidential-client
		// rule, which is exactly the folklore the flag exists to delete.
		const publicClient = {
			clientId: TEST_CLIENT_ID,
			tokenEndpointAuthMethod: "none" as const,
			allowedRedirectUris: [],
			allowedScopes: ["read"],
			allowedAudiences: [],
		};
		const repo: ClientRepository = {
			findById: async (id) => (id === TEST_CLIENT_ID ? publicClient : null),
			authenticate: async () => null,
		};
		const app = await buildApp(repo);
		const res = await request(app)
			.post("/oauth/token")
			.type("form")
			.send({ grant_type: "client_credentials", client_id: TEST_CLIENT_ID });

		expect(res.status).toBe(400);
		expect(res.body.error).toBe("unauthorized_client");
	});

	it("propagates allowedScopes so the scope subset check sees the client's allowlist", async () => {
		const app = await buildApp(
			clientRepoWith({
				allowedGrantTypes: ["client_credentials"],
				allowedScopes: ["scope:a"],
			}),
		);
		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", TEST_BASIC_AUTH)
			.type("form")
			.send({ grant_type: "client_credentials", scope: "scope:a" });

		expect(res.status).toBe(200);
		const payload = decodeJwt(res.body.access_token);
		expect(payload.scope).toBe("scope:a");
	});

	it("propagates allowedAudiences so the issued aud claim matches the client's preferred audience", async () => {
		const app = await buildApp(
			clientRepoWith({
				allowedGrantTypes: ["client_credentials"],
				allowedAudiences: ["urn:custom:audience"],
			}),
		);
		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", TEST_BASIC_AUTH)
			.type("form")
			.send({ grant_type: "client_credentials" });

		expect(res.status).toBe(200);
		const payload = decodeJwt(res.body.access_token);
		expect(payload.aud).toBe("urn:custom:audience");
	});
});
