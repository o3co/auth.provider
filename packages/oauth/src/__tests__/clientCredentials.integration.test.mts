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

import { randomUUID } from "node:crypto";
import {
	type AppConfig,
	type ClientRepository,
	type CodeRepository,
	createMemoryReplaySeenSet,
	createSymmetricKeyStore,
} from "@o3co/auth-provider-core";
import { GrantRegistry } from "@o3co/auth-provider-core/testing";
import express from "express";
import { decodeJwt, exportJWK, generateKeyPair, type JWK, SignJWT } from "jose";
import request from "supertest";
import { beforeAll, describe, expect, it } from "vitest";
import { createClientCredentialsGrant } from "#/grants/clientCredentials.mjs";
import { JWT_BEARER_CLIENT_ASSERTION_TYPE } from "#/middleware/clientAssertion.mjs";
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
		// #396: the old implicit omitted-scope grant, now declared.
		defaultScopes: opts.allowedScopes ?? ["read", "write"],
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

	it("returns 400 invalid_request when grant_type is missing (RFC 6749 §5.2, #293 item 10)", async () => {
		// A missing required parameter is `invalid_request`; the server answers
		// `unsupported_grant_type` only for a VALUE it does not support.
		const app = await buildApp(clientRepoWith({ allowedGrantTypes: ["client_credentials"] }));
		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", TEST_BASIC_AUTH)
			.type("form")
			.send({});

		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_request");
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
			// #396: the old implicit omitted-scope grant, now declared.
			defaultScopes: ["read"],
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
				// #396: the old implicit omitted-scope grant, now declared.
				defaultScopes: ["scope:a"],
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

describe("client_credentials — private_key_jwt client authentication at /oauth/token (#484)", () => {
	const RP = "rp-jwt";
	let privateKey: CryptoKey;
	let publicJwk: JWK;
	beforeAll(async () => {
		const pair = await generateKeyPair("ES256");
		privateKey = pair.privateKey;
		publicJwk = { ...(await exportJWK(pair.publicKey)), kid: "rp-k1" };
	});

	const jwtClientRepo = (): ClientRepository => {
		const rp = {
			clientId: RP,
			tokenEndpointAuthMethod: "private_key_jwt" as const,
			jwks: { keys: [publicJwk] },
			allowedRedirectUris: [],
			allowedScopes: ["read"],
			defaultScopes: ["read"],
			allowedAudiences: ["https://api.example"],
			allowedGrantTypes: ["client_credentials"],
		};
		return {
			findById: async (id) => (id === RP ? rp : null),
			authenticate: async () => null,
		};
	};

	const assertion = async (claims: Record<string, unknown> = {}): Promise<string> => {
		const now = Math.floor(Date.now() / 1000);
		return new SignJWT({
			iss: RP,
			sub: RP,
			aud: `${ISSUER}/oauth/token`,
			iat: now,
			exp: now + 60,
			jti: randomUUID(),
			...claims,
		})
			.setProtectedHeader({ alg: "ES256", kid: "rp-k1" })
			.sign(privateKey);
	};

	async function buildJwtApp(
		replaySeenSet = createMemoryReplaySeenSet(),
	): Promise<express.Express> {
		const app = express();
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
			clientRepository: jwtClientRepo(),
			codeRepository: codeRepoStub,
			keyStore,
			replaySeenSet,
		});
		app.use("/oauth", router);
		return app;
	}

	it("a client registered with a JWKS authenticates with an assertion and receives a token", async () => {
		const res = await request(await buildJwtApp())
			.post("/oauth/token")
			.type("form")
			.send({
				grant_type: "client_credentials",
				client_assertion_type: JWT_BEARER_CLIENT_ASSERTION_TYPE,
				client_assertion: await assertion(),
			});
		expect(res.status).toBe(200);
		expect(decodeJwt(res.body.access_token).sub).toBe(RP);
	});

	it.each([
		["a replayed jti", async (a: () => Promise<string>) => a(), true],
		["a wrong aud", async () => assertion({ aud: "https://other.example/oauth/token" }), false],
		[
			"an expired assertion",
			async () => assertion({ exp: Math.floor(Date.now() / 1000) - 120 }),
			false,
		],
	])("refuses %s with 401 invalid_client", async (_label, make, replay) => {
		const app = await buildJwtApp();
		const first = await (make as (a: () => Promise<string>) => Promise<string>)(assertion);
		const send = (client_assertion: string) =>
			request(app).post("/oauth/token").type("form").send({
				grant_type: "client_credentials",
				client_assertion_type: JWT_BEARER_CLIENT_ASSERTION_TYPE,
				client_assertion,
			});
		if (replay) expect((await send(first)).status).toBe(200);
		const res = await send(first);
		expect(res.status).toBe(401);
		expect(res.body.error).toBe("invalid_client");
	});

	it("refuses a signature from a key outside the registered JWKS", async () => {
		const other = await generateKeyPair("ES256");
		const now = Math.floor(Date.now() / 1000);
		const forged = await new SignJWT({
			iss: RP,
			sub: RP,
			aud: `${ISSUER}/oauth/token`,
			iat: now,
			exp: now + 60,
			jti: randomUUID(),
		})
			.setProtectedHeader({ alg: "ES256", kid: "rp-k1" })
			.sign(other.privateKey);
		const res = await request(await buildJwtApp())
			.post("/oauth/token")
			.type("form")
			.send({
				grant_type: "client_credentials",
				client_assertion_type: JWT_BEARER_CLIENT_ASSERTION_TYPE,
				client_assertion: forged,
			});
		expect(res.status).toBe(401);
		expect(res.body.error).toBe("invalid_client");
	});
});
