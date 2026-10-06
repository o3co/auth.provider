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
 * End-to-end coverage for the route → ctx.authenticatedClient propagation of
 * the `client_credentials` grant. The unit tests in `clientCredentials.test.mts`
 * construct `AuthenticatedClient` directly, so they cannot catch a fault in how
 * `routes/token.mts` maps `req.oauthClient.*` into the handler input; this file
 * drives the full HTTP path via supertest.
 */

import { randomUUID } from "node:crypto";
import {
	type AppConfig,
	type ClientRepository,
	type CodeRepository,
	createMemoryReplaySeenSet,
	createSymmetricKeyStore,
	type ReplaySeenSet,
} from "@o3co/auth-provider-core";
import { GrantRegistry, resolverForTests } from "@o3co/auth-provider-core/testing";
import express from "express";
import { decodeJwt, exportJWK, generateKeyPair, type JWK, SignJWT } from "jose";
import request from "supertest";
import { beforeAll, describe, expect, it } from "vitest";
import { createClientCredentialsGrant } from "#/grants/clientCredentials.mjs";
import { JWT_BEARER_CLIENT_ASSERTION_TYPE } from "#/middleware/clientAssertion.mjs";
import { createOAuthRouter } from "#/routes.mjs";
import { codeRecord } from "./_helpers/codeRecord.mjs";
import { grantSettingsFrom } from "./_helpers/grantSettings.mjs";
import { routerInputsOf } from "./_helpers/sections.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const ISSUER = "https://auth.example";
const TEST_CLIENT_ID = "cc-client";
const TEST_CLIENT_SECRET = "cc-secret";
const TEST_BASIC_AUTH = `Basic ${Buffer.from(`${TEST_CLIENT_ID}:${TEST_CLIENT_SECRET}`).toString("base64")}`;

const fullConfig = {
	oauth: {
		jwt: { issuer: ISSUER },
		accessToken: { defaultExpiresIn: 3600 },
	},
	rateLimit: { failMode: "open" as const },
	endpoints: { login: { url: "/login" } },
} as unknown as AppConfig;

const codeRepoStub: CodeRepository = {
	createCode: async () =>
		codeRecord({
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
		// What an omitted `scope` grants: nothing is granted implicitly.
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
		createClientCredentialsGrant({ ...grantSettingsFrom(fullConfig), keyStore }),
	);
	const { router } = await createOAuthRouter(express, {
		requirements: resolverForTests([]),
		registry,
		...routerInputsOf(fullConfig),
		clientRepository: clientRepo,
		codeRepository: codeRepoStub,
		keyStore,
	});
	app.use("/oauth", router);
	return app;
}

describe("client_credentials — /oauth/token integration (route → ctx propagation)", () => {
	it("issues 200 + access_token when the client record surfaces allowedGrantTypes: ['client_credentials']", async () => {
		// routes/token.mts copies allowedGrantTypes from req.oauthClient into
		// ctx.authenticatedClient; without it this request is 400
		// unauthorized_client.
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

	it("answers a malformed scope 400 invalid_scope on the wire, and a tab alone is not an omitted scope", async () => {
		const app = await buildApp(clientRepoWith({ allowedGrantTypes: ["client_credentials"] }));
		for (const scope of ["read\twrite", "\t"]) {
			const res = await request(app)
				.post("/oauth/token")
				.set("Authorization", TEST_BASIC_AUTH)
				.type("form")
				.send({ grant_type: "client_credentials", scope });
			expect(res.status, JSON.stringify(scope)).toBe(400);
			expect(res.body).toEqual({
				error: "invalid_scope",
				error_description: "scope is not a space-delimited list of scope-tokens",
			});
		}
	});

	it("returns 400 invalid_request when grant_type is missing (RFC 6749 §5.2)", async () => {
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
		// The field's absence is propagated as undefined (not coerced to [] or
		// an allow-all default), so §3.4.1 deny-by-absence holds.
		const app = await buildApp(clientRepoWith({ allowedGrantTypes: undefined }));
		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", TEST_BASIC_AUTH)
			.type("form")
			.send({ grant_type: "client_credentials" });

		expect(res.status).toBe(400);
		expect(res.body.error).toBe("unauthorized_client");
	});

	it("refuses deny-by-absence in the base allowlist rule's words", async () => {
		// Deny-by-absence runs at dispatch (`requiresExplicitGrantAllowlist`)
		// and answers as the base allowlist check does, code and description, so
		// the two rules cannot be told apart on the wire.
		const app = await buildApp(clientRepoWith({ allowedGrantTypes: undefined }));
		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", TEST_BASIC_AUTH)
			.type("form")
			.send({ grant_type: "client_credentials" });

		expect(res.status).toBe(400);
		expect(res.body.error).toBe("unauthorized_client");
		expect(res.body.error_description).toBe(
			"client is not authorized for grant_type 'client_credentials'",
		);
	});

	it("denies a public client with no allowlist through the allowlist rule, ahead of the confidential-client rule", async () => {
		// Deliberate precedence: dispatch-level deny-by-absence runs before any
		// handler code, so this doubly-ineligible request (public client AND
		// absent allowlist) is denied by the allowlist rule (`unauthorized_client`),
		// not the handler's confidential-client rule (`invalid_client`). The
		// other order would mean teaching dispatch that confidential-client rule.
		const publicClient = {
			clientId: TEST_CLIENT_ID,
			tokenEndpointAuthMethod: "none" as const,
			allowedRedirectUris: [],
			allowedScopes: ["read"],
			// What an omitted `scope` grants: nothing is granted implicitly.
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

describe("client_credentials — private_key_jwt client authentication at /oauth/token", () => {
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
		replaySeenSet: ReplaySeenSet | null = createMemoryReplaySeenSet(),
	): Promise<express.Express> {
		const app = express();
		app.use(express.urlencoded({ extended: false }));
		const keyStore = createSymmetricKeyStore(SECRET);
		const registry = new GrantRegistry();
		registry.register(
			"client_credentials",
			createClientCredentialsGrant({ ...grantSettingsFrom(fullConfig), keyStore }),
		);
		const { router } = await createOAuthRouter(express, {
			requirements: resolverForTests([]),
			registry,
			...routerInputsOf(fullConfig),
			clientRepository: jwtClientRepo(),
			codeRepository: codeRepoStub,
			keyStore,
			...(replaySeenSet === null ? {} : { replaySeenSet }),
		});
		app.use("/oauth", router);
		return app;
	}

	it("the replay seen-set alone switches the method on: the same client, without one, is refused 500 server_error", async () => {
		// The coupling a composition inherits when it installs a seen-set for
		// another consumer, such as DPoP's proofs. Same client, same keys, same
		// assertion shape; only the seen-set differs. (Discovery follows the
		// same condition: oauthEndpointsModule advertises private_key_jwt iff a
		// replaySeenSet is wired — pinned in discovery-contribution.test.mts.)
		const send = async (app: express.Express) =>
			request(app)
				.post("/oauth/token")
				.type("form")
				.send({
					grant_type: "client_credentials",
					client_assertion_type: JWT_BEARER_CLIENT_ASSERTION_TYPE,
					client_assertion: await assertion(),
				});

		const without = await send(await buildJwtApp(null));
		expect(without.status).toBe(500);
		expect(without.body.error).toBe("server_error");

		const withSeenSet = await send(await buildJwtApp());
		expect(withSeenSet.status).toBe(200);
		expect(decodeJwt(withSeenSet.body.access_token).sub).toBe(RP);
	});

	it("still authenticates when DPoP proofs have filled their share of a memory seen-set", async () => {
		// Every consumer shares the seen-set, and DPoP records a proof before
		// any rate limit or token check: a flood of fresh proofs filling DPoP's
		// share must not refuse client authentication.
		const seenSet = createMemoryReplaySeenSet({ maxEntries: 10 });
		let proofs = 0;
		for (;;) {
			try {
				await seenSet.markSeen("dpop-proof:flood-key", `jti-${proofs}`, Date.now() + 300_000);
				proofs += 1;
			} catch {
				break;
			}
		}
		expect(proofs).toBe(9);

		const res = await request(await buildJwtApp(seenSet))
			.post("/oauth/token")
			.type("form")
			.send({
				grant_type: "client_credentials",
				client_assertion_type: JWT_BEARER_CLIENT_ASSERTION_TYPE,
				client_assertion: await assertion(),
			});
		expect(res.status).toBe(200);
		expect(decodeJwt(res.body.access_token).sub).toBe(RP);
		expect(seenSet.size).toBe(10);
	});

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
