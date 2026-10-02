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
 * oauth's entry points that take a `ClientRepository`, `createOAuthRouter`
 * and `createClientAuthMiddleware`, read registered clients through core's
 * client-record boundary, outermost, with Client ID Metadata Documents off
 * as with them on. A boundary handed in is not wrapped again, and a document
 * fallback handed in is not wrapped at all.
 */

import crypto, { randomUUID } from "node:crypto";
import {
	type AppConfig,
	type AuthenticatedClient,
	type ClientRepository,
	type CodeRepository,
	createMemoryAccessTokenDenylist,
	createMemoryConsentStore,
	createMemoryPendingConsentStore,
	createMemoryReplaySeenSet,
	createSymmetricKeyStore,
	type GrantHandler,
	type PublicClient,
	validatedClientRepository,
} from "@o3co/auth-provider-core";
import {
	createTestLoginEntry,
	GrantRegistry,
	makeValidAppConfig,
	resolverForTests,
} from "@o3co/auth-provider-core/testing";
import express from "express";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import request from "supertest";
import { beforeAll, describe, expect, it, vi } from "vitest";
import {
	isClientIdMetadataDocumentClient,
	withClientIdMetadataDocuments,
} from "#/clients/clientIdMetadataDocument.mjs";
import { JWT_BEARER_CLIENT_ASSERTION_TYPE } from "#/middleware/clientAssertion.mjs";
import { createClientAuthMiddleware } from "#/middleware/clientAuth.mjs";
import { createOAuthRouter } from "#/routes.mjs";
import { oauthConfigForTests } from "#/testing/index.mjs";
import { OAUTH_ADMISSION_ACTIONS } from "./_helpers/admissionActions.mjs";
import { codeRecord } from "./_helpers/codeRecord.mjs";
import { createMockLogger } from "./_helpers/mockLogger.mjs";

const ISSUER = "https://issuer.test";
const CLIENT_ID = "rp-1";
const SECRET = "rp-1-secret";
const REDIRECT_URI = "https://rp.example/cb";
const VERIFIER = "pkce-verifier".padEnd(43, "x");
const S256_CHALLENGE = crypto.createHash("sha256").update(VERIFIER).digest("base64url");

/** Documents off: `oauthConfigForTests` leaves them at the reference default. */
const config = { ...makeValidAppConfig(), ...oauthConfigForTests({ issuer: ISSUER }) } as AppConfig;

const VALID = {
	clientId: CLIENT_ID,
	tokenEndpointAuthMethod: "client_secret_basic",
	allowedRedirectUris: [REDIRECT_URI],
	allowedScopes: ["openid", "read"],
	firstParty: true,
	clientName: "Acme",
};

/** A record the registration schema refuses: its name is empty. */
const REFUSED = { ...VALID, clientName: "" };

const answering = (record: unknown): ClientRepository => ({
	findById: async (id) => (id === CLIENT_ID ? (record as PublicClient) : null),
	authenticate: async (id, secret) =>
		id === CLIENT_ID && secret === SECRET ? (record as PublicClient) : null,
});

const throwing: ClientRepository = {
	findById: async () => {
		throw new Error("store down");
	},
	authenticate: async () => {
		throw new Error("store down");
	},
};

const codeRepository: CodeRepository = {
	createCode: async () =>
		codeRecord({ code: "code-x", client_id: CLIENT_ID, redirect_uri: REDIRECT_URI }),
	findByCode: async () => null,
	consumeByCode: async () => null,
	removeByCode: async () => {},
};

/**
 * A stand-in `authorization_code` grant: it mounts `/authorize`, and at
 * `/token` records the client it was dispatched with.
 */
const capturingGrant = () => {
	const seen: (AuthenticatedClient | null)[] = [];
	const grant: GrantHandler = {
		handle: async (ctx) => {
			seen.push(ctx.authenticatedClient);
			return { result: { status: 400, error: "invalid_grant", errorDescription: "stand-in" } };
		},
	};
	const registry = new GrantRegistry();
	registry.register("authorization_code", grant);
	return { registry, seen };
};

const buildRouter = async (
	clientRepository: ClientRepository,
	{ consent = false }: { consent?: boolean } = {},
) => {
	const logger = createMockLogger();
	const { registry, seen } = capturingGrant();
	const { router } = await createOAuthRouter(express, {
		loginEntry: createTestLoginEntry(),
		requirements: resolverForTests([], { issuer: ISSUER, actions: OAUTH_ADMISSION_ACTIONS }),
		registry,
		config,
		clientRepository,
		codeRepository,
		keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
		accessTokenDenylist: createMemoryAccessTokenDenylist(),
		...(consent
			? {
					consentStore: createMemoryConsentStore(),
					pendingConsentStore: createMemoryPendingConsentStore(),
				}
			: {}),
		logger,
	});
	const session: Record<string, unknown> = { isAuthenticated: true, user: { id: "user-1" } };
	const app = express();
	app.use((req, _res, next) => {
		(req as unknown as { session: Record<string, unknown> }).session = session;
		(req as unknown as { sessionID?: string }).sessionID = "sess-1";
		next();
	});
	app.use("/oauth", router);
	return { app, logger, seen };
};

const authorize = (app: express.Express, clientId = CLIENT_ID) =>
	request(app).get("/oauth/authorize").query({
		response_type: "code",
		client_id: clientId,
		redirect_uri: REDIRECT_URI,
		state: "xyz",
		nonce: "n-1",
		code_challenge: S256_CHALLENGE,
		code_challenge_method: "S256",
		scope: "openid read",
	});

const basic = (path: string, app: express.Express, body: Record<string, string>) =>
	request(app).post(path).auth(CLIENT_ID, SECRET).type("form").send(body);

const token = (app: express.Express) =>
	basic("/oauth/token", app, {
		grant_type: "authorization_code",
		code: "code-x",
		redirect_uri: REDIRECT_URI,
		code_verifier: VERIFIER,
	});

const refusals = (logger: ReturnType<typeof createMockLogger>) =>
	logger.warn.mock.calls.filter(([, message]) => message === "client_record_refused");

describe("createOAuthRouter with documents off reads registered clients through core's boundary", () => {
	it("answers a refused record 400 invalid_client at /authorize, with no redirect, and warns it", async () => {
		const { app, logger } = await buildRouter(answering(REFUSED));
		const res = await authorize(app);
		expect(res.status).toBe(400);
		expect(res.body).toMatchObject({ error: "invalid_client" });
		expect(res.headers.location).toBeUndefined();
		expect(refusals(logger).map(([line]) => [line.step, line.clientId])).toEqual([
			["find", CLIENT_ID],
		]);
	});

	it("serves the same client at /authorize once its record is valid", async () => {
		const { app, logger } = await buildRouter(answering(VALID));
		const res = await authorize(app);
		expect(res.status).toBe(302);
		const location = new URL(res.headers.location as string);
		expect(`${location.origin}${location.pathname}`).toBe(REDIRECT_URI);
		expect(location.searchParams.get("code")).toBe("code-x");
		expect(refusals(logger)).toEqual([]);
	});

	it("answers a refused record 401 invalid_client at /token, before any grant runs", async () => {
		const { app, seen } = await buildRouter(answering(REFUSED));
		const res = await token(app);
		expect(res.status).toBe(401);
		expect(res.body).toMatchObject({ error: "invalid_client" });
		expect(seen).toEqual([]);
	});

	it("answers a refused record invalid_client at /revoke", async () => {
		const { app } = await buildRouter(answering(REFUSED));
		const res = await basic("/oauth/revoke", app, { token: "some-token" });
		expect(res.status).toBe(401);
		expect(res.body).toMatchObject({ error: "invalid_client" });
	});

	it("answers a refused record invalid_client at /introspect", async () => {
		const { app } = await buildRouter(answering(REFUSED));
		const res = await basic("/oauth/introspect", app, { token: "some-token" });
		expect(res.status).toBe(401);
		expect(res.body).toMatchObject({ error: "invalid_client" });
	});

	it("answers a repository that throws 503 at /authorize and /token", async () => {
		const { app } = await buildRouter(throwing);
		const authorized = await authorize(app);
		expect(authorized.status).toBe(503);
		expect(authorized.body).toMatchObject({ error: "temporarily_unavailable" });
		const exchanged = await token(app);
		expect(exchanged.status).toBe(503);
		expect(exchanged.body).toMatchObject({ error: "temporarily_unavailable" });
	});

	it("dispatches /token with the client a boundary handed in answered, not a second copy of it", async () => {
		const boundary = validatedClientRepository(answering(VALID), { logger: createMockLogger() });
		const authenticate = vi.spyOn(boundary, "authenticate");
		const { app, seen } = await buildRouter(boundary);
		const res = await token(app);
		expect(res.status).toBe(400);
		expect(authenticate).toHaveBeenCalledTimes(1);
		const answered = (await authenticate.mock.results[0]?.value) as PublicClient;
		expect(seen).toHaveLength(1);
		// The grant's client is built from the boundary's answer: the frozen
		// array is the same one, which a second boundary would have copied.
		expect(seen[0]?.allowedScopes).toBe(answered.allowedScopes);
	});
});

describe("createOAuthRouter handed a document fallback", () => {
	const DOC_ID = "https://tools.example/oauth/client.json";
	const fallback = () =>
		withClientIdMetadataDocuments(answering(null), {
			allowedScopes: ["openid", "read"],
			allowedAudiences: [],
			lookup: async () => ["93.184.216.34"],
			fetch: (async () =>
				new Response(
					JSON.stringify({
						client_id: DOC_ID,
						client_name: "Tools",
						redirect_uris: [REDIRECT_URI],
						token_endpoint_auth_method: "none",
					}),
					{ status: 200, headers: { "content-type": "application/json" } },
				)) as typeof fetch,
		});

	it("reads it unwrapped, so consent still names the host of a document client", async () => {
		const { app } = await buildRouter(fallback(), { consent: true });
		const res = await authorize(app, DOC_ID);
		expect(res.status).toBe(302);
		const location = new URL(res.headers.location as string, ISSUER);
		expect(location.pathname).toBe("/consent");
		const challenge = location.searchParams.get("challenge");
		const page = await request(app).get("/oauth/consent").query({ challenge });
		expect(page.status).toBe(200);
		expect(page.body).toMatchObject({ client_id: DOC_ID, client_id_host: "tools.example" });
	});
});

describe("createClientAuthMiddleware reads clients through core's boundary", () => {
	const app = (clientRepository: ClientRepository, logger = createMockLogger()) => {
		const server = express();
		server.use(express.urlencoded({ extended: false }));
		server.post(
			"/token",
			createClientAuthMiddleware(clientRepository, {
				issuer: ISSUER,
				logger,
				allowPublicClients: true,
				replaySeenSet: createMemoryReplaySeenSet(),
			}),
			(req, res) => {
				res.status(200).json({
					clientId: req.oauthClient?.clientId,
					frozen: Object.isFrozen(req.oauthClient),
					document: isClientIdMetadataDocumentClient(req.oauthClient),
				});
			},
		);
		return server;
	};

	it("refuses a client whose record the boundary refuses 401 invalid_client, and warns it", async () => {
		const logger = createMockLogger();
		const res = await basic("/token", app(answering(REFUSED), logger), {});
		expect(res.status).toBe(401);
		expect(res.body).toMatchObject({ error: "invalid_client" });
		expect(refusals(logger).map(([line]) => line.clientId)).toEqual([CLIENT_ID]);
	});

	it("passes a valid record on as the boundary's frozen copy", async () => {
		const res = await basic("/token", app(answering(VALID)), {});
		expect(res.status).toBe(200);
		expect(res.body).toEqual({ clientId: CLIENT_ID, frozen: true, document: false });
	});

	it("answers a repository that throws 503", async () => {
		const res = await basic("/token", app(throwing), {});
		expect(res.status).toBe(503);
		expect(res.body).toMatchObject({ error: "temporarily_unavailable" });
	});

	it("sets the client a boundary handed in answered, not a second copy of it", async () => {
		const boundary = validatedClientRepository(answering(VALID), { logger: createMockLogger() });
		const authenticate = vi.spyOn(boundary, "authenticate");
		const server = express();
		server.use(express.urlencoded({ extended: false }));
		let set: PublicClient | undefined;
		server.post("/token", createClientAuthMiddleware(boundary, { issuer: ISSUER }), (req, res) => {
			set = req.oauthClient;
			res.status(200).end();
		});
		const res = await basic("/token", server, {});
		expect(res.status).toBe(200);
		expect(authenticate).toHaveBeenCalledTimes(1);
		expect(set).toBe(await authenticate.mock.results[0]?.value);
	});

	it("reads a document fallback unwrapped, so a document client keeps its provenance", async () => {
		const DOC_ID = "https://tools.example/oauth/client.json";
		const fallback = withClientIdMetadataDocuments(answering(null), {
			allowedScopes: ["read"],
			allowedAudiences: [],
			lookup: async () => ["93.184.216.34"],
			fetch: (async () =>
				new Response(
					JSON.stringify({
						client_id: DOC_ID,
						client_name: "Tools",
						redirect_uris: [REDIRECT_URI],
						token_endpoint_auth_method: "none",
					}),
					{ status: 200, headers: { "content-type": "application/json" } },
				)) as typeof fetch,
		});
		const res = await request(app(fallback))
			.post("/token")
			.type("form")
			.send({ client_id: DOC_ID, grant_type: "authorization_code" });
		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(res.body).toEqual({ clientId: DOC_ID, frozen: false, document: true });
	});

	describe("private_key_jwt: the assertion's key is looked up through the boundary", () => {
		let privateKey: CryptoKey;
		let jwks: { keys: Record<string, unknown>[] };
		beforeAll(async () => {
			const pair = await generateKeyPair("ES256");
			privateKey = pair.privateKey;
			jwks = { keys: [{ ...(await exportJWK(pair.publicKey)), kid: "k1" }] };
		});
		const jwtRecord = (over: Record<string, unknown> = {}) => ({
			...VALID,
			tokenEndpointAuthMethod: "private_key_jwt",
			jwks,
			...over,
		});
		const assertion = async () => {
			const now = Math.floor(Date.now() / 1000);
			return new SignJWT({
				iss: CLIENT_ID,
				sub: CLIENT_ID,
				aud: `${ISSUER}/oauth/token`,
				iat: now,
				exp: now + 60,
				jti: randomUUID(),
			})
				.setProtectedHeader({ alg: "ES256", kid: "k1" })
				.sign(privateKey);
		};
		const send = async (record: unknown) =>
			request(app(answering(record)))
				.post("/token")
				.type("form")
				.send({
					client_assertion_type: JWT_BEARER_CLIENT_ASSERTION_TYPE,
					client_assertion: await assertion(),
				});

		it("refuses an assertion whose client's record the boundary refuses", async () => {
			const res = await send(jwtRecord({ clientName: "" }));
			expect(res.status).toBe(401);
			expect(res.body).toMatchObject({ error: "invalid_client" });
		});

		it("authenticates the same assertion once the record is valid", async () => {
			const res = await send(jwtRecord());
			expect(res.status).toBe(200);
			expect(res.body).toMatchObject({ clientId: CLIENT_ID, frozen: true });
		});
	});
});
