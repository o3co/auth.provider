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
 * as with them on. A boundary handed in is not wrapped again, and the
 * router's document fallback, handed to the client authentication, is not
 * wrapped at all.
 */

import crypto, { randomUUID } from "node:crypto";
import {
	type AppConfig,
	type AuthenticatedClient,
	type ClientRepository,
	type CodeRepository,
	createMemoryAccessTokenDenylist,
	createMemoryReplaySeenSet,
	createOutboundFetch,
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
import { behindClientBoundary } from "#/clients/clientBoundary.mjs";
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
import { routerInputsOf } from "./_helpers/sections.mjs";

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

const buildRouter = async (clientRepository: ClientRepository) => {
	const logger = createMockLogger();
	const { registry, seen } = capturingGrant();
	const { router } = await createOAuthRouter(express, {
		loginEntry: createTestLoginEntry(),
		requirements: resolverForTests([], { issuer: ISSUER, actions: OAUTH_ADMISSION_ACTIONS }),
		registry,
		...routerInputsOf(config),
		clientRepository,
		codeRepository,
		keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
		accessTokenDenylist: createMemoryAccessTokenDenylist(),
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

/** The outage lines naming the boundary's refusal as their cause. */
const refusedLookups = (logger: ReturnType<typeof createMockLogger>) =>
	logger.error.mock.calls.filter(
		([line, message]) =>
			message === "client_repository_unavailable" &&
			(line as { err?: { reason?: string } }).err?.reason === "client_record_refused",
	);

describe("createOAuthRouter with documents off reads registered clients through core's boundary", () => {
	it("answers a refused record 503 at /authorize, with no redirect, and warns it once", async () => {
		const { app, logger } = await buildRouter(answering(REFUSED));
		const res = await authorize(app);
		expect(res.status).toBe(503);
		expect(res.body).toMatchObject({ error: "temporarily_unavailable" });
		expect(res.headers.location).toBeUndefined();
		expect(refusals(logger).map(([line]) => [line.step, line.clientId])).toEqual([
			["find", CLIENT_ID],
		]);
		expect(refusedLookups(logger)).toHaveLength(1);
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

	it("answers a refused record 503 at /token, before any grant runs, with no challenge", async () => {
		const { app, seen } = await buildRouter(answering(REFUSED));
		const res = await token(app);
		expect(res.status).toBe(503);
		expect(res.body).toMatchObject({ error: "temporarily_unavailable" });
		expect(res.headers["www-authenticate"]).toBeUndefined();
		expect(seen).toEqual([]);
	});

	it("answers a refused record 503 at /revoke", async () => {
		const { app } = await buildRouter(answering(REFUSED));
		const res = await basic("/oauth/revoke", app, { token: "some-token" });
		expect(res.status).toBe(503);
		expect(res.body).toMatchObject({ error: "temporarily_unavailable" });
	});

	it("answers a refused record 503 at /introspect", async () => {
		const { app } = await buildRouter(answering(REFUSED));
		const res = await basic("/oauth/introspect", app, { token: "some-token" });
		expect(res.status).toBe(503);
		expect(res.body).toMatchObject({ error: "temporarily_unavailable" });
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

	it("dispatches /token with the client a boundary handed in answered, read through it as it is", async () => {
		const inner = answering(VALID);
		const authenticate = vi.spyOn(inner, "authenticate");
		const boundary = validatedClientRepository(inner, { logger: createMockLogger() });
		// The boundary is frozen, so it cannot be spied on: it is kept as it is.
		expect(behindClientBoundary(boundary, createMockLogger())).toBe(boundary);
		const { app, seen } = await buildRouter(boundary);
		const res = await token(app);
		expect(res.status).toBe(400);
		expect(authenticate).toHaveBeenCalledTimes(1);
		expect(seen).toHaveLength(1);
		expect(seen[0]).toMatchObject({ clientId: CLIENT_ID, allowedScopes: VALID.allowedScopes });
		expect(Object.isFrozen(seen[0]?.allowedScopes)).toBe(true);
	});
});

describe("a record whose defaultScopes leave its allowedScopes never reaches a scope decision", () => {
	// `/authorize` and the grants `/token` dispatches to grant an omitted scope
	// from the client's defaultScopes as they are: the boundary is what holds
	// them within the allowlist.
	const OVER_DEFAULT = { ...VALID, defaultScopes: ["read", "admin"] };

	it("answers it 503 at /authorize for a request that omits scope, with no redirect", async () => {
		const { app, logger } = await buildRouter(answering(OVER_DEFAULT));
		const res = await request(app).get("/oauth/authorize").query({
			response_type: "code",
			client_id: CLIENT_ID,
			redirect_uri: REDIRECT_URI,
			state: "xyz",
			code_challenge: S256_CHALLENGE,
			code_challenge_method: "S256",
		});
		expect(res.status).toBe(503);
		expect(res.body).toMatchObject({ error: "temporarily_unavailable" });
		expect(res.headers.location).toBeUndefined();
		expect(refusals(logger).map(([line]) => line.reasons)).toEqual([
			[expect.stringContaining("defaultScopes")],
		]);
	});

	it.each(["client_credentials", "urn:ietf:params:oauth:grant-type:jwt-bearer"])(
		"answers it 503 at /token for %s, before any grant runs",
		async (grantType) => {
			const { app, seen } = await buildRouter(answering(OVER_DEFAULT));
			const res = await basic("/oauth/token", app, { grant_type: grantType });
			expect(res.status).toBe(503);
			expect(res.body).toMatchObject({ error: "temporarily_unavailable" });
			expect(seen).toEqual([]);
		},
	);
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
				fetch: createOutboundFetch({ config: {}, source: "registration" }),
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

	it("answers a client whose record the boundary refuses 503, and warns it once", async () => {
		const logger = createMockLogger();
		const res = await basic("/token", app(answering(REFUSED), logger), {});
		expect(res.status).toBe(503);
		expect(res.body).toMatchObject({ error: "temporarily_unavailable" });
		expect(refusals(logger).map(([line]) => line.clientId)).toEqual([CLIENT_ID]);
		expect(refusedLookups(logger).map(([line]) => line.step)).toEqual(["find"]);
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

	it("sets the client a boundary handed in answered, read through it as it is", async () => {
		const inner = answering(VALID);
		const authenticate = vi.spyOn(inner, "authenticate");
		const boundary = validatedClientRepository(inner, { logger: createMockLogger() });
		const server = express();
		server.use(express.urlencoded({ extended: false }));
		let set: PublicClient | undefined;
		server.post(
			"/token",
			createClientAuthMiddleware(boundary, {
				issuer: ISSUER,
				fetch: createOutboundFetch({ config: {}, source: "registration" }),
			}),
			(req, res) => {
				set = req.oauthClient;
				res.status(200).end();
			},
		);
		const res = await basic("/token", server, {});
		expect(res.status).toBe(200);
		expect(authenticate).toHaveBeenCalledTimes(1);
		expect(set).toMatchObject({ clientId: CLIENT_ID, clientName: VALID.clientName });
		expect(Object.isFrozen(set)).toBe(true);
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

		it("answers an assertion whose client's record the boundary refuses 503", async () => {
			const res = await send(jwtRecord({ clientName: "" }));
			expect(res.status).toBe(503);
			expect(res.body).toMatchObject({ error: "temporarily_unavailable" });
		});

		it("authenticates the same assertion once the record is valid", async () => {
			const res = await send(jwtRecord());
			expect(res.status).toBe(200);
			expect(res.body).toMatchObject({ clientId: CLIENT_ID, frozen: true });
		});
	});
});
