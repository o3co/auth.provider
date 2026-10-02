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
 * oauth's entry points that take a `ClientRepository` — `createOAuthRouter`
 * and `createClientAuthMiddleware` — read clients through core's
 * client-record boundary when a composition calls them directly: a record
 * the boundary refuses is an unknown client, and with Client ID Metadata
 * Documents on, it never falls through to a document.
 */

import crypto from "node:crypto";
import {
	type AppConfig,
	type ClientRepository,
	type CodeRepository,
	createMemoryConsentStore,
	createMemoryPendingConsentStore,
	createSymmetricKeyStore,
	type PublicClient,
	validatedClientRepository,
} from "@o3co/auth-provider-core";
import { createTestLoginEntry, resolverForTests } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { withClientIdMetadataDocuments } from "#/clients/clientIdMetadataDocument.mjs";
import { createClientAuthMiddleware } from "#/middleware/clientAuth.mjs";
import { createOAuthRouter } from "#/routes.mjs";
import { OAUTH_ADMISSION_ACTIONS } from "./_helpers/admissionActions.mjs";
import { authorizationServerRegistry } from "./_helpers/authorizationServerRegistry.mjs";
import { codeRecord } from "./_helpers/codeRecord.mjs";
import { createMockLogger } from "./_helpers/mockLogger.mjs";

const CLIENT_URL = "https://client.example/oauth/client-metadata.json";
const REDIRECT_URI = "https://client.example/cb";
const VERIFIER = "pkce-verifier".padEnd(43, "x");
const S256_CHALLENGE = crypto.createHash("sha256").update(VERIFIER).digest("base64url");

const document = {
	client_id: CLIENT_URL,
	client_name: "Acme Chat",
	redirect_uris: [REDIRECT_URI],
	scope: "read",
};

/** A registration under the document's URL that the boundary refuses: its name is empty. */
const malformedRegistration = {
	clientId: CLIENT_URL,
	tokenEndpointAuthMethod: "client_secret_basic",
	allowedRedirectUris: [REDIRECT_URI],
	allowedScopes: ["read"],
	firstParty: true,
	clientName: "",
};

const answering = (record: unknown, clientId = CLIENT_URL): ClientRepository => ({
	findById: async (id) => (id === clientId ? (record as PublicClient) : null),
	authenticate: async (id) => (id === clientId ? (record as PublicClient) : null),
});

/** A client authenticating with HTTP Basic: its id holds no `:`, which Basic splits on. */
const RP = "rp-1";
const rpRecord = (over: Record<string, unknown> = {}) => ({
	...malformedRegistration,
	clientId: RP,
	clientName: "Acme",
	...over,
});

const config = {
	oauth: {
		jwt: { issuer: "https://issuer.example" },
		oidcMode: "dual",
		grants: {},
		clientIdMetadataDocuments: {
			enabled: true,
			allowedScopes: ["read"],
			allowedAudiences: [],
		},
	},
	rateLimit: { failMode: "open" as const },
	endpoints: { login: { url: "/login" }, consent: { url: "/consent" } },
} as unknown as AppConfig;

const codeRepository: CodeRepository = {
	createCode: async () =>
		codeRecord({ code: "code-x", client_id: CLIENT_URL, redirect_uri: REDIRECT_URI }),
	findByCode: async () => null,
	consumeByCode: async () => null,
	removeByCode: async () => {},
};

const buildRouter = async (clientRepository: ClientRepository) => {
	const fetchImpl = vi.fn(
		async () =>
			new Response(JSON.stringify(document), {
				status: 200,
				headers: { "content-type": "application/json" },
			}),
	) as unknown as typeof fetch;
	const logger = createMockLogger();
	const { router } = await createOAuthRouter(express, {
		loginEntry: createTestLoginEntry(),
		requirements: resolverForTests([], { actions: OAUTH_ADMISSION_ACTIONS }),
		registry: authorizationServerRegistry(),
		config,
		clientRepository,
		codeRepository,
		keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
		consentStore: createMemoryConsentStore(),
		pendingConsentStore: createMemoryPendingConsentStore(),
		clientIdMetadataDocuments: { fetch: fetchImpl, lookup: async () => ["93.184.216.34"] },
		logger,
	});
	const app = express();
	app.use((req, _res, next) => {
		(req as unknown as { session: Record<string, unknown> }).session = {
			isAuthenticated: true,
			user: { id: "user-1" },
		};
		(req as unknown as { sessionID?: string }).sessionID = "sess-1";
		next();
	});
	app.use("/oauth", router);
	return { app, fetchImpl, logger };
};

const authorize = (app: express.Express) =>
	request(app).get("/oauth/authorize").query({
		response_type: "code",
		client_id: CLIENT_URL,
		redirect_uri: REDIRECT_URI,
		state: "xyz",
		code_challenge: S256_CHALLENGE,
		code_challenge_method: "S256",
		scope: "read",
	});

describe("createOAuthRouter, composed directly", () => {
	it("answers a registration the boundary refuses as an unknown client, and never fetches its document", async () => {
		const { app, fetchImpl, logger } = await buildRouter(answering(malformedRegistration));
		const res = await authorize(app);
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_client");
		expect(res.headers.location).toBeUndefined();
		expect(fetchImpl).not.toHaveBeenCalled();
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({ clientId: CLIENT_URL }),
			"client_record_refused",
		);
	});

	it("still resolves the document when no client is registered under the id", async () => {
		const { app, fetchImpl } = await buildRouter(answering(null));
		const res = await authorize(app);
		expect(res.status).toBe(302);
		expect(new URL(res.headers.location as string, "https://issuer.example").pathname).toBe(
			"/consent",
		);
		expect(fetchImpl).toHaveBeenCalledTimes(1);
	});

	it("answers a repository that cannot answer as an outage, never a document", async () => {
		const { app, fetchImpl } = await buildRouter({
			findById: async () => {
				throw new Error("store down");
			},
			authenticate: async () => null,
		});
		const res = await authorize(app);
		expect(res.status).toBe(503);
		expect(res.body.error).toBe("temporarily_unavailable");
		expect(fetchImpl).not.toHaveBeenCalled();
	});

	it("refuses to build over a repository that already resolves documents", async () => {
		const nested = withClientIdMetadataDocuments(answering(null), {
			allowedScopes: [],
			allowedAudiences: [],
		});
		await expect(buildRouter(nested)).rejects.toThrow(/Client ID Metadata Document/);
	});
});

describe("createClientAuthMiddleware, composed directly", () => {
	const app = (clientRepository: ClientRepository, logger = createMockLogger()) => {
		const server = express();
		server.use(express.urlencoded({ extended: false }));
		server.post("/token", createClientAuthMiddleware(clientRepository, { logger }), (_req, res) => {
			res.status(200).json({ ok: true });
		});
		return server;
	};

	it("refuses a client whose record the boundary refuses, as an unknown client", async () => {
		const logger = createMockLogger();
		const res = await request(app(answering(rpRecord({ clientName: "" }), RP), logger))
			.post("/token")
			.auth(RP, "secret")
			.type("form")
			.send({ grant_type: "authorization_code" });
		expect(res.status).toBe(401);
		expect(res.body.error).toBe("invalid_client");
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({ clientId: RP }),
			"client_record_refused",
		);
	});

	it("authenticates a valid record read through the boundary", async () => {
		const res = await request(app(answering(rpRecord(), RP)))
			.post("/token")
			.auth(RP, "secret")
			.type("form")
			.send({ grant_type: "authorization_code" });
		expect(res.status).toBe(200);
	});

	it("reads a repository already behind the boundary once per lookup", async () => {
		const inner = answering(rpRecord(), RP);
		const findById = vi.spyOn(inner, "findById");
		const authenticate = vi.spyOn(inner, "authenticate");
		const res = await request(app(validatedClientRepository(inner)))
			.post("/token")
			.auth(RP, "secret")
			.type("form")
			.send({ grant_type: "authorization_code" });
		expect(res.status).toBe(200);
		expect(findById.mock.calls.length).toBeLessThanOrEqual(1);
		expect(authenticate.mock.calls.length).toBeLessThanOrEqual(1);
	});
});
