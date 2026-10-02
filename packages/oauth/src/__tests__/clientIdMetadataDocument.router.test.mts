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
 * The router with Client ID Metadata Documents on: its one document
 * fallback reads every registered client through core's boundary, so a
 * registration the boundary refuses, of any id shape, rejects the lookup
 * with core's refusal, `503` as for any rejected lookup, and is never
 * replaced by a document. With documents off the router reads the
 * repository through the boundary itself, with the same answer. An id no
 * client is registered under still resolves its document, and consent names
 * the document's host. The fallback is the router's own: the package entry
 * exports neither it nor its resolver.
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
} from "@o3co/auth-provider-core";
import { createTestLoginEntry, resolverForTests } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createOAuthRouter } from "#/routes.mjs";
import { OAUTH_ADMISSION_ACTIONS } from "./_helpers/admissionActions.mjs";
import { authorizationServerRegistry } from "./_helpers/authorizationServerRegistry.mjs";
import { codeRecord } from "./_helpers/codeRecord.mjs";
import { createMockLogger } from "./_helpers/mockLogger.mjs";

const CLIENT_ID = "rp-1";
const REDIRECT_URI = "https://rp.example/cb";
const VERIFIER = "pkce-verifier".padEnd(43, "x");
const S256_CHALLENGE = crypto.createHash("sha256").update(VERIFIER).digest("base64url");

/** A registration the boundary refuses (its name is empty), under an id that is not a URL. */
const refusedRecord = {
	clientId: CLIENT_ID,
	tokenEndpointAuthMethod: "none",
	allowedRedirectUris: [REDIRECT_URI],
	allowedScopes: ["read"],
	firstParty: true,
	clientName: "",
};

const answering = (record: unknown, id: string = CLIENT_ID): ClientRepository => ({
	findById: async (asked) => (asked === id ? (record as PublicClient) : null),
	authenticate: async () => null,
});

/** A URL-shaped client id, the shape a document client takes. */
const DOC_ID = "https://tools.example/oauth/client.json";

/** A registration under the URL-shaped id that the boundary refuses (its name is empty). */
const refusedUrlRecord = { ...refusedRecord, clientId: DOC_ID };

/** A fetch that serves the document at `DOC_ID`. */
const servingDocument = () =>
	vi.fn(
		async () =>
			new Response(
				JSON.stringify({
					client_id: DOC_ID,
					client_name: "Tools",
					redirect_uris: [REDIRECT_URI],
					token_endpoint_auth_method: "none",
				}),
				{ status: 200, headers: { "content-type": "application/json" } },
			),
	) as unknown as typeof fetch;

const configWith = (documents: boolean) =>
	({
		oauth: {
			jwt: { issuer: "https://issuer.example" },
			oidcMode: "dual",
			grants: {},
			clientIdMetadataDocuments: {
				enabled: documents,
				allowedScopes: ["read"],
				allowedAudiences: [],
			},
		},
		rateLimit: { failMode: "open" as const },
		endpoints: { login: { url: "/login" }, consent: { url: "/consent" } },
	}) as unknown as AppConfig;

const codeRepository: CodeRepository = {
	createCode: async () =>
		codeRecord({ code: "code-x", client_id: CLIENT_ID, redirect_uri: REDIRECT_URI }),
	findByCode: async () => null,
	consumeByCode: async () => null,
	removeByCode: async () => {},
};

const buildRouter = async (
	clientRepository: ClientRepository,
	{
		documents = true,
		fetchImpl = vi.fn(async () => new Response("{}", { status: 404 })) as unknown as typeof fetch,
	}: { documents?: boolean; fetchImpl?: typeof fetch } = {},
) => {
	const logger = createMockLogger();
	const { router } = await createOAuthRouter(express, {
		loginEntry: createTestLoginEntry(),
		requirements: resolverForTests([], { actions: OAUTH_ADMISSION_ACTIONS }),
		registry: authorizationServerRegistry(),
		config: configWith(documents),
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

const authorize = (app: express.Express, clientId = CLIENT_ID) =>
	request(app).get("/oauth/authorize").query({
		response_type: "code",
		client_id: clientId,
		redirect_uri: REDIRECT_URI,
		state: "xyz",
		code_challenge: S256_CHALLENGE,
		code_challenge_method: "S256",
		scope: "read",
	});

/** A public client's `/token` request: client authentication looks the client up first. */
const token = (app: express.Express, clientId: string) =>
	request(app).post("/oauth/token").type("form").send({
		grant_type: "authorization_code",
		client_id: clientId,
		code: "code-x",
		redirect_uri: REDIRECT_URI,
		code_verifier: VERIFIER,
	});

/** The outage lines naming the boundary's refusal as their cause. */
const refusedLookups = (logger: ReturnType<typeof createMockLogger>) =>
	logger.error.mock.calls.filter(
		([line, message]) =>
			message === "client_repository_unavailable" &&
			(line as { err?: { reason?: string } }).err?.reason === "client_record_refused",
	);

describe("the router's one document fallback reads every registered client through core's boundary", () => {
	it("answers a refused registration whose id is not a URL 503, with documents on", async () => {
		const { app, fetchImpl, logger } = await buildRouter(answering(refusedRecord));
		const res = await authorize(app);
		expect(res.status).toBe(503);
		expect(res.body.error).toBe("temporarily_unavailable");
		expect(res.headers.location).toBeUndefined();
		expect(fetchImpl).not.toHaveBeenCalled();
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({ clientId: CLIENT_ID }),
			"client_record_refused",
		);
	});

	it("answers the same refused registration 503 with documents off", async () => {
		const { app, fetchImpl, logger } = await buildRouter(answering(refusedRecord), {
			documents: false,
		});
		const res = await authorize(app);
		expect(res.status).toBe(503);
		expect(res.body.error).toBe("temporarily_unavailable");
		expect(res.headers.location).toBeUndefined();
		expect(fetchImpl).not.toHaveBeenCalled();
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({ clientId: CLIENT_ID }),
			"client_record_refused",
		);
	});
});

describe("a refused registration under a URL-shaped id, with documents on", () => {
	it("answers 503 at /authorize, with no redirect, and never fetches the document", async () => {
		const fetchImpl = servingDocument();
		const { app, logger } = await buildRouter(answering(refusedUrlRecord, DOC_ID), { fetchImpl });
		const res = await authorize(app, DOC_ID);
		expect(res.status).toBe(503);
		expect(res.body.error).toBe("temporarily_unavailable");
		expect(res.headers.location).toBeUndefined();
		expect(fetchImpl).not.toHaveBeenCalled();
		expect(refusedLookups(logger)).toHaveLength(1);
	});

	it("answers 503 at client authentication, with no challenge, and never fetches the document", async () => {
		const fetchImpl = servingDocument();
		const { app, logger } = await buildRouter(answering(refusedUrlRecord, DOC_ID), { fetchImpl });
		const res = await token(app, DOC_ID);
		expect(res.status).toBe(503);
		expect(res.body.error).toBe("temporarily_unavailable");
		expect(res.headers["www-authenticate"]).toBeUndefined();
		expect(fetchImpl).not.toHaveBeenCalled();
		expect(refusedLookups(logger)).toHaveLength(1);
	});

	it("still resolves the document for the same id when no client is registered under it, and consent names its host", async () => {
		const fetchImpl = servingDocument();
		const { app } = await buildRouter(answering(null, DOC_ID), { fetchImpl });
		const res = await authorize(app, DOC_ID);
		expect(res.status).toBe(302);
		expect(fetchImpl).toHaveBeenCalledTimes(1);
		const location = new URL(res.headers.location as string, "https://issuer.example");
		expect(location.pathname).toBe("/consent");
		const challenge = location.searchParams.get("challenge");
		const page = await request(app).get("/oauth/consent").query({ challenge });
		expect(page.status).toBe(200);
		expect(page.body).toMatchObject({ client_id: DOC_ID, client_id_host: "tools.example" });
	});
});

describe("only the router installs the document fallback", () => {
	it("leaves the fallback and its resolver out of the package entry", async () => {
		const entry: Record<string, unknown> = await import("#/index.mjs");
		expect(entry).not.toHaveProperty("withClientIdMetadataDocuments");
		expect(entry).not.toHaveProperty("createClientIdMetadataDocumentResolver");
	});

	it("still exports the predicates on a client id and on a resolved client", async () => {
		const entry: Record<string, unknown> = await import("#/index.mjs");
		expect(entry.isClientIdMetadataDocumentUrl).toBeTypeOf("function");
		expect(entry.isClientIdMetadataDocumentClient).toBeTypeOf("function");
	});
});
