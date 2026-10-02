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
 * registration the boundary refuses, of any id shape, is an unknown client.
 * With documents off the router reads the repository as it is handed. A
 * router built over a repository that already is a document fallback is
 * refused, when it would stack its own.
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
import { withClientIdMetadataDocuments } from "#/clients/clientIdMetadataDocument.mjs";
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

const answering = (record: unknown): ClientRepository => ({
	findById: async (id) => (id === CLIENT_ID ? (record as PublicClient) : null),
	authenticate: async () => null,
});

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
	{ documents = true, consent = true }: { documents?: boolean; consent?: boolean } = {},
) => {
	const fetchImpl = vi.fn(
		async () => new Response("{}", { status: 404 }),
	) as unknown as typeof fetch;
	const logger = createMockLogger();
	const { router } = await createOAuthRouter(express, {
		loginEntry: createTestLoginEntry(),
		requirements: resolverForTests([], { actions: OAUTH_ADMISSION_ACTIONS }),
		registry: authorizationServerRegistry(),
		config: configWith(documents),
		clientRepository,
		codeRepository,
		keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
		...(consent
			? {
					consentStore: createMemoryConsentStore(),
					pendingConsentStore: createMemoryPendingConsentStore(),
				}
			: {}),
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
		client_id: CLIENT_ID,
		redirect_uri: REDIRECT_URI,
		state: "xyz",
		code_challenge: S256_CHALLENGE,
		code_challenge_method: "S256",
		scope: "read",
	});

describe("the router's one document fallback reads every registered client through core's boundary", () => {
	it("answers a refused registration whose id is not a URL as an unknown client, with documents on", async () => {
		const { app, fetchImpl, logger } = await buildRouter(answering(refusedRecord));
		const res = await authorize(app);
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_client");
		expect(fetchImpl).not.toHaveBeenCalled();
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({ clientId: CLIENT_ID }),
			"client_record_refused",
		);
	});

	it("serves the record as handed with documents off, until the router itself reads through the boundary", async () => {
		const { app, logger } = await buildRouter(answering(refusedRecord), { documents: false });
		const res = await authorize(app);
		// The first-party client gets its code at the registered redirect URI.
		expect(res.status).toBe(302);
		const location = new URL(res.headers.location as string);
		expect(`${location.origin}${location.pathname}`).toBe(REDIRECT_URI);
		expect(location.searchParams.get("code")).toBeTruthy();
		expect(logger.warn).not.toHaveBeenCalledWith(expect.anything(), "client_record_refused");
	});
});

describe("one document fallback per router", () => {
	const fallback = () =>
		withClientIdMetadataDocuments(answering(null), { allowedScopes: [], allowedAudiences: [] });

	it("refuses to build over a fallback when documents are on, with a consent store and /authorize", async () => {
		await expect(buildRouter(fallback())).rejects.toThrow(TypeError);
		await expect(buildRouter(fallback())).rejects.toThrow(/Client ID Metadata Document/);
	});

	it("builds over one when it stacks none of its own: documents off, or no consent store", async () => {
		await expect(buildRouter(fallback(), { documents: false })).resolves.toBeDefined();
		await expect(buildRouter(fallback(), { consent: false })).resolves.toBeDefined();
	});
});
