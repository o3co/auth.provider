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
 * #529 — a Client ID Metadata Document client at `/oauth/authorize`: resolved
 * through the router's own repository, never first-party, so it lands on the
 * consent step (#527) with what the document says about it.
 */

import crypto from "node:crypto";
import {
	type AppConfig,
	type ClientRepository,
	type CodeRepository,
	createMemoryConsentStore,
	createSymmetricKeyStore,
} from "@o3co/auth-provider-core";
import { GrantRegistry } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createOAuthRouter } from "#/routes.mjs";
import { createMockLogger } from "./_helpers/mockLogger.mjs";

const CLIENT_URL = "https://client.example/oauth/client-metadata.json";
const REDIRECT_URI = "https://client.example/cb";
const VERIFIER = "pkce-verifier".padEnd(43, "x");
const S256_CHALLENGE = crypto.createHash("sha256").update(VERIFIER).digest("base64url");

const document = {
	client_id: CLIENT_URL,
	client_name: "Acme Chat",
	client_uri: "https://client.example",
	redirect_uris: [REDIRECT_URI],
	scope: "read write",
};

const makeApp = async (opts: { enabled: boolean; document?: unknown }) => {
	const config = {
		oauth: {
			jwt: { issuer: "https://issuer.example" },
			oidcMode: "dual",
			grants: {},
			clientIdMetadataDocuments: {
				enabled: opts.enabled,
				allowedScopes: ["read"],
				allowedAudiences: ["https://mcp.example"],
			},
		},
		rateLimit: { failMode: "open" as const },
		endpoints: { login: { url: "/login" }, consent: { url: "/consent" } },
	} as unknown as AppConfig;
	const clientRepository: ClientRepository = {
		findById: async () => null,
		authenticate: async () => null,
	};
	const codeRepository: CodeRepository = {
		createCode: async () => ({ code: "code-x", client_id: CLIENT_URL, redirect_uri: REDIRECT_URI }),
		findByCode: async () => null,
		consumeByCode: async () => null,
		removeByCode: async () => {},
	};
	const fetchImpl = vi.fn(
		async () =>
			new Response(JSON.stringify(opts.document ?? document), {
				status: 200,
				headers: { "content-type": "application/json" },
			}),
	) as unknown as typeof fetch;
	const { router } = await createOAuthRouter(express, {
		registry: new GrantRegistry(),
		config,
		clientRepository,
		codeRepository,
		keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
		consentStore: createMemoryConsentStore(),
		clientIdMetadataDocuments: { fetch: fetchImpl, lookup: async () => ["93.184.216.34"] },
		logger: createMockLogger(),
	});
	const session: Record<string, unknown> = { isAuthenticated: true, user: { id: "user-1" } };
	const app = express();
	app.use((req, _res, next) => {
		(req as unknown as { session: Record<string, unknown> }).session = session;
		next();
	});
	app.use("/oauth", router);
	return { app, fetchImpl };
};

const authorize = (app: express.Express, extra: Record<string, string> = {}) =>
	request(app)
		.get("/oauth/authorize")
		.query({
			response_type: "code",
			client_id: CLIENT_URL,
			redirect_uri: REDIRECT_URI,
			state: "xyz",
			code_challenge: S256_CHALLENGE,
			code_challenge_method: "S256",
			scope: "read",
			...extra,
		});

describe("/authorize with a Client ID Metadata Document client (#529)", () => {
	it("resolves the client from its document and routes it through consent, which shows what the document said", async () => {
		const { app, fetchImpl } = await makeApp({ enabled: true });
		const res = await authorize(app);
		expect(res.status).toBe(302);
		const location = new URL(res.headers.location as string, "https://issuer.example");
		expect(location.pathname).toBe("/consent");
		const challenge = location.searchParams.get("challenge") as string;

		const page = await request(app).get("/oauth/consent").query({ challenge });
		expect(page.status).toBe(200);
		expect(page.body).toMatchObject({
			client_id: CLIENT_URL,
			client_name: "Acme Chat",
			client_uri: "https://client.example",
			// `write` is in the document; the operator's ceiling admits `read` only,
			// and the request asked for `read`.
			scopes: ["read"],
			redirect_uri: REDIRECT_URI,
		});
		expect(fetchImpl).toHaveBeenCalledTimes(1);
	});

	it("does not know such a client when the feature is off", async () => {
		const { app, fetchImpl } = await makeApp({ enabled: false });
		const res = await authorize(app);
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_client");
		expect(fetchImpl).not.toHaveBeenCalled();
	});

	it("holds the presented redirect_uri to the document's list", async () => {
		const { app } = await makeApp({ enabled: true });
		const res = await authorize(app, { redirect_uri: "https://client.example/other" });
		expect(res.status).toBe(400);
		expect(res.body.error_description).toBe("redirect_uri not allowed");
	});

	it("treats a document that does not validate as no client", async () => {
		const { app } = await makeApp({
			enabled: true,
			document: { ...document, client_id: "https://elsewhere.example/x" },
		});
		const res = await authorize(app);
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_client");
	});
});
