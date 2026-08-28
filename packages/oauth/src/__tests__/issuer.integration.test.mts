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
 * `iss` is a property of the deployment, never of a request (#266).
 *
 * `/oauth/token` used to compute `config.oauth.jwt.issuer ?? req.get("host")`,
 * so a deployment that had not configured an issuer minted access and refresh
 * tokens whose `iss` came from a header the caller controls behind a trusted
 * proxy. These tests pin that the configured value is the only source.
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

function configWith(jwt: Record<string, unknown>): AppConfig {
	return {
		oauth: {
			jwt,
			accessToken: { expiresIn: 3600 },
		},
		rateLimit: { failMode: "open" as const },
		endpoints: { login: { url: "/login" } },
	} as unknown as AppConfig;
}

const clientRepo: ClientRepository = (() => {
	const client = {
		clientId: TEST_CLIENT_ID,
		tokenEndpointAuthMethod: "client_secret_basic" as const,
		allowedRedirectUris: [],
		allowedScopes: ["read"],
		// #396: the old implicit omitted-scope grant, now declared.
		defaultScopes: ["read"],
		allowedAudiences: ["https://api.example"],
		allowedGrantTypes: ["client_credentials"],
	};
	return {
		findById: async (id) => (id === TEST_CLIENT_ID ? client : null),
		authenticate: async (id, secret) =>
			id === TEST_CLIENT_ID && secret === TEST_CLIENT_SECRET ? client : null,
	};
})();

const codeRepoStub: CodeRepository = {
	createCode: async () => ({ code: "code-x", client_id: TEST_CLIENT_ID, redirect_uri: "" }),
	findByCode: async () => null,
	consumeByCode: async () => null,
	removeByCode: async () => {},
};

async function buildApp(config: AppConfig): Promise<express.Express> {
	const app = express();
	// Trusting the proxy is what makes X-Forwarded-Host reach req.get("host") —
	// the deployment shape in which the old fallback was caller-controlled.
	app.set("trust proxy", 1);
	app.use(express.json());
	app.use(express.urlencoded({ extended: false }));
	const keyStore = createSymmetricKeyStore(SECRET);
	const registry = new GrantRegistry();
	registry.register("client_credentials", createClientCredentialsGrant({ config, keyStore }));
	const { router } = await createOAuthRouter(express, {
		registry,
		config,
		clientRepository: clientRepo,
		codeRepository: codeRepoStub,
		keyStore,
	});
	app.use("/oauth", router);
	return app;
}

describe("/oauth/token — issuer is never derived from the request (#266)", () => {
	it("stamps the configured issuer even when Host says otherwise", async () => {
		const app = await buildApp(configWith({ issuer: ISSUER }));
		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", TEST_BASIC_AUTH)
			.set("Host", "evil.example")
			.type("form")
			.send({ grant_type: "client_credentials" });

		expect(res.status).toBe(200);
		const payload = decodeJwt(res.body.access_token);
		expect(payload.iss).toBe(ISSUER);
	});

	it("stamps the configured issuer even when X-Forwarded-Host says otherwise", async () => {
		const app = await buildApp(configWith({ issuer: ISSUER }));
		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", TEST_BASIC_AUTH)
			.set("X-Forwarded-Host", "evil.example")
			.type("form")
			.send({ grant_type: "client_credentials" });

		expect(res.status).toBe(200);
		const payload = decodeJwt(res.body.access_token);
		expect(payload.iss).toBe(ISSUER);
		expect(String(payload.iss)).not.toContain("evil.example");
	});

	it("refuses to build the router when no issuer is configured", async () => {
		await expect(buildApp(configWith({}))).rejects.toThrow(/oauth\.jwt\.issuer/);
	});

	it("refuses to build the router when the issuer is a bare host", async () => {
		await expect(buildApp(configWith({ issuer: "auth.example:3000" }))).rejects.toThrow(
			/oauth\.jwt\.issuer/,
		);
	});
});
