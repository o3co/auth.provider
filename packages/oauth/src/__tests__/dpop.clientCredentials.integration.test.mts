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
 * Coverage for DPoP cnf-claim propagation in the client_credentials grant —
 * Wave 2 Phase 2 §9.1.
 *
 * Uses a fake `TokenBindingMechanism` whose `extract` returns a fixed binding,
 * decoupling these tests from the real DPoP verifier package. The full HTTP
 * path (supertest + `createOAuthRouter`) exercises the tokenBindingMw →
 * ctx.tokenBinding → grant → token-issuance chain end-to-end.
 */

import {
	type AppConfig,
	type CodeRepository,
	createSymmetricKeyStore,
	InMemoryClientRepository,
	type TokenBinding,
	type TokenBindingMechanism,
	tokenBindingMw,
} from "@o3co/auth-provider-core";
import { GrantRegistry } from "@o3co/auth-provider-core/testing";
import express from "express";
import { decodeJwt } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createClientCredentialsGrant } from "#/grants/clientCredentials.mjs";
import { createOAuthRouter } from "#/routes.mjs";

// ---------------------------------------------------------------------------
// Shared test fixtures
// ---------------------------------------------------------------------------

const SECRET = "test-secret-at-least-32-chars!!";
const ISSUER = "https://auth.example";
const TEST_CLIENT_ID = "dpop-cc-client";
const TEST_CLIENT_SECRET = "dpop-cc-secret";
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
	createCode: async () => ({ code: "code-x", client_id: TEST_CLIENT_ID, redirect_uri: "" }),
	findByCode: async () => null,
	consumeByCode: async () => null,
	removeByCode: async () => {},
};

const clientRepo = new InMemoryClientRepository(
	new Map([
		[
			TEST_CLIENT_ID,
			{
				clientSecret: TEST_CLIENT_SECRET,
				tokenEndpointAuthMethod: "client_secret_basic" as const,
				allowedRedirectUris: [],
				allowedScopes: ["read"],
				allowedAudiences: ["https://api.example"],
				allowedGrantTypes: ["client_credentials"],
			},
		],
	]),
);

// ---------------------------------------------------------------------------
// App builder — mirrors senderConstrained.integration.test.mts pattern
// ---------------------------------------------------------------------------

async function buildApp(
	mechanisms: readonly TokenBindingMechanism[] = [],
): Promise<express.Express> {
	const app = express();
	app.set("trust proxy", 1);
	app.use(express.json());
	app.use(express.urlencoded({ extended: false }));
	const keyStore = createSymmetricKeyStore(SECRET);

	if (mechanisms.length > 0) {
		app.use(
			tokenBindingMw({
				mechanisms,
				dispatchPolicy: "intent-explicit",
			}),
		);
	}

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

// ---------------------------------------------------------------------------
// Fake mechanisms
// ---------------------------------------------------------------------------

function makeDpopMechanism(jkt: string): TokenBindingMechanism {
	const binding: TokenBinding = { kind: "dpop", confirmation: { jkt } };
	return {
		kind: "dpop",
		intentExplicit: true,
		extract: async () => binding,
	};
}

function makeMtlsMechanism(thumbprint: string): TokenBindingMechanism {
	const binding: TokenBinding = {
		kind: "mtls",
		confirmation: { "x5t#S256": thumbprint },
	};
	return {
		kind: "mtls",
		intentExplicit: true,
		extract: async () => binding,
	};
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("DPoP cnf-claim propagation — client_credentials grant (§9.1)", () => {
	describe("AT cnf propagation", () => {
		it("issues unbound AT when no DPoP mechanism is mounted", async () => {
			// No tokenBindingMw → ctx.tokenBinding is undefined → plain Bearer token
			const app = await buildApp(/* no mechanisms */);

			const res = await request(app)
				.post("/oauth/token")
				.set("Authorization", TEST_BASIC_AUTH)
				.type("form")
				.send({ grant_type: "client_credentials" });

			expect(res.status).toBe(200);
			expect(res.body.token_type).toBe("Bearer");
			const payload = decodeJwt(res.body.access_token as string);
			// RFC 7800 cnf claim MUST NOT be present when no binding was established
			expect(payload.cnf).toBeUndefined();
		});

		it("issues DPoP-bound AT and sets token_type to DPoP when proof is presented", async () => {
			// Fake DPoP mechanism returns a fixed binding so we can assert exact JKT
			const app = await buildApp([makeDpopMechanism("TEST-CC-JKT")]);

			const res = await request(app)
				.post("/oauth/token")
				.set("Authorization", TEST_BASIC_AUTH)
				.type("form")
				.send({ grant_type: "client_credentials" });

			expect(res.status).toBe(200);
			expect(res.body.token_type).toBe("DPoP");
			const payload = decodeJwt(res.body.access_token as string);
			// RFC 7800 §3.1: cnf.jkt MUST equal the SHA-256 thumbprint carried by the proof
			expect((payload.cnf as { jkt: string } | undefined)?.jkt).toBe("TEST-CC-JKT");
		});
	});

	describe("refresh_token absence (RFC 6749 §4.4.3)", () => {
		it("refresh_token is NOT issued for client_credentials even with DPoP binding", async () => {
			// RFC 6749 §4.4.3 prohibits refresh tokens for client_credentials.
			// This must hold regardless of DPoP binding presence.
			const app = await buildApp([makeDpopMechanism("NO-RT-JKT")]);

			const res = await request(app)
				.post("/oauth/token")
				.set("Authorization", TEST_BASIC_AUTH)
				.type("form")
				.send({ grant_type: "client_credentials" });

			expect(res.status).toBe(200);
			// refresh_token MUST be absent — not null, not empty, but strictly undefined
			expect(res.body.refresh_token).toBeUndefined();
		});
	});

	describe("token_type response wrapper", () => {
		it("keeps token_type Bearer when the mechanism kind is not dpop (e.g. mtls)", async () => {
			// mTLS binds via x5t#S256 (RFC 8705 §3) and MUST keep Bearer.
			// Pins that the DPoP gate is `kind === "dpop"` — not just any binding.
			const app = await buildApp([makeMtlsMechanism("MTLS-THUMBPRINT")]);

			const res = await request(app)
				.post("/oauth/token")
				.set("Authorization", TEST_BASIC_AUTH)
				.type("form")
				.send({ grant_type: "client_credentials" });

			expect(res.status).toBe(200);
			expect(res.body.token_type).toBe("Bearer");
			const payload = decodeJwt(res.body.access_token as string);
			// cnf is present (mTLS binding) but shaped differently from DPoP
			const cnf = payload.cnf as Record<string, string> | undefined;
			expect(cnf?.["x5t#S256"]).toBe("MTLS-THUMBPRINT");
			// jkt MUST NOT appear in an mTLS-bound token
			expect(cnf?.jkt).toBeUndefined();
		});
	});
});
