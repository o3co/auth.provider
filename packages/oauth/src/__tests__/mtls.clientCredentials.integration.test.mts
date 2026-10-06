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
 * mTLS cnf-claim propagation in the client_credentials grant, over the full
 * HTTP path (tokenBindingMw → ctx.tokenBinding → grant → token issuance).
 * A fake `TokenBindingMechanism` returns a fixed mTLS binding; the real
 * extractor and PKI chain validation are tested in `@o3co/auth-provider-mtls`.
 *
 * Key behavioral contracts:
 *   - AT carries `cnf.x5t#S256` when an mTLS mechanism extracted a cert
 *   - token_type stays "Bearer": mTLS never sets "DPoP" (RFC 8705 §3)
 *   - client_credentials never issues a refresh_token regardless of binding
 *     (RFC 6749 §4.4.3)
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
import { clientEntries, GrantRegistry, resolverForTests } from "@o3co/auth-provider-core/testing";
import express from "express";
import { decodeJwt } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createClientCredentialsGrant } from "#/grants/clientCredentials.mjs";
import { createOAuthRouter } from "#/routes.mjs";
import { codeRecord } from "./_helpers/codeRecord.mjs";
import { grantSettingsFrom } from "./_helpers/grantSettings.mjs";
import { routerInputsOf } from "./_helpers/sections.mjs";

// ---------------------------------------------------------------------------
// Shared test fixtures
// ---------------------------------------------------------------------------

const SECRET = "test-secret-at-least-32-chars!!";
const ISSUER = "https://auth.example";
const TEST_CLIENT_ID = "mtls-cc-client";
const TEST_CLIENT_SECRET = "mtls-cc-secret";
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
		codeRecord({ code: "code-x", client_id: TEST_CLIENT_ID, redirect_uri: "" }),
	findByCode: async () => null,
	consumeByCode: async () => null,
	removeByCode: async () => {},
};

const clientRepo = new InMemoryClientRepository(
	clientEntries([
		[
			TEST_CLIENT_ID,
			{
				clientSecret: TEST_CLIENT_SECRET,
				tokenEndpointAuthMethod: "client_secret_basic" as const,
				allowedRedirectUris: [],
				allowedScopes: ["read"],
				// An omitted scope is granted these, never the allowlist.
				defaultScopes: ["read"],
				allowedAudiences: ["https://api.example"],
				allowedGrantTypes: ["client_credentials"],
			},
		],
	]),
);

// ---------------------------------------------------------------------------
// App builder
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

// ---------------------------------------------------------------------------
// Fake mTLS mechanism — returns a fixed thumbprint binding
// ---------------------------------------------------------------------------

function makeMtlsMechanism(thumbprint: string): TokenBindingMechanism {
	const binding: TokenBinding = {
		kind: "mtls",
		confirmation: { "x5t#S256": thumbprint },
	};
	return {
		kind: "mtls",
		// mTLS is ambient (RFC 8705) — not explicit-intent like DPoP.
		intentExplicit: false,
		extract: async () => binding,
	};
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("mTLS cnf-claim propagation — client_credentials grant", () => {
	describe("AT cnf propagation", () => {
		it("issues mTLS-bound AT with cnf.x5t#S256 when a cert is presented", async () => {
			const app = await buildApp([makeMtlsMechanism("MTLS-CC-THUMB")]);

			const res = await request(app)
				.post("/oauth/token")
				.set("Authorization", TEST_BASIC_AUTH)
				.type("form")
				.send({ grant_type: "client_credentials" });

			expect(res.status).toBe(200);
			// mTLS keeps wire-level Bearer per RFC 8705 §3.
			expect(res.body.token_type).toBe("Bearer");
			const payload = decodeJwt(res.body.access_token as string);
			// RFC 8705 §3.1 + RFC 7800 §3.5: cnf.x5t#S256 IS the binding.
			const cnf = payload.cnf as Record<string, string> | undefined;
			expect(cnf?.["x5t#S256"]).toBe("MTLS-CC-THUMB");
			// jkt MUST NOT appear in an mTLS-bound token.
			expect(cnf?.jkt).toBeUndefined();
		});

		it("issues plain Bearer AT when no mTLS mechanism is mounted", async () => {
			const app = await buildApp(/* no mechanisms */);

			const res = await request(app)
				.post("/oauth/token")
				.set("Authorization", TEST_BASIC_AUTH)
				.type("form")
				.send({ grant_type: "client_credentials" });

			expect(res.status).toBe(200);
			expect(res.body.token_type).toBe("Bearer");
			const payload = decodeJwt(res.body.access_token as string);
			expect(payload.cnf).toBeUndefined();
		});
	});

	describe("refresh_token absence (RFC 6749 §4.4.3 — pins grant-level prohibition)", () => {
		it("refresh_token is NOT issued for client_credentials even with mTLS binding", async () => {
			// The RT-binding gate (`bindRefreshToken` in `authorization.mts`)
			// must not turn on refresh tokens for a grant that never emits one.
			const app = await buildApp([makeMtlsMechanism("NO-RT-MTLS-THUMB")]);

			const res = await request(app)
				.post("/oauth/token")
				.set("Authorization", TEST_BASIC_AUTH)
				.type("form")
				.send({ grant_type: "client_credentials" });

			expect(res.status).toBe(200);
			expect(res.body.refresh_token).toBeUndefined();
		});
	});
});
