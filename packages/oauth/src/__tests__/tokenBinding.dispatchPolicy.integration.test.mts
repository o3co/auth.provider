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
 * Cross-mechanism dispatch policy — Wave 2 Phase 3 §12.3.
 *
 * The cross-mechanism dispatch refactor (PR #188) gave `tokenBindingMw` a
 * single configurable `DispatchPolicy` that arbitrates when more than one
 * mechanism's `extract` succeeds against the same request. This file pins
 * the grant-visible side of that contract:
 *
 *   `intent-explicit` (default) — DPoP wins over mTLS because DPoP is
 *     explicit-intent (the client sent a header on purpose) while mTLS is
 *     ambient (the TLS handshake produces a cert whether the client meant
 *     to bind or not). The grant's AT cnf carries `jkt`, NOT `x5t#S256`.
 *
 *   `strict-mutual-exclusion` — both mechanisms succeeding is treated as
 *     a malformed request (the client is presenting contradictory binding
 *     evidence). The grant never runs; tokenBindingMw rejects with HTTP
 *     400 `invalid_request`.
 *
 * Uses fake mechanisms (no real DPoP proof / cert chain validation) so the
 * test is decoupled from the upstream verifier packages — those have their
 * own dedicated test files. The cross-mechanism plumbing itself was already
 * exercised at the middleware layer in
 * `@o3co/auth-provider-mtls/__tests__/dual-mechanism.integration.test.mts`;
 * this file is the grant-visible regression guard at the HTTP boundary.
 */

import {
	type AppConfig,
	type CodeRepository,
	createSymmetricKeyStore,
	type DispatchPolicy,
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
// Shared fixtures
// ---------------------------------------------------------------------------

const SECRET = "test-secret-at-least-32-chars!!";
const ISSUER = "https://auth.example";
const TEST_CLIENT_ID = "dispatch-policy-client";
const TEST_CLIENT_SECRET = "dispatch-policy-secret";
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
				// #396: the old implicit omitted-scope grant, now declared.
				defaultScopes: ["read"],
				allowedAudiences: ["https://api.example"],
				allowedGrantTypes: ["client_credentials"],
			},
		],
	]),
);

// ---------------------------------------------------------------------------
// Fake mechanisms — both succeed for every request
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
		intentExplicit: false,
		extract: async () => binding,
	};
}

async function buildApp(dispatchPolicy: DispatchPolicy): Promise<express.Express> {
	const app = express();
	app.set("trust proxy", 1);
	app.use(express.json());
	app.use(express.urlencoded({ extended: false }));
	const keyStore = createSymmetricKeyStore(SECRET);

	app.use(
		tokenBindingMw({
			// Order intentionally puts mTLS first to prove that DispatchPolicy
			// (not registration order) picks the winner under intent-explicit.
			mechanisms: [makeMtlsMechanism("DISPATCH-THUMB"), makeDpopMechanism("DISPATCH-JKT")],
			dispatchPolicy,
		}),
	);

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
// Tests
// ---------------------------------------------------------------------------

describe("Cross-mechanism dispatch policy (§12.3) — grant-visible behavior", () => {
	it("intent-explicit: DPoP + mTLS both succeed → DPoP wins; AT carries jkt only", async () => {
		const app = await buildApp("intent-explicit");

		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", TEST_BASIC_AUTH)
			.type("form")
			.send({ grant_type: "client_credentials" });

		expect(res.status).toBe(200);
		// DPoP won → token_type wrapper reflects DPoP per RFC 9449.
		expect(res.body.token_type).toBe("DPoP");
		const payload = decodeJwt(res.body.access_token as string);
		const cnf = payload.cnf as Record<string, string> | undefined;
		expect(cnf?.jkt).toBe("DISPATCH-JKT");
		// x5t#S256 MUST NOT appear — the mTLS branch lost arbitration.
		expect(cnf?.["x5t#S256"]).toBeUndefined();
	});

	it("strict-mutual-exclusion: DPoP + mTLS both succeed → 400 invalid_request", async () => {
		const app = await buildApp("strict-mutual-exclusion");

		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", TEST_BASIC_AUTH)
			.type("form")
			.send({ grant_type: "client_credentials" });

		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_request");
		// Token was never issued — the grant code didn't run.
		expect(res.body.access_token).toBeUndefined();
	});
});
