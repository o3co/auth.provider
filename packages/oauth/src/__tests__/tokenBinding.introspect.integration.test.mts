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
 * Issuance and introspection on the same token: `tokenBindingMw` extracts a
 * binding from a fake mechanism, the client_credentials grant emits the AT
 * with a `cnf` claim, and `/oauth/introspect` reports it back — `token_type`
 * `DPoP` for a DPoP binding (RFC 9449 §5), `Bearer` for an mTLS binding
 * (RFC 8705 §3) and for a plain AT.
 */

import { createSecretKey } from "node:crypto";
import {
	type AppConfig,
	type CodeRepository,
	createSymmetricKeyStore,
	InMemoryClientRepository,
	type TokenBinding,
	type TokenBindingMechanism,
	tokenBindingMw,
} from "@o3co/auth-provider-core";
import { GrantRegistry, resolverForTests } from "@o3co/auth-provider-core/testing";
import express from "express";
import { decodeJwt, decodeProtectedHeader, SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createClientCredentialsGrant } from "#/grants/clientCredentials.mjs";
import { createOAuthRouter } from "#/routes.mjs";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const SECRET = "test-secret-at-least-32-chars!!";
const ISSUER = "https://auth.example";
const TEST_CLIENT_ID = "introspect-e2e-client";
const TEST_CLIENT_SECRET = "introspect-e2e-secret";
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
	createCode: async () => ({ code: "x", client_id: TEST_CLIENT_ID, redirect_uri: "" }),
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
				// What an omitted `scope` grants.
				defaultScopes: ["read"],
				// AT audience defaults to allowedAudiences[0]; introspect's
				// expectedAudience is the calling client's clientId. Align
				// them so the AT introspects as active.
				allowedAudiences: [TEST_CLIENT_ID],
				allowedGrantTypes: ["client_credentials"],
			},
		],
	]),
);

// ---------------------------------------------------------------------------
// Fake mechanisms
// ---------------------------------------------------------------------------

function makeDpopMechanism(jkt: string): TokenBindingMechanism {
	const binding: TokenBinding = { kind: "dpop", confirmation: { jkt } };
	return { kind: "dpop", intentExplicit: true, extract: async () => binding };
}

function makeMtlsMechanism(thumbprint: string): TokenBindingMechanism {
	const binding: TokenBinding = {
		kind: "mtls",
		confirmation: { "x5t#S256": thumbprint },
	};
	return { kind: "mtls", intentExplicit: false, extract: async () => binding };
}

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
		// Path-scoped to `/oauth/token`, as `assembleApp` mounts it: unscoped,
		// it would also stamp `req.tokenBinding` on `/oauth/introspect` and
		// could mask introspect reading it.
		// The introspect handler MUST derive `cnf` from the JWT payload, not
		// from request state.
		app.use(
			"/oauth/token",
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
		requirements: resolverForTests([]),
		registry,
		config: fullConfig,
		clientRepository: clientRepo,
		codeRepository: codeRepoStub,
		keyStore,
	});
	app.use("/oauth", router);
	return app;
}

async function issueAndIntrospect(
	app: express.Express,
): Promise<{ accessToken: string; introspect: Record<string, unknown> }> {
	const tokenRes = await request(app)
		.post("/oauth/token")
		.set("Authorization", TEST_BASIC_AUTH)
		.type("form")
		.send({ grant_type: "client_credentials" });
	expect(tokenRes.status).toBe(200);
	const accessToken = tokenRes.body.access_token as string;

	const introspectRes = await request(app)
		.post("/oauth/introspect")
		.set("Authorization", TEST_BASIC_AUTH)
		.type("form")
		.send({ token: accessToken });
	expect(introspectRes.status).toBe(200);
	return { accessToken, introspect: introspectRes.body as Record<string, unknown> };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("Phase 4 T4.1 — end-to-end issuance + introspection cnf propagation", () => {
	it("DPoP-bound AT: /introspect echoes cnf.jkt and token_type DPoP", async () => {
		const app = await buildApp([makeDpopMechanism("E2E-DPOP-JKT")]);

		const { introspect } = await issueAndIntrospect(app);

		expect(introspect.active).toBe(true);
		expect(introspect.token_type).toBe("DPoP");
		const cnf = introspect.cnf as Record<string, string> | undefined;
		expect(cnf?.jkt).toBe("E2E-DPOP-JKT");
		// mTLS thumbprint MUST NOT appear in a DPoP-bound token.
		expect(cnf?.["x5t#S256"]).toBeUndefined();
	});

	it("mTLS-bound AT: /introspect echoes cnf.x5t#S256 and token_type Bearer", async () => {
		// mTLS keeps wire-level Bearer (RFC 8705 §3) even though the token IS
		// sender-constrained — the cnf carries the binding evidence.
		const app = await buildApp([makeMtlsMechanism("E2E-MTLS-THUMB")]);

		const { introspect } = await issueAndIntrospect(app);

		expect(introspect.active).toBe(true);
		expect(introspect.token_type).toBe("Bearer");
		const cnf = introspect.cnf as Record<string, string> | undefined;
		expect(cnf?.["x5t#S256"]).toBe("E2E-MTLS-THUMB");
		// jkt MUST NOT appear in an mTLS-bound token.
		expect(cnf?.jkt).toBeUndefined();
	});

	it("plain AT (no mechanism mounted): /introspect omits cnf and token_type stays Bearer", async () => {
		const app = await buildApp(/* no mechanisms */);

		const { introspect } = await issueAndIntrospect(app);

		expect(introspect.active).toBe(true);
		expect(introspect.token_type).toBe("Bearer");
		expect(introspect.cnf).toBeUndefined();
	});
});

// ---------------------------------------------------------------------------
// Compound-cnf rejection
// ---------------------------------------------------------------------------

/**
 * Re-signs a genuine AT with an added compound `cnf` claim. The grant emits
 * exactly one mechanism's confirmation, so such a token at `/introspect` is a
 * forgery (signing-key compromise) or an AS bug. Every other claim and header
 * member stays as issued, so the token passes verification and the cnf shape
 * is the single variable.
 */
async function forgeCompoundCnfToken(genuineAccessToken: string): Promise<string> {
	const header = decodeProtectedHeader(genuineAccessToken);
	const payload = decodeJwt(genuineAccessToken);
	const { iss, aud, sub, exp, iat, ...rest } = payload;
	return new SignJWT({
		...rest,
		cnf: { jkt: "FORGED-JKT", "x5t#S256": "FORGED-THUMB" },
	})
		.setProtectedHeader({
			alg: header.alg as string,
			...(header.kid !== undefined && { kid: header.kid }),
			...(header.typ !== undefined && { typ: header.typ }),
		})
		.setIssuer(iss as string)
		.setAudience(aud as string)
		.setSubject(sub as string)
		.setIssuedAt(iat)
		.setExpirationTime(exp as number)
		.sign(createSecretKey(Buffer.from(SECRET)));
}

describe("#199 I3 — compound cnf on introspection", () => {
	it("reports active:false for an AT carrying both cnf.jkt and cnf.x5t#S256", async () => {
		// Fail closed, as the refresh path does (see ADR
		// 2026-05-20-token-binding-first-class-abstraction, "Compound cnf across
		// the AS surfaces"). RFC 7662 §2.2 permits active:false for any token
		// the AS declines to vouch for.
		const app = await buildApp([makeDpopMechanism("E2E-DPOP-JKT")]);
		const { accessToken } = await issueAndIntrospect(app);
		const forged = await forgeCompoundCnfToken(accessToken);

		const res = await request(app)
			.post("/oauth/introspect")
			.set("Authorization", TEST_BASIC_AUTH)
			.type("form")
			.send({ token: forged });

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(false);
		// Nothing about the rejected token leaks alongside active:false.
		expect(res.body.cnf).toBeUndefined();
		expect(res.body.token_type).toBeUndefined();
		expect(res.body.sub).toBeUndefined();
	});

	it("does not weaken a genuine single-mechanism binding", async () => {
		// The fail-open shape: dropping cnf while keeping active:true would
		// present a DPoP-bound token to the RS as a plain bearer token.
		const app = await buildApp([makeDpopMechanism("E2E-DPOP-JKT")]);

		const { introspect } = await issueAndIntrospect(app);

		expect(introspect.active).toBe(true);
		expect(introspect.token_type).toBe("DPoP");
		expect((introspect.cnf as Record<string, string>).jkt).toBe("E2E-DPOP-JKT");
	});
});
