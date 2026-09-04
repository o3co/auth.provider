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
 * R4 — a resource server must be able to introspect its own tokens.
 *
 * `/oauth/introspect` pinned `expectedAudience` to the calling client's
 * `clientId`. With RFC 8707 resource indicators in use every access token
 * carries `aud: <resource URI>`, so a resource server asking about a token
 * issued *for it* got `active: false` unless it happened to be registered
 * under a `client_id` equal to the resource URI. Registering a client whose
 * id IS the resource URI is what made it work live — which is a workaround,
 * not a design.
 *
 * The pin is now the calling client's `allowedAudiences` ∪ `{clientId}`: the
 * set of audiences that client is already trusted to be associated with, the
 * same ceiling every issuing grant derives an audience within. It is a
 * widening of exactly that set and of nothing else, which is what the
 * negative cases below are here to hold.
 */

import { createSecretKey } from "node:crypto";
import {
	type AppConfig,
	type ClientRepository,
	type CodeRepository,
	createSymmetricKeyStore,
	type PublicClient,
} from "@o3co/auth-provider-core";
import { GrantRegistry } from "@o3co/auth-provider-core/testing";
import express from "express";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createOAuthRouter } from "#/routes.mjs";
import { createMockLogger } from "./_helpers/mockLogger.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const ISSUER = "https://auth.example";
const RESOURCE = "https://api.example.com";
const OTHER_RESOURCE = "https://other.example.com";

const RS_CLIENT_ID = "resource-server-1";
const RS_SECRET = "rs-secret";
const RS_BASIC = `Basic ${Buffer.from(`${RS_CLIENT_ID}:${RS_SECRET}`).toString("base64")}`;

const PUBLIC_CLIENT_ID = "spa-client";

const keyStore = createSymmetricKeyStore(SECRET);
const secretKey = createSecretKey(Buffer.from(SECRET));

const config = {
	oauth: {
		jwt: { issuer: ISSUER },
		accessToken: { expiresIn: 3600 },
		grants: {},
	},
	rateLimit: { failMode: "open" as const },
	endpoints: { login: { url: "/login" } },
} as unknown as AppConfig;

const rsClient = {
	clientId: RS_CLIENT_ID,
	tokenEndpointAuthMethod: "client_secret_basic" as const,
	allowedRedirectUris: [],
	allowedScopes: [],
	allowedAudiences: [RESOURCE],
} as unknown as PublicClient;

/** A caller with no `allowedAudiences` at all — only its own id should match. */
const bareClient = {
	clientId: "bare-client",
	tokenEndpointAuthMethod: "client_secret_basic" as const,
	allowedRedirectUris: [],
	allowedScopes: [],
} as unknown as PublicClient;
const BARE_BASIC = `Basic ${Buffer.from("bare-client:bare-secret").toString("base64")}`;

const publicClient = {
	clientId: PUBLIC_CLIENT_ID,
	tokenEndpointAuthMethod: "none" as const,
	allowedRedirectUris: [],
	allowedScopes: [],
	allowedAudiences: [RESOURCE],
} as unknown as PublicClient;

const REGISTRY: ReadonlyArray<readonly [PublicClient, string | null]> = [
	[rsClient, RS_SECRET],
	[bareClient, "bare-secret"],
	[publicClient, null],
];

const clientRepository: ClientRepository = {
	findById: async (id) => REGISTRY.find(([c]) => c.clientId === id)?.[0] ?? null,
	authenticate: async (id, secret) => {
		const entry = REGISTRY.find(([c]) => c.clientId === id);
		return entry && entry[1] !== null && entry[1] === secret ? entry[0] : null;
	},
};

const codeRepository: CodeRepository = {
	createCode: async () => ({ code: "c", client_id: "x", redirect_uri: "" }),
	findByCode: async () => null,
	consumeByCode: async () => null,
	removeByCode: async () => {},
};

async function mintAccessToken(
	opts: { audience?: string; issuer?: string; expired?: boolean } = {},
): Promise<string> {
	const jwt = new SignJWT({ sub: "u1", scope: "read" })
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "at+jwt" })
		.setIssuer(opts.issuer ?? ISSUER)
		.setIssuedAt()
		.setExpirationTime(opts.expired ? "-2h" : "1h");
	if (opts.audience !== undefined) jwt.setAudience(opts.audience);
	return jwt.sign(secretKey);
}

async function buildApp(logger?: ReturnType<typeof createMockLogger>) {
	const app = express();
	app.use(express.json());
	app.use(express.urlencoded({ extended: false }));
	const { router } = await createOAuthRouter(express, {
		registry: new GrantRegistry(),
		config,
		clientRepository,
		codeRepository,
		keyStore,
		...(logger ? { logger } : {}),
	});
	app.use("/oauth", router);
	return app;
}

/** Introspect as an authenticated client (the resource-server shape). */
const introspectAs = (app: express.Express, basic: string, token: string) =>
	request(app).post("/oauth/introspect").set("Authorization", basic).type("form").send({ token });

describe("/oauth/introspect — audience pin (R4)", () => {
	it("a resource server can introspect a token issued for its resource URI", async () => {
		const app = await buildApp();
		const token = await mintAccessToken({ audience: RESOURCE });

		const res = await introspectAs(app, RS_BASIC, token);

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(true);
		expect(res.body.aud).toBe(RESOURCE);
	});

	it("still accepts a token whose aud is the calling client's own id", async () => {
		// The pre-fix behaviour, preserved: `clientId` stays in the set.
		const app = await buildApp();
		const token = await mintAccessToken({ audience: RS_CLIENT_ID });

		const res = await introspectAs(app, RS_BASIC, token);

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(true);
	});

	it("refuses a token for an audience the caller is not associated with", async () => {
		// The widening is exactly `allowedAudiences ∪ {clientId}`. A resource
		// URI outside that set is another party's token.
		const app = await buildApp();
		const token = await mintAccessToken({ audience: OTHER_RESOURCE });

		const res = await introspectAs(app, RS_BASIC, token);

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(false);
	});

	it("a client with no allowedAudiences matches only its own id", async () => {
		const app = await buildApp();

		const own = await introspectAs(
			app,
			BARE_BASIC,
			await mintAccessToken({ audience: "bare-client" }),
		);
		expect(own.body.active).toBe(true);

		const foreign = await introspectAs(
			app,
			BARE_BASIC,
			await mintAccessToken({ audience: RESOURCE }),
		);
		expect(foreign.body.active).toBe(false);
	});

	it("refuses a token from another issuer", async () => {
		const app = await buildApp();
		const token = await mintAccessToken({ audience: RESOURCE, issuer: "https://evil.example" });

		const res = await introspectAs(app, RS_BASIC, token);

		expect(res.body.active).toBe(false);
	});

	it("refuses an expired token", async () => {
		const app = await buildApp();
		const token = await mintAccessToken({ audience: RESOURCE, expired: true });

		const res = await introspectAs(app, RS_BASIC, token);

		expect(res.body.active).toBe(false);
	});

	it("refuses a token carrying no aud at all", async () => {
		// Pinning against a set is still pinning: `aud` must be present and
		// must be in it.
		const app = await buildApp();
		const token = await mintAccessToken();

		const res = await introspectAs(app, RS_BASIC, token);

		expect(res.body.active).toBe(false);
	});

	it("still refuses public clients per RFC 7662 §2.1", async () => {
		const app = await buildApp();
		const token = await mintAccessToken({ audience: RESOURCE });

		const res = await request(app)
			.post("/oauth/introspect")
			.type("form")
			.send({ token, client_id: PUBLIC_CLIENT_ID });

		expect(res.status).toBe(401);
		expect(res.body.error).toBe("invalid_client");
	});

	it("the bearer self-introspection fall-through still records jwt_verify_aud_skipped", async () => {
		// That path establishes no calling-client identity, so there is no set
		// to pin against and the verifier records the gap. Widening the pin
		// must not quietly close that hole by pretending an identity exists.
		const logger = createMockLogger();
		const app = await buildApp(logger);
		const token = await mintAccessToken({ audience: RESOURCE });

		const res = await request(app)
			.post("/oauth/introspect")
			.set("Authorization", `Bearer ${token}`)
			.type("form")
			.send({ token });

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(true);
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({ reason: "aud", type: "access_token" }),
			"jwt_verify_aud_skipped",
		);
	});
});
