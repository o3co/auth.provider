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
 * A client repository that cannot answer is the server's outage at every
 * client-authenticated endpoint, never `invalid_client`.
 *
 * Client authentication answered a lookup that threw — `findById` or
 * `authenticate`, for a secret or a `private_key_jwt` assertion — with `401
 * invalid_client`: "client authentication failed" (RFC 6749 §5.2), which a
 * client reads as a bad secret or a revoked registration. The client did
 * nothing wrong, and the request is refused either way, so the answer is
 * `503 temporarily_unavailable`, logged at error level with the error's
 * projection.
 *
 * Driven through the real router (`createOAuthRouter`) at `/oauth/token`,
 * `/oauth/introspect` and `/oauth/revoke`, with a repository whose lookup
 * rejects. The control: a client the working repository does not know is
 * still `401 invalid_client`.
 */

import { randomUUID } from "node:crypto";
import {
	type AppConfig,
	type ClientRepository,
	type CodeRepository,
	createMemoryAccessTokenDenylist,
	createMemoryReplaySeenSet,
	createSymmetricKeyStore,
	type PublicClient,
} from "@o3co/auth-provider-core";
import { GrantRegistry } from "@o3co/auth-provider-core/testing";
import express from "express";
import { generateKeyPair, SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { JWT_BEARER_CLIENT_ASSERTION_TYPE } from "#/middleware/clientAssertion.mjs";
import { createOAuthRouter } from "#/routes.mjs";
import { codeRecord } from "./_helpers/codeRecord.mjs";
import { createMockLogger, type MockLogger } from "./_helpers/mockLogger.mjs";
import {
	REFUSED_COMMAND_MARKER,
	serialisedCalls,
	storeReplyError,
} from "./_helpers/projectedLog.mjs";

const ISSUER = "https://auth.example.com";
const TOKEN_ENDPOINT = `${ISSUER}/oauth/token`;
const CLIENT_ID = "rp";
const CLIENT_SECRET = "rp-secret";

const config = {
	oauth: {
		jwt: { issuer: ISSUER },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		grants: { client_credentials: { enabled: true } },
	},
	rateLimit: { failMode: "open" as const },
	endpoints: { login: { url: "/login" } },
} as unknown as AppConfig;

const confidential: PublicClient = {
	clientId: CLIENT_ID,
	tokenEndpointAuthMethod: "client_secret_basic",
	allowedRedirectUris: [],
	allowedScopes: [],
};

/** Which repository call fails, or none. */
type Outage = "findById" | "authenticate" | "none";

const repositoryWith = (outage: Outage): ClientRepository => ({
	findById: async (id) => {
		if (outage === "findById") throw storeReplyError();
		return id === CLIENT_ID ? confidential : null;
	},
	authenticate: async (id, secret) => {
		if (outage === "authenticate") throw storeReplyError();
		return id === CLIENT_ID && secret === CLIENT_SECRET ? confidential : null;
	},
});

const codeRepository: CodeRepository = {
	createCode: async () => codeRecord({ code: "unused", client_id: CLIENT_ID, redirect_uri: "" }),
	findByCode: async () => null,
	consumeByCode: async () => null,
	removeByCode: async () => {},
};

async function buildApp(outage: Outage): Promise<{ app: express.Express; logger: MockLogger }> {
	const logger = createMockLogger();
	const { router } = await createOAuthRouter(express, {
		registry: new GrantRegistry(),
		config,
		clientRepository: repositoryWith(outage),
		codeRepository,
		keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!", "v0"),
		accessTokenDenylist: createMemoryAccessTokenDenylist(),
		replaySeenSet: createMemoryReplaySeenSet(),
		logger,
	});
	const app = express();
	app.use("/oauth", router);
	return { app, logger };
}

const ENDPOINTS = [
	{ path: "/oauth/token", body: { grant_type: "client_credentials" } },
	{ path: "/oauth/introspect", body: { token: "an-access-token" } },
	{ path: "/oauth/revoke", body: { token: "a-token" } },
] as const;

type Endpoint = (typeof ENDPOINTS)[number];

const withBasic = (app: express.Express, endpoint: Endpoint, clientId = CLIENT_ID) =>
	request(app)
		.post(endpoint.path)
		.auth(clientId, CLIENT_SECRET)
		.type("form")
		.send({ ...endpoint.body });

const withPostedSecret = (app: express.Express, endpoint: Endpoint) =>
	request(app)
		.post(endpoint.path)
		.type("form")
		.send({ ...endpoint.body, client_id: CLIENT_ID, client_secret: CLIENT_SECRET });

/**
 * A `private_key_jwt` assertion naming the client. Its client is looked up
 * before its signature can be checked, so an outage is met first.
 */
const withAssertion = async (app: express.Express, endpoint: Endpoint) => {
	const { privateKey } = await generateKeyPair("ES256");
	const now = Math.floor(Date.now() / 1000);
	const assertion = await new SignJWT({ jti: randomUUID() })
		.setProtectedHeader({ alg: "ES256", kid: "k1" })
		.setIssuer(CLIENT_ID)
		.setSubject(CLIENT_ID)
		.setAudience(TOKEN_ENDPOINT)
		.setIssuedAt(now)
		.setExpirationTime(now + 60)
		.sign(privateKey);
	return request(app)
		.post(endpoint.path)
		.type("form")
		.send({
			...endpoint.body,
			client_assertion_type: JWT_BEARER_CLIENT_ASSERTION_TYPE,
			client_assertion: assertion,
		});
};

const OUTAGE = {
	error: "temporarily_unavailable",
	error_description: "client repository unavailable",
};

/** An error-level line naming the outage, carrying the projection and not the error. */
const expectLoggedOutage = (logger: MockLogger, event: string): void => {
	const line = logger.error.mock.calls.find(([, name]) => name === event);
	expect(line, `an error-level ${event} line`).toBeDefined();
	expect(line?.[0]).toMatchObject({ err: expect.objectContaining({ name: "ReplyError" }) });
	expect(line?.[0].err).not.toBeInstanceOf(Error);
	expect(serialisedCalls(logger)).not.toContain(REFUSED_COMMAND_MARKER);
};

describe("a client repository that cannot answer is 503 at every client-authenticated endpoint", () => {
	for (const endpoint of ENDPOINTS) {
		describe(endpoint.path, () => {
			it("answers 503 when the lookup fails for Basic credentials, with no Basic challenge", async () => {
				const { app, logger } = await buildApp("findById");
				const res = await withBasic(app, endpoint);
				expect(res.status).toBe(503);
				expect(res.body).toEqual(OUTAGE);
				expect(res.headers["www-authenticate"]).toBeUndefined();
				expectLoggedOutage(logger, "client_repository_unavailable");
			});

			it("answers 503 when the secret check fails", async () => {
				const { app, logger } = await buildApp("authenticate");
				const res = await withBasic(app, endpoint);
				expect(res.status).toBe(503);
				expect(res.body).toEqual(OUTAGE);
				expectLoggedOutage(logger, "client_repository_unavailable");
			});

			it("answers 503 when the lookup fails for a posted secret", async () => {
				const { app } = await buildApp("findById");
				const res = await withPostedSecret(app, endpoint);
				expect(res.status).toBe(503);
				expect(res.body).toEqual(OUTAGE);
			});

			it("answers 503 when the lookup fails for a private_key_jwt assertion", async () => {
				const { app, logger } = await buildApp("findById");
				const res = await withAssertion(app, endpoint);
				expect(res.status).toBe(503);
				expect(res.body).toEqual(OUTAGE);
				expectLoggedOutage(logger, "client_assertion_refused");
			});

			it("still answers an unknown client 401 invalid_client from a working repository", async () => {
				const { app } = await buildApp("none");
				const res = await withBasic(app, endpoint, "nobody");
				expect(res.status).toBe(401);
				expect(res.body.error).toBe("invalid_client");
			});
		});
	}
});
