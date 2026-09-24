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
 * A `client_id` that cannot name a client is refused as the client's fault
 * before the client repository is asked.
 *
 * A repository outage is now `503`, so a repository that throws on input it
 * cannot handle — a SQL driver refusing a NUL byte, an HTTP store refusing a
 * URL too long — would turn a client's malformed `client_id` into the
 * server's outage. RFC 6749 Appendix A.1 makes `client_id` `*VSCHAR`: no
 * control character can be part of one. So a `client_id` carrying a control
 * character, or longer than `MAX_CLIENT_ID_LENGTH`, is `invalid_client` at
 * client authentication (a secret or an assertion) and at `/authorize`, and
 * the repository never sees it. `/authorize` also answered a repository that
 * could not answer `500 server_error`, unlogged; it is `503` like client
 * authentication's. The id a `client_repository_unavailable` line records is
 * the client's input, so it is sanitised and capped.
 *
 * Driven through the real router (`createOAuthRouter`).
 */

import {
	type AppConfig,
	type ClientRepository,
	type CodeRepository,
	createMemoryAccessTokenDenylist,
	createMemoryReplaySeenSet,
	createSymmetricKeyStore,
	MAX_CLIENT_ID_LENGTH,
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
import { storeReplyError } from "./_helpers/projectedLog.mjs";

const ISSUER = "https://auth.example.com";
const TOKEN_ENDPOINT = `${ISSUER}/oauth/token`;

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

const codeRepository: CodeRepository = {
	createCode: async () => codeRecord({ code: "unused", client_id: "rp", redirect_uri: "" }),
	findByCode: async () => null,
	consumeByCode: async () => null,
	removeByCode: async () => {},
};

/**
 * A repository in the manner of a SQL-backed one: its driver throws on a
 * control character, and every id it is asked for is recorded.
 */
const sqlLikeRepository = () => {
	const asked: string[] = [];
	const lookup = (id: string): PublicClient | null => {
		asked.push(id);
		// biome-ignore lint/suspicious/noControlCharactersInRegex: the driver's refusal is what is modelled.
		if (/[\u0000-\u001f\u007f]/.test(id)) throw storeReplyError();
		return null;
	};
	const repository: ClientRepository = {
		findById: async (id) => lookup(id),
		authenticate: async (id) => lookup(id),
	};
	return { repository, asked };
};

async function buildApp(clientRepository: ClientRepository) {
	const logger = createMockLogger();
	const { router } = await createOAuthRouter(express, {
		registry: new GrantRegistry(),
		config,
		clientRepository,
		codeRepository,
		keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!", "v0"),
		accessTokenDenylist: createMemoryAccessTokenDenylist(),
		replaySeenSet: createMemoryReplaySeenSet(),
		logger,
	});
	const app = express();
	// `/authorize` reads the session the host's session middleware mounts; a
	// signed-in user, so the request reaches the client lookup rather than
	// the login redirect.
	app.use((req, _res, next) => {
		(req as unknown as { session: unknown }).session = {
			isAuthenticated: true,
			user: { id: "user-1" },
		};
		next();
	});
	app.use("/oauth", router);
	return { app, logger };
}

const MALFORMED: ReadonlyArray<readonly [string, string]> = [
	["a NUL byte", "rp\u0000"],
	["a line feed", "rp\nx"],
	["DEL", "rp\u007f"],
	["a C1 control character", "rp\u0085"],
	["more than MAX_CLIENT_ID_LENGTH characters", "c".repeat(MAX_CLIENT_ID_LENGTH + 1)],
];

const assertionFor = async (iss: string) => {
	const { privateKey } = await generateKeyPair("ES256");
	const now = Math.floor(Date.now() / 1000);
	return new SignJWT({ jti: "j-1" })
		.setProtectedHeader({ alg: "ES256", kid: "k1" })
		.setIssuer(iss)
		.setSubject(iss)
		.setAudience(TOKEN_ENDPOINT)
		.setIssuedAt(now)
		.setExpirationTime(now + 60)
		.sign(privateKey);
};

describe("a client_id that cannot name a client never reaches the repository", () => {
	for (const [label, clientId] of MALFORMED) {
		describe(label, () => {
			it("is 401 invalid_client under Basic at /oauth/token", async () => {
				const { repository, asked } = sqlLikeRepository();
				const { app } = await buildApp(repository);
				const basic = Buffer.from(`${encodeURIComponent(clientId)}:secret`).toString("base64");
				const res = await request(app)
					.post("/oauth/token")
					.set("Authorization", `Basic ${basic}`)
					.type("form")
					.send({ grant_type: "client_credentials" });
				expect(res.status).toBe(401);
				expect(res.body.error).toBe("invalid_client");
				expect(asked).toEqual([]);
			});

			it("is 401 invalid_client for a posted client_id at /oauth/introspect", async () => {
				const { repository, asked } = sqlLikeRepository();
				const { app } = await buildApp(repository);
				const res = await request(app)
					.post("/oauth/introspect")
					.type("form")
					.send({ token: "t", client_id: clientId, client_secret: "secret" });
				expect(res.status).toBe(401);
				expect(res.body.error).toBe("invalid_client");
				expect(asked).toEqual([]);
			});

			it("is 401 invalid_client for an assertion naming it at /oauth/revoke", async () => {
				const { repository, asked } = sqlLikeRepository();
				const { app } = await buildApp(repository);
				const res = await request(app)
					.post("/oauth/revoke")
					.type("form")
					.send({
						token: "t",
						client_assertion_type: JWT_BEARER_CLIENT_ASSERTION_TYPE,
						client_assertion: await assertionFor(clientId),
					});
				expect(res.status).toBe(401);
				expect(res.body.error).toBe("invalid_client");
				expect(asked).toEqual([]);
			});

			it("is 400 invalid_client at /authorize", async () => {
				const { repository, asked } = sqlLikeRepository();
				const { app } = await buildApp(repository);
				const res = await request(app)
					.get("/oauth/authorize")
					.query({ client_id: clientId, redirect_uri: "https://rp.example/cb" });
				expect(res.status).toBe(400);
				expect(res.body.error).toBe("invalid_client");
				expect(asked).toEqual([]);
			});
		});
	}

	it("still asks the repository for a client_id at the length bound", async () => {
		const { repository, asked } = sqlLikeRepository();
		const { app } = await buildApp(repository);
		const clientId = "c".repeat(MAX_CLIENT_ID_LENGTH);
		const res = await request(app)
			.post("/oauth/introspect")
			.type("form")
			.send({ token: "t", client_id: clientId, client_secret: "secret" });
		expect(res.status).toBe(401);
		expect(asked).toEqual([clientId]);
	});
});

describe("/authorize — a client repository that cannot answer", () => {
	it("answers 503 temporarily_unavailable, logged, not 500", async () => {
		const failing: ClientRepository = {
			findById: async () => {
				throw storeReplyError();
			},
			authenticate: async () => null,
		};
		const { app, logger } = await buildApp(failing);
		const res = await request(app)
			.get("/oauth/authorize")
			.query({ client_id: "rp", redirect_uri: "https://rp.example/cb" });
		expect(res.status).toBe(503);
		expect(res.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "client repository unavailable",
		});
		expectOutageLine(logger, { step: "find", site: "authorize" });
	});
});

describe("the client_id a client_repository_unavailable line records", () => {
	it("is the client's input, sanitised and capped", async () => {
		const failing: ClientRepository = {
			findById: async () => {
				throw storeReplyError();
			},
			authenticate: async () => null,
		};
		const { app, logger } = await buildApp(failing);
		const clientId = `"${"c".repeat(MAX_CLIENT_ID_LENGTH - 2)}\\`;
		await request(app)
			.post("/oauth/introspect")
			.type("form")
			.send({ token: "t", client_id: clientId, client_secret: "secret" });
		const line = expectOutageLine(logger, { step: "find" });
		const logged = String(line.clientId);
		expect(logged.length).toBeLessThanOrEqual(203);
		expect(logged).not.toMatch(/["\\]/);
	});
});

function expectOutageLine(logger: MockLogger, fields: Record<string, unknown>) {
	const line = logger.error.mock.calls.find(
		([, event]) => event === "client_repository_unavailable",
	);
	expect(line, "an error-level client_repository_unavailable line").toBeDefined();
	expect(line?.[0]).toMatchObject(fields);
	return line?.[0] as Record<string, unknown>;
}
