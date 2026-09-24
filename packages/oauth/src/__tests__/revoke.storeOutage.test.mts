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
 * `POST /oauth/revoke` when the store behind a revocation fails.
 *
 * RFC 7009 §2.2 makes `200` the answer for a revocation that happened and for
 * a token the server could not use — invalid, unknown, or another client's.
 * It is not the answer for a revocation the server could not perform: §2.2.1
 * gives `503` for that, and says the client "should assume the token still
 * exists". A `200` over a denylist or family-store outage told the client its
 * token was revoked while the token kept verifying until it expired.
 *
 * Driven through the real route: the real `verifyJwt`, a real memory denylist
 * and family revocation, with only the write that fails replaced.
 */

import { createSecretKey } from "node:crypto";
import {
	type AccessTokenDenylist,
	type ClientRepository,
	createMemoryAccessTokenDenylist,
	createSymmetricKeyStore,
	type RefreshTokenFamilyRevocation,
} from "@o3co/auth-provider-core";
import express from "express";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createRevokeRouter } from "#/routes/revoke.mjs";
import { createMockLogger, type MockLogger } from "./_helpers/mockLogger.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const keyStore = createSymmetricKeyStore(SECRET);
const secretKey = createSecretKey(Buffer.from(SECRET));

const ISSUER = "https://auth.example";
const CLIENT_ID = "c-1";
const CLIENT_SECRET = "c-1-secret";
const OTHER_CLIENT_ID = "c-other";

const registration = (clientId: string) => ({
	clientId,
	tokenEndpointAuthMethod: "client_secret_basic" as const,
	allowedRedirectUris: [],
	allowedScopes: [],
});

const clientRepository: ClientRepository = {
	findById: async (id) => (id === CLIENT_ID || id === OTHER_CLIENT_ID ? registration(id) : null),
	authenticate: async (id, secret) =>
		id === CLIENT_ID && secret === CLIENT_SECRET ? registration(CLIENT_ID) : null,
};

/** What a Redis client rejects with when the server is gone. */
const outage = (): Error =>
	Object.assign(new Error("connect ECONNREFUSED 127.0.0.1:6379"), { code: "ECONNREFUSED" });

/** A memory denylist whose writes fail, as a Redis-backed one does when Redis is down. */
function denylistThatCannotWrite(): AccessTokenDenylist & {
	readonly add: ReturnType<typeof vi.fn>;
} {
	const real = createMemoryAccessTokenDenylist();
	return {
		kind: real.kind,
		has: (jti) => real.has(jti),
		add: vi.fn(async () => {
			throw outage();
		}),
	};
}

function familyRevocation(fails: boolean): RefreshTokenFamilyRevocation & {
	readonly revokeFamily: ReturnType<typeof vi.fn>;
} {
	return {
		revokeFamily: vi.fn(async () => {
			if (fails) throw outage();
		}),
		isFamilyRevoked: vi.fn(async () => false),
	};
}

async function accessToken(clientId: string, jti = "at-1"): Promise<string> {
	return new SignJWT({ sub: "u1", scope: "read", client_id: clientId, jti })
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "at+jwt" })
		.setIssuer(ISSUER)
		.setAudience(clientId)
		.setExpirationTime("1h")
		.sign(secretKey);
}

async function refreshToken(clientId: string, familyId = "fam-1"): Promise<string> {
	return new SignJWT({ sub: "u1", scope: "read", family_id: familyId, azp: clientId })
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
		.setIssuer(ISSUER)
		.setAudience(clientId)
		.setExpirationTime("24h")
		.sign(secretKey);
}

function appWith(opts: {
	denylist?: AccessTokenDenylist;
	revocation: RefreshTokenFamilyRevocation;
	logger: MockLogger;
}): express.Express {
	const app = express();
	app.use(
		"/oauth",
		createRevokeRouter(express, {
			clientRepository,
			keyStore,
			refreshTokenFamilyRevocation: opts.revocation,
			...(opts.denylist === undefined
				? { accessTokenRevocation: "unsupported" as const }
				: { accessTokenDenylist: opts.denylist }),
			logger: opts.logger,
			issuer: ISSUER,
		}),
	);
	return app;
}

const revoke = (app: express.Express, form: Record<string, string>) =>
	request(app).post("/oauth/revoke").auth(CLIENT_ID, CLIENT_SECRET).type("form").send(form);

/** The one error-level line an outage writes, with the error projected. */
function expectOutageLogged(logger: MockLogger, store: string): void {
	const lines = logger.error.mock.calls.filter(([, event]) => event === "revoke_store_unavailable");
	expect(lines).toHaveLength(1);
	const [fields] = lines[0] as [Record<string, unknown>, string];
	expect(fields.store).toBe(store);
	// `loggableError`'s projection, never the error itself: a store's error can
	// carry the command it refused, and a token is exactly such an argument.
	expect(fields.err).not.toBeInstanceOf(Error);
	expect(fields.err).toMatchObject({ name: "Error", code: "ECONNREFUSED" });
}

describe("POST /oauth/revoke — a denylist that cannot be written", () => {
	for (const hint of ["access_token", undefined] as const) {
		it(`answers 503 temporarily_unavailable, not 200, for the client's own access token (hint ${hint ?? "absent"})`, async () => {
			const denylist = denylistThatCannotWrite();
			const logger = createMockLogger();
			const app = appWith({ denylist, revocation: familyRevocation(false), logger });

			const token = await accessToken(CLIENT_ID);
			const res = await revoke(
				app,
				hint === undefined ? { token } : { token, token_type_hint: hint },
			);

			expect(denylist.add).toHaveBeenCalledTimes(1);
			expect(res.status).toBe(503);
			expect(res.body.error).toBe("temporarily_unavailable");
			expect(res.body.error_description).toEqual(expect.any(String));
			expectOutageLogged(logger, "accessTokenDenylist");
		});
	}

	it("still answers 200 for another client's token: the store is never asked", async () => {
		const denylist = denylistThatCannotWrite();
		const logger = createMockLogger();
		const app = appWith({ denylist, revocation: familyRevocation(false), logger });

		const res = await revoke(app, { token: await accessToken(OTHER_CLIENT_ID) });

		expect(res.status).toBe(200);
		expect(denylist.add).not.toHaveBeenCalled();
		expect(logger.error).not.toHaveBeenCalled();
	});

	it("still answers 200 for a token that does not verify: the store is never asked", async () => {
		const denylist = denylistThatCannotWrite();
		const logger = createMockLogger();
		const app = appWith({ denylist, revocation: familyRevocation(false), logger });

		const res = await revoke(app, { token: "not.a.token", token_type_hint: "access_token" });

		expect(res.status).toBe(200);
		expect(denylist.add).not.toHaveBeenCalled();
		expect(logger.error).not.toHaveBeenCalled();
	});
});

describe("POST /oauth/revoke — a refresh-token family store that cannot be written", () => {
	for (const hint of ["refresh_token", "access_token", undefined] as const) {
		it(`answers 503 temporarily_unavailable, not 200, for the client's own refresh token (hint ${hint ?? "absent"})`, async () => {
			const revocation = familyRevocation(true);
			const logger = createMockLogger();
			const app = appWith({ denylist: createMemoryAccessTokenDenylist(), revocation, logger });

			const token = await refreshToken(CLIENT_ID);
			const res = await revoke(
				app,
				hint === undefined ? { token } : { token, token_type_hint: hint },
			);

			expect(revocation.revokeFamily).toHaveBeenCalledWith("fam-1");
			expect(res.status).toBe(503);
			expect(res.body.error).toBe("temporarily_unavailable");
			expectOutageLogged(logger, "refreshTokenFamilyRevocation");
		});
	}

	it('answers 503 under accessTokenRevocation: "unsupported" too — the refresh path is the same', async () => {
		const revocation = familyRevocation(true);
		const logger = createMockLogger();
		const app = appWith({ revocation, logger });

		const res = await revoke(app, { token: await refreshToken(CLIENT_ID) });

		expect(res.status).toBe(503);
		expect(res.body.error).toBe("temporarily_unavailable");
		expectOutageLogged(logger, "refreshTokenFamilyRevocation");
	});

	it("still answers 200 for another client's refresh token: the store is never asked", async () => {
		const revocation = familyRevocation(true);
		const logger = createMockLogger();
		const app = appWith({ denylist: createMemoryAccessTokenDenylist(), revocation, logger });

		const res = await revoke(app, { token: await refreshToken(OTHER_CLIENT_ID) });

		expect(res.status).toBe(200);
		expect(revocation.revokeFamily).not.toHaveBeenCalled();
		expect(logger.error).not.toHaveBeenCalled();
	});
});
