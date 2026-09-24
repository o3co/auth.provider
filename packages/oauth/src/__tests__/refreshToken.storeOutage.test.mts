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
 * Every store outage the refresh grant answers `503` is logged.
 *
 * The grant answered a family store that threw — on the rotation, or on the
 * fallback revocation a replay needs — and a session store that threw with
 * `503 temporarily_unavailable` and no log line at all: an operator saw
 * refreshes failing and nothing saying why. Each is now an error-level
 * `refresh_token_store_unavailable` line carrying the store, the step and
 * the error's projection — never the error, which can carry what the store
 * was sent.
 *
 * Driven through the real grant with core's real rotation over a store that
 * rejects the way ioredis does.
 */

import { createSecretKey } from "node:crypto";
import {
	createMemoryRefreshTokenFamilyStore,
	createRefreshTokenFamilyRotation,
	createSymmetricKeyStore,
	type GrantContext,
	type GrantDependencies,
	type RefreshTokenFamilyRevocation,
	type RefreshTokenFamilyRotation,
	type RefreshTokenFamilyStore,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { createRefreshTokenGrant } from "#/grants/refreshToken.mjs";
import { createMockLogger, type MockLogger } from "./_helpers/mockLogger.mjs";
import {
	REFUSED_COMMAND_MARKER,
	serialisedCalls,
	storeReplyError,
} from "./_helpers/projectedLog.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const CLIENT_ID = "client1";

const config = {
	oauth: {
		jwt: { issuer: "localhost" },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400, unknownFamilyPolicy: "reject", legacyRtPolicy: "reject" },
		grants: { refresh_token: { enabled: true } },
	},
} as unknown as GrantDependencies["config"];

const refreshToken = (claims: Record<string, unknown> = {}) =>
	new SignJWT({ sub: "u1", family_id: "fam-1", jti: "rt-1", azp: CLIENT_ID, ...claims })
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
		.setIssuedAt()
		.setIssuer("localhost")
		.setAudience(CLIENT_ID)
		.setExpirationTime("24h")
		.sign(createSecretKey(Buffer.from(SECRET)));

const ctx = async (claims: Record<string, unknown> = {}): Promise<GrantContext> => ({
	body: { refresh_token: await refreshToken(claims) },
	session: {},
	issuer: "localhost",
	metadata: {},
	authenticatedClient: { clientId: CLIENT_ID, tokenEndpointAuthMethod: "client_secret_basic" },
});

/** A family store whose writes fail the way an ioredis reply error does. */
const failingFamilyStore = (): RefreshTokenFamilyStore => {
	const store = createMemoryRefreshTokenFamilyStore();
	return {
		kind: "failing",
		registerFamily: (family) => store.registerFamily(family),
		findFamily: (familyId) => store.findFamily(familyId),
		updateFamily: async () => {
			throw storeReplyError();
		},
	};
};

const grant = (deps: Partial<GrantDependencies>, logger: MockLogger) =>
	createRefreshTokenGrant({
		config,
		keyStore: createSymmetricKeyStore(SECRET),
		logger,
		...deps,
	} as GrantDependencies);

/** The one error-level line for the outage, with its projection and not the error. */
const expectLogged = (logger: MockLogger, fields: Record<string, unknown>): void => {
	const line = logger.error.mock.calls.find(
		([, event]) => event === "refresh_token_store_unavailable",
	);
	expect(line, "an error-level refresh_token_store_unavailable line").toBeDefined();
	expect(line?.[0]).toMatchObject({
		...fields,
		err: expect.objectContaining({ name: "ReplyError" }),
	});
	expect(line?.[0].err).not.toBeInstanceOf(Error);
	expect(serialisedCalls(logger)).not.toContain(REFUSED_COMMAND_MARKER);
};

describe("refresh grant — a store outage is logged, not only answered", () => {
	it("logs a family store that fails the rotation", async () => {
		const logger = createMockLogger();
		const refreshTokenFamilyRotation = createRefreshTokenFamilyRotation({
			refreshTokenFamilyStore: failingFamilyStore(),
			accessTokenHorizonMs: 3_600_000,
		});
		const { result } = await grant({ refreshTokenFamilyRotation }, logger).handle(await ctx());
		expect(result).toMatchObject({ status: 503, error: "temporarily_unavailable" });
		expectLogged(logger, { store: "refresh_token_family", step: "rotate", familyId: "fam-1" });
	});

	it("logs a family store that fails the revocation a replay needs", async () => {
		// A rotation written before replays were revoked in the same write
		// reports a bare `replayed`, so the grant revokes the family itself.
		const logger = createMockLogger();
		const refreshTokenFamilyRotation: RefreshTokenFamilyRotation = {
			register: async () => {},
			rotate: async () => ({ outcome: "replayed" }),
		};
		const refreshTokenFamilyRevocation: RefreshTokenFamilyRevocation = {
			revokeFamily: async () => {
				throw storeReplyError();
			},
			isFamilyRevoked: async () => false,
		};
		const { result } = await grant(
			{ refreshTokenFamilyRotation, refreshTokenFamilyRevocation },
			logger,
		).handle(await ctx());
		expect(result).toMatchObject({ status: 503, error: "temporarily_unavailable" });
		expectLogged(logger, { store: "refresh_token_family", step: "revoke", familyId: "fam-1" });
	});

	it("logs a session store that cannot be read", async () => {
		const logger = createMockLogger();
		const userSessionStore = {
			kind: "failing",
			create: async () => {},
			get: async () => {
				throw storeReplyError();
			},
			delete: async () => {},
		} as unknown as UserSessionStore;
		const { result } = await grant({ userSessionStore }, logger).handle(
			await ctx({ sid: "sid-1" }),
		);
		expect(result).toMatchObject({
			status: 503,
			error: "temporarily_unavailable",
			errorDescription: "session store unavailable",
		});
		expectLogged(logger, { store: "user_session" });
	});
});
