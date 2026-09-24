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
 * A keystore that cannot answer is an outage at the token-exchange grant, not
 * a verdict on the `subject_token` or the `actor_token`.
 *
 * The built-in validator rethrows only what core's verifier reports as an
 * outage; a failed key lookup was reported as `kid_unknown`, so the validator
 * returned `null` and the grant answered `400 invalid_request` "subject_token
 * validation failed" — telling the client its token is bad while the server's
 * key service was down. Driven through the real grant and the real validator,
 * with the real keystore whose lookup is made to fail.
 */

import {
	type ClientRepository,
	createSymmetricKeyStore,
	type GrantContext,
	type KeyStore,
	type Logger,
	type PublicClient,
} from "@o3co/auth-provider-core";
import { SignJWT } from "jose";
import { describe, expect, it, vi } from "vitest";
import { createTokenExchangeGrant, TOKEN_EXCHANGE_GRANT_TYPE } from "#/grant.mjs";
import { createSelfIssuedAccessTokenValidator } from "#/validator/selfIssuedAccessToken.mjs";
import {
	ISSUER,
	makeFamilyRevocation,
	SECRET,
	secretKey,
	signSelfIssuedAccessToken,
} from "./fixtures.mjs";

const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

const client: PublicClient = {
	clientId: "client-a",
	tokenEndpointAuthMethod: "client_secret_basic",
	allowedRedirectUris: [],
	allowedScopes: ["read"],
	allowedGrantTypes: [TOKEN_EXCHANGE_GRANT_TYPE],
};

const clientRepository: ClientRepository = {
	findById: async (id) => (id === client.clientId ? client : null),
	authenticate: async (id) => (id === client.clientId ? client : null),
};

function keyStoreWith(lookup: "up" | "down"): KeyStore {
	const real = createSymmetricKeyStore(SECRET);
	return {
		algorithm: real.algorithm,
		sign: (o) => real.sign(o),
		getSigningKidFallback: () => real.getSigningKidFallback(),
		getVerificationKeys: () => real.getVerificationKeys(),
		getVerificationKey: async (kid) => {
			if (lookup === "down") {
				throw Object.assign(new Error("connect ECONNREFUSED 10.0.0.7:8200"), {
					code: "ECONNREFUSED",
				});
			}
			return real.getVerificationKey(kid);
		},
	};
}

const spyLogger = () => {
	const logger = {
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		fatal: vi.fn(),
		child: () => logger,
	};
	return logger;
};

function grantWith(lookup: "up" | "down", logger: Logger = spyLogger() as unknown as Logger) {
	const keyStore = keyStoreWith(lookup);
	return createTokenExchangeGrant({
		config: {
			oauth: {
				jwt: { issuer: ISSUER },
				accessToken: { expiresIn: 300 },
				refreshToken: { expiresIn: 86400 },
				grants: {},
			},
			// biome-ignore lint/suspicious/noExplicitAny: test scaffold config
		} as any,
		keyStore,
		logger,
		refreshTokenFamilyRevocation: makeFamilyRevocation(),
		tokenExchangeValidatorResolver: new Map([
			[ACCESS_TOKEN_TYPE, createSelfIssuedAccessTokenValidator({ keyStore, issuer: ISSUER })],
		]),
		clientRepository,
	});
}

const ctx = (body: Record<string, unknown>): GrantContext => ({
	body,
	session: {},
	issuer: ISSUER,
	metadata: {},
	authenticatedClient: client,
});

const fabricatedKid = () =>
	new SignJWT({ sub: "user-1", scope: "read", iss: ISSUER, aud: "client-a" })
		.setProtectedHeader({ alg: "HS256", kid: "fabricated", typ: "at+jwt" })
		.setIssuedAt()
		.setExpirationTime("1h")
		.sign(secretKey);

describe("token exchange — a keystore that cannot answer", () => {
	it("answers the subject_token with 503, not invalid_request", async () => {
		const { result } = await grantWith("down").handle(
			ctx({
				subject_token: await signSelfIssuedAccessToken({}),
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({
			status: 503,
			error: "temporarily_unavailable",
			errorDescription: "subject_token validation store unavailable",
		});
	});

	it("answers the actor_token with 503 too", async () => {
		// The subject verifies against a working keystore; only the actor's
		// lookup fails. Two grants would verify both with one keystore, so the
		// actor validator is built on the failing one.
		const working = keyStoreWith("up");
		const failing = keyStoreWith("down");
		const subjectValidator = createSelfIssuedAccessTokenValidator({
			keyStore: working,
			issuer: ISSUER,
		});
		const actorValidator = createSelfIssuedAccessTokenValidator({
			keyStore: failing,
			issuer: ISSUER,
		});
		const ACTOR_TYPE = "urn:example:actor";
		const grant = createTokenExchangeGrant({
			config: {
				oauth: {
					jwt: { issuer: ISSUER },
					accessToken: { expiresIn: 300 },
					refreshToken: { expiresIn: 86400 },
					grants: {},
				},
				// biome-ignore lint/suspicious/noExplicitAny: test scaffold config
			} as any,
			keyStore: working,
			refreshTokenFamilyRevocation: makeFamilyRevocation(),
			tokenExchangeValidatorResolver: new Map([
				[ACCESS_TOKEN_TYPE, subjectValidator],
				[ACTOR_TYPE, actorValidator],
			]),
			clientRepository,
		});
		const { result } = await grant.handle(
			ctx({
				subject_token: await signSelfIssuedAccessToken({}),
				subject_token_type: ACCESS_TOKEN_TYPE,
				actor_token: await signSelfIssuedAccessToken({ sub: "agent-1" }),
				actor_token_type: ACTOR_TYPE,
			}),
		);
		expect(result).toMatchObject({
			status: 503,
			error: "temporarily_unavailable",
			errorDescription: "actor_token validation store unavailable",
		});
	});

	it("logs the outage with the keystore's error as its cause", async () => {
		const logger = spyLogger();
		await grantWith("down", logger as unknown as Logger).handle(
			ctx({
				subject_token: await signSelfIssuedAccessToken({}),
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		const line = logger.error.mock.calls.find(
			([, event]) => event === "token_exchange_validation_unavailable",
		);
		expect(line, "a token_exchange_validation_unavailable error line").toBeDefined();
		expect(line?.[0]).toMatchObject({
			role: "subject",
			err: {
				name: "JwtVerificationError",
				cause: { name: "Error", code: "ECONNREFUSED" },
			},
		});
		expect(line?.[0].err).not.toBeInstanceOf(Error);
	});

	it("still refuses a kid the working keystore does not hold as the client's fault", async () => {
		const { result } = await grantWith("up").handle(
			ctx({ subject_token: await fabricatedKid(), subject_token_type: ACCESS_TOKEN_TYPE }),
		);
		expect(result).toMatchObject({
			status: 400,
			error: "invalid_request",
			errorDescription: "subject_token validation failed",
		});
	});
});
