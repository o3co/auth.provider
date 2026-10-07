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
 * A validator's answer is read once, as soon as `validate` resolves, into a
 * plain frozen copy that every later stage reads: the caller binding, the
 * standing rules, delegation, the email gate, the targets, the policy and
 * issuance. An answer whose members are accessors that answer differently on
 * a later read cannot have one value checked and another minted. A member
 * whose read throws is the validator's outage (503), and a `sub` that is not
 * a string is a failed validation.
 */

import type {
	ClientRepository,
	ExchangeTokenValidator,
	GrantPolicyRequest,
	GrantResult,
	PublicClient,
	User,
	ValidatedToken,
} from "@o3co/auth-provider-core";
import {
	createTestOAuthTokenSettings,
	createTestUserRepository,
} from "@o3co/auth-provider-core/testing";
import { decodeJwt } from "jose";
import { describe, expect, it, vi } from "vitest";
import { createTokenExchangeGrant, TOKEN_EXCHANGE_GRANT_TYPE } from "#/grant.mjs";
import { ISSUER, keyStore, makeFamilyRevocation, tokensOf } from "./fixtures.mjs";

const JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";
const SECRET = "client-secret";

const client: PublicClient = {
	clientId: "client-a",
	tokenEndpointAuthMethod: "client_secret_basic",
	allowedRedirectUris: [],
	allowedScopes: ["read", "write"],
	allowedAudiences: ["billing", "ledger"],
	allowedGrantTypes: [TOKEN_EXCHANGE_GRANT_TYPE],
	backchannelLogoutSessionRequired: true,
	frontchannelLogoutSessionRequired: true,
	allowedAzpForFederationToken: false,
};

const clientRepository: ClientRepository = {
	findById: async (id) => (id === client.clientId ? client : null),
	authenticate: async (id, secret) => (id === client.clientId && secret === SECRET ? client : null),
};

const users: User[] = [
	{ id: "user-1", username: "alice", emailVerified: true },
	{ id: "user-2", username: "bob", emailVerified: false },
];

/** A getter that answers `first` on its first read and `later` on every read after. */
function shifting<T>(first: T, later: T): () => T {
	let reads = 0;
	return () => (reads++ === 0 ? first : later);
}

/**
 * A frozen answer whose `sub` reads `user-1` then `user-2`, and whose `aud`
 * reads `billing` then `ledger`; its `azp` names the client.
 */
function shiftingAnswer(): ValidatedToken {
	return Object.freeze(
		Object.defineProperties(
			{},
			{
				sub: { get: shifting("user-1", "user-2"), enumerable: true },
				aud: { get: shifting("billing", "ledger"), enumerable: true },
				scope: { value: "read", enumerable: true },
				claims: {
					value: Object.freeze({
						azp: client.clientId,
						exp: Math.floor(Date.now() / 1000) + 3600,
					}),
					enumerable: true,
				},
			},
		),
	) as ValidatedToken;
}

function build(answer: () => ValidatedToken) {
	const userRepository = createTestUserRepository({ users });
	const policyRequests: GrantPolicyRequest[] = [];
	const validator: ExchangeTokenValidator = { validate: vi.fn(async () => answer()) };
	const logger = {
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		fatal: vi.fn(),
		child: vi.fn(),
	};
	logger.child.mockReturnValue(logger);
	const grant = createTokenExchangeGrant({
		oauthTokenSettings: createTestOAuthTokenSettings({
			issuer: ISSUER,
			accessTokenLifetime: { defaultExpiresIn: 300, maxExpiresIn: 300 },
			requireEmailVerified: true,
		}),
		keyStore,
		refreshTokenFamilyRevocation: makeFamilyRevocation(),
		tokenExchangeValidatorResolver: new Map([[JWT_TOKEN_TYPE, validator]]),
		clientRepository,
		userRepository,
		logger,
		grantPolicy: {
			kind: "recording",
			evaluate: async (request) => {
				policyRequests.push(request);
				return { outcome: "allow" };
			},
		},
	});
	const exchange = async (): Promise<GrantResult> =>
		(
			await grant.handle({
				body: {
					grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
					client_id: client.clientId,
					client_secret: SECRET,
					subject_token: "an-external-token",
					subject_token_type: JWT_TOKEN_TYPE,
				},
				session: {},
				issuer: ISSUER,
				metadata: {},
				authenticatedClient: null,
			})
		).result;
	return { exchange, lookups: () => userRepository.lookups, policyRequests, logger };
}

describe("token exchange reads each validator answer once", () => {
	it("mints for the subject and audience the checks passed, when the answer's accessors change on a later read", async () => {
		const h = build(shiftingAnswer);

		const result = await h.exchange();

		const issued = decodeJwt(tokensOf(result).access_token);
		expect(issued.sub).toBe("user-1");
		expect(issued.aud).toBe("billing");
		expect(h.lookups()).toEqual(["user-1"]);
		expect(h.policyRequests.map((request) => request.subject)).toEqual(["user-1"]);
	});

	it("answers 503 when reading a member of the answer throws, logged as the validator's outage", async () => {
		const h = build(
			() =>
				Object.defineProperties(
					{ claims: { azp: client.clientId } },
					{
						sub: {
							get() {
								throw new Error("lazy load failed: secret");
							},
							enumerable: true,
						},
					},
				) as unknown as ValidatedToken,
		);

		const result = await h.exchange();

		expect(result).toEqual({
			status: 503,
			error: "temporarily_unavailable",
			errorDescription: "subject_token validation store unavailable",
		});
		expect(h.lookups()).toEqual([]);
		expect(h.logger.error.mock.calls[0]?.[1]).toBe("token_exchange_validation_unavailable");
	});

	for (const [label, sub] of [
		["a number", 42],
		["missing", undefined],
	] as const) {
		it(`refuses an answer whose sub is ${label} as a failed validation`, async () => {
			const h = build(
				() =>
					({ sub, aud: "billing", claims: { azp: client.clientId } }) as unknown as ValidatedToken,
			);

			const result = await h.exchange();

			expect(result).toEqual({
				status: 400,
				error: "invalid_request",
				errorDescription: "subject_token validation failed",
			});
			expect(h.lookups()).toEqual([]);
		});
	}
});
