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
 * The authentication context an exchanged token carries: the subject token's
 * `acr`, `amr` and `auth_time` when this provider issued and verified it, and
 * nothing from a token another validator answered for, nor from the actor.
 */

import type {
	ClientRepository,
	ExchangeTokenValidator,
	GrantContext,
	PublicClient,
	ValidatedToken,
} from "@o3co/auth-provider-core";
import { decodeJwt, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { createTokenExchangeGrant, TOKEN_EXCHANGE_GRANT_TYPE } from "#/grant.mjs";
import { createSelfIssuedAccessTokenValidator } from "#/validator/selfIssuedAccessToken.mjs";
import {
	ISSUER,
	keyStore,
	makeFamilyRevocation,
	secretKey,
	signSelfIssuedAccessToken,
	tokenSettings,
	tokensOf,
} from "./fixtures.mjs";

const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
const JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";

const AUTHENTICATION = {
	acr: "urn:o3co:acr:mfa",
	amr: ["pwd", "otp", "mfa"],
} as const;

const client: PublicClient = {
	clientId: "client-a",
	tokenEndpointAuthMethod: "client_secret_basic",
	allowedRedirectUris: [],
	allowedScopes: ["read", "write"],
	allowedAudiences: [],
	allowedGrantTypes: [TOKEN_EXCHANGE_GRANT_TYPE],
	backchannelLogoutSessionRequired: true,
	frontchannelLogoutSessionRequired: true,
	allowedAzpForFederationToken: false,
};

const clientRepository: ClientRepository = {
	findById: async (id) => (id === client.clientId ? client : null),
	authenticate: async (id) => (id === client.clientId ? client : null),
};

function buildGrant(validators: ReadonlyMap<string, ExchangeTokenValidator>) {
	return createTokenExchangeGrant({
		oauthTokenSettings: tokenSettings,
		keyStore,
		refreshTokenFamilyRevocation: makeFamilyRevocation(),
		tokenExchangeValidatorResolver: validators,
		clientRepository,
	});
}

const selfIssued = (issuer = ISSUER) => createSelfIssuedAccessTokenValidator({ keyStore, issuer });

const ctx = (
	body: Record<string, unknown>,
	overrides: Partial<GrantContext> = {},
): GrantContext => ({
	body: { client_id: "client-a", client_secret: "s", ...body },
	session: {},
	issuer: ISSUER,
	metadata: {},
	authenticatedClient: null,
	...overrides,
});

const now = () => Math.floor(Date.now() / 1000);

/** The claims of the access token an exchange minted. */
async function exchanged(
	validators: ReadonlyMap<string, ExchangeTokenValidator>,
	body: Record<string, unknown>,
	overrides: Partial<GrantContext> = {},
): Promise<Record<string, unknown>> {
	const { result } = await buildGrant(validators).handle(ctx(body, overrides));
	return decodeJwt(tokensOf(result).access_token);
}

describe("token exchange — the subject's authentication context", () => {
	it("carries acr, amr and auth_time from a subject token this provider issued", async () => {
		const authTime = now() - 120;
		const claims = await exchanged(new Map([[ACCESS_TOKEN_TYPE, selfIssued()]]), {
			subject_token: await signSelfIssuedAccessToken({ ...AUTHENTICATION, auth_time: authTime }),
			subject_token_type: ACCESS_TOKEN_TYPE,
		});
		expect(claims).toMatchObject({ ...AUTHENTICATION, auth_time: authTime });
	});

	it("carries each claim that is well formed, and omits each that is not", async () => {
		const claims = await exchanged(new Map([[ACCESS_TOKEN_TYPE, selfIssued()]]), {
			subject_token: await signSelfIssuedAccessToken({
				acr: "",
				amr: ["pwd"],
				auth_time: 1.5,
			}),
			subject_token_type: ACCESS_TOKEN_TYPE,
		});
		expect(claims.amr).toEqual(["pwd"]);
		expect(claims).not.toHaveProperty("acr");
		expect(claims).not.toHaveProperty("auth_time");

		const empty = await exchanged(new Map([[ACCESS_TOKEN_TYPE, selfIssued()]]), {
			subject_token: await signSelfIssuedAccessToken({ amr: [], acr: "urn:o3co:acr:mfa" }),
			subject_token_type: ACCESS_TOKEN_TYPE,
		});
		expect(empty).not.toHaveProperty("amr");
		expect(empty.acr).toBe("urn:o3co:acr:mfa");
	});

	it("never carries an auth_time later than the subject token's own iat", async () => {
		const iat = now() - 60;
		const subjectToken = await new SignJWT({
			sub: "user-1",
			scope: "read",
			iss: ISSUER,
			aud: "client-a",
			auth_time: iat + 30,
		})
			.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "at+jwt" })
			.setIssuedAt(iat)
			.setExpirationTime("1h")
			.sign(secretKey);
		const claims = await exchanged(new Map([[ACCESS_TOKEN_TYPE, selfIssued()]]), {
			subject_token: subjectToken,
			subject_token_type: ACCESS_TOKEN_TYPE,
		});
		expect(claims.auth_time).toBe(iat);
	});

	it("carries the context on through a chain of exchanges", async () => {
		const authTime = now() - 120;
		const validators = new Map([[ACCESS_TOKEN_TYPE, selfIssued()]]);
		const first = await buildGrant(validators).handle(
			ctx({
				subject_token: await signSelfIssuedAccessToken({ ...AUTHENTICATION, auth_time: authTime }),
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		const claims = await exchanged(validators, {
			subject_token: tokensOf(first.result).access_token,
			subject_token_type: ACCESS_TOKEN_TYPE,
		});
		expect(claims).toMatchObject({ ...AUTHENTICATION, auth_time: authTime });
	});

	it("carries nothing from a subject token another validator answered for, whatever its iss", async () => {
		// A contributed validator's answer is not this provider's to vouch for,
		// even when it names this provider as the issuer.
		const foreign: ExchangeTokenValidator = {
			async validate(): Promise<ValidatedToken> {
				return {
					sub: "user-1",
					scope: "read",
					aud: "client-a",
					claims: {
						sub: "user-1",
						iss: ISSUER,
						exp: now() + 3600,
						iat: now(),
						...AUTHENTICATION,
						auth_time: now() - 10,
					},
				};
			},
		};
		const claims = await exchanged(new Map([[JWT_TOKEN_TYPE, foreign]]), {
			subject_token: "opaque-foreign-token",
			subject_token_type: JWT_TOKEN_TYPE,
		});
		expectNoAuthenticationContext(claims);
	});

	it("carries nothing from an answer copied off the built-in validator's", async () => {
		const builtIn = selfIssued();
		const copying: ExchangeTokenValidator = {
			async validate(token, context) {
				const answer = await builtIn.validate(token, context);
				return answer && { ...answer };
			},
		};
		const claims = await exchanged(new Map([[ACCESS_TOKEN_TYPE, copying]]), {
			subject_token: await signSelfIssuedAccessToken({ ...AUTHENTICATION, auth_time: now() - 5 }),
			subject_token_type: ACCESS_TOKEN_TYPE,
		});
		expectNoAuthenticationContext(claims);
	});

	it("carries nothing from a token verified for another issuer than the one minting", async () => {
		const otherIssuer = "https://other.example";
		const subjectToken = await signSelfIssuedAccessToken({
			...AUTHENTICATION,
			auth_time: now() - 5,
			iss: otherIssuer,
		});
		const claims = await exchanged(new Map([[ACCESS_TOKEN_TYPE, selfIssued(otherIssuer)]]), {
			subject_token: subjectToken,
			subject_token_type: ACCESS_TOKEN_TYPE,
		});
		expectNoAuthenticationContext(claims);
	});

	it("carries nothing when the request names no issuer to compare against", async () => {
		const { result } = await buildGrant(new Map([[ACCESS_TOKEN_TYPE, selfIssued()]])).handle(
			ctx(
				{
					subject_token: await signSelfIssuedAccessToken({
						...AUTHENTICATION,
						auth_time: now() - 5,
					}),
					subject_token_type: ACCESS_TOKEN_TYPE,
				},
				{ issuer: undefined },
			),
		);
		expectNoAuthenticationContext(decodeJwt(tokensOf(result).access_token));
	});

	it("carries nothing from the actor token", async () => {
		const validators = new Map([[ACCESS_TOKEN_TYPE, selfIssued()]]);
		const claims = await exchanged(validators, {
			subject_token: await signSelfIssuedAccessToken({}),
			subject_token_type: ACCESS_TOKEN_TYPE,
			actor_token: await signSelfIssuedAccessToken({
				sub: "service-b",
				...AUTHENTICATION,
				auth_time: now() - 5,
			}),
			actor_token_type: ACCESS_TOKEN_TYPE,
		});
		expect(claims.act).toMatchObject({ sub: "service-b" });
		expectNoAuthenticationContext(claims);
	});

	it("carries the subject's context, not the actor's, when both carry one", async () => {
		const subjectAuthTime = now() - 300;
		const claims = await exchanged(new Map([[ACCESS_TOKEN_TYPE, selfIssued()]]), {
			subject_token: await signSelfIssuedAccessToken({
				acr: "urn:o3co:acr:pwd",
				amr: ["pwd"],
				auth_time: subjectAuthTime,
			}),
			subject_token_type: ACCESS_TOKEN_TYPE,
			actor_token: await signSelfIssuedAccessToken({
				sub: "service-b",
				...AUTHENTICATION,
				auth_time: now() - 5,
			}),
			actor_token_type: ACCESS_TOKEN_TYPE,
		});
		expect(claims).toMatchObject({
			acr: "urn:o3co:acr:pwd",
			amr: ["pwd"],
			auth_time: subjectAuthTime,
		});
	});
});

function expectNoAuthenticationContext(claims: Record<string, unknown>): void {
	expect(claims).not.toHaveProperty("acr");
	expect(claims).not.toHaveProperty("amr");
	expect(claims).not.toHaveProperty("auth_time");
}
