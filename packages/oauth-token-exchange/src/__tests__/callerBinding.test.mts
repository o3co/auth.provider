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

import type { ClientRepository, GrantContext, PublicClient } from "@o3co/auth-provider-core";
import { decodeJwt } from "jose";
import { describe, expect, it, vi } from "vitest";
import { createTokenExchangeGrant, TOKEN_EXCHANGE_GRANT_TYPE } from "#/grant.mjs";
import { createSelfIssuedAccessTokenValidator } from "#/validator/selfIssuedAccessToken.mjs";
import {
	ISSUER,
	keyStore,
	makeFamilyRevocation,
	signSelfIssuedAccessToken,
	tokenSettings,
	tokensOf,
} from "./fixtures.mjs";

const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
const NOT_FOR_CLIENT = "subject_token azp and aud do not name this client";
const ACTOR_NOT_FOR_CLIENT = "actor_token azp and aud do not name this client";

/** The calling client: `resource-server`, a confidential client enabled for the exchange. */
const client = (overrides: Partial<PublicClient> = {}): PublicClient => ({
	clientId: "resource-server",
	tokenEndpointAuthMethod: "client_secret_basic",
	allowedRedirectUris: [],
	allowedScopes: ["read", "write"],
	allowedAudiences: [],
	allowedGrantTypes: [TOKEN_EXCHANGE_GRANT_TYPE],
	backchannelLogoutSessionRequired: true,
	frontchannelLogoutSessionRequired: true,
	allowedAzpForFederationToken: false,
	...overrides,
});

const repositoryOf = (registered: PublicClient): ClientRepository => ({
	findById: async (id) => (id === registered.clientId ? registered : null),
	authenticate: async (id) => (id === registered.clientId ? registered : null),
});

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

function buildGrant(
	registered: PublicClient = client(),
	logger: ReturnType<typeof spyLogger> = spyLogger(),
) {
	return createTokenExchangeGrant({
		oauthTokenSettings: tokenSettings,
		keyStore,
		logger,
		refreshTokenFamilyRevocation: makeFamilyRevocation(),
		tokenExchangeValidatorResolver: new Map([
			[ACCESS_TOKEN_TYPE, createSelfIssuedAccessTokenValidator({ keyStore, issuer: ISSUER })],
		]),
		clientRepository: repositoryOf(registered),
	});
}

const ctx = (
	body: Record<string, unknown>,
	overrides: Partial<GrantContext> = {},
): GrantContext => ({
	body: { client_id: "resource-server", client_secret: "s", ...body },
	session: {},
	issuer: ISSUER,
	metadata: {},
	authenticatedClient: null,
	...overrides,
});

/** An exchange of a subject token carrying `claims`, without an actor token. */
async function exchange(
	claims: Record<string, unknown>,
	registered: PublicClient = client(),
	logger: ReturnType<typeof spyLogger> = spyLogger(),
) {
	const subject = await signSelfIssuedAccessToken(claims);
	return (
		await buildGrant(registered, logger).handle(
			ctx({ subject_token: subject, subject_token_type: ACCESS_TOKEN_TYPE }),
		)
	).result;
}

describe("token exchange — the calling client must be named by the subject token", () => {
	it("accepts a subject token whose aud is the calling client, as a string", async () => {
		const result = await exchange({ aud: "resource-server", azp: "web-app" });
		expect(result.status).toBe(200);
	});

	it("accepts a subject token whose aud array contains the calling client", async () => {
		const result = await exchange({ aud: ["other-api", "resource-server"], azp: "web-app" });
		expect(result.status).toBe(200);
	});

	it("accepts a subject token whose azp is the calling client", async () => {
		const result = await exchange({ aud: "other-api", azp: "resource-server" });
		expect(result.status).toBe(200);
	});

	it("refuses a subject token whose aud string and azp name another client", async () => {
		const logger = spyLogger();
		const result = await exchange({ aud: "other-api", azp: "web-app" }, client(), logger);
		expect(result).toEqual({
			status: 400,
			error: "invalid_request",
			errorDescription: NOT_FOR_CLIENT,
		});
		expect(logger.warn).toHaveBeenCalledWith(
			{ subject: "user-1", clientId: "resource-server" },
			"token_exchange_subject_not_for_client",
		);
	});

	it("refuses a subject token whose aud array does not contain the calling client", async () => {
		const result = await exchange({ aud: ["other-api", "billing"], azp: "web-app" });
		expect(result).toMatchObject({ status: 400, errorDescription: NOT_FOR_CLIENT });
	});

	it("refuses a subject token that carries neither aud nor azp", async () => {
		const result = await exchange({ aud: undefined, azp: undefined });
		expect(result).toMatchObject({ status: 400, errorDescription: NOT_FOR_CLIENT });
	});

	it("does not read a client_id claim as naming the calling client", async () => {
		// Every token this provider stamps with `client_id` carries the same value as `azp`.
		const result = await exchange({
			aud: "other-api",
			azp: "web-app",
			client_id: "resource-server",
		});
		expect(result).toMatchObject({ status: 400, errorDescription: NOT_FOR_CLIENT });
	});

	it("compares the client id exactly", async () => {
		const result = await exchange({ aud: "Resource-Server", azp: "resource-server " });
		expect(result).toMatchObject({ status: 400, errorDescription: NOT_FOR_CLIENT });
	});

	it("refuses the client authenticated by the route as it refuses one authenticated by the body", async () => {
		const subject = await signSelfIssuedAccessToken({ aud: "other-api", azp: "web-app" });
		const { result } = await buildGrant().handle(
			ctx(
				{ subject_token: subject, subject_token_type: ACCESS_TOKEN_TYPE, client_secret: undefined },
				{
					authenticatedClient: {
						clientId: "resource-server",
						tokenEndpointAuthMethod: "client_secret_basic",
					} as GrantContext["authenticatedClient"],
				},
			),
		);
		expect(result).toMatchObject({ status: 400, errorDescription: NOT_FOR_CLIENT });
	});
});

describe("token exchange — allowExchangeOfTokensIssuedToOthers on the registration", () => {
	it("accepts a subject token naming another client when the registration sets it", async () => {
		const result = await exchange(
			{ aud: "other-api", azp: "web-app" },
			client({ allowExchangeOfTokensIssuedToOthers: true }),
		);
		expect(result.status).toBe(200);
		// An omitted audience still defaults to the calling client's own id.
		expect(decodeJwt(tokensOf(result).access_token).aud).toBe("resource-server");
	});

	it("still refuses when the registration sets it to false", async () => {
		const result = await exchange(
			{ aud: "other-api", azp: "web-app" },
			client({ allowExchangeOfTokensIssuedToOthers: false }),
		);
		expect(result).toMatchObject({ status: 400, errorDescription: NOT_FOR_CLIENT });
	});

	it("reads only a strict true", async () => {
		const result = await exchange(
			{ aud: "other-api", azp: "web-app" },
			client({ allowExchangeOfTokensIssuedToOthers: "true" as unknown as boolean }),
		);
		expect(result).toMatchObject({ status: 400, errorDescription: NOT_FOR_CLIENT });
	});

	it("is read from the registration, never from the request", async () => {
		const result = await exchange({ aud: "other-api", azp: "web-app" }, client(), spyLogger());
		expect(result).toMatchObject({ status: 400, errorDescription: NOT_FOR_CLIENT });
		const subject = await signSelfIssuedAccessToken({ aud: "other-api", azp: "web-app" });
		const { result: withParameter } = await buildGrant().handle(
			ctx({
				subject_token: subject,
				subject_token_type: ACCESS_TOKEN_TYPE,
				allowExchangeOfTokensIssuedToOthers: "true",
				allow_exchange_of_tokens_issued_to_others: "true",
			}),
		);
		expect(withParameter).toMatchObject({ status: 400, errorDescription: NOT_FOR_CLIENT });
	});

	it("does not relax may_act on an exchange without an actor token", async () => {
		const result = await exchange(
			{ aud: "other-api", azp: "web-app", may_act: { sub: "someone-else" } },
			client({ allowExchangeOfTokensIssuedToOthers: true }),
		);
		expect(result).toMatchObject({
			status: 400,
			errorDescription: "may_act_violation: client not authorized by subject token",
		});
	});
});

/**
 * An exchange of a subject token carrying `subjectClaims` with an actor token
 * carrying `actorClaims`; by default the actor is `svc-a` and names the calling
 * client in its `aud`.
 */
async function delegate(
	subjectClaims: Record<string, unknown>,
	registered: PublicClient = client(),
	actorClaims: Record<string, unknown> = { aud: "resource-server" },
	logger: ReturnType<typeof spyLogger> = spyLogger(),
) {
	const subject = await signSelfIssuedAccessToken(subjectClaims);
	const actor = await signSelfIssuedAccessToken({ sub: "svc-a", ...actorClaims });
	return (
		await buildGrant(registered, logger).handle(
			ctx({
				subject_token: subject,
				subject_token_type: ACCESS_TOKEN_TYPE,
				actor_token: actor,
				actor_token_type: ACCESS_TOKEN_TYPE,
			}),
		)
	).result;
}

describe("token exchange — the client binding beside an actor token", () => {
	it("delegates to the actor when the subject token names the calling client", async () => {
		const result = await delegate({ aud: "resource-server" });
		expect(result.status).toBe(200);
		expect(decodeJwt(tokensOf(result).access_token).act).toEqual({ sub: "svc-a" });
	});

	it("still applies may_act to the actor", async () => {
		const result = await delegate({ aud: "resource-server", may_act: { sub: "svc-b" } });
		expect(result).toMatchObject({
			status: 400,
			errorDescription: "may_act_violation: actor not authorized by subject token",
		});
	});

	it("refuses a subject token naming another client, whoever the actor is", async () => {
		const result = await delegate({ aud: "other-api", azp: "web-app", may_act: { sub: "svc-a" } });
		expect(result).toMatchObject({ status: 400, errorDescription: NOT_FOR_CLIENT });
	});

	it("delegates for a subject token naming another client when the registration sets the opt-out", async () => {
		const result = await delegate(
			{ aud: "other-api", azp: "web-app" },
			client({ allowExchangeOfTokensIssuedToOthers: true }),
		);
		expect(result.status).toBe(200);
		expect(decodeJwt(tokensOf(result).access_token).act).toEqual({ sub: "svc-a" });
	});

	it("refuses a subject token naming another client before reading the actor token", async () => {
		const result = await delegate({ aud: "other-api", azp: "web-app" }, client(), {
			aud: "other-api",
			azp: "web-app",
		});
		expect(result).toMatchObject({ status: 400, errorDescription: NOT_FOR_CLIENT });
	});
});

describe("token exchange — the calling client must be named by the actor token", () => {
	const subjectForClient = { aud: "resource-server", may_act: { sub: "svc-a" } };

	it("accepts an actor token whose aud is the calling client, as a string", async () => {
		const result = await delegate(subjectForClient, client(), {
			aud: "resource-server",
			azp: "web-app",
		});
		expect(result.status).toBe(200);
		expect(decodeJwt(tokensOf(result).access_token).act).toEqual({ sub: "svc-a" });
	});

	it("accepts an actor token whose aud array contains the calling client", async () => {
		const result = await delegate(subjectForClient, client(), {
			aud: ["other-api", "resource-server"],
			azp: "web-app",
		});
		expect(result.status).toBe(200);
	});

	it("accepts an actor token whose azp is the calling client", async () => {
		const result = await delegate(subjectForClient, client(), {
			aud: "other-api",
			azp: "resource-server",
		});
		expect(result.status).toBe(200);
	});

	it("refuses an actor token whose aud and azp name another client, even one may_act names", async () => {
		const logger = spyLogger();
		const result = await delegate(
			subjectForClient,
			client(),
			{ aud: "other-api", azp: "web-app" },
			logger,
		);
		expect(result).toEqual({
			status: 400,
			error: "invalid_request",
			errorDescription: ACTOR_NOT_FOR_CLIENT,
		});
		expect(logger.warn).toHaveBeenCalledWith(
			{ subject: "user-1", actor: "svc-a", clientId: "resource-server" },
			"token_exchange_actor_not_for_client",
		);
	});

	it("refuses an actor token whose aud array does not contain the calling client", async () => {
		const result = await delegate(subjectForClient, client(), {
			aud: ["other-api", "billing"],
			azp: "web-app",
		});
		expect(result).toMatchObject({ status: 400, errorDescription: ACTOR_NOT_FOR_CLIENT });
	});

	it("refuses an actor token that carries neither aud nor azp", async () => {
		const result = await delegate(subjectForClient, client(), {
			aud: undefined,
			azp: undefined,
		});
		expect(result).toMatchObject({ status: 400, errorDescription: ACTOR_NOT_FOR_CLIENT });
	});

	it("does not read an actor token's client_id claim as naming the calling client", async () => {
		const result = await delegate(subjectForClient, client(), {
			aud: "other-api",
			azp: "web-app",
			client_id: "resource-server",
		});
		expect(result).toMatchObject({ status: 400, errorDescription: ACTOR_NOT_FOR_CLIENT });
	});

	it("refuses an actor token naming another client when the subject token carries no may_act", async () => {
		const result = await delegate({ aud: "resource-server" }, client(), {
			aud: "other-api",
			azp: "web-app",
		});
		expect(result).toMatchObject({ status: 400, errorDescription: ACTOR_NOT_FOR_CLIENT });
	});

	it("accepts an actor token naming another client when the registration sets allowExchangeOfTokensIssuedToOthers", async () => {
		const result = await delegate(
			subjectForClient,
			client({ allowExchangeOfTokensIssuedToOthers: true }),
			{ aud: "other-api", azp: "web-app" },
		);
		expect(result.status).toBe(200);
		expect(decodeJwt(tokensOf(result).access_token).act).toEqual({ sub: "svc-a" });
	});

	it("reads only a strict true for the actor token too", async () => {
		const result = await delegate(
			subjectForClient,
			client({ allowExchangeOfTokensIssuedToOthers: "true" as unknown as boolean }),
			{ aud: "other-api", azp: "web-app" },
		);
		expect(result).toMatchObject({ status: 400, errorDescription: ACTOR_NOT_FOR_CLIENT });
	});

	it("does not relax may_act for an actor token naming another client under the opt-out", async () => {
		const result = await delegate(
			{ aud: "resource-server", may_act: { sub: "svc-b" } },
			client({ allowExchangeOfTokensIssuedToOthers: true }),
			{ aud: "other-api", azp: "web-app" },
		);
		expect(result).toMatchObject({
			status: 400,
			errorDescription: "may_act_violation: actor not authorized by subject token",
		});
	});
});
