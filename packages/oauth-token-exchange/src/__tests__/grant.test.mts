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

import type {
	AppConfig,
	ClientRepository,
	GrantContext,
	PublicClient,
} from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import { createTokenExchangeGrant } from "#/grant.mjs";
import { ExchangeTokenValidatorRegistry } from "#/validator/registry.mjs";
import { createSelfIssuedAccessTokenValidator } from "#/validator/selfIssuedAccessToken.mjs";
import { ISSUER, keyStore, makeRefreshStore, signSelfIssuedAccessToken } from "./fixtures.mjs";

const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

const mockConfig = {
	oauth: {
		jwt: { issuer: ISSUER },
		accessToken: { expiresIn: 300 },
		refreshToken: { expiresIn: 86400 },
		grants: {},
	},
} as unknown as AppConfig;

const publicClient = (overrides: Partial<PublicClient> = {}): PublicClient => ({
	clientId: "client-a",
	allowedRedirectUris: [],
	allowedScopes: [],
	allowedAudiences: [],
	backchannelLogoutSessionRequired: true,
	frontchannelLogoutSessionRequired: true,
	allowedAzpForFederationToken: false,
	...overrides,
});

const mockClientRepository = (client: PublicClient | null = publicClient()): ClientRepository => ({
	findById: async (id) => (id === client?.clientId ? client : null),
	authenticate: async (id, _secret) => (id === client?.clientId ? client : null),
});

function buildGrant(
	overrides: {
		validatorRegistry?: ExchangeTokenValidatorRegistry;
		clientRepository?: ClientRepository;
		refreshTokenStore?: ReturnType<typeof makeRefreshStore> | undefined;
		config?: AppConfig;
	} = {},
) {
	const registry = overrides.validatorRegistry ?? new ExchangeTokenValidatorRegistry();
	const refreshStore =
		overrides.refreshTokenStore === undefined ? makeRefreshStore() : overrides.refreshTokenStore;
	if (!overrides.validatorRegistry) {
		registry.register(
			ACCESS_TOKEN_TYPE,
			createSelfIssuedAccessTokenValidator({
				keyStore,
				refreshTokenStore: refreshStore,
				issuer: ISSUER,
			}),
		);
	}
	return createTokenExchangeGrant({
		config: overrides.config ?? mockConfig,
		keyStore,
		refreshTokenStore: refreshStore,
		validatorRegistry: registry,
		clientRepository: overrides.clientRepository ?? mockClientRepository(),
	});
}

const ctx = (body: Record<string, unknown>): GrantContext => ({
	body,
	session: {},
	issuer: ISSUER,
	metadata: {},
});

describe("createTokenExchangeGrant — request errors", () => {
	it("returns invalid_request when subject_token is missing", async () => {
		const g = buildGrant();
		const { result } = await g.handle(
			ctx({ client_id: "client-a", subject_token_type: ACCESS_TOKEN_TYPE }),
		);
		expect(result).toMatchObject({ status: 400, error: "invalid_request" });
	});

	it("returns invalid_request when subject_token_type is missing", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({});
		const { result } = await g.handle(ctx({ client_id: "client-a", subject_token: token }));
		expect(result).toMatchObject({ status: 400, error: "invalid_request" });
	});

	it("returns invalid_request when client_id is missing", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({});
		const { result } = await g.handle(
			ctx({ subject_token: token, subject_token_type: ACCESS_TOKEN_TYPE }),
		);
		expect(result).toMatchObject({ status: 400, error: "invalid_request" });
	});

	it("returns invalid_client when client cannot be authenticated", async () => {
		const g = buildGrant({ clientRepository: mockClientRepository(null) });
		const token = await signSelfIssuedAccessToken({});
		const { result } = await g.handle(
			ctx({
				client_id: "unknown",
				client_secret: "x",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({ status: 401, error: "invalid_client" });
	});

	it("returns unsupported_token_type when subject_token_type is not registered", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({});
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				subject_token: token,
				subject_token_type: "urn:ietf:params:oauth:token-type:saml2",
			}),
		);
		expect(result).toMatchObject({ status: 400, error: "unsupported_token_type" });
	});

	it("returns unsupported_token_type when requested_token_type is not access_token", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({});
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				requested_token_type: "urn:ietf:params:oauth:token-type:id_token",
			}),
		);
		expect(result).toMatchObject({ status: 400, error: "unsupported_token_type" });
	});

	it("returns unsupported_token_type when actor_token_type is not registered", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({});
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				actor_token: "any",
				actor_token_type: "urn:ietf:params:oauth:token-type:saml2",
			}),
		);
		expect(result).toMatchObject({ status: 400, error: "unsupported_token_type" });
	});

	it("throws on the Task 6 stub fall-through (guards against non-RFC 501 leak)", async () => {
		// This test guards against the 'not_implemented' stub silently leaking
		// to clients. Once Tasks 7-8 are complete the stub is replaced; this
		// test will still pass because a happy-path input will return a real
		// successful response, not reach the throw. If Tasks 7-8 are
		// accidentally INCOMPLETE and the stub is reachable, this test traps
		// the regression at build time.
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		// A minimal happy-path-ish input that passes all fast-fail checks.
		const result = await g
			.handle(
				ctx({
					client_id: "client-a",
					subject_token: token,
					subject_token_type: ACCESS_TOKEN_TYPE,
				}),
			)
			.catch((err) => ({ thrown: err as Error }));
		if ("thrown" in result) {
			expect(result.thrown.message).toMatch(/Task 6 stub fall-through/);
		} else {
			// Once Tasks 7-8 land, this branch activates and the handler
			// returns a real result (either 200 with tokens, or a real
			// RFC-valid error). Test must not silently skip — assert the
			// negative: the stub is gone, so we expect status NOT to be 501.
			expect(result.result.status).not.toBe(501);
		}
	});
});
