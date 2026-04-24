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
	ClientRepository,
	GrantContext,
	PublicClient,
	RefreshTokenStoreBase,
} from "@o3co/auth-provider-core";
import { decodeJwt } from "jose";
import { describe, expect, it } from "vitest";
import { createTokenExchangeGrant, TOKEN_EXCHANGE_GRANT_TYPE } from "#/grant.mjs";
import { ExchangeTokenValidatorRegistry } from "#/validator/registry.mjs";
import { createSelfIssuedAccessTokenValidator } from "#/validator/selfIssuedAccessToken.mjs";
import { ISSUER, keyStore, signSelfIssuedAccessToken } from "./fixtures.mjs";

const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

const client: PublicClient = {
	clientId: "client-a",
	allowedRedirectUris: [],
	allowedScopes: ["read", "write"],
	allowedAudiences: ["billing"],
	backchannelLogoutSessionRequired: true,
	frontchannelLogoutSessionRequired: true,
	allowedAzpForFederationToken: false,
};

const clientRepository: ClientRepository = {
	findById: async (id) => (id === client.clientId ? client : null),
	authenticate: async (id) => (id === client.clientId ? client : null),
};

// In-memory refresh token store preserving family revocation state between
// calls, so we can revoke then re-exchange and observe the cascade.
function makeStatefulStore(): RefreshTokenStoreBase & { revokedFamilies: Set<string> } {
	const revoked = new Set<string>();
	return {
		kind: "stateful-fixture",
		revokedFamilies: revoked,
		async rotate() {
			return { outcome: "rotated" };
		},
		async isFamilyRevoked(familyId) {
			return revoked.has(familyId);
		},
		async revokeFamily(familyId) {
			revoked.add(familyId);
		},
	};
}

function buildHandler(store: RefreshTokenStoreBase) {
	const registry = new ExchangeTokenValidatorRegistry();
	// Validator has no refreshTokenStore so it returns a ValidatedToken with
	// familyId set. The grant handler's re-surface block then consults
	// deps.refreshTokenStore and emits the family_revoked errorDescription.
	// This matches the unit-test pattern (validatorRefreshStore: null) and is
	// required for the cascade test to observe "family_revoked" vs the opaque
	// "subject_token validation failed" that would result if the validator
	// absorbed the revocation check itself.
	registry.register(
		ACCESS_TOKEN_TYPE,
		createSelfIssuedAccessTokenValidator({
			keyStore,
			issuer: ISSUER,
		}),
	);
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
		refreshTokenStore: store,
		validatorRegistry: registry,
		clientRepository,
	});
}

const ctx = (body: Record<string, unknown>): GrantContext => ({
	body,
	session: {},
	issuer: ISSUER,
	metadata: {},
});

describe("token_exchange — integration", () => {
	it("exchanges a subject access_token for a narrower audience access_token", async () => {
		const store = makeStatefulStore();
		const handler = buildHandler(store);
		const subjectToken = await signSelfIssuedAccessToken({
			family_id: "fam-1",
			scope: "read write",
		});

		const { result } = await handler.handle(
			ctx({
				client_id: "client-a",
				subject_token: subjectToken,
				subject_token_type: ACCESS_TOKEN_TYPE,
				audience: "billing",
				scope: "read",
			}),
		);

		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.aud).toBe("billing");
		expect(payload.scope).toBe("read");
		expect(payload.family_id).toBe("fam-1");
		expect(payload.sub).toBe("user-1");
	});

	it("rejects exchange after the subject family is revoked (cascade)", async () => {
		const store = makeStatefulStore();
		const handler = buildHandler(store);
		const subjectToken = await signSelfIssuedAccessToken({ family_id: "fam-cascade" });

		// First exchange succeeds.
		const ok = await handler.handle(
			ctx({
				client_id: "client-a",
				subject_token: subjectToken,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(ok.result.status).toBe(200);

		// Revoke the family (simulating a logout).
		await store.revokeFamily("fam-cascade");

		// Second exchange with the same subject must now fail.
		const denied = await handler.handle(
			ctx({
				client_id: "client-a",
				subject_token: subjectToken,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(denied.result).toMatchObject({
			status: 400,
			error: "invalid_grant",
			errorDescription: "family_revoked",
		});
	});

	it("registers successfully via GrantRegistry.addModule", async () => {
		// Guard against drift between the GrantModule wiring and the grant handler.
		const { GrantRegistry } = await import("@o3co/auth-provider-core");
		const { tokenExchangeModule } = await import("#/module.mjs");
		const store = makeStatefulStore();
		const registry = new ExchangeTokenValidatorRegistry();
		registry.register(
			ACCESS_TOKEN_TYPE,
			createSelfIssuedAccessTokenValidator({
				keyStore,
				refreshTokenStore: store,
				issuer: ISSUER,
			}),
		);

		const grantRegistry = new GrantRegistry();
		grantRegistry.addModule(tokenExchangeModule, {
			config: {
				oauth: {
					jwt: { issuer: ISSUER },
					accessToken: { expiresIn: 300 },
					refreshToken: { expiresIn: 86400 },
					grants: {},
				},
				// biome-ignore lint/suspicious/noExplicitAny: test scaffold
			} as any,
			keyStore,
			refreshTokenStore: store,
			validatorRegistry: registry,
			clientRepository,
			// biome-ignore lint/suspicious/noExplicitAny: extra deps beyond GrantDependencies base type
		} as any);

		const handler = grantRegistry.get(TOKEN_EXCHANGE_GRANT_TYPE);
		expect(handler).toBeDefined();
	});
});
