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

import {
	type AppHandle,
	type ClientRepository,
	createApp,
	defaultRefreshTokenFamilyRevocationModule,
	defineModule,
	type GrantContext,
	type GrantHandler,
	type Module,
	memoryRefreshTokenFamilyStoreModule,
	type PublicClient,
	type RefreshTokenFamilyRevocation,
} from "@o3co/auth-provider-core";
import { makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import { decodeJwt } from "jose";
import { afterEach, describe, expect, it } from "vitest";
import { createTokenExchangeGrant, TOKEN_EXCHANGE_GRANT_TYPE } from "#/grant.mjs";
import { tokenExchangeModule } from "#/module.mjs";
import { ExchangeTokenValidatorRegistry } from "#/validator/registry.mjs";
import { createSelfIssuedAccessTokenValidator } from "#/validator/selfIssuedAccessToken.mjs";
import { ISSUER, keyStore, signSelfIssuedAccessToken } from "./fixtures.mjs";

const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

const client: PublicClient = {
	clientId: "client-a",
	tokenEndpointAuthMethod: "none",
	allowedRedirectUris: [],
	allowedScopes: ["read", "write"],
	allowedAudiences: ["billing"],
	// #326: the exchange grant denies by absence of `allowedGrantTypes`.
	allowedGrantTypes: [TOKEN_EXCHANGE_GRANT_TYPE],
	backchannelLogoutSessionRequired: true,
	frontchannelLogoutSessionRequired: true,
	allowedAzpForFederationToken: false,
};

const clientRepository: ClientRepository = {
	findById: async (id) => (id === client.clientId ? client : null),
	authenticate: async (id) => (id === client.clientId ? client : null),
};

// In-memory family revocation slot preserving state between calls, so we can
// revoke then re-exchange and observe the cascade.
function makeStatefulStore(): RefreshTokenFamilyRevocation & { revokedFamilies: Set<string> } {
	const revoked = new Set<string>();
	return {
		revokedFamilies: revoked,
		async isFamilyRevoked(familyId) {
			return revoked.has(familyId);
		},
		async revokeFamily(familyId) {
			revoked.add(familyId);
		},
	};
}

function buildHandler(store: RefreshTokenFamilyRevocation) {
	const registry = new ExchangeTokenValidatorRegistry();
	// Validator has no refreshTokenFamilyRevocation so it returns a ValidatedToken with
	// familyId set. The grant handler's re-surface block then consults
	// deps.refreshTokenFamilyRevocation and emits the family_revoked errorDescription.
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
	// ExchangeTokenValidatorRegistry is structurally compatible with
	// TokenExchangeValidatorResolver (both expose .get); A2-γ §3.3 removed
	// the registry from the public surface but the class remains for
	// test scaffolding.
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
		refreshTokenFamilyRevocation: store,
		tokenExchangeValidatorResolver: registry,
		clientRepository,
	});
}

const ctx = (body: Record<string, unknown>): GrantContext => ({
	body,
	session: {},
	issuer: ISSUER,
	metadata: {},
	// The client is resolved from the body here; the grant reads a `null`
	// and an absent `authenticatedClient` the same way.
	authenticatedClient: null,
});

describe("token_exchange — integration", () => {
	it("exchanges a subject access_token for a narrower audience access_token", async () => {
		const store = makeStatefulStore();
		const handler = buildHandler(store);
		const subjectToken = await signSelfIssuedAccessToken({
			family_id: "fam-1",
			scope: "read write",
			aud: "billing",
		});

		const { result } = await handler.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: subjectToken,
				subject_token_type: ACCESS_TOKEN_TYPE,
				audience: "billing",
				scope: "read",
			}),
		);

		expect(result.status).toBe(200);
		// Both `GrantResult` members carry `status`, so only the field narrows.
		if (!("tokens" in result)) return;
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
				client_secret: "any",
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
				client_secret: "any",
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

	it("registers token_exchange grant + access_token validator via createTestApp boot", async () => {
		// Guard against drift between the defineModule manifest and the grant
		// handler. Per A2-γ §3.3: tokenExchangeModule is a static defineModule
		// value; addModule is replaced by createTestApp boot. The built-in
		// validator contribution flows through the planner's
		// tokenExchangeValidators collector and is read back via deps.
		const { defineModule } = await import("@o3co/auth-provider-core");
		const { createTestApp, makeValidAppConfig } = await import("@o3co/auth-provider-core/testing");
		const { tokenExchangeModule } = await import("#/module.mjs");

		const clientRepositoryModule = defineModule({
			name: "test:client-repository",
			provides: { clientRepository: () => clientRepository },
		});
		const keyStoreModule = defineModule({
			name: "test:key-store",
			provides: { keyStore: () => keyStore },
		});

		const base = makeValidAppConfig();
		const config = {
			...base,
			oauth: {
				...base.oauth,
				jwt: { ...base.oauth.jwt, issuer: ISSUER },
				// #367 enrolled this module in the #277 boot guard by declaring
				// `accessTokenDenylist` in its optional keys, and #406 did the
				// same for `subjectRevocation`. This composition wires neither
				// and is not about revocation, so it declares both capabilities
				// absent — loudly, which is the point.
				revocation: { accessToken: "unsupported" as const, subject: "unsupported" as const },
			},
		};

		const handle = await createTestApp({
			modules: [tokenExchangeModule, clientRepositoryModule, keyStoreModule],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});

		expect(handle.inspect.grants.has(TOKEN_EXCHANGE_GRANT_TYPE)).toBe(true);
		expect(handle.inspect.tokenExchangeValidators.get(ACCESS_TOKEN_TYPE)).toBeDefined();

		await handle.dispose();
	});

	it("declares a configSchema for boot-time config validation", async () => {
		const { tokenExchangeModule } = await import("#/module.mjs");
		expect(tokenExchangeModule.configSchema).toBeDefined();
	});

	it("fails boot with config-validation-failed when oauth.jwt.issuer is missing", async () => {
		const { BootError, defineModule } = await import("@o3co/auth-provider-core");
		const { createTestApp, makeValidAppConfig } = await import("@o3co/auth-provider-core/testing");
		const { tokenExchangeModule } = await import("#/module.mjs");

		const clientRepositoryModule = defineModule({
			name: "test:client-repository",
			provides: { clientRepository: () => clientRepository },
		});
		const keyStoreModule = defineModule({
			name: "test:key-store",
			provides: { keyStore: () => keyStore },
		});

		// The fixture carries an issuer (required since auth.provider#266), so strip
		// it here to reach the state this test is about.
		const config = makeValidAppConfig();
		delete (config.oauth.jwt as { issuer?: unknown }).issuer;
		await expect(
			createTestApp({
				modules: [tokenExchangeModule, clientRepositoryModule, keyStoreModule],
				bootstrapComponents: { config, pathResolver: (s) => s },
			}),
		).rejects.toMatchObject({
			name: "BootError",
			reason: "config-validation-failed",
		} satisfies Partial<InstanceType<typeof BootError>>);
	});

	// Boot planner only injects keys listed in `requires` ∪ `optional` into
	// contribution-factory `deps`. Both the grant handler (`grant.mts:212-266`,
	// family_revoked re-surface) and the built-in self-issued validator
	// (`module.mts:68`, family revocation check) read `deps.refreshTokenFamilyRevocation`.
	// Without declaring it here, a composition root that wires the store
	// will have it silently dropped: family-revocation observability turns
	// off, and self-issued exchanges that carry a `family_id` are rejected
	// as if the store were absent. RFC 8693 §7.2 state 1 requirement.
	it("declares refreshTokenFamilyRevocation in optional so the family-revocation path receives it", async () => {
		const { tokenExchangeModule } = await import("#/module.mjs");
		expect(tokenExchangeModule.optional).toContain("refreshTokenFamilyRevocation");
	});

	// Symmetric to the refreshTokenFamilyRevocation guard above. The token-exchange grant
	// reads `deps.grantPolicy` at grant.mts:339,362 to enforce CP-18 fail-
	// closed policy decisions on exchange requests. Other OAuth grants
	// (createAuthorizationGrant / createRefreshTokenGrant) declare grantPolicy
	// in oauthAuthorizationModule.optional; without declaring it here as well,
	// token-exchange would silently sit outside the policy gate while sibling
	// grants are enforced — a structural inconsistency in CP-18 coverage.
	it("declares grantPolicy in optional so CP-18 enforcement reaches token-exchange", async () => {
		const { tokenExchangeModule } = await import("#/module.mjs");
		expect(tokenExchangeModule.optional).toContain("grantPolicy");
	});
});

// The deployment the README's "Register the grant" section documents, booted
// for real: `tokenExchangeModule` beside core's memory refresh-token family
// store and its default revocation wrapper, through core's `createApp`. The
// handler is the one the boot planner puts in `grantHandlerResolver` — the
// resolver `/oauth/token` dispatches through — invoked the way dispatch
// invokes it, after client authentication has set `authenticatedClient`.
// Nothing here is hand-wired: whether the validator or the grant reads
// `refreshTokenFamilyRevocation` is decided by the module's own manifest, so
// these tests see the answer a deployment returns.
describe("tokenExchangeModule booted through createApp — refresh-token family revocation", () => {
	const authenticatedClient: NonNullable<GrantContext["authenticatedClient"]> = {
		clientId: client.clientId,
		tokenEndpointAuthMethod: "client_secret_basic",
		allowedScopes: client.allowedScopes,
		allowedGrantTypes: client.allowedGrantTypes,
	};
	const confidentialClientRepository: ClientRepository = {
		findById: async (id) =>
			id === client.clientId ? { ...client, tokenEndpointAuthMethod: "client_secret_basic" } : null,
		authenticate: async () => null,
	};

	let handle: AppHandle | undefined;
	afterEach(async () => {
		await handle?.dispose();
		handle = undefined;
	});

	async function boot(familyModules: readonly Module[]) {
		const base = makeValidAppConfig();
		handle = await createApp({
			modules: [
				tokenExchangeModule,
				...familyModules,
				defineModule({
					name: "test:client-repository",
					provides: { clientRepository: () => confidentialClientRepository },
				}),
				defineModule({ name: "test:key-store", provides: { keyStore: () => keyStore } }),
			],
			bootstrapComponents: {
				config: {
					...base,
					oauth: {
						...base.oauth,
						jwt: { ...base.oauth.jwt, issuer: ISSUER },
						// Not about the denylist or the subject watermark: both
						// declared absent, as the manifest test above does.
						revocation: { accessToken: "unsupported" as const, subject: "unsupported" as const },
					},
				},
				pathResolver: (s: string) => s,
			},
		});
		const grant: GrantHandler | undefined =
			handle.components.grantHandlerResolver?.get(TOKEN_EXCHANGE_GRANT_TYPE);
		if (!grant) throw new Error("the boot did not register the token-exchange grant");
		return { grant, components: handle.components };
	}

	const exchange = (grant: GrantHandler, body: Record<string, unknown>) =>
		grant.handle({ body, session: {}, issuer: ISSUER, metadata: {}, authenticatedClient });

	async function liveFamily(components: AppHandle["components"], familyId: string): Promise<void> {
		const store = components.refreshTokenFamilyStore;
		if (!store) throw new Error("the boot did not provide refreshTokenFamilyStore");
		await store.registerFamily({
			familyId,
			activeJti: `rt-${familyId}`,
			revoked: false,
			expiresAtMs: Date.now() + 3_600_000,
		});
	}

	async function revoke(components: AppHandle["components"], familyId: string): Promise<void> {
		const revocation = components.refreshTokenFamilyRevocation;
		if (!revocation) throw new Error("the boot did not provide refreshTokenFamilyRevocation");
		await revocation.revokeFamily(familyId);
	}

	it("answers invalid_grant / family_revoked for a subject_token whose family was revoked", async () => {
		const { grant, components } = await boot([
			memoryRefreshTokenFamilyStoreModule,
			defaultRefreshTokenFamilyRevocationModule,
		]);
		await liveFamily(components, "fam-subject");
		const subjectToken = await signSelfIssuedAccessToken({ family_id: "fam-subject" });
		const body = { subject_token: subjectToken, subject_token_type: ACCESS_TOKEN_TYPE };

		// While the family is live the token is exchangeable — the family store
		// is wired, so the family can be read.
		expect((await exchange(grant, body)).result.status).toBe(200);

		// Logout revokes the family; the same subject_token is now refused, and
		// the answer names why.
		await revoke(components, "fam-subject");
		expect((await exchange(grant, body)).result).toMatchObject({
			status: 400,
			error: "invalid_grant",
			errorDescription: "family_revoked",
		});
	});

	it("answers invalid_grant / actor_token family_revoked for an actor_token whose family was revoked", async () => {
		const { grant, components } = await boot([
			memoryRefreshTokenFamilyStoreModule,
			defaultRefreshTokenFamilyRevocationModule,
		]);
		await liveFamily(components, "fam-subject");
		await liveFamily(components, "fam-actor");
		const body = {
			subject_token: await signSelfIssuedAccessToken({ family_id: "fam-subject" }),
			subject_token_type: ACCESS_TOKEN_TYPE,
			actor_token: await signSelfIssuedAccessToken({ sub: "svc-a", family_id: "fam-actor" }),
			actor_token_type: ACCESS_TOKEN_TYPE,
		};

		expect((await exchange(grant, body)).result.status).toBe(200);

		// The actor's identity is folded into the issued token's `act` claim, so
		// a revoked actor credential is refused exactly as a revoked subject is.
		await revoke(components, "fam-actor");
		expect((await exchange(grant, body)).result).toMatchObject({
			status: 400,
			error: "invalid_grant",
			errorDescription: "actor_token family_revoked",
		});
	});

	it("refuses a family-bearing subject_token when no refreshTokenFamilyRevocation is wired", async () => {
		const { grant } = await boot([]);
		const { result } = await exchange(grant, {
			subject_token: await signSelfIssuedAccessToken({ family_id: "fam-subject" }),
			subject_token_type: ACCESS_TOKEN_TYPE,
		});
		expect(result).toMatchObject({
			status: 400,
			error: "invalid_grant",
			errorDescription:
				"refresh token family revocation not configured (revocation cannot be verified)",
		});
	});

	it("refuses a family-bearing actor_token when no refreshTokenFamilyRevocation is wired", async () => {
		const { grant } = await boot([]);
		// A subject without `family_id` (a client_credentials token, say) passes
		// the subject's family rule, so the refusal below is the actor's.
		const { result } = await exchange(grant, {
			subject_token: await signSelfIssuedAccessToken({}),
			subject_token_type: ACCESS_TOKEN_TYPE,
			actor_token: await signSelfIssuedAccessToken({ sub: "svc-a", family_id: "fam-actor" }),
			actor_token_type: ACCESS_TOKEN_TYPE,
		});
		expect(result).toMatchObject({
			status: 400,
			error: "invalid_grant",
			errorDescription:
				"refresh token family revocation not configured (revocation cannot be verified)",
		});
	});
});

describe("absence policy (#375)", () => {
	it("carries the shared ACCESS_TOKEN_DENYLIST_ABSENCE_POLICY constant, by identity", async () => {
		// Identity, not shape: the declared-absence guard refuses modules whose
		// policies for one key disagree; sharing oauthModule's constant makes
		// disagreement impossible by construction.
		const { ACCESS_TOKEN_DENYLIST_ABSENCE_POLICY } = await import("@o3co/auth-provider-core");
		const { tokenExchangeModule } = await import("#/module.mjs");
		expect(tokenExchangeModule.absencePolicies?.accessTokenDenylist).toBe(
			ACCESS_TOKEN_DENYLIST_ABSENCE_POLICY,
		);
	});
});
