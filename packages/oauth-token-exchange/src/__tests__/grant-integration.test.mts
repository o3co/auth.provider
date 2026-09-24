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
	type GrantPolicyDecision,
	type GrantPolicyRequest,
	type Module,
	memoryRefreshTokenFamilyStoreModule,
	type PublicClient,
	type RefreshTokenFamilyRevocation,
	type TokenBinding,
} from "@o3co/auth-provider-core";
import { makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import { decodeJwt } from "jose";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createTokenExchangeGrant, TOKEN_EXCHANGE_GRANT_TYPE } from "#/grant.mjs";
import { tokenExchangeModule } from "#/module.mjs";
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
	// The validator projects `familyId` and the grant checks it against
	// `refreshTokenFamilyRevocation` — the same split `tokenExchangeModule`
	// wires, which the createApp suite below boots for real. The resolver the
	// grant reads is `get` alone, which a Map provides.
	const validators = new Map([
		[ACCESS_TOKEN_TYPE, createSelfIssuedAccessTokenValidator({ keyStore, issuer: ISSUER })],
	]);
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
		tokenExchangeValidatorResolver: validators,
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
			error: "invalid_request",
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
	// contribution-factory `deps`. The grant handler reads
	// `deps.refreshTokenFamilyRevocation` for its family rule (`familyRefusal`
	// in grant.mts). Without declaring it here, a composition root that wires
	// the store would have it silently dropped, and every self-issued exchange
	// carrying a `family_id` would be refused as if the store were absent.
	it("declares refreshTokenFamilyRevocation in optional so the family-revocation path receives it", async () => {
		const { tokenExchangeModule } = await import("#/module.mjs");
		expect(tokenExchangeModule.optional).toContain("refreshTokenFamilyRevocation");
	});

	// Symmetric to the refreshTokenFamilyRevocation guard above. The token-exchange grant
	// reads `deps.grantPolicy` in grant.mts to enforce CP-18 fail-
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
// Nothing here is hand-wired: which revocation store the validator or the
// grant reads, and what each does when it cannot answer, is decided by the
// module's own manifest, so these tests see the answer a deployment returns.
describe("tokenExchangeModule booted through createApp — revocation", () => {
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

	type RevocationDeclaration = {
		readonly accessToken: "denylist" | "unsupported";
		readonly subject: "watermark" | "unsupported";
	};

	// `revocation` declares which of the denylist and the subject watermark a
	// test leaves unwired (the #277 / #406 boot guard); by default both.
	async function boot(
		modules: readonly Module[],
		revocation: RevocationDeclaration = { accessToken: "unsupported", subject: "unsupported" },
	) {
		const base = makeValidAppConfig();
		handle = await createApp({
			modules: [
				tokenExchangeModule,
				...modules,
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
						revocation,
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

	const exchange = (
		grant: GrantHandler,
		body: Record<string, unknown>,
		tokenBinding?: TokenBinding,
	) =>
		grant.handle({
			body,
			session: {},
			issuer: ISSUER,
			metadata: {},
			authenticatedClient,
			...(tokenBinding ? { tokenBinding } : {}),
		});

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

	it("answers invalid_request / family_revoked for a subject_token whose family was revoked", async () => {
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
			error: "invalid_request",
			errorDescription: "family_revoked",
		});
	});

	it("answers invalid_request / actor_token family_revoked for an actor_token whose family was revoked", async () => {
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
			error: "invalid_request",
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
			error: "invalid_request",
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
			error: "invalid_request",
			errorDescription:
				"actor_token refresh token family revocation not configured (revocation cannot be verified)",
		});
	});

	// The family rule keys on the family a validator asserts, not on the token
	// type it was registered for: the issued token inherits the subject's
	// `family_id` whichever validator produced it. Here the built-in validator
	// is registered a second time, under the `jwt` token type, the way a
	// composition accepting its own access tokens under that type would.
	describe("a validator registered for another token type that asserts a family", () => {
		const JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";
		const selfIssuedAsJwt = defineModule({
			name: "test:self-issued-as-jwt",
			requires: ["keyStore"],
			contributes: {
				tokenExchangeValidators: {
					[JWT_TOKEN_TYPE]: (deps) =>
						createSelfIssuedAccessTokenValidator({ keyStore: deps.keyStore, issuer: ISSUER }),
				},
			},
		});

		it("answers invalid_request / family_revoked once the family is revoked", async () => {
			const { grant, components } = await boot([
				memoryRefreshTokenFamilyStoreModule,
				defaultRefreshTokenFamilyRevocationModule,
				selfIssuedAsJwt,
			]);
			await liveFamily(components, "fam-jwt");
			const body = {
				subject_token: await signSelfIssuedAccessToken({ family_id: "fam-jwt" }),
				subject_token_type: JWT_TOKEN_TYPE,
			};
			expect((await exchange(grant, body)).result.status).toBe(200);

			await revoke(components, "fam-jwt");
			expect((await exchange(grant, body)).result).toMatchObject({
				status: 400,
				error: "invalid_request",
				errorDescription: "family_revoked",
			});
		});

		it("refuses the family-bearing token when no refreshTokenFamilyRevocation is wired", async () => {
			const { grant } = await boot([selfIssuedAsJwt]);
			const { result } = await exchange(grant, {
				subject_token: await signSelfIssuedAccessToken({ family_id: "fam-jwt" }),
				subject_token_type: JWT_TOKEN_TYPE,
			});
			expect(result).toMatchObject({
				status: 400,
				error: "invalid_request",
				errorDescription:
					"refresh token family revocation not configured (revocation cannot be verified)",
			});
		});

		// The actor half: the actor_token goes through the same rule whatever
		// actor_token_type named its validator.
		it("answers actor_token family_revoked for an actor_token of that type once its family is revoked", async () => {
			const { grant, components } = await boot([
				memoryRefreshTokenFamilyStoreModule,
				defaultRefreshTokenFamilyRevocationModule,
				selfIssuedAsJwt,
			]);
			await liveFamily(components, "fam-subject");
			await liveFamily(components, "fam-actor-jwt");
			const body = {
				subject_token: await signSelfIssuedAccessToken({ family_id: "fam-subject" }),
				subject_token_type: ACCESS_TOKEN_TYPE,
				actor_token: await signSelfIssuedAccessToken({ sub: "svc-a", family_id: "fam-actor-jwt" }),
				actor_token_type: JWT_TOKEN_TYPE,
			};
			expect((await exchange(grant, body)).result.status).toBe(200);

			await revoke(components, "fam-actor-jwt");
			expect((await exchange(grant, body)).result).toMatchObject({
				status: 400,
				error: "invalid_request",
				errorDescription: "actor_token family_revoked",
			});
		});

		it("refuses a family-bearing actor_token of that type when no refreshTokenFamilyRevocation is wired", async () => {
			const { grant } = await boot([selfIssuedAsJwt]);
			const { result } = await exchange(grant, {
				subject_token: await signSelfIssuedAccessToken({}),
				subject_token_type: ACCESS_TOKEN_TYPE,
				actor_token: await signSelfIssuedAccessToken({ sub: "svc-a", family_id: "fam-actor-jwt" }),
				actor_token_type: JWT_TOKEN_TYPE,
			});
			expect(result).toMatchObject({
				status: 400,
				error: "invalid_request",
				errorDescription:
					"actor_token refresh token family revocation not configured (revocation cannot be verified)",
			});
		});

		// An empty `familyId` names no family: there is nothing to check, and
		// nothing for the issued token to inherit — not a `family_id: ""` that
		// no revocation could ever reach.
		it("treats an empty familyId as no family: nothing checked, nothing inherited", async () => {
			const EMPTY_FAMILY_TOKEN_TYPE = "urn:example:params:oauth:token-type:empty-family";
			const { grant } = await boot([
				defineModule({
					name: "test:empty-family-validator",
					contributes: {
						tokenExchangeValidators: {
							[EMPTY_FAMILY_TOKEN_TYPE]: () => ({
								validate: async () => ({
									sub: "user-1",
									claims: { sub: "user-1", family_id: "" },
									familyId: "",
								}),
							}),
						},
					},
				}),
			]);
			const { result } = await exchange(grant, {
				subject_token: "opaque-subject-token",
				subject_token_type: EMPTY_FAMILY_TOKEN_TYPE,
			});
			expect(result.status).toBe(200);
			if (!("tokens" in result)) return;
			expect(decodeJwt(result.tokens.access_token)).not.toHaveProperty("family_id");
		});
	});

	// RFC 8693 §2.2.2: "If the request itself is not valid or if either the
	// subject_token or actor_token are invalid for any reason, or are
	// unacceptable based on policy, the authorization server MUST construct an
	// error response [...] The value of the error parameter MUST be the
	// invalid_request error code." Every refusal of a presented token is
	// therefore `invalid_request`, whichever check made it; the description is
	// what tells a client which check that was, so each one is pinned exactly.
	// The family refusals of note 1 are pinned by the tests above, the
	// denylisted token by the store-outage suite below.
	describe("RFC 8693 §2.2.2: a refused subject_token or actor_token is invalid_request", () => {
		const JKT = "L0AXB6c64d2QW3rhCLLADhOMLf_7u2eTGH-q9ZGja24";
		const OTHER_JKT = "ZmFrZS1qa3QtdGhhdC1pcy1ub3QtdGhlLXNhbWUtdmFsdWU";
		const X5T = "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2";
		const OTHER_X5T = "ZmFrZS10aHVtYnByaW50LXRoYXQtaXMtbm90LXRoZS1zYW1l";
		const dpop = (jkt: string): TokenBinding => ({ kind: "dpop", confirmation: { jkt } });
		const mtls = (x5t: string): TokenBinding => ({
			kind: "mtls",
			confirmation: { "x5t#S256": x5t },
		});
		const tampered = async (claims: Record<string, unknown>) =>
			`${(await signSelfIssuedAccessToken(claims)).slice(0, -4)}AAAA`;

		// A validator of the deployment's own that accepts a token with no
		// lifetime left: the built-in validator never does (jose refuses an
		// expired token first), so the grant's own expiry check is reached
		// only through one.
		const EXPIRED_TOKEN_TYPE = "urn:example:params:oauth:token-type:expired";
		const expiredValidatorModule = defineModule({
			name: "test:expired-token-validator",
			contributes: {
				tokenExchangeValidators: {
					[EXPIRED_TOKEN_TYPE]: () => ({
						validate: async () => ({
							sub: "user-1",
							claims: { sub: "user-1", exp: Math.floor(Date.now() / 1000) - 30 },
						}),
					}),
				},
			},
		});

		const subject = async (claims: Record<string, unknown> = {}) => ({
			subject_token: await signSelfIssuedAccessToken(claims),
			subject_token_type: ACCESS_TOKEN_TYPE,
		});
		const withActor = async (actorToken: string) => ({
			...(await subject()),
			actor_token: actorToken,
			actor_token_type: ACCESS_TOKEN_TYPE,
		});
		const actor = (claims: Record<string, unknown>) =>
			signSelfIssuedAccessToken({ sub: "svc-a", ...claims });

		const cases: ReadonlyArray<
			readonly [
				label: string,
				body: () => Promise<Record<string, unknown>>,
				tokenBinding: TokenBinding | undefined,
				errorDescription: string,
			]
		> = [
			[
				"a subject_token whose signature does not verify",
				async () => ({
					subject_token: await tampered({}),
					subject_token_type: ACCESS_TOKEN_TYPE,
				}),
				undefined,
				"subject_token validation failed",
			],
			[
				"a DPoP-bound subject_token with no proof",
				() => subject({ cnf: { jkt: JKT } }),
				undefined,
				"subject_token requires a DPoP proof",
			],
			[
				"a DPoP-bound subject_token with a proof from another key",
				() => subject({ cnf: { jkt: JKT } }),
				dpop(OTHER_JKT),
				"DPoP proof does not match subject_token binding",
			],
			[
				"a certificate-bound subject_token with no certificate",
				() => subject({ cnf: { "x5t#S256": X5T } }),
				undefined,
				"subject_token requires a client certificate",
			],
			[
				"a certificate-bound subject_token with another certificate",
				() => subject({ cnf: { "x5t#S256": X5T } }),
				mtls(OTHER_X5T),
				"client certificate does not match subject_token binding",
			],
			[
				"a subject_token carrying a compound cnf",
				() => subject({ cnf: { jkt: JKT, "x5t#S256": X5T } }),
				dpop(JKT),
				"subject_token has compound cnf binding which is not supported (Stage 1)",
			],
			[
				"a subject_token with no lifetime left",
				async () => ({ subject_token: "opaque", subject_token_type: EXPIRED_TOKEN_TYPE }),
				undefined,
				"subject_token has expired",
			],
			[
				"an actor_token whose signature does not verify",
				async () => withActor(await tampered({ sub: "svc-a" })),
				undefined,
				"actor_token validation failed",
			],
			[
				"a DPoP-bound actor_token with no proof",
				async () => withActor(await actor({ cnf: { jkt: JKT } })),
				undefined,
				"actor_token requires a DPoP proof",
			],
			[
				"a DPoP-bound actor_token with a proof from another key",
				async () => withActor(await actor({ cnf: { jkt: JKT } })),
				dpop(OTHER_JKT),
				"DPoP proof does not match actor_token binding",
			],
			[
				"a certificate-bound actor_token with no certificate",
				async () => withActor(await actor({ cnf: { "x5t#S256": X5T } })),
				undefined,
				"actor_token requires a client certificate",
			],
			[
				"a certificate-bound actor_token with another certificate",
				async () => withActor(await actor({ cnf: { "x5t#S256": X5T } })),
				mtls(OTHER_X5T),
				"client certificate does not match actor_token binding",
			],
			[
				"an actor_token carrying a compound cnf",
				async () => withActor(await actor({ cnf: { jkt: JKT, "x5t#S256": X5T } })),
				dpop(JKT),
				"actor_token has compound cnf binding which is not supported (Stage 1)",
			],
			[
				"a subject_token whose may_act does not name the actor_token's subject",
				async () => ({
					subject_token: await signSelfIssuedAccessToken({ may_act: { sub: "svc-b" } }),
					subject_token_type: ACCESS_TOKEN_TYPE,
					actor_token: await actor({}),
					actor_token_type: ACCESS_TOKEN_TYPE,
				}),
				undefined,
				"may_act_violation: actor not authorized by subject token",
			],
			[
				"a subject_token whose may_act does not name the calling client",
				() => subject({ may_act: { sub: "svc-b" } }),
				undefined,
				"may_act_violation: client not authorized by subject token",
			],
			[
				"an actor_token that would extend a full actor chain",
				async () => ({
					subject_token: await signSelfIssuedAccessToken({
						act: { sub: "svc-1", act: { sub: "svc-2", act: { sub: "svc-3" } } },
					}),
					subject_token_type: ACCESS_TOKEN_TYPE,
					actor_token: await actor({}),
					actor_token_type: ACCESS_TOKEN_TYPE,
				}),
				undefined,
				"actor_chain_too_deep: actor chain depth limit exceeded",
			],
		];

		it.each(cases)(
			"refuses %s with invalid_request",
			async (_label, body, tokenBinding, errorDescription) => {
				const { grant } = await boot([expiredValidatorModule]);
				const { result } = await exchange(grant, await body(), tokenBinding);
				expect(result).toEqual({ status: 400, error: "invalid_request", errorDescription });
			},
		);
	});

	// The request's other refusals, through the same boot. A token type the
	// deployment has no validator for, or a `requested_token_type` it cannot
	// issue, is RFC 6749 §5.2's `invalid_request` ("an unsupported parameter
	// value"): `unsupported_token_type` is RFC 7009's code for the revocation
	// endpoint, and RFC 8693 defines no token-type error of its own.
	describe("unsupported token types are invalid_request (RFC 6749 §5.2)", () => {
		const SAML2 = "urn:ietf:params:oauth:token-type:saml2";
		const cases: ReadonlyArray<
			readonly [label: string, body: () => Promise<Record<string, unknown>>, description: string]
		> = [
			[
				"a subject_token_type no validator is registered for",
				async () => ({ subject_token: "opaque", subject_token_type: SAML2 }),
				`subject_token_type '${SAML2}' is not supported`,
			],
			[
				"an actor_token_type no validator is registered for",
				async () => ({
					subject_token: await signSelfIssuedAccessToken({}),
					subject_token_type: ACCESS_TOKEN_TYPE,
					actor_token: "opaque",
					actor_token_type: SAML2,
				}),
				`actor_token_type '${SAML2}' is not supported`,
			],
			[
				"a requested_token_type other than access_token",
				async () => ({
					subject_token: await signSelfIssuedAccessToken({}),
					subject_token_type: ACCESS_TOKEN_TYPE,
					requested_token_type: "urn:ietf:params:oauth:token-type:refresh_token",
				}),
				"requested_token_type 'urn:ietf:params:oauth:token-type:refresh_token' is not supported",
			],
		];

		it.each(cases)("refuses %s with invalid_request", async (_label, body, errorDescription) => {
			const { grant } = await boot([]);
			const { result } = await exchange(grant, await body());
			expect(result).toEqual({ status: 400, error: "invalid_request", errorDescription });
		});
	});

	// Who asked for more decides the answer. The request's own `scope` past
	// the subject token is the caller's mistake, `invalid_scope` (RFC 6749
	// §5.2), and its own `audience` past it is RFC 8693 §2.2.2's
	// `invalid_target`; both are refused before the policy runs, so no policy
	// decision can turn them into anything else. A policy decision past the
	// exchange's ceilings is the deployment's, answered as every other grant
	// answers it: core's `policyOutOfBounds`. The client "client-a" is
	// registered for `allowedAudiences: ["billing"]` and
	// `allowedScopes: ["read", "write"]`.
	describe("scope and audience past the ceilings", () => {
		const policyModule = (
			evaluate: (request: GrantPolicyRequest) => Promise<{
				outcome: "allow";
				grantedScope?: readonly string[];
				grantedAudience?: readonly string[];
			}>,
		) =>
			defineModule({
				name: "test:grant-policy",
				provides: { grantPolicy: () => ({ kind: "test", evaluate }) },
			});
		const deciding = (decision: {
			readonly grantedScope?: readonly string[];
			readonly grantedAudience?: readonly string[];
		}) => policyModule(async () => ({ outcome: "allow", ...decision }));
		// A policy that hands the request back unchanged — the shape a
		// pass-through or logging policy has.
		const echoing = policyModule(async (request) => ({
			outcome: "allow",
			grantedScope: request.requestedScope,
			grantedAudience: request.requestedAudience,
		}));

		const logged = () => {
			const logger = {
				trace: vi.fn(),
				debug: vi.fn(),
				info: vi.fn(),
				warn: vi.fn(),
				error: vi.fn(),
				fatal: vi.fn(),
				child: () => logger,
			};
			return {
				logger,
				module: defineModule({ name: "test:logger", provides: { logger: () => logger } }),
				// This grant's own events; the central verifier logs its own
				// (`jwt_verify_aud_skipped`) on every exchange.
				events: () =>
					logger.warn.mock.calls
						.map((call) => call[1])
						.filter((event) => String(event).startsWith("token_exchange_")),
			};
		};

		const audienceWidening = {
			status: 400,
			error: "invalid_target",
			errorDescription: "audience_widening_not_allowed: billing",
		};

		it("answers invalid_scope when the request asks for a scope the subject_token does not carry", async () => {
			const { grant } = await boot([]);
			const { result } = await exchange(grant, {
				subject_token: await signSelfIssuedAccessToken({ scope: "read" }),
				subject_token_type: ACCESS_TOKEN_TYPE,
				scope: "read write",
			});
			expect(result).toEqual({
				status: 400,
				error: "invalid_scope",
				errorDescription: "scope 'write' is not in subject_token scope",
			});
		});

		// The request's scope and audience past the client's registration.
		// Descriptions quote the value with `'`: RFC 6749 §5.2 does not allow
		// `"` in an error_description.
		it("answers invalid_scope when the request asks for a scope the client is not registered for", async () => {
			const { grant } = await boot([]);
			const { result } = await exchange(grant, {
				subject_token: await signSelfIssuedAccessToken({ scope: "read admin" }),
				subject_token_type: ACCESS_TOKEN_TYPE,
				scope: "admin",
			});
			expect(result).toEqual({
				status: 400,
				error: "invalid_scope",
				errorDescription: "scope 'admin' is not allowed for this client",
			});
		});

		it("answers invalid_target when the request names an audience the client is not registered for", async () => {
			const { grant } = await boot([]);
			const { result } = await exchange(grant, {
				subject_token: await signSelfIssuedAccessToken({ aud: ["payments", "client-a"] }),
				subject_token_type: ACCESS_TOKEN_TYPE,
				audience: "payments",
			});
			expect(result).toEqual({
				status: 400,
				error: "invalid_target",
				errorDescription: "audience 'payments' is not allowed for this client",
			});
		});

		it("answers 500 server_error, and logs the policy's refusal, when the policy grants a scope the subject_token does not carry", async () => {
			const log = logged();
			const { grant } = await boot([deciding({ grantedScope: ["read", "write"] }), log.module]);
			const { result } = await exchange(grant, {
				subject_token: await signSelfIssuedAccessToken({ scope: "read" }),
				subject_token_type: ACCESS_TOKEN_TYPE,
			});
			expect(result).toEqual({
				status: 500,
				error: "server_error",
				errorDescription:
					"policy returned scopes exceeding the subject_token scope or client allowedScopes: write",
			});
			expect(log.events()).toEqual(["token_exchange_policy_scope_refused"]);
		});

		it("answers invalid_target, and logs the request's refusal, when the request names an audience the subject_token does not carry", async () => {
			const log = logged();
			const { grant } = await boot([log.module]);
			const { result } = await exchange(grant, {
				subject_token: await signSelfIssuedAccessToken({ aud: "client-a" }),
				subject_token_type: ACCESS_TOKEN_TYPE,
				audience: "billing",
			});
			expect(result).toEqual(audienceWidening);
			expect(log.events()).toEqual(["token_exchange_audience_widening_rejected"]);
		});

		// The request's audience is held to the subject token before the policy
		// runs, so what the policy then does with it cannot change the answer:
		// not echoing it back, not replacing it with an audience the subject
		// token does carry, and not widening the scope as well.
		it.each([
			["a policy that echoes the request back", echoing],
			[
				"a policy that replaces it with the subject_token's audience",
				deciding({ grantedAudience: ["client-a"] }),
			],
			["a policy that also widens the scope", deciding({ grantedScope: ["read", "admin"] })],
			["a policy that names no audience", deciding({})],
		])("still answers the request's invalid_target under %s", async (_label, policy) => {
			const { grant } = await boot([policy]);
			const { result } = await exchange(grant, {
				subject_token: await signSelfIssuedAccessToken({ aud: "client-a", scope: "read" }),
				subject_token_type: ACCESS_TOKEN_TYPE,
				audience: "billing",
			});
			expect(result).toEqual(audienceWidening);
		});

		// A policy's `grantedAudience` is held to what the subject token carries
		// AND what the client is registered for — `allowedAudiences` plus its
		// own client id — before it replaces the request's. The request's
		// audience meets both bounds too; the policy does not get a wider one.
		it("answers 500 server_error, and logs the policy's refusal, when the policy grants an audience the subject_token does not carry", async () => {
			const log = logged();
			const { grant } = await boot([deciding({ grantedAudience: ["billing"] }), log.module]);
			const { result } = await exchange(grant, {
				subject_token: await signSelfIssuedAccessToken({ aud: "client-a" }),
				subject_token_type: ACCESS_TOKEN_TYPE,
			});
			expect(result).toEqual({
				status: 500,
				error: "server_error",
				errorDescription:
					"policy returned audiences outside the subject_token audience or client allowedAudiences: billing",
			});
			expect(log.events()).toEqual(["token_exchange_policy_audience_refused"]);
		});

		it("answers 500 server_error when the policy grants an audience the subject_token carries but the client is not registered for", async () => {
			const { grant } = await boot([deciding({ grantedAudience: ["payments"] })]);
			const { result } = await exchange(grant, {
				subject_token: await signSelfIssuedAccessToken({ aud: ["payments", "client-a"] }),
				subject_token_type: ACCESS_TOKEN_TYPE,
			});
			expect(result).toEqual({
				status: 500,
				error: "server_error",
				errorDescription:
					"policy returned audiences outside the subject_token audience or client allowedAudiences: payments",
			});
		});

		it("mints for an audience the policy narrows to within both bounds", async () => {
			const { grant } = await boot([deciding({ grantedAudience: ["billing"] })]);
			const { result } = await exchange(grant, {
				subject_token: await signSelfIssuedAccessToken({ aud: ["billing", "client-a"] }),
				subject_token_type: ACCESS_TOKEN_TYPE,
			});
			expect(result.status).toBe(200);
			if (!("tokens" in result)) return;
			expect(decodeJwt(result.tokens.access_token).aud).toBe("billing");
		});

		// An empty `grantedAudience` is no decision, as core's
		// `boundPolicyAudience` reads it for every other grant: the request's
		// audience stands.
		// A `resource` is the request's too (RFC 8707): the issued audience must
		// equal it, and that audience is either the client id or one both the
		// registration and the subject token carry. A resource outside that set
		// can never be represented, so it is refused before the policy runs —
		// a policy that turns the resource into its granted audience must not
		// convert the caller's 400 into a 500.
		it("answers invalid_target for a resource no issued audience could equal, whatever the policy does with it", async () => {
			const resourceEchoing = policyModule(async (request) => ({
				outcome: "allow",
				grantedAudience: request.resource,
			}));
			for (const modules of [[], [resourceEchoing]]) {
				const { grant } = await boot(modules);
				const { result } = await exchange(grant, {
					subject_token: await signSelfIssuedAccessToken({ aud: "client-a" }),
					subject_token_type: ACCESS_TOKEN_TYPE,
					resource: "https://elsewhere.example",
				});
				expect(result).toEqual({
					status: 400,
					error: "invalid_target",
					errorDescription: "requested_resources_not_in_audience: https://elsewhere.example",
				});
				await handle?.dispose();
				handle = undefined;
			}
		});

		// The early refusal names what the check after the policy names when no
		// policy replaces the audience: every requested resource the audience
		// the request asks for would not equal — a reachable one included.
		it("names every requested resource the requested audience would not equal", async () => {
			const { grant } = await boot([]);
			const { result } = await exchange(grant, {
				subject_token: await signSelfIssuedAccessToken({ aud: ["billing", "client-a"] }),
				subject_token_type: ACCESS_TOKEN_TYPE,
				audience: "billing",
				resource: ["client-a", "https://elsewhere.example"],
			});
			expect(result).toEqual({
				status: 400,
				error: "invalid_target",
				errorDescription: "requested_resources_not_in_audience: client-a https://elsewhere.example",
			});
		});

		// Answered before the policy runs, so a policy deny is not reached: the
		// request's own invalid_target comes first.
		it("answers an unrepresentable resource before a policy deny", async () => {
			const denyAll = defineModule({
				name: "test:deny-all-grant-policy",
				provides: {
					grantPolicy: () => ({
						kind: "test",
						evaluate: async () => ({ outcome: "deny" as const, error: "access_denied" }),
					}),
				},
			});
			const { grant } = await boot([denyAll]);
			const { result } = await exchange(grant, {
				subject_token: await signSelfIssuedAccessToken({ aud: "client-a" }),
				subject_token_type: ACCESS_TOKEN_TYPE,
				resource: "https://elsewhere.example",
			});
			expect(result).toEqual({
				status: 400,
				error: "invalid_target",
				errorDescription: "requested_resources_not_in_audience: https://elsewhere.example",
			});
		});

		it("keeps the request's audience when the policy returns an empty grantedAudience", async () => {
			const { grant } = await boot([deciding({ grantedAudience: [] })]);
			const { result } = await exchange(grant, {
				subject_token: await signSelfIssuedAccessToken({ aud: ["billing", "client-a"] }),
				subject_token_type: ACCESS_TOKEN_TYPE,
				audience: "billing",
			});
			expect(result.status).toBe(200);
			if (!("tokens" in result)) return;
			expect(decodeJwt(result.tokens.access_token).aud).toBe("billing");
		});
	});

	// A policy deny carries the policy's own `error`. RFC 6749 §5.2 makes
	// `error` 1*NQSCHAR (printable ASCII without `"` and `\`), so a code
	// outside that set — or none — is answered `invalid_request`, §2.2.2's
	// code for a request refused by policy, and the policy's code is logged,
	// sanitised, for the operator who wrote it.
	describe("a policy deny", () => {
		const denying = (error: string, errorDescription: unknown = "denied by the test policy") =>
			defineModule({
				name: "test:denying-grant-policy",
				provides: {
					grantPolicy: () => ({
						kind: "test",
						evaluate: async () =>
							({
								outcome: "deny",
								error,
								errorDescription,
							}) as unknown as GrantPolicyDecision,
					}),
				},
			});
		const warnings = () => {
			const logger = {
				trace: vi.fn(),
				debug: vi.fn(),
				info: vi.fn(),
				warn: vi.fn(),
				error: vi.fn(),
				fatal: vi.fn(),
				child: () => logger,
			};
			return {
				module: defineModule({ name: "test:logger", provides: { logger: () => logger } }),
				of: (event: string) => logger.warn.mock.calls.filter((call) => call[1] === event),
			};
		};
		const body = async () => ({
			subject_token: await signSelfIssuedAccessToken({}),
			subject_token_type: ACCESS_TOKEN_TYPE,
		});

		it.each([
			["a double quote", 'bad "code"', "bad ?code?"],
			["non-ASCII", "d\u00e9ny", "d?ny"],
			["nothing", "", ""],
		])(
			"answers invalid_request for a deny code with %s, and logs it sanitised",
			async (_label, code, logged) => {
				const log = warnings();
				const { grant } = await boot([denying(code), log.module]);
				const { result } = await exchange(grant, await body());
				expect(result).toEqual({
					status: 400,
					error: "invalid_request",
					errorDescription: "denied by the test policy",
				});
				expect(log.of("token_exchange_policy_deny_error_malformed")).toEqual([
					[{ error: logged }, "token_exchange_policy_deny_error_malformed"],
				]);
			},
		);

		it("logs a long malformed code capped, as the audit stream caps client text", async () => {
			const log = warnings();
			const { grant } = await boot([denying(`"${"x".repeat(300)}`), log.module]);
			await exchange(grant, await body());
			expect(log.of("token_exchange_policy_deny_error_malformed")).toEqual([
				[{ error: `?${"x".repeat(196)}...` }, "token_exchange_policy_deny_error_malformed"],
			]);
		});

		// A JavaScript policy can return anything as its description; one that
		// is not a non-empty string is not sent — the grant's own default is.
		it.each([
			["a number", 42],
			["the empty string", ""],
		])(
			"answers the default description for a deny description that is %s",
			async (_label, description) => {
				const { grant } = await boot([denying("access_denied", description)]);
				const { result } = await exchange(grant, await body());
				expect(result).toEqual({
					status: 403,
					error: "access_denied",
					errorDescription: "denied by policy",
				});
			},
		);

		it("keeps a well-formed deny code, access_denied as 403", async () => {
			const { grant } = await boot([denying("access_denied")]);
			const { result } = await exchange(grant, await body());
			expect(result).toEqual({
				status: 403,
				error: "access_denied",
				errorDescription: "denied by the test policy",
			});
		});
	});

	// Core's ExchangeTokenValidator contract: `null` means the token is not
	// acceptable (the grant answers `invalid_request`, RFC 8693 §2.2.2), a
	// throw means the answer is not knowable (`503 temporarily_unavailable`).
	// A revocation store that cannot be read is the second: the token is still
	// refused — the verifier fails closed — but a client told its token is
	// unacceptable discards a credential that may be perfectly good, so an
	// outage must not be reported as a finding. The refresh grant makes the
	// same split for the same reason.
	describe("a revocation store that cannot answer", () => {
		const unreachableDenylist = (failFor: (jti: string) => boolean, revoked = new Set<string>()) =>
			defineModule({
				name: "test:access-token-denylist",
				provides: {
					accessTokenDenylist: () => ({
						kind: "test",
						add: async () => {},
						has: async (jti: string) => {
							if (failFor(jti)) throw new Error("denylist backend unreachable");
							return revoked.has(jti);
						},
					}),
				},
			});
		const denylistWired = { accessToken: "denylist", subject: "unsupported" } as const;

		it("answers 503 temporarily_unavailable when the denylist cannot be read for the subject_token", async () => {
			const { grant } = await boot([unreachableDenylist(() => true)], denylistWired);
			const { result } = await exchange(grant, {
				subject_token: await signSelfIssuedAccessToken({ jti: "at-subject" }),
				subject_token_type: ACCESS_TOKEN_TYPE,
			});
			expect(result).toMatchObject({
				status: 503,
				error: "temporarily_unavailable",
				errorDescription: "subject_token validation store unavailable",
			});
		});

		it("answers 503 temporarily_unavailable when the denylist cannot be read for the actor_token", async () => {
			const { grant } = await boot(
				[unreachableDenylist((jti) => jti === "at-actor")],
				denylistWired,
			);
			const { result } = await exchange(grant, {
				subject_token: await signSelfIssuedAccessToken({ jti: "at-subject" }),
				subject_token_type: ACCESS_TOKEN_TYPE,
				actor_token: await signSelfIssuedAccessToken({ sub: "svc-a", jti: "at-actor" }),
				actor_token_type: ACCESS_TOKEN_TYPE,
			});
			expect(result).toMatchObject({
				status: 503,
				error: "temporarily_unavailable",
				errorDescription: "actor_token validation store unavailable",
			});
		});

		it("answers 503 temporarily_unavailable when the subject watermark cannot be read", async () => {
			const { grant } = await boot(
				[
					defineModule({
						name: "test:subject-revocation",
						provides: {
							subjectRevocation: () => ({
								kind: "test",
								revokeBefore: async () => {},
								revokedBefore: async () => {
									throw new Error("watermark backend unreachable");
								},
							}),
						},
					}),
				],
				{ accessToken: "unsupported", subject: "watermark" },
			);
			const { result } = await exchange(grant, {
				subject_token: await signSelfIssuedAccessToken({}),
				subject_token_type: ACCESS_TOKEN_TYPE,
			});
			expect(result).toMatchObject({
				status: 503,
				error: "temporarily_unavailable",
				errorDescription: "subject_token validation store unavailable",
			});
		});

		it("still answers invalid_request for a subject_token the denylist does hold", async () => {
			// The other half of the split: a store that answers "revoked" is a
			// finding about the token, not an outage.
			const { grant } = await boot(
				[unreachableDenylist(() => false, new Set(["at-revoked"]))],
				denylistWired,
			);
			const { result } = await exchange(grant, {
				subject_token: await signSelfIssuedAccessToken({ jti: "at-revoked" }),
				subject_token_type: ACCESS_TOKEN_TYPE,
			});
			expect(result).toMatchObject({
				status: 400,
				error: "invalid_request",
				errorDescription: "subject_token validation failed",
			});
		});

		it("answers 503 temporarily_unavailable when the subject watermark cannot be read for the actor_token", async () => {
			const { grant } = await boot(
				[
					defineModule({
						name: "test:subject-revocation",
						provides: {
							subjectRevocation: () => ({
								kind: "test",
								revokeBefore: async () => {},
								revokedBefore: async (sub: string) => {
									if (sub === "svc-a") throw new Error("watermark backend unreachable");
									return null;
								},
							}),
						},
					}),
				],
				{ accessToken: "unsupported", subject: "watermark" },
			);
			const { result } = await exchange(grant, {
				subject_token: await signSelfIssuedAccessToken({}),
				subject_token_type: ACCESS_TOKEN_TYPE,
				actor_token: await signSelfIssuedAccessToken({ sub: "svc-a" }),
				actor_token_type: ACCESS_TOKEN_TYPE,
			});
			expect(result).toMatchObject({
				status: 503,
				error: "temporarily_unavailable",
				errorDescription: "actor_token validation store unavailable",
			});
		});

		// The family store is the grant's (`familyRefusal`), so its outage is
		// answered and logged there — with the role and the store error's
		// projection, never the error: ioredis puts the command it sent on a
		// reply error, and Redis's own reply to an unknown command echoes its
		// first arguments — here the family's key.
		const unreachableFamilyRevocation = (failFor: (familyId: string) => boolean) =>
			defineModule({
				name: "test:refresh-token-family-revocation",
				provides: {
					refreshTokenFamilyRevocation: () => ({
						revokeFamily: async () => {},
						isFamilyRevoked: async (familyId: string) => {
							if (failFor(familyId)) {
								throw Object.assign(
									new Error(
										`ERR unknown command 'evalsha', with args beginning with: 'sha' '1' 'rtf:family:${familyId}'`,
									),
									{
										name: "ReplyError",
										command: { name: "evalsha", args: ["sha", "1", `rtf:family:${familyId}`] },
									},
								);
							}
							return false;
						},
					}),
				},
			});
		/**
		 * A logger that serialises every own property of what it is handed,
		 * `cause` and non-enumerable fields included — a deployment is free
		 * to install one. Its levels are spies.
		 */
		const serialiseEverythingLogger = () => {
			const lines: string[] = [];
			const walk = (value: unknown, seen = new WeakSet<object>()): unknown => {
				if (typeof value !== "object" || value === null) return value;
				if (seen.has(value)) return "[circular]";
				seen.add(value);
				const out: Record<string, unknown> = {};
				for (const key of Object.getOwnPropertyNames(value)) {
					out[key] = walk((value as Record<string, unknown>)[key], seen);
				}
				return out;
			};
			const record = (level: string) =>
				vi.fn((...args: unknown[]): void => {
					lines.push(JSON.stringify({ level, args: walk(args) }));
				});
			const logger = {
				trace: record("trace"),
				debug: record("debug"),
				info: record("info"),
				warn: record("warn"),
				error: record("error"),
				fatal: record("fatal"),
				child: () => logger,
			};
			return { logger, lines };
		};
		/**
		 * The store error as `loggableError` projects it: Redis's echo cut, the
		 * command's name without its arguments, frames only.
		 */
		const projectedStoreError = {
			name: "ReplyError",
			detail: "ERR unknown command 'evalsha'",
			command: { name: "evalsha" },
			stack: expect.stringMatching(/^ {4}at /),
		};

		it("answers 503 and logs the outage when the family store cannot be read for the subject_token", async () => {
			const { logger, lines } = serialiseEverythingLogger();
			const { grant } = await boot([
				unreachableFamilyRevocation(() => true),
				defineModule({ name: "test:logger", provides: { logger: () => logger } }),
			]);
			const { result } = await exchange(grant, {
				subject_token: await signSelfIssuedAccessToken({ family_id: "fam-subject" }),
				subject_token_type: ACCESS_TOKEN_TYPE,
			});
			expect(result).toMatchObject({
				status: 503,
				error: "temporarily_unavailable",
				errorDescription: "refresh token store unavailable",
			});
			expect(logger.error).toHaveBeenCalledWith(
				{ err: projectedStoreError, role: "subject" },
				"token_exchange_family_store_unavailable",
			);
			for (const line of lines) expect(line).not.toContain("fam-subject");
		});

		it("answers 503 naming the actor, and logs the actor's role, when the family store cannot be read for the actor_token", async () => {
			const { logger, lines } = serialiseEverythingLogger();
			const { grant } = await boot([
				unreachableFamilyRevocation((id) => id === "fam-actor"),
				defineModule({ name: "test:logger", provides: { logger: () => logger } }),
			]);
			const { result } = await exchange(grant, {
				subject_token: await signSelfIssuedAccessToken({ family_id: "fam-subject" }),
				subject_token_type: ACCESS_TOKEN_TYPE,
				actor_token: await signSelfIssuedAccessToken({ sub: "svc-a", family_id: "fam-actor" }),
				actor_token_type: ACCESS_TOKEN_TYPE,
			});
			expect(result).toMatchObject({
				status: 503,
				error: "temporarily_unavailable",
				errorDescription: "actor_token refresh token store unavailable",
			});
			expect(logger.error).toHaveBeenCalledWith(
				{ err: projectedStoreError, role: "actor" },
				"token_exchange_family_store_unavailable",
			);
			for (const line of lines) expect(line).not.toContain("fam-actor");
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
