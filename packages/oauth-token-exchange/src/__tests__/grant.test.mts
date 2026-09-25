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
	type AppConfig,
	type ClientRepository,
	createInMemoryUserSessionStore,
	type GrantContext,
	type GrantPolicyContext,
	type GrantPolicyHook,
	type GrantPolicyRequest,
	type Logger,
	MAX_CLIENT_ID_LENGTH,
	type PublicClient,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { decodeJwt } from "jose";
import { describe, expect, it, vi } from "vitest";
import { createTokenExchangeGrant, TOKEN_EXCHANGE_GRANT_TYPE } from "#/grant.mjs";
import { createSelfIssuedAccessTokenValidator } from "#/validator/selfIssuedAccessToken.mjs";
import { ISSUER, keyStore, makeFamilyRevocation, signSelfIssuedAccessToken } from "./fixtures.mjs";

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
	// The registration is a ceiling on both axes now: it must name the scopes
	// this client may receive (an empty list grants none) and it must name the
	// exchange grant type itself (#326 deny-by-absence). The fixture declares
	// what these tests already assumed it had.
	allowedScopes: ["read", "write"],
	allowedAudiences: [],
	allowedGrantTypes: [TOKEN_EXCHANGE_GRANT_TYPE],
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
		clientRepository?: ClientRepository;
		/** Pass `null` to explicitly omit the store from deps (fail-closed tests). */
		refreshTokenFamilyRevocation?: ReturnType<typeof makeFamilyRevocation> | null;
		config?: AppConfig;
		grantPolicy?: GrantPolicyHook;
		logger?: Logger;
		userSessionStore?: UserSessionStore;
	} = {},
) {
	// null = explicitly absent; undefined = use default
	const grantStore =
		overrides.refreshTokenFamilyRevocation === null
			? undefined
			: (overrides.refreshTokenFamilyRevocation ?? makeFamilyRevocation());
	// The resolver the grant reads is `get` alone, which a Map provides. The
	// validator takes no family store: the grant owns the family check.
	const validators = new Map([
		[ACCESS_TOKEN_TYPE, createSelfIssuedAccessTokenValidator({ keyStore, issuer: ISSUER })],
	]);
	return createTokenExchangeGrant({
		config: overrides.config ?? mockConfig,
		keyStore,
		refreshTokenFamilyRevocation: grantStore,
		tokenExchangeValidatorResolver: validators,
		clientRepository: overrides.clientRepository ?? mockClientRepository(),
		...(overrides.grantPolicy ? { grantPolicy: overrides.grantPolicy } : {}),
		...(overrides.logger ? { logger: overrides.logger } : {}),
		...(overrides.userSessionStore ? { userSessionStore: overrides.userSessionStore } : {}),
	});
}

/** A logger whose every level is a spy. */
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

/**
 * What a Redis-backed store rejects with: a ReplyError whose command carries
 * the key it refused — which must never reach a log.
 */
const storeReplyError = (): Error =>
	Object.assign(new Error("READONLY You can't write against a read only replica."), {
		name: "ReplyError",
		command: { name: "get", args: ["client:client-a", "refused-command-marker"] },
	});

/**
 * The branch logged exactly one line, at error level, as `event`, carrying
 * `fields` and the error's projection — and nothing at warn.
 */
const expectOutageLine = (
	logger: ReturnType<typeof spyLogger>,
	event: string,
	fields: Record<string, unknown>,
) => {
	expect(logger.warn).not.toHaveBeenCalled();
	expect(logger.error).toHaveBeenCalledTimes(1);
	const [line, name] = logger.error.mock.calls[0] as [Record<string, unknown>, string];
	expect(name).toBe(event);
	expect(line).toMatchObject(fields);
	expect(line.err).not.toBeInstanceOf(Error);
	expect(JSON.stringify(logger.error.mock.calls)).not.toContain("refused-command-marker");
	return line;
};

/**
 * Default test context. The standalone-wiring path (no `clientAuthMw`) is
 * exercised by leaving `authenticatedClient: null`; tests that need to verify
 * the route-bound (`/oauth/token` after `clientAuthMw`) path override it.
 */
const ctx = (
	body: Record<string, unknown>,
	overrides: Partial<GrantContext> = {},
): GrantContext => ({
	body,
	session: {},
	issuer: ISSUER,
	metadata: {},
	authenticatedClient: null,
	...overrides,
});

describe("createTokenExchangeGrant — the lifetime it mints with, read when it is built", () => {
	it("is refused when it is built with an access-token lifetime the resolver refuses", () => {
		// Read per request, a hand-built lifetime failed every exchange with a
		// 500, after client authentication had spent whatever it spends.
		const base = mockConfig as unknown as { oauth: Record<string, unknown> };
		for (const accessToken of [
			{ expiresIn: 1.5 },
			{ expiresIn: 0 },
			{ defaultExpiresIn: 600, maxExpiresIn: 60 },
			{},
		]) {
			const config = { oauth: { ...base.oauth, accessToken } } as unknown as AppConfig;
			expect(() => buildGrant({ config }), JSON.stringify(accessToken)).toThrow(RangeError);
		}
	});
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

	// RFC 6749 §5.2 `invalid_request`: "an unsupported parameter value (other
	// than grant type)". `unsupported_token_type` is RFC 7009's code for the
	// revocation endpoint; RFC 8693 defines no token-type error of its own.
	it("returns invalid_request when subject_token_type is not registered", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({});
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: "urn:ietf:params:oauth:token-type:saml2",
			}),
		);
		expect(result).toEqual({
			status: 400,
			error: "invalid_request",
			errorDescription:
				"subject_token_type 'urn:ietf:params:oauth:token-type:saml2' is not supported",
		});
	});

	it("returns invalid_request when requested_token_type is not access_token", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({});
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				requested_token_type: "urn:ietf:params:oauth:token-type:id_token",
			}),
		);
		expect(result).toEqual({
			status: 400,
			error: "invalid_request",
			errorDescription:
				"requested_token_type 'urn:ietf:params:oauth:token-type:id_token' is not supported",
		});
	});

	it("returns invalid_request when actor_token_type is not registered", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({});
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				actor_token: "any",
				actor_token_type: "urn:ietf:params:oauth:token-type:saml2",
			}),
		);
		expect(result).toEqual({
			status: 400,
			error: "invalid_request",
			errorDescription:
				"actor_token_type 'urn:ietf:params:oauth:token-type:saml2' is not supported",
		});
	});

	it("mints a token for the minimal happy-path input (was Task 6 stub guard)", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result.status).toBe(200);
	});

	it("rejects client_secret as array (prevents auth bypass via repeated params)", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({});
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: ["x", "y"], // repeated params → array
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({
			status: 400,
			error: "invalid_request",
			errorDescription: expect.stringMatching(/client_secret/),
		});
	});

	it("Copilot review: standalone-wiring authenticate throw → 503 temporarily_unavailable (matches authenticated-client branch)", async () => {
		// Standalone wiring (no `clientAuthMw`) — the in-grant `authenticate(...)`
		// call must be guarded so a transient repository outage surfaces as a
		// controlled 503 instead of an unhandled 500. This mirrors the
		// authenticated-client branch's try/catch.
		const throwingRepo: ClientRepository = {
			findById: async () => null,
			authenticate: async () => {
				throw new Error("redis down");
			},
		};
		const g = buildGrant({ clientRepository: throwingRepo });
		const token = await signSelfIssuedAccessToken({});
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result.status).toBe(503);
		if (!("error" in result)) expect.fail("Expected error in result");
		expect(result.error).toBe("temporarily_unavailable");
	});

	describe("a client repository that cannot answer is logged, not only answered 503", () => {
		it("on the authenticated path: findById, as client_repository_unavailable", async () => {
			const logger = spyLogger();
			const failing: ClientRepository = {
				findById: async () => {
					throw storeReplyError();
				},
				authenticate: async () => null,
			};
			const g = buildGrant({ clientRepository: failing, logger });
			const { result } = await g.handle(
				ctx(
					{
						subject_token: await signSelfIssuedAccessToken({}),
						subject_token_type: ACCESS_TOKEN_TYPE,
					},
					{ authenticatedClient: publicClient({ tokenEndpointAuthMethod: "client_secret_basic" }) },
				),
			);
			expect(result).toMatchObject({ status: 503, error: "temporarily_unavailable" });
			expectOutageLine(logger, "client_repository_unavailable", {
				site: "token_exchange",
				step: "find",
				clientId: "client-a",
				err: { name: "ReplyError" },
			});
		});

		it("on the standalone path: authenticate, as client_repository_unavailable", async () => {
			const logger = spyLogger();
			const failing: ClientRepository = {
				findById: async () => null,
				authenticate: async () => {
					throw storeReplyError();
				},
			};
			const g = buildGrant({ clientRepository: failing, logger });
			const { result } = await g.handle(
				ctx({
					client_id: "client-a",
					client_secret: "any",
					subject_token: await signSelfIssuedAccessToken({}),
					subject_token_type: ACCESS_TOKEN_TYPE,
				}),
			);
			expect(result).toMatchObject({ status: 503, error: "temporarily_unavailable" });
			expectOutageLine(logger, "client_repository_unavailable", {
				site: "token_exchange",
				step: "authenticate",
				clientId: "client-a",
				err: { name: "ReplyError" },
			});
		});

		it("records the client's id capped at 200 characters", async () => {
			const logger = spyLogger();
			const failing: ClientRepository = {
				findById: async () => null,
				authenticate: async () => {
					throw storeReplyError();
				},
			};
			const clientId = "c".repeat(MAX_CLIENT_ID_LENGTH);
			await buildGrant({ clientRepository: failing, logger }).handle(
				ctx({
					client_id: clientId,
					client_secret: "any",
					subject_token: await signSelfIssuedAccessToken({}),
					subject_token_type: ACCESS_TOKEN_TYPE,
				}),
			);
			const line = expectOutageLine(logger, "client_repository_unavailable", {
				step: "authenticate",
			});
			expect(String(line.clientId).length).toBeLessThanOrEqual(200);
		});
	});

	it("logs a grant policy that cannot answer as grant_policy_unavailable, at error level", async () => {
		const logger = spyLogger();
		const throwing: GrantPolicyHook = {
			kind: "throw",
			async evaluate() {
				throw storeReplyError();
			},
		};
		const { result } = await buildGrant({ grantPolicy: throwing, logger }).handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: await signSelfIssuedAccessToken({ family_id: "fam-1" }),
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({ status: 503, error: "temporarily_unavailable" });
		expectOutageLine(logger, "grant_policy_unavailable", {
			grantType: TOKEN_EXCHANGE_GRANT_TYPE,
			policy: "throw",
			err: { name: "ReplyError" },
		});
	});

	it.each([
		["a NUL byte", "client-a\u0000"],
		["a line feed", "client-a\nx"],
		["more than MAX_CLIENT_ID_LENGTH characters", "c".repeat(MAX_CLIENT_ID_LENGTH + 1)],
	])(
		"standalone wiring: a client_id carrying %s is invalid_client, never asked of the repository",
		async (_label, clientId) => {
			// A repository throws only when its store cannot answer (503), so a
			// client_id it would choke on — a SQL driver refusing a NUL byte — is
			// refused as the client's before it is asked (core's isWellFormedClientId).
			const asked: string[] = [];
			const choking: ClientRepository = {
				findById: async () => null,
				authenticate: async (id) => {
					asked.push(id);
					throw new Error("driver refused the parameter");
				},
			};
			const g = buildGrant({ clientRepository: choking });
			const token = await signSelfIssuedAccessToken({});
			const { result } = await g.handle(
				ctx({
					client_id: clientId,
					client_secret: "any",
					subject_token: token,
					subject_token_type: ACCESS_TOKEN_TYPE,
				}),
			);
			expect(result).toMatchObject({ status: 401, error: "invalid_client" });
			expect(asked).toEqual([]);
		},
	);

	it.each([
		["number", 123],
		["object", { a: 1 }],
		["boolean", true],
	])("rejects client_secret with non-string type %s", async (_label, badValue) => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({});
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: badValue,
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({
			status: 400,
			error: "invalid_request",
			errorDescription: expect.stringMatching(/client_secret/),
		});
	});

	it("rejects actor_token_type without actor_token (prevents delegation-policy bypass)", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				actor_token_type: ACCESS_TOKEN_TYPE, // no actor_token
			}),
		);
		expect(result).toMatchObject({
			status: 400,
			error: "invalid_request",
			errorDescription: expect.stringMatching(/actor_token is required/),
		});
	});

	it("rejects actor_token without actor_token_type (symmetric guard)", async () => {
		const g = buildGrant();
		const subject = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const actor = await signSelfIssuedAccessToken({ sub: "svc-a", family_id: "fam-2" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: subject,
				subject_token_type: ACCESS_TOKEN_TYPE,
				actor_token: actor, // no actor_token_type
			}),
		);
		expect(result).toMatchObject({
			status: 400,
			error: "invalid_request",
			errorDescription: expect.stringMatching(/actor_token_type is required/),
		});
	});

	it("rejects request when client_secret is omitted (confidential clients only)", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({
			status: 401,
			error: "invalid_client",
			errorDescription: expect.stringMatching(/client_secret/),
		});
	});
});

describe("createTokenExchangeGrant — token validation", () => {
	it("returns invalid_request when subject_token signature is invalid (RFC 8693 §2.2.2)", async () => {
		const g = buildGrant();
		const token = `${(await signSelfIssuedAccessToken({})).slice(0, -4)}AAAA`;
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({ status: 400, error: "invalid_request" });
	});

	it("returns invalid_request/family_revoked when subject family is revoked", async () => {
		const store = makeFamilyRevocation({
			isFamilyRevoked: async (id) => id === "fam-bad",
		});
		// The validator projects `familyId`; the grant consults
		// `refreshTokenFamilyRevocation` and answers `family_revoked`.
		const g = buildGrant({ refreshTokenFamilyRevocation: store });
		const token = await signSelfIssuedAccessToken({ family_id: "fam-bad" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({
			status: 400,
			error: "invalid_request",
			errorDescription: "family_revoked",
		});
	});

	it("returns invalid_request when refreshTokenFamilyRevocation is not wired (fail-closed)", async () => {
		// refreshTokenFamilyRevocation: null → deps.refreshTokenFamilyRevocation is undefined (absent).
		// The grant's fail-closed check fires: familyId present + no store → 400.
		const g = buildGrant({ refreshTokenFamilyRevocation: null });
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({ status: 400, error: "invalid_request" });
	});

	it("returns temporarily_unavailable (503) when the family store throws (runtime store failure)", async () => {
		const store = makeFamilyRevocation({
			isFamilyRevoked: async () => {
				throw new Error("redis down");
			},
		});
		const g = buildGrant({ refreshTokenFamilyRevocation: store });
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({ status: 503, error: "temporarily_unavailable" });
	});

	it("returns temporarily_unavailable (503) when the family store throws on the actor_token's family", async () => {
		// The subject's family answers; the actor's cannot be read. An outage is
		// never reported as a revoked (or a live) actor.
		const store = makeFamilyRevocation({
			isFamilyRevoked: async (id) => {
				if (id === "fam-actor") throw new Error("redis down");
				return false;
			},
		});
		const g = buildGrant({ refreshTokenFamilyRevocation: store });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: await signSelfIssuedAccessToken({ family_id: "fam-1" }),
				subject_token_type: ACCESS_TOKEN_TYPE,
				actor_token: await signSelfIssuedAccessToken({ sub: "svc-a", family_id: "fam-actor" }),
				actor_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({
			status: 503,
			error: "temporarily_unavailable",
			errorDescription: "actor_token refresh token store unavailable",
		});
	});

	it("returns invalid_request when actor_token fails validation (RFC 8693 §2.2.2)", async () => {
		const g = buildGrant();
		const subject = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const badActor = `${(await signSelfIssuedAccessToken({ sub: "svc-a" })).slice(0, -4)}AAAA`;
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: subject,
				subject_token_type: ACCESS_TOKEN_TYPE,
				actor_token: badActor,
				actor_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({ status: 400, error: "invalid_request" });
	});
});

describe("createTokenExchangeGrant — narrowing checks", () => {
	it("returns invalid_scope when requested scope is a superset of subject scope", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ scope: "read", family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				scope: "read write",
			}),
		);
		expect(result).toMatchObject({ status: 400, error: "invalid_scope" });
	});

	it("returns invalid_target when audience is not in allowlist", async () => {
		const g = buildGrant({
			clientRepository: mockClientRepository(publicClient({ allowedAudiences: ["billing"] })),
		});
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				audience: "inventory",
			}),
		);
		expect(result).toMatchObject({ status: 400, error: "invalid_target" });
	});

	it("mints a token when audience matches clientId even without allowlist", async () => {
		const g = buildGrant({
			clientRepository: mockClientRepository(publicClient({ allowedAudiences: [] })),
		});
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				audience: "client-a",
			}),
		);
		expect(result.status).toBe(200);
		if (result.status === 200) {
			expect(result.tokens.access_token).toBeDefined();
			expect(result.tokens.issued_token_type).toBe(ACCESS_TOKEN_TYPE);
			expect(result.tokens.token_type).toBe("Bearer");
			expect(result.tokens.refresh_token).toBeFalsy();
		}
	});

	it("mints a token when multi-value audience entries are in allowlist ∪ {clientId}", async () => {
		const g = buildGrant({
			clientRepository: mockClientRepository(
				publicClient({ allowedAudiences: ["billing", "inventory"] }),
			),
		});
		const token = await signSelfIssuedAccessToken({
			family_id: "fam-1",
			aud: ["billing", "inventory"],
		});
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				audience: ["billing", "inventory"],
			}),
		);
		expect(result.status).toBe(200);
	});

	it("rejects audience that is client-allowed but outside the subject audience", async () => {
		const g = buildGrant({
			clientRepository: mockClientRepository(publicClient({ allowedAudiences: ["inventory"] })),
		});
		const token = await signSelfIssuedAccessToken({ aud: "billing", family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				audience: "inventory",
			}),
		);
		expect(result).toMatchObject({
			status: 400,
			error: "invalid_target",
			errorDescription: expect.stringMatching(/audience_widening_not_allowed/),
		});
	});

	it("mints a token when audience is empty array (treated as no audience requested)", async () => {
		const g = buildGrant({
			clientRepository: mockClientRepository(publicClient({ allowedAudiences: [] })),
		});
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				audience: [],
			}),
		);
		expect(result.status).toBe(200);
	});

	it("mints a token when audience array contains only empty strings (filtered to none)", async () => {
		const g = buildGrant({
			clientRepository: mockClientRepository(publicClient({ allowedAudiences: ["billing"] })),
		});
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				audience: ["", ""],
			}),
		);
		expect(result.status).toBe(200);
	});

	it("treats scope='' as omitted (inherits subject scope, not explicit empty)", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ scope: "read write", family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				scope: "",
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		// Scope was explicitly empty → normalized to "omitted" → inherited.
		expect(result.tokens.scope).toBe("read write");
	});

	it("treats scope='  ' (whitespace-only) as omitted (inherits subject scope)", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ scope: "read write", family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				scope: "   ",
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		expect(result.tokens.scope).toBe("read write");
	});
});

describe("createTokenExchangeGrant — the scope grammar (RFC 6749 §3.3)", () => {
	it("refuses a requested scope that is not a space-delimited list of scope-tokens as malformed", async () => {
		// The request is read strictly: a tab is not a delimiter, and a tab
		// alone is not an omitted scope that inherits the subject's.
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ scope: "read write", family_id: "fam-1" });
		for (const scope of ["read\twrite", 'read "write"', "\t"]) {
			const { result } = await g.handle(
				ctx({
					client_id: "client-a",
					client_secret: "any",
					subject_token: token,
					subject_token_type: ACCESS_TOKEN_TYPE,
					scope,
				}),
			);
			expect(result, JSON.stringify(scope)).toEqual({
				status: 400,
				error: "invalid_scope",
				errorDescription: "scope is not a space-delimited list of scope-tokens",
			});
		}
	});

	it("reads scope: null as an omitted scope, and refuses any other value that is not a string", async () => {
		// RFC 6749 §3.2: a parameter sent without a value is treated as
		// omitted. A JSON body's `null` is that, as `scope=""` is for a form
		// body — the same reading token exchange gives `expires_in: null`. Any
		// other value that is not a string is `invalid_request`.
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ scope: "read write", family_id: "fam-1" });
		const exchange = (scope: unknown) =>
			g.handle(
				ctx({
					client_id: "client-a",
					client_secret: "any",
					subject_token: token,
					subject_token_type: ACCESS_TOKEN_TYPE,
					scope,
				}),
			);
		const nulled = (await exchange(null)).result;
		if (nulled.status === 200) expect(nulled.tokens.scope).toBe("read write");
		else expect.fail(`expected 200, got ${nulled.status}`);

		for (const scope of [42, {}, true]) {
			expect((await exchange(scope)).result, JSON.stringify(scope)).toMatchObject({
				status: 400,
				error: "invalid_request",
			});
		}
	});

	it("refuses a repeated scope parameter rather than reading it as omitted", async () => {
		// `scope=a&scope=b` arrives as an array. Read as no scope, it inherited
		// the subject's whole scope — a wider answer than either value asked for.
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ scope: "read write", family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				scope: ["read", "write"],
			}),
		);
		expect(result).toEqual({
			status: 400,
			error: "invalid_request",
			errorDescription: "scope must be a space-delimited string",
		});
	});

	it("never reads a subject's scope wider than it was minted: a tab joins nothing", async () => {
		// A subject token minted before requests were read strictly can carry
		// `read\twrite` as one entry, which named no scope. Split on the tab,
		// an exchange could ask for `write` — or inherit it — from a subject
		// that was never granted it, so the entry is dropped.
		const g = buildGrant();
		const exchange = (subject: string, scope?: string) =>
			g.handle(
				ctx({
					client_id: "client-a",
					client_secret: "any",
					subject_token: subject,
					subject_token_type: ACCESS_TOKEN_TYPE,
					...(scope === undefined ? {} : { scope }),
				}),
			);
		const legacy = await signSelfIssuedAccessToken({ scope: "read\twrite", family_id: "fam-1" });

		const asked = (await exchange(legacy, "write")).result;
		expect(asked).toEqual({
			status: 400,
			error: "invalid_scope",
			errorDescription: "scope 'write' is not in subject_token scope",
		});
		const inherited = (await exchange(legacy)).result;
		expect(inherited.status).toBe(200);
		if (inherited.status === 200) expect(inherited.tokens.scope).toBeUndefined();

		const spaced = await signSelfIssuedAccessToken({ scope: "read  write", family_id: "fam-1" });
		const canonical = (await exchange(spaced)).result;
		if (canonical.status === 200) expect(canonical.tokens.scope).toBe("read write");
		else expect.fail(`expected 200, got ${canonical.status}`);
	});
});

describe("createTokenExchangeGrant — SF-5 policy subset enforcement", () => {
	// The request's own `scope` never reaches this check — a scope outside
	// either ceiling is `invalid_scope` before the policy runs — so a widening
	// here is the policy's fault, answered as every other grant answers a
	// decision past its ceiling: core's `policyOutOfBounds`, 500 server_error.
	it("answers server_error when the policy hook widens scope beyond subject scope", async () => {
		const wideningPolicy: GrantPolicyHook = {
			kind: "scope-widening",
			async evaluate() {
				return {
					outcome: "allow",
					grantedScope: ["read", "write"],
				};
			},
		};
		const g = buildGrant({ grantPolicy: wideningPolicy });
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1", scope: "read" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toEqual({
			status: 500,
			error: "server_error",
			errorDescription:
				"policy returned scopes exceeding the subject_token scope or client allowedScopes: write",
		});
	});

	// The policy's audience is checked before it replaces the request's, so a
	// widening here is the policy's alone and gets `policyOutOfBounds`, as
	// `boundPolicyAudience` answers for every other grant. The client is
	// registered for both audiences, so the bound this crosses is the subject
	// token's. The request's own audience past the subject token stays
	// `invalid_target` (RFC 8693 §2.2.2) — see the case above.
	it("answers server_error when the policy hook widens audience beyond subject aud", async () => {
		const wideningPolicy: GrantPolicyHook = {
			kind: "audience-widening",
			async evaluate() {
				return {
					outcome: "allow",
					grantedAudience: ["billing", "inventory"],
				};
			},
		};
		const g = buildGrant({
			grantPolicy: wideningPolicy,
			clientRepository: mockClientRepository(
				publicClient({ allowedAudiences: ["billing", "inventory"] }),
			),
		});
		const token = await signSelfIssuedAccessToken({
			aud: "billing",
			family_id: "fam-1",
		});
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toEqual({
			status: 500,
			error: "server_error",
			errorDescription:
				"policy returned audiences outside the subject_token audience or client allowedAudiences: inventory",
		});
	});
});

describe("createTokenExchangeGrant — a malformed policy decision (#521, v0.13.0 audit)", () => {
	// Every other grant refuses a non-array `grantedScope` / `grantedAudience`
	// since #521. Token exchange read them on truthiness and then called
	// `.filter`, so a JS policy returning a string threw a TypeError out of the
	// handler: an unhandled 500 with no description, where the others answer
	// `server_error` naming the policy's fault.
	it.each([
		["grantedScope", { grantedScope: "read" }],
		["grantedAudience", { grantedAudience: "https://api.example.com" }],
	])("answers server_error for a non-array %s instead of throwing", async (field, extra) => {
		const malformed: GrantPolicyHook = {
			kind: "malformed",
			async evaluate() {
				return { outcome: "allow", ...extra } as unknown as Awaited<
					ReturnType<GrantPolicyHook["evaluate"]>
				>;
			},
		};
		const g = buildGrant({ grantPolicy: malformed });
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1", scope: "read" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({
			status: 500,
			error: "server_error",
			errorDescription: expect.stringContaining(`non-array ${field}`),
		});
	});
});

describe("createTokenExchangeGrant — audience inheritance", () => {
	it("rejects inherited subject.aud when not in client allowlist (cross-client confusion)", async () => {
		// Subject token was issued with aud="a-api" (for Client A).
		// Our handler's client is client-a but has allowedAudiences=[].
		// When audience request parameter is omitted, we must NOT silently
		// inherit "a-api" (which would be permissive) — fall back to clientId.
		const g = buildGrant({
			clientRepository: mockClientRepository(publicClient({ allowedAudiences: [] })),
		});
		const token = await signSelfIssuedAccessToken({ aud: "a-api", family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		const payload = decodeJwt(result.tokens.access_token);
		// aud must be the clientId (fallback), NOT the inherited subject.aud
		expect(payload.aud).toBe("client-a");
	});

	it("inherits subject.aud when it matches client allowlist (happy path)", async () => {
		// Subject issued with aud="billing". Client has allowedAudiences including "billing".
		const g = buildGrant({
			clientRepository: mockClientRepository(publicClient({ allowedAudiences: ["billing"] })),
		});
		const token = await signSelfIssuedAccessToken({ aud: "billing", family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.aud).toBe("billing");
	});

	it("inherits subject.aud when it matches clientId (default allowlist)", async () => {
		// Subject issued with aud=clientId. No allowedAudiences configured.
		// This is the common case for non-Token-Exchange access_tokens.
		const g = buildGrant({
			clientRepository: mockClientRepository(publicClient({ allowedAudiences: [] })),
		});
		const token = await signSelfIssuedAccessToken({ aud: "client-a", family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.aud).toBe("client-a");
	});

	it("inherits subject.aud when encoded as a single-element array (RFC 7519 §4.1.3)", async () => {
		// RFC 7519 permits aud as a string OR an array. A single-element array
		// is semantically equivalent to a bare string and must not silently fall
		// back to clientId.
		const g = buildGrant({
			clientRepository: mockClientRepository(publicClient({ allowedAudiences: ["billing"] })),
		});
		const token = await signSelfIssuedAccessToken({ aud: ["billing"], family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.aud).toBe("billing");
	});

	it("falls back to clientId when subject.aud is a multi-element array", async () => {
		// Multi-valued audience cannot be represented in a single-aud token.
		// Falling back to clientId is the safe choice (no surprise widening).
		const g = buildGrant({
			clientRepository: mockClientRepository(
				publicClient({ allowedAudiences: ["billing", "inventory"] }),
			),
		});
		const token = await signSelfIssuedAccessToken({
			aud: ["billing", "inventory"],
			family_id: "fam-1",
		});
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.aud).toBe("client-a");
	});

	it("rejects single-element-array subject.aud when not in allowlist", async () => {
		// Same cross-client confusion defense as the string case.
		const g = buildGrant({
			clientRepository: mockClientRepository(publicClient({ allowedAudiences: [] })),
		});
		const token = await signSelfIssuedAccessToken({ aud: ["a-api"], family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.aud).toBe("client-a");
	});
});

const denyPolicy: GrantPolicyHook = {
	kind: "deny-all",
	async evaluate() {
		return { outcome: "deny", error: "access_denied" };
	},
};

const overridePolicy: GrantPolicyHook = {
	kind: "override",
	async evaluate(_req: GrantPolicyRequest, _ctx: GrantPolicyContext) {
		return {
			outcome: "allow",
			grantedScope: ["read"],
			grantedAudience: ["billing"],
		};
	},
};

describe("createTokenExchangeGrant — happy path", () => {
	it("mints an access_token with issued_token_type set (minimal impersonation)", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1", scope: "read write" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		expect(result.tokens.access_token).toBeDefined();
		expect(result.tokens.issued_token_type).toBe(ACCESS_TOKEN_TYPE);
		expect(result.tokens.refresh_token).toBeFalsy();
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.sub).toBe("user-1");
		expect(payload.family_id).toBe("fam-1");
		expect(payload.act).toBeUndefined();
	});

	it("inherits subject scope when scope parameter is omitted", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1", scope: "read write" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		expect(result.tokens.scope).toBe("read write");
	});

	it("narrows scope to requested subset", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1", scope: "read write" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				scope: "read",
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		expect(result.tokens.scope).toBe("read");
	});

	it("adds act claim when actor_token is provided (delegation)", async () => {
		const g = buildGrant();
		const subject = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const actor = await signSelfIssuedAccessToken({ sub: "svc-a", family_id: "fam-2" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: subject,
				subject_token_type: ACCESS_TOKEN_TYPE,
				actor_token: actor,
				actor_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.act).toEqual({ sub: "svc-a" });
	});

	it("nests subject.act inside new act for multi-step delegation", async () => {
		const g = buildGrant();
		const subject = await signSelfIssuedAccessToken({
			family_id: "fam-1",
			act: { sub: "svc-upstream" },
		});
		const actor = await signSelfIssuedAccessToken({ sub: "svc-b", family_id: "fam-2" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: subject,
				subject_token_type: ACCESS_TOKEN_TYPE,
				actor_token: actor,
				actor_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.act).toEqual({ sub: "svc-b", act: { sub: "svc-upstream" } });
	});

	it("rejects actor delegation when subject may_act does not authorize actor.sub", async () => {
		const g = buildGrant();
		const subject = await signSelfIssuedAccessToken({
			family_id: "fam-1",
			may_act: [{ sub: "svc-allowed" }],
		});
		const actor = await signSelfIssuedAccessToken({ sub: "svc-attacker" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: subject,
				subject_token_type: ACCESS_TOKEN_TYPE,
				actor_token: actor,
				actor_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({
			status: 400,
			error: "invalid_request",
			errorDescription: expect.stringMatching(/may_act_violation/),
		});
	});

	it("accepts actor delegation when actor matches may_act sub and iss", async () => {
		const g = buildGrant();
		const subject = await signSelfIssuedAccessToken({
			family_id: "fam-1",
			may_act: [{ sub: "svc-a", iss: ISSUER }],
		});
		const actor = await signSelfIssuedAccessToken({ sub: "svc-a", iss: ISSUER });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: subject,
				subject_token_type: ACCESS_TOKEN_TYPE,
				actor_token: actor,
				actor_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.act).toEqual({ sub: "svc-a" });
	});

	it("rejects actor delegation when may_act iss does not match actor iss", async () => {
		const g = buildGrant();
		const subject = await signSelfIssuedAccessToken({
			family_id: "fam-1",
			may_act: [{ sub: "svc-a", iss: "https://trusted.example" }],
		});
		const actor = await signSelfIssuedAccessToken({ sub: "svc-a", iss: ISSUER });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: subject,
				subject_token_type: ACCESS_TOKEN_TYPE,
				actor_token: actor,
				actor_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({
			status: 400,
			error: "invalid_request",
			errorDescription: expect.stringMatching(/may_act_violation/),
		});
	});

	it("rejects actor delegation when may_act is an empty actor list", async () => {
		const g = buildGrant();
		const subject = await signSelfIssuedAccessToken({
			family_id: "fam-1",
			may_act: [],
		});
		const actor = await signSelfIssuedAccessToken({ sub: "svc-a" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: subject,
				subject_token_type: ACCESS_TOKEN_TYPE,
				actor_token: actor,
				actor_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({
			status: 400,
			error: "invalid_request",
			errorDescription: expect.stringMatching(/may_act_violation/),
		});
	});

	it("rejects actor delegation fail-closed when may_act is malformed", async () => {
		const g = buildGrant();
		const subject = await signSelfIssuedAccessToken({
			family_id: "fam-1",
			may_act: "svc-a",
		});
		const actor = await signSelfIssuedAccessToken({ sub: "svc-a" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: subject,
				subject_token_type: ACCESS_TOKEN_TYPE,
				actor_token: actor,
				actor_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({
			status: 400,
			error: "invalid_request",
			errorDescription: expect.stringMatching(/may_act_violation/),
		});
	});

	it("rejects actor delegation when adding actor would exceed maxActorChainDepth", async () => {
		const g = buildGrant({
			config: {
				...mockConfig,
				oauth: {
					...mockConfig.oauth,
					tokenExchange: { maxActorChainDepth: 2 },
				},
			} as unknown as AppConfig,
		});
		const subject = await signSelfIssuedAccessToken({
			family_id: "fam-1",
			act: { sub: "svc-2", act: { sub: "svc-1" } },
		});
		const actor = await signSelfIssuedAccessToken({ sub: "svc-3" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: subject,
				subject_token_type: ACCESS_TOKEN_TYPE,
				actor_token: actor,
				actor_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({
			status: 400,
			error: "invalid_request",
			errorDescription: expect.stringMatching(/actor_chain_too_deep/),
		});
	});

	it("inherits family_id from subject (cascade revoke)", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ family_id: "fam-xyz" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.family_id).toBe("fam-xyz");
	});
});

describe("createTokenExchangeGrant — policy hook", () => {
	it("rejects with access_denied when policy hook denies", async () => {
		const g = buildGrant({ grantPolicy: denyPolicy });
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({ status: 403, error: "access_denied" });
	});

	it("applies policy hook grantedScope / grantedAudience overrides", async () => {
		const g = buildGrant({
			grantPolicy: overridePolicy,
			clientRepository: mockClientRepository(
				publicClient({ allowedAudiences: ["billing", "inventory"] }),
			),
		});
		const token = await signSelfIssuedAccessToken({
			family_id: "fam-1",
			scope: "read write",
			aud: ["billing", "inventory"],
		});
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				scope: "read write",
				audience: ["billing", "inventory"],
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		expect(result.tokens.scope).toBe("read");
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.aud).toBe("billing");
	});

	it("returns temporarily_unavailable (503) when policy hook throws", async () => {
		const throwing: GrantPolicyHook = {
			kind: "throw",
			async evaluate() {
				throw new Error("policy infrastructure down");
			},
		};
		const g = buildGrant({ grantPolicy: throwing });
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			}),
		);
		expect(result).toMatchObject({ status: 503, error: "temporarily_unavailable" });
	});

	it("passes resource parameter through to the policy hook request", async () => {
		let captured: GrantPolicyRequest | null = null;
		const capturing: GrantPolicyHook = {
			kind: "capture",
			async evaluate(req) {
				captured = req;
				return { outcome: "allow", grantedAudience: ["https://api.example.com"] };
			},
		};
		const g = buildGrant({
			grantPolicy: capturing,
			clientRepository: mockClientRepository(
				publicClient({ allowedAudiences: ["https://api.example.com"] }),
			),
		});
		const token = await signSelfIssuedAccessToken({
			aud: ["https://api.example.com"],
			family_id: "fam-1",
		});
		await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				resource: "https://api.example.com",
			}),
		);
		expect(captured).not.toBeNull();
		expect(captured?.resource).toEqual(["https://api.example.com"]);
	});

	it("rejects resource when it is missing from the issued-token audience", async () => {
		const policy: GrantPolicyHook = {
			kind: "resource-missing",
			async evaluate() {
				return { outcome: "allow", grantedAudience: ["https://other.example.com"] };
			},
		};
		const g = buildGrant({
			grantPolicy: policy,
			clientRepository: mockClientRepository(
				publicClient({ allowedAudiences: ["https://other.example.com"] }),
			),
		});
		const token = await signSelfIssuedAccessToken({
			aud: ["https://api.example.com", "https://other.example.com"],
			family_id: "fam-1",
		});
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				resource: "https://api.example.com",
			}),
		);
		expect(result).toMatchObject({
			status: 400,
			error: "invalid_target",
			errorDescription: expect.stringMatching(/requested_resources_not_in_audience/),
		});
	});

	it("rejects resources that are only present in non-issued policy audience entries", async () => {
		const policy: GrantPolicyHook = {
			kind: "resource-non-issued-aud",
			async evaluate() {
				return {
					outcome: "allow",
					grantedAudience: ["https://api.example.com/users", "https://api.example.com/orders"],
				};
			},
		};
		const g = buildGrant({
			grantPolicy: policy,
			clientRepository: mockClientRepository(
				publicClient({
					allowedAudiences: ["https://api.example.com/users", "https://api.example.com/orders"],
				}),
			),
		});
		const token = await signSelfIssuedAccessToken({
			aud: ["https://api.example.com/users", "https://api.example.com/orders"],
			family_id: "fam-1",
		});
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				resource: ["https://api.example.com/users", "https://api.example.com/orders"],
			}),
		);
		expect(result).toMatchObject({
			status: 400,
			error: "invalid_target",
			errorDescription: expect.stringMatching(/requested_resources_not_in_audience/),
		});
	});

	it("mints a token when requested resource equals the issued-token audience", async () => {
		const policy: GrantPolicyHook = {
			kind: "resource-ok",
			async evaluate() {
				return {
					outcome: "allow",
					grantedAudience: ["https://api.example.com/users"],
				};
			},
		};
		const g = buildGrant({
			grantPolicy: policy,
			clientRepository: mockClientRepository(
				publicClient({ allowedAudiences: ["https://api.example.com/users"] }),
			),
		});
		const token = await signSelfIssuedAccessToken({
			aud: ["https://api.example.com/users"],
			family_id: "fam-1",
		});
		const { result } = await g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token: token,
				subject_token_type: ACCESS_TOKEN_TYPE,
				resource: "https://api.example.com/users",
			}),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.aud).toBe("https://api.example.com/users");
	});
});

// D-6 Codex post-review P2: when this grant runs behind `clientAuthMw` on
// `/oauth/token`, the route already authenticated the client via Basic header
// or body credentials and populated `ctx.authenticatedClient`. Trusting that
// identity (and falling back to body credentials only when it is null) keeps
// Basic-authenticated callers working AND retains the body-credential gate
// for consumers wiring the grant onto a custom route.
describe("createTokenExchangeGrant — D-6 ctx.authenticatedClient route-bound flow", () => {
	const authedConfidential = {
		clientId: "client-a",
		tokenEndpointAuthMethod: "client_secret_basic" as const,
	};

	it("accepts a request with no body credentials when ctx.authenticatedClient is set (Basic auth at /token)", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx(
				{
					// no client_secret in body — Basic auth supplied it via clientAuthMw
					client_id: "client-a",
					subject_token: token,
					subject_token_type: ACCESS_TOKEN_TYPE,
				},
				{ authenticatedClient: authedConfidential },
			),
		);
		expect(result.status).toBe(200);
	});

	it("accepts a Basic-auth request that omits body.client_id entirely (uses ctx.authenticatedClient.clientId)", async () => {
		// Standard `Authorization: Basic <creds>` callers don't repeat
		// `client_id` in the body. The grant must derive identity from
		// `ctx.authenticatedClient` rather than rejecting the request.
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx(
				{
					subject_token: token,
					subject_token_type: ACCESS_TOKEN_TYPE,
				},
				{ authenticatedClient: authedConfidential },
			),
		);
		expect(result.status).toBe(200);
		if (result.status !== 200) return;
		// `azp` is bound to the authenticated client id.
		const at = decodeJwt((result.tokens as { access_token: string }).access_token) as Record<
			string,
			unknown
		>;
		expect(at.azp).toBe("client-a");
	});

	it("rejects when body.client_id differs from ctx.authenticatedClient.clientId (cross-client spoof)", async () => {
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx(
				{
					client_id: "spoofed-client", // ≠ authenticatedClient.clientId
					subject_token: token,
					subject_token_type: ACCESS_TOKEN_TYPE,
				},
				{ authenticatedClient: authedConfidential },
			),
		);
		expect(result.status).toBe(400);
		if (!("error" in result)) expect.fail("Expected error in result");
		expect(result.error).toBe("invalid_request");
		expect(result.errorDescription).toMatch(/client_id does not match/);
	});

	it("rejects malformed body.client_id (string[]) instead of silently falling back to authenticated client", async () => {
		// Codex P2: a repeated `client_id` form param produces `string[]`. The
		// fallback path must NOT treat this as "absent" — otherwise an attacker
		// could append a bogus client_id alongside a valid Basic header and
		// bypass the cross-client equality check.
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx(
				{
					client_id: ["client-a", "spoof"], // malformed — repeated param
					subject_token: token,
					subject_token_type: ACCESS_TOKEN_TYPE,
				},
				{ authenticatedClient: authedConfidential },
			),
		);
		expect(result.status).toBe(400);
		if (!("error" in result)) expect.fail("Expected error in result");
		expect(result.error).toBe("invalid_request");
		expect(result.errorDescription).toMatch(/client_id must be a single string value/);
	});

	it("rejects public clients (`tokenEndpointAuthMethod: 'none'`) regardless of route", async () => {
		// `clientAuthMw` admits public clients on `/oauth/token` (PKCE is
		// the authenticity gate at `/oauth/authorize`), but Token Exchange
		// has no PKCE and is confidential-only. The grant must refuse.
		const g = buildGrant();
		const token = await signSelfIssuedAccessToken({ family_id: "fam-1" });
		const { result } = await g.handle(
			ctx(
				{
					client_id: "spa-client",
					subject_token: token,
					subject_token_type: ACCESS_TOKEN_TYPE,
				},
				{
					authenticatedClient: {
						clientId: "spa-client",
						tokenEndpointAuthMethod: "none",
					},
				},
			),
		);
		expect(result.status).toBe(401);
		if (!("error" in result)) expect.fail("Expected error in result");
		expect(result.error).toBe("invalid_client");
		expect(result.errorDescription).toMatch(/does not support public clients/);
	});
});

describe("createTokenExchangeGrant — the session behind a sid-carrying token", () => {
	// A token minted from a browser session carries its `sid`, and a logout
	// ends it: introspection, `/userinfo` and the refresh grant all read the
	// UserSession it names. The exchange dropped the `sid`, so the token it
	// issued stayed active after the logout that ended its subject token —
	// and it accepted a subject token whose session was already gone.

	/** A store holding `user-1`'s live session under `sid-live`, and `svc-a`'s under `sid-actor`. */
	const liveSessions = async (): Promise<UserSessionStore> => {
		const store = createInMemoryUserSessionStore();
		for (const [sid, sub] of [
			["sid-live", "user-1"],
			["sid-actor", "svc-a"],
		] as const) {
			await store.create({
				sid,
				sub,
				authTime: new Date(),
				expiresAt: new Date(Date.now() + 3_600_000),
				claims: {},
				amr: ["pwd"],
			});
		}
		return store;
	};

	const exchange = (g: ReturnType<typeof buildGrant>, body: Record<string, unknown>) =>
		g.handle(
			ctx({
				client_id: "client-a",
				client_secret: "any",
				subject_token_type: ACCESS_TOKEN_TYPE,
				...body,
			}),
		);

	const issued = (result: Awaited<ReturnType<typeof exchange>>["result"]) => {
		if (!("tokens" in result)) throw new Error(`expected tokens, got ${JSON.stringify(result)}`);
		return decodeJwt(result.tokens.access_token);
	};

	it("carries the subject token's sid onto the issued token", async () => {
		const g = buildGrant({ userSessionStore: await liveSessions() });
		const { result } = await exchange(g, {
			subject_token: await signSelfIssuedAccessToken({ sid: "sid-live" }),
		});
		expect(result.status).toBe(200);
		expect(issued(result).sid).toBe("sid-live");
	});

	it("carries the sid without a store to check it against, as introspection reads it then", async () => {
		// With no UserSession store wired nothing anywhere judges a `sid`, and
		// the one the exchange would drop is the one a later wiring reads.
		const g = buildGrant();
		const { result } = await exchange(g, {
			subject_token: await signSelfIssuedAccessToken({ sid: "sid-live" }),
		});
		expect(result.status).toBe(200);
		expect(issued(result).sid).toBe("sid-live");
	});

	it("stamps no sid for a subject token without one, and reads no session", async () => {
		const store = await liveSessions();
		const get = vi.spyOn(store, "get");
		const { result } = await exchange(buildGrant({ userSessionStore: store }), {
			subject_token: await signSelfIssuedAccessToken({}),
		});
		expect(result.status).toBe(200);
		expect(issued(result)).not.toHaveProperty("sid");
		expect(get).not.toHaveBeenCalled();
	});

	it("refuses a subject token whose session has ended, with invalid_request session_invalid", async () => {
		// RFC 8693 §2.2.2: a subject_token unacceptable for any reason is
		// `invalid_request`. The refresh grant's words for the same finding.
		const store = await liveSessions();
		const g = buildGrant({ userSessionStore: store });
		const subject = await signSelfIssuedAccessToken({ sid: "sid-live" });
		await store.delete("sid-live");
		const { result } = await exchange(g, { subject_token: subject });
		expect(result).toEqual({
			status: 400,
			error: "invalid_request",
			errorDescription: "session_invalid",
		});
	});

	it("refuses an actor_token whose session has ended, naming the actor", async () => {
		const store = await liveSessions();
		const g = buildGrant({ userSessionStore: store });
		const actor = await signSelfIssuedAccessToken({ sub: "svc-a", sid: "sid-actor" });
		await store.delete("sid-actor");
		const { result } = await exchange(g, {
			subject_token: await signSelfIssuedAccessToken({
				sid: "sid-live",
				may_act: [{ sub: "svc-a", iss: ISSUER }],
			}),
			actor_token: actor,
			actor_token_type: ACCESS_TOKEN_TYPE,
		});
		expect(result).toEqual({
			status: 400,
			error: "invalid_request",
			errorDescription: "actor_token session_invalid",
		});
	});

	it("answers a session store that cannot be read with 503, logged once at error, and issues nothing", async () => {
		const store = await liveSessions();
		vi.spyOn(store, "get").mockRejectedValue(storeReplyError());
		const logger = spyLogger();
		const { result } = await exchange(buildGrant({ userSessionStore: store, logger }), {
			subject_token: await signSelfIssuedAccessToken({ sid: "sid-live" }),
		});
		expect(result).toEqual({
			status: 503,
			error: "temporarily_unavailable",
			errorDescription: "session store unavailable",
		});
		expectOutageLine(logger, "token_exchange_session_store_unavailable", {
			store: "user_session",
			step: "get",
			role: "subject",
			err: expect.objectContaining({ name: "ReplyError" }),
		});
	});
});
