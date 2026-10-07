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
 * The token-exchange grant under `oauth.requireEmailVerified`, read from the
 * `oauthTokenSettings` slot. With the setting on, the grant reads the user
 * behind the subject token's `sub` — the subject the issued token names —
 * through `userRepository.findBySubject`, once the presented tokens have
 * passed their checks and before the targets, the grant policy and signing:
 * a user the Store does not hold, or whose email is not verified
 * (`isEmailVerified`), is `invalid_grant` "email address is not verified";
 * a lookup that throws is a 503. No subject is exempt: a subject token whose
 * `sub` is a client's (a `client_credentials` token) names no user, and is
 * refused. The actor is not read. A grant built with the setting on and no
 * repository that can look a user up is refused, and so is the composition.
 * With the setting off, nothing is read.
 */

import {
	type AppConfig,
	type AppHandle,
	type ClientRepository,
	type CodeRepository,
	createApp,
	defaultRefreshTokenFamilyRevocationModule,
	defineModule,
	type GrantHandler,
	type GrantResult,
	jwksModule,
	type Module,
	memoryRefreshTokenFamilyStoreModule,
	type PublicClient,
	type User,
	type UserRepository,
} from "@o3co/auth-provider-core";
import {
	createTestOAuthTokenSettings,
	createTestUserRepository,
	makeValidAppConfig,
	renamedVariableCaptures,
	type TestUserRepositoryOptions,
} from "@o3co/auth-provider-core/testing";
import { oauthEndpointsModule } from "@o3co/auth-provider-oauth";
import express from "express";
import { decodeJwt } from "jose";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	ACCESS_TOKEN_TYPE,
	createTokenExchangeGrant,
	TOKEN_EXCHANGE_GRANT_TYPE,
} from "#/grant.mjs";
import { tokenExchangeModule } from "#/module.mjs";
import { createSelfIssuedAccessTokenValidator } from "#/validator/selfIssuedAccessToken.mjs";
import {
	ISSUER,
	keyStore,
	makeFamilyRevocation,
	signSelfIssuedAccessToken,
	tokensOf,
} from "./fixtures.mjs";

const SUBJECT = "user-1";
const ACTOR = "svc-a";
const SECRET = "client-secret";

const NOT_VERIFIED = {
	status: 400,
	error: "invalid_grant",
	errorDescription: "email address is not verified",
} as const;

const verified: User = { id: SUBJECT, username: "alice", emailVerified: true };

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
	authenticate: async (id, secret) => (id === client.clientId && secret === SECRET ? client : null),
};

/** A logger whose every level is a spy; `child` answers the same logger. */
function spyLogger() {
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
	return logger;
}

interface Arrangement {
	readonly requireEmailVerified: boolean;
	/** The repository in the deps; `null` leaves the slot unfilled. */
	readonly userRepository?: TestUserRepositoryOptions | null;
}

/** The deps, the spies a run reads, and the grant built over them. */
function arrange(a: Arrangement) {
	const evaluate = vi.fn(async () => ({ outcome: "allow" }) as const);
	const sign = vi.spyOn(keyStore, "sign");
	const userRepository =
		a.userRepository === null
			? undefined
			: createTestUserRepository(a.userRepository ?? { users: [verified] });
	const logger = spyLogger();
	const deps = {
		oauthTokenSettings: createTestOAuthTokenSettings({
			issuer: ISSUER,
			accessTokenLifetime: { defaultExpiresIn: 300, maxExpiresIn: 300 },
			requireEmailVerified: a.requireEmailVerified,
		}),
		keyStore,
		refreshTokenFamilyRevocation: makeFamilyRevocation(),
		tokenExchangeValidatorResolver: new Map([
			[ACCESS_TOKEN_TYPE, createSelfIssuedAccessTokenValidator({ keyStore, issuer: ISSUER })],
		]),
		clientRepository,
		grantPolicy: { kind: "test-allow", evaluate },
		logger,
		...(userRepository === undefined
			? {}
			: { userRepository: userRepository satisfies UserRepository }),
	};
	return {
		deps,
		evaluate,
		sign,
		logger,
		lookups: () => userRepository?.lookups ?? [],
		build: () => createTokenExchangeGrant(deps),
	};
}

const exchange = async (grant: GrantHandler, body: Record<string, unknown>): Promise<GrantResult> =>
	(
		await grant.handle({
			body: {
				client_id: client.clientId,
				client_secret: SECRET,
				subject_token_type: ACCESS_TOKEN_TYPE,
				...body,
			},
			session: {},
			issuer: ISSUER,
			metadata: {},
			authenticatedClient: null,
		})
	).result;

afterEach(() => {
	vi.restoreAllMocks();
});

describe("createTokenExchangeGrant — oauth.requireEmailVerified on", () => {
	for (const [label, users] of [
		["whose email is not verified", [{ ...verified, emailVerified: false }]],
		["whose Store publishes no verification state", [{ id: SUBJECT, username: "alice" }]],
		[
			"whose verification state is a truthy non-boolean",
			[{ ...verified, emailVerified: "true" as unknown as boolean }],
		],
		["the Store does not hold", []],
	] as const) {
		it(`refuses a subject ${label}, with no policy asked and nothing signed`, async () => {
			const h = arrange({ requireEmailVerified: true, userRepository: { users } });

			const result = await exchange(h.build(), {
				subject_token: await signSelfIssuedAccessToken({}),
			});

			expect(result).toEqual(NOT_VERIFIED);
			expect(h.lookups()).toEqual([SUBJECT]);
			expect(h.evaluate).not.toHaveBeenCalled();
			expect(h.sign).not.toHaveBeenCalled();
		});
	}

	it("refuses a subject token whose sub is a client's: no machine subject is exempt", async () => {
		// A `client_credentials` access token names the client as its subject.
		const h = arrange({ requireEmailVerified: true });

		const result = await exchange(h.build(), {
			subject_token: await signSelfIssuedAccessToken({ sub: client.clientId }),
		});

		expect(result).toEqual(NOT_VERIFIED);
		expect(h.lookups()).toEqual([client.clientId]);
		expect(h.sign).not.toHaveBeenCalled();
	});

	it("mints for a verified subject, after reading the user behind its sub", async () => {
		const h = arrange({ requireEmailVerified: true });

		const result = await exchange(h.build(), {
			subject_token: await signSelfIssuedAccessToken({}),
		});

		expect(decodeJwt(tokensOf(result).access_token)).toMatchObject({ sub: SUBJECT });
		expect(h.lookups()).toEqual([SUBJECT]);
		expect(h.evaluate).toHaveBeenCalledTimes(1);
	});

	it("reads the subject alone, not the actor", async () => {
		const h = arrange({ requireEmailVerified: true });

		const result = await exchange(h.build(), {
			subject_token: await signSelfIssuedAccessToken({}),
			actor_token: await signSelfIssuedAccessToken({ sub: ACTOR }),
			actor_token_type: ACCESS_TOKEN_TYPE,
		});

		expect(decodeJwt(tokensOf(result).access_token)).toMatchObject({
			sub: SUBJECT,
			act: { sub: ACTOR },
		});
		expect(h.lookups()).toEqual([SUBJECT]);
	});

	it("reads no user for a subject token that does not validate", async () => {
		const h = arrange({ requireEmailVerified: true });

		const result = await exchange(h.build(), { subject_token: "not-a-jwt" });

		expect(result).toMatchObject({ status: 400, error: "invalid_request" });
		expect(h.lookups()).toEqual([]);
	});

	it("answers 503 when the lookup throws, logged as a store outage, with no policy asked and nothing signed", async () => {
		const h = arrange({
			requireEmailVerified: true,
			userRepository: { users: [verified], unavailable: new Error("store down: secret") },
		});

		const result = await exchange(h.build(), {
			subject_token: await signSelfIssuedAccessToken({}),
		});

		expect(result).toEqual({
			status: 503,
			error: "temporarily_unavailable",
			errorDescription: "identity resolution unavailable",
		});
		expect(h.evaluate).not.toHaveBeenCalled();
		expect(h.sign).not.toHaveBeenCalled();
		expect(h.logger.error).toHaveBeenCalledTimes(1);
		const [fields, event] = h.logger.error.mock.calls[0] as [Record<string, unknown>, string];
		expect(event).toBe("token_exchange_user_repository_unavailable");
		expect(fields).toMatchObject({
			store: "user_repository",
			step: "read",
			clientId: client.clientId,
		});
		expect(fields.err).not.toBeInstanceOf(Error);
	});

	it("answers 503 when reading the user's emailVerified throws", async () => {
		// An accessor-backed record (an ORM entity) whose field read reaches the backend.
		class LazyUser {
			readonly id = SUBJECT;
			readonly username = "alice";
			get emailVerified(): boolean {
				throw new Error("lazy load failed: secret");
			}
		}
		const h = arrange({
			requireEmailVerified: true,
			userRepository: { users: [new LazyUser() as User] },
		});

		const result = await exchange(h.build(), {
			subject_token: await signSelfIssuedAccessToken({}),
		});

		expect(result).toEqual({
			status: 503,
			error: "temporarily_unavailable",
			errorDescription: "identity resolution unavailable",
		});
		expect(h.evaluate).not.toHaveBeenCalled();
		expect(h.sign).not.toHaveBeenCalled();
		expect(h.logger.error).toHaveBeenCalledTimes(1);
		expect(h.logger.error.mock.calls[0]?.[1]).toBe("token_exchange_user_repository_unavailable");
	});

	it("refuses to build without a userRepository", () => {
		const h = arrange({ requireEmailVerified: true, userRepository: null });

		expect(() => h.build()).toThrow(/requireEmailVerified.*userRepository.*findBySubject/);
	});

	it("refuses to build over a userRepository without findBySubject", () => {
		const h = arrange({
			requireEmailVerified: true,
			userRepository: { users: [verified], subjectLookup: false },
		});

		expect(() => h.build()).toThrow(/requireEmailVerified.*userRepository.*findBySubject/);
	});
});

describe("createTokenExchangeGrant — oauth.requireEmailVerified off", () => {
	for (const [label, userRepository] of [
		["reads no user from a repository that can look one up", { users: [] }],
		["builds and mints without a userRepository", null],
		["builds and mints over a userRepository without findBySubject", { subjectLookup: false }],
	] as const) {
		it(label, async () => {
			const h = arrange({ requireEmailVerified: false, userRepository });

			const result = await exchange(h.build(), {
				subject_token: await signSelfIssuedAccessToken({}),
			});

			expect(result).toMatchObject({ status: 200 });
			expect(h.lookups()).toEqual([]);
		});
	}
});

describe("tokenExchangeModule — the userRepository slot", () => {
	it("declares it optional, with no absence policy, and hands it to the grant", async () => {
		expect(tokenExchangeModule.optional).toContain("userRepository");
		expect(tokenExchangeModule.requires).not.toContain("userRepository");
		expect(Object.keys(tokenExchangeModule.absencePolicies ?? {})).not.toContain("userRepository");

		const h = arrange({
			requireEmailVerified: true,
			userRepository: { users: [{ ...verified, emailVerified: false }] },
		});
		const factory = tokenExchangeModule.contributes?.grants?.[TOKEN_EXCHANGE_GRANT_TYPE];
		if (!factory) throw new Error("tokenExchangeModule contributes no token_exchange grant");
		const grant = (await factory(h.deps as never)) as GrantHandler;

		const result = await exchange(grant, { subject_token: await signSelfIssuedAccessToken({}) });

		expect(result).toEqual(NOT_VERIFIED);
		expect(h.lookups()).toEqual([SUBJECT]);
	});
});

describe("a composition installing tokenExchangeModule under oauth.requireEmailVerified", () => {
	let handle: AppHandle | undefined;
	afterEach(async () => {
		await handle?.dispose();
		handle = undefined;
	});

	/** `oauthEndpointsModule` requires one; nothing here runs the authorization-code flow. */
	const codeRepository: CodeRepository = {
		createCode: async () => {
			throw new Error("the authorization-code flow is not exercised here");
		},
		findByCode: async () => null,
		consumeByCode: async () => null,
		removeByCode: async () => {},
	};

	/** Boots the token-exchange composition with the setting on, `userRepository` filled when given. */
	async function boot(userRepository?: UserRepository): Promise<express.Express> {
		const base = makeValidAppConfig();
		const config: AppConfig = {
			...base,
			oauth: {
				...base.oauth,
				jwt: { ...base.oauth.jwt, issuer: ISSUER },
				oidcMode: "oidc-required",
				requireEmailVerified: true,
				revocation: { accessToken: "unsupported", subject: "unsupported" },
			},
		};
		const modules: Module[] = [
			oauthEndpointsModule,
			tokenExchangeModule,
			memoryRefreshTokenFamilyStoreModule,
			defaultRefreshTokenFamilyRevocationModule,
			jwksModule,
			defineModule({
				name: "test:deployment-providers",
				provides: {
					clientRepository: () => clientRepository,
					codeRepository: () => codeRepository,
					keyStore: () => keyStore,
					...(userRepository === undefined ? {} : { userRepository: () => userRepository }),
				},
			}),
		];
		handle = await createApp({
			modules,
			bootstrapComponents: {
				config: {
					...config,
					"renamed-variables": {
						...(config as { "renamed-variables"?: object })["renamed-variables"],
						...renamedVariableCaptures({ modules, env: {} }),
					},
				},
				pathResolver: (s: string) => s,
			},
		});
		const app = express();
		app.use(handle.router);
		return app;
	}

	const post = async (app: express.Express) =>
		request(app)
			.post("/oauth/token")
			.auth(client.clientId, SECRET)
			.type("form")
			.send({
				grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
				subject_token: await signSelfIssuedAccessToken({}),
				subject_token_type: ACCESS_TOKEN_TYPE,
			});

	it("refuses to start without a userRepository", async () => {
		await expect(boot()).rejects.toThrow(/requireEmailVerified.*userRepository.*findBySubject/);
	});

	it("refuses to start over a userRepository without findBySubject", async () => {
		await expect(
			boot(createTestUserRepository({ users: [verified], subjectLookup: false })),
		).rejects.toThrow(/requireEmailVerified.*userRepository.*findBySubject/);
	});

	it("answers 400 invalid_grant at /oauth/token for a subject whose email is not verified", async () => {
		const app = await boot(
			createTestUserRepository({ users: [{ ...verified, emailVerified: false }] }),
		);

		const res = await post(app);

		expect(res.status).toBe(400);
		expect(res.body).toEqual({
			error: "invalid_grant",
			error_description: "email address is not verified",
		});
	});

	it("mints at /oauth/token for a verified subject", async () => {
		const app = await boot(createTestUserRepository({ users: [verified] }));

		const res = await post(app);

		expect(res.status).toBe(200);
		expect(decodeJwt(res.body.access_token as string)).toMatchObject({ sub: SUBJECT });
	});
});
