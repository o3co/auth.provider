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
 * What the exchange holds to at the instant it mints: the presented tokens are
 * validated, and their family and session rules applied, again after the
 * policy, and the issued token's `iat` is the instant fixed before the first
 * validation.
 */

import {
	type AccessTokenDenylist,
	type ClientRepository,
	createInMemorySubjectRevocation,
	createInMemoryUserSessionStore,
	createMemoryAccessTokenDenylist,
	type ExchangeTokenValidator,
	type GrantPolicyHook,
	type GrantResult,
	type PublicClient,
	passwordSessionAuthentication,
	type RefreshTokenFamilyRevocation,
	type SubjectRevocation,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { decodeJwt } from "jose";
import { afterEach, describe, expect, it, vi } from "vitest";
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
const SUBJECT = "user-1";
const ACTOR = "svc-a";

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

interface Wiring {
	readonly accessTokenDenylist?: AccessTokenDenylist;
	readonly subjectRevocation?: SubjectRevocation;
	readonly userSessionStore?: UserSessionStore;
	readonly refreshTokenFamilyRevocation?: RefreshTokenFamilyRevocation;
	readonly grantPolicy?: GrantPolicyHook;
	readonly logger?: ReturnType<typeof spyLogger>;
	/** In place of the built-in validator over the wired revocation stores. */
	readonly validator?: ExchangeTokenValidator;
}

function buildGrant(wiring: Wiring = {}) {
	const validator =
		wiring.validator ??
		createSelfIssuedAccessTokenValidator({
			keyStore,
			issuer: ISSUER,
			...(wiring.accessTokenDenylist ? { accessTokenDenylist: wiring.accessTokenDenylist } : {}),
			...(wiring.subjectRevocation ? { subjectRevocation: wiring.subjectRevocation } : {}),
		});
	return createTokenExchangeGrant({
		oauthTokenSettings: tokenSettings,
		keyStore,
		refreshTokenFamilyRevocation: wiring.refreshTokenFamilyRevocation ?? makeFamilyRevocation(),
		tokenExchangeValidatorResolver: new Map([[ACCESS_TOKEN_TYPE, validator]]),
		clientRepository,
		...(wiring.grantPolicy ? { grantPolicy: wiring.grantPolicy } : {}),
		...(wiring.logger ? { logger: wiring.logger } : {}),
		...(wiring.userSessionStore ? { userSessionStore: wiring.userSessionStore } : {}),
	});
}

const exchange = async (
	grant: ReturnType<typeof buildGrant>,
	body: Record<string, unknown>,
): Promise<GrantResult> =>
	(
		await grant.handle({
			body: {
				client_id: "client-a",
				client_secret: "any",
				subject_token_type: ACCESS_TOKEN_TYPE,
				...body,
			},
			session: {},
			issuer: ISSUER,
			metadata: {},
			authenticatedClient: null,
		})
	).result;

/** A policy that allows once `during` has run. */
const allowAfter = (during: () => Promise<void> | void): GrantPolicyHook => ({
	kind: "slow",
	evaluate: async () => {
		await during();
		return { outcome: "allow" };
	},
});

/** The presented tokens, each with a jti, a family and a session. */
const presented = async (role: "subject" | "actor") => {
	const subject = await signSelfIssuedAccessToken({
		jti: "at-subject",
		family_id: "fam-subject",
		sid: "sid-subject",
	});
	if (role === "subject") return { subject_token: subject };
	return {
		subject_token: subject,
		actor_token: await signSelfIssuedAccessToken({
			sub: ACTOR,
			jti: "at-actor",
			family_id: "fam-actor",
			sid: "sid-actor",
		}),
		actor_token_type: ACCESS_TOKEN_TYPE,
	};
};

const SUB_OF = { subject: SUBJECT, actor: ACTOR } as const;
const forRole = (role: "subject" | "actor", description: string) =>
	role === "actor" ? `actor_token ${description}` : description;
const refusal = (role: "subject" | "actor", description: string) => ({
	status: 400,
	error: "invalid_request",
	errorDescription: forRole(role, description),
});
/** The validator's own answers name the token: `subject_token …`, `actor_token …`. */
const validation = (role: "subject" | "actor", what: string) => `${role}_token validation ${what}`;
const outage = (description: string) => ({
	status: 503,
	error: "temporarily_unavailable",
	errorDescription: description,
});

/** The subject's and the actor's live sessions. */
const liveSessions = async (): Promise<UserSessionStore> => {
	const store = createInMemoryUserSessionStore();
	for (const [sid, sub] of [
		["sid-subject", SUBJECT],
		["sid-actor", ACTOR],
	] as const) {
		await store.create({
			sid,
			sub,
			authTime: new Date(),
			expiresAt: new Date(Date.now() + 3_600_000),
			claims: {},
			...passwordSessionAuthentication(),
		});
	}
	return store;
};

/** A family store whose revoked set the test changes. */
const families = () => {
	const revoked = new Set<string>();
	return {
		revoked,
		revocation: makeFamilyRevocation({ isFamilyRevoked: async (f) => revoked.has(f) }),
	};
};

/** Answers through `answer`, but throws from its `failing`-th call for `key` on. */
const failingFrom = <T,>(failing: number, key: string, answer: (k: string) => T | Promise<T>) => {
	let calls = 0;
	return async (k: string): Promise<T> => {
		if (k === key) {
			calls += 1;
			if (calls >= failing) throw new Error("store unreachable");
		}
		return await answer(k);
	};
};

afterEach(() => {
	vi.useRealTimers();
});

describe("token exchange — the presented tokens are checked again after the policy, before minting", () => {
	it.each(["subject", "actor"] as const)(
		"a %s revocation landing while the policy evaluates mints nothing",
		async (role) => {
			const subjectRevocation = createInMemorySubjectRevocation();
			const policy = allowAfter(() =>
				subjectRevocation.revokeBefore(SUB_OF[role], new Date(), new Date(Date.now() + 3_600_000)),
			);
			const body = await presented(role);
			const during = await exchange(buildGrant({ subjectRevocation, grantPolicy: policy }), body);
			expect(during).toEqual({
				status: 400,
				error: "invalid_request",
				errorDescription: validation(role, "failed"),
			});
			// The answer the same request gets once the revocation has landed.
			expect(during).toEqual(await exchange(buildGrant({ subjectRevocation }), body));
		},
	);

	it.each(["subject", "actor"] as const)(
		"a %s_token denylisted while the policy evaluates mints nothing",
		async (role) => {
			const accessTokenDenylist = createMemoryAccessTokenDenylist();
			const policy = allowAfter(() =>
				accessTokenDenylist.add(`at-${role}`, Date.now() + 3_600_000),
			);
			const body = await presented(role);
			const during = await exchange(buildGrant({ accessTokenDenylist, grantPolicy: policy }), body);
			expect(during).toEqual({
				status: 400,
				error: "invalid_request",
				errorDescription: validation(role, "failed"),
			});
			expect(during).toEqual(await exchange(buildGrant({ accessTokenDenylist }), body));
		},
	);

	it.each(["subject", "actor"] as const)(
		"a %s session deleted while the policy evaluates mints nothing",
		async (role) => {
			const userSessionStore = await liveSessions();
			const policy = allowAfter(() => userSessionStore.delete(`sid-${role}`));
			const body = await presented(role);
			const during = await exchange(buildGrant({ userSessionStore, grantPolicy: policy }), body);
			expect(during).toEqual(refusal(role, "session_invalid"));
			expect(during).toEqual(await exchange(buildGrant({ userSessionStore }), body));
		},
	);

	it.each(["subject", "actor"] as const)(
		"a %s family revoked while the policy evaluates mints nothing",
		async (role) => {
			const { revoked, revocation } = families();
			const policy = allowAfter(() => {
				revoked.add(`fam-${role}`);
			});
			const body = await presented(role);
			const during = await exchange(
				buildGrant({ refreshTokenFamilyRevocation: revocation, grantPolicy: policy }),
				body,
			);
			expect(during).toEqual(refusal(role, "family_revoked"));
			expect(during).toEqual(
				await exchange(buildGrant({ refreshTokenFamilyRevocation: revocation }), body),
			);
		},
	);

	describe("an outage on the second check is answered and logged as on the first", () => {
		const policy = allowAfter(() => {});

		/** The answer and the one error line, for stores failing from their `failing`-th read. */
		const answered = async (
			role: "subject" | "actor",
			wire: (failing: number) => Wiring | Promise<Wiring>,
		) => {
			const runs = [];
			for (const failing of [1, 2]) {
				const logger = spyLogger();
				const result = await exchange(
					buildGrant({ ...(await wire(failing)), grantPolicy: policy, logger }),
					await presented(role),
				);
				expect(logger.error).toHaveBeenCalledTimes(1);
				const [line, event] = logger.error.mock.calls[0] as [Record<string, unknown>, string];
				runs.push({ result, event, role: line.role, store: line.store });
			}
			const [first, second] = runs;
			expect(second).toEqual(first);
			return second;
		};

		it.each(["subject", "actor"] as const)("the denylist, for the %s_token", async (role) => {
			const run = await answered(role, (failing) => ({
				accessTokenDenylist: {
					kind: "test",
					add: async () => {},
					has: failingFrom(failing, `at-${role}`, () => false),
				},
			}));
			expect(run.result).toEqual(outage(validation(role, "store unavailable")));
			expect(run.event).toBe("token_exchange_validation_unavailable");
		});

		it.each(["subject", "actor"] as const)("the watermark, for the %s_token", async (role) => {
			const run = await answered(role, (failing) => ({
				subjectRevocation: {
					kind: "test",
					revokeBefore: async () => {},
					revokedBefore: failingFrom(failing, SUB_OF[role], () => null),
				},
			}));
			expect(run.result).toEqual(outage(validation(role, "store unavailable")));
			expect(run.event).toBe("token_exchange_validation_unavailable");
		});

		it.each(["subject", "actor"] as const)("the session store, for the %s_token", async (role) => {
			const run = await answered(role, async (failing) => {
				const store = await liveSessions();
				const get = store.get.bind(store);
				return {
					userSessionStore: Object.assign(store, { get: failingFrom(failing, `sid-${role}`, get) }),
				};
			});
			expect(run.result).toEqual(outage(forRole(role, "session store unavailable")));
			expect(run.event).toBe("token_exchange_session_store_unavailable");
			expect(run.store).toBe("user_session");
		});

		it.each(["subject", "actor"] as const)("the family store, for the %s_token", async (role) => {
			const run = await answered(role, (failing) => ({
				refreshTokenFamilyRevocation: makeFamilyRevocation({
					isFamilyRevoked: failingFrom(failing, `fam-${role}`, () => false),
				}),
			}));
			expect(run.result).toEqual(outage(forRole(role, "refresh token store unavailable")));
			expect(run.event).toBe("token_exchange_family_store_unavailable");
		});
	});

	it("still mints for a token nothing revoked, asking the validator and the stores twice", async () => {
		const validator = createSelfIssuedAccessTokenValidator({
			keyStore,
			issuer: ISSUER,
			accessTokenDenylist: createMemoryAccessTokenDenylist(),
			subjectRevocation: createInMemorySubjectRevocation(),
		});
		const validate = vi.spyOn(validator, "validate");
		const userSessionStore = await liveSessions();
		const get = vi.spyOn(userSessionStore, "get");
		const { revocation } = families();
		const isFamilyRevoked = vi.spyOn(revocation, "isFamilyRevoked");
		const result = await exchange(
			buildGrant({ validator, userSessionStore, refreshTokenFamilyRevocation: revocation }),
			await presented("actor"),
		);
		const claims = decodeJwt(tokensOf(result).access_token);
		expect(claims).toMatchObject({
			sub: SUBJECT,
			family_id: "fam-subject",
			liveness_sid: "sid-subject",
			act: { sub: ACTOR },
		});
		expect(validate.mock.calls.map(([, context]) => context.role)).toEqual([
			"subject",
			"actor",
			"subject",
			"actor",
		]);
		expect(get.mock.calls.map(([sid]) => sid)).toEqual([
			"sid-subject",
			"sid-actor",
			"sid-subject",
			"sid-actor",
		]);
		expect(isFamilyRevoked).toHaveBeenCalledTimes(4);
	});
});

describe("token exchange — the issued token's iat is the instant fixed before validation", () => {
	it("a subject revocation landing after a validator that reads no watermark answered covers the issued token", async () => {
		vi.useFakeTimers({ toFake: ["Date"] });
		vi.setSystemTime(new Date("2026-10-05T00:00:00.500Z"));
		const before = Math.floor(Date.now() / 1000);
		const subjectRevocation = createInMemorySubjectRevocation();
		const policy = allowAfter(async () => {
			await subjectRevocation.revokeBefore(SUBJECT, new Date(), new Date(Date.now() + 3_600_000));
			// The policy runs on past the revocation.
			vi.setSystemTime(Date.now() + 5_000);
		});
		// A validator of its own that consults no watermark: only the issuance
		// instant ties the issued token to the revocation.
		const result = await exchange(
			buildGrant({
				validator: createSelfIssuedAccessTokenValidator({ keyStore, issuer: ISSUER }),
				grantPolicy: policy,
			}),
			{ subject_token: await signSelfIssuedAccessToken({}) },
		);
		const issued = tokensOf(result).access_token;
		expect(decodeJwt(issued).iat).toBe(before);
		const watermarked = createSelfIssuedAccessTokenValidator({
			keyStore,
			issuer: ISSUER,
			subjectRevocation,
		});
		expect(await watermarked.validate(issued, { role: "subject" })).toBeNull();
	});

	it("refuses a subject token that expired while the exchange ran, and caps exp at its expiry", async () => {
		vi.useFakeTimers({ toFake: ["Date"] });
		vi.setSystemTime(new Date("2026-10-05T00:00:00.000Z"));
		const now = Math.floor(Date.now() / 1000);
		// A validator of its own that holds no expiry: the grant's own backstop is all there is.
		const reporting = (exp: number): ExchangeTokenValidator => ({
			validate: async () => ({ sub: SUBJECT, claims: { sub: SUBJECT, exp } }),
		});
		const advance = allowAfter(() => {
			vi.setSystemTime(Date.now() + 5_000);
		});
		const expired = await exchange(
			buildGrant({ validator: reporting(now + 3), grantPolicy: advance }),
			{ subject_token: "opaque" },
		);
		expect(expired).toEqual(refusal("subject", "subject_token has expired"));

		vi.setSystemTime(new Date("2026-10-05T00:00:00.000Z"));
		const live = await exchange(
			buildGrant({ validator: reporting(now + 60), grantPolicy: advance }),
			{ subject_token: "opaque" },
		);
		const claims = decodeJwt(tokensOf(live).access_token);
		expect(claims.iat).toBe(now);
		expect(claims.exp).toBe(now + 60);
	});
});
