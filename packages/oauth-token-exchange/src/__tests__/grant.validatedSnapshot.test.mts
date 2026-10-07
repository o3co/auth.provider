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
 * a string, or `claims` that are not an object, is a failed validation, at the
 * first asking and at the second. A claim key never changes what the copy
 * answers for another claim: an own `__proto__` key is copied as a key.
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
import { snapshotValidated } from "#/validatedSnapshot.mjs";
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

/** The answer for `role`'s token, on that token's `call`th asking (from 1). */
type Answering = (role: "subject" | "actor", call: number) => unknown;

function build(answer: Answering) {
	const userRepository = createTestUserRepository({ users });
	const policyRequests: GrantPolicyRequest[] = [];
	const calls = { subject: 0, actor: 0 };
	const validator: ExchangeTokenValidator = {
		validate: vi.fn(
			async (_token: string, { role }: { readonly role: "subject" | "actor" }) =>
				answer(role, ++calls[role]) as ValidatedToken | null,
		),
	};
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
	const exchange = async (body: Record<string, string> = {}): Promise<GrantResult> =>
		(
			await grant.handle({
				body: {
					grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
					client_id: client.clientId,
					client_secret: SECRET,
					subject_token: "an-external-token",
					subject_token_type: JWT_TOKEN_TYPE,
					...body,
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

const EXP = () => Math.floor(Date.now() / 1000) + 3600;

/** A well-formed subject answer naming the client, with `extra` laid over it. */
const subjectAnswer = (extra: Record<string, unknown> = {}): Record<string, unknown> => ({
	sub: "user-1",
	aud: "billing",
	scope: "read",
	claims: { azp: client.clientId, exp: EXP() },
	...extra,
});

const WITH_ACTOR = { actor_token: "an-actor-token", actor_token_type: JWT_TOKEN_TYPE };

const failedValidation = (role: "subject" | "actor") => ({
	status: 400,
	error: "invalid_request",
	errorDescription: `${role}_token validation failed`,
});

describe("token exchange reads each validator answer once — shapes and claims", () => {
	it("refuses an answer whose claims are not an object as a failed validation", async () => {
		const h = build(() => subjectAnswer({ claims: "azp=client-a" }));

		expect(await h.exchange()).toEqual(failedValidation("subject"));
		expect(h.lookups()).toEqual([]);
	});

	for (const [label, second] of [
		["whose sub is not a string", { sub: 42, claims: {} }],
		["whose claims are not an object", { sub: "user-1", claims: null }],
		["that is not an object", "user-1"],
	] as const) {
		it(`refuses an exchange whose second asking answers ${label}, as a failed validation`, async () => {
			const h = build((_role, call) => (call === 1 ? subjectAnswer() : second));

			expect(await h.exchange()).toEqual(failedValidation("subject"));
		});
	}

	it("mints from the claims the checks read, when a claim's accessor changes on a later read", async () => {
		const exp = EXP();
		const claims = Object.defineProperties(
			{},
			{
				azp: { get: shifting(client.clientId, "client-other"), enumerable: true },
				// Unbound at the matrix; bound on any later read.
				cnf: { get: shifting<unknown>(undefined, { jkt: "a-key" }), enumerable: true },
				// Live at the expiry check; long past on any later read.
				exp: { get: shifting(exp, 1), enumerable: true },
			},
		);
		const h = build(() => subjectAnswer({ claims }));

		const issued = decodeJwt(tokensOf(await h.exchange()).access_token);

		expect(issued.cnf).toBeUndefined();
		expect(issued.exp).toBeLessThanOrEqual(exp);
	});

	it("carries the subject's act chain as the checks read it, when a nested accessor changes", async () => {
		const act = Object.defineProperties(
			{},
			{ sub: { get: shifting("svc-0", "svc-9"), enumerable: true } },
		);
		const h = build((role) =>
			role === "subject"
				? subjectAnswer({
						act,
						claims: { azp: client.clientId, exp: EXP(), may_act: { sub: "svc-a" } },
					})
				: { sub: "svc-a", claims: {} },
		);

		const issued = decodeJwt(tokensOf(await h.exchange(WITH_ACTOR)).access_token);

		expect(issued.act).toEqual({ sub: "svc-a", act: { sub: "svc-0" } });
	});

	it("holds delegation to the may_act it checked, when the claim's accessor changes on a later read", async () => {
		const claims = Object.defineProperties(
			{ azp: client.clientId, exp: EXP() },
			{
				may_act: {
					get: shifting<unknown>({ sub: "svc-a" }, { sub: "svc-other" }),
					enumerable: true,
				},
			},
		);
		const h = build((role) =>
			role === "subject" ? subjectAnswer({ claims }) : { sub: "svc-a", claims: {} },
		);

		const issued = decodeJwt(tokensOf(await h.exchange(WITH_ACTOR)).access_token);

		expect(issued.act).toEqual({ sub: "svc-a" });
	});

	it("records the actor the checks passed, when the actor answer's sub changes on a later read", async () => {
		const actor = Object.freeze(
			Object.defineProperties(
				{},
				{
					sub: { get: shifting("svc-a", "svc-b"), enumerable: true },
					claims: { value: Object.freeze({}), enumerable: true },
				},
			),
		);
		const h = build((role) =>
			role === "subject"
				? subjectAnswer({ claims: { azp: client.clientId, exp: EXP(), may_act: { sub: "svc-a" } } })
				: actor,
		);

		const issued = decodeJwt(tokensOf(await h.exchange(WITH_ACTOR)).access_token);

		expect(issued.act).toEqual({ sub: "svc-a" });
	});
});

describe("snapshotValidated — an own __proto__ key", () => {
	it("copies a claims key named __proto__ as a key, never as the copy's prototype", () => {
		const answer = JSON.parse(
			'{"sub":"user-1","claims":{"__proto__":{"azp":"client-a","cnf":{"jkt":"a-key"}}}}',
		);

		const copy = snapshotValidated(answer);
		if (copy === null) throw new Error("expected a copy");

		expect(copy.claims.azp).toBeUndefined();
		expect(copy.claims.cnf).toBeUndefined();
		expect(Object.getPrototypeOf(copy.claims)).toBe(Object.prototype);
		expect(Object.hasOwn(copy.claims ?? {}, "__proto__")).toBe(true);
	});

	it("copies a nested key named __proto__ as a key", () => {
		const answer = JSON.parse(
			'{"sub":"user-1","claims":{"cnf":{"__proto__":{"jkt":"a-key"}},"may_act":{"__proto__":{"sub":"svc-a"}}},"act":{"__proto__":{"sub":"svc-0"}}}',
		);

		const copy = snapshotValidated(answer);
		if (copy === null) throw new Error("expected a copy");

		expect((copy.claims.cnf as Record<string, unknown>).jkt).toBeUndefined();
		expect((copy.claims.may_act as Record<string, unknown>).sub).toBeUndefined();
		expect(copy.act?.sub).toBeUndefined();
		expect(Object.hasOwn(copy.claims.cnf as object, "__proto__")).toBe(true);
	});

	it("refuses, at the exchange, a subject token whose only azp sits under an own __proto__ key", async () => {
		const h = build(() =>
			JSON.parse('{"sub":"user-1","aud":"billing","claims":{"__proto__":{"azp":"client-a"}}}'),
		);

		expect(await h.exchange()).toEqual({
			status: 400,
			error: "invalid_request",
			errorDescription: "subject_token azp and aud do not name this client",
		});
	});

	it("mints unbound, at the exchange, for a subject token whose only cnf sits under an own __proto__ key", async () => {
		const exp = EXP();
		const h = build(() =>
			JSON.parse(
				`{"sub":"user-1","aud":"billing","claims":{"azp":"client-a","exp":${exp},"cnf":{"__proto__":{"jkt":"a-key"}},"__proto__":{"cnf":{"jkt":"a-key"}}}}`,
			),
		);

		const issued = decodeJwt(tokensOf(await h.exchange()).access_token);

		expect(issued.cnf).toBeUndefined();
	});
});

describe("token exchange reads each validator answer once — members read by name", () => {
	it("still requires the proof for a cnf whose jkt is inherited", async () => {
		const cnf = Object.create({ jkt: "a-key" });
		const h = build(() => subjectAnswer({ claims: { azp: client.clientId, exp: EXP(), cnf } }));

		expect(await h.exchange()).toEqual({
			status: 400,
			error: "invalid_request",
			errorDescription: "subject_token requires a DPoP proof",
		});
	});

	it("still refuses the actor a may_act with an inherited iss refuses", async () => {
		const mayAct = Object.create(
			{ iss: "https://another-issuer.example" },
			{ sub: { value: "svc-a", enumerable: true } },
		);
		const h = build((role) =>
			role === "subject"
				? subjectAnswer({ claims: { azp: client.clientId, exp: EXP(), may_act: mayAct } })
				: { sub: "svc-a", claims: { iss: "https://actor-issuer.example" } },
		);

		expect(await h.exchange(WITH_ACTOR)).toEqual({
			status: 400,
			error: "invalid_request",
			errorDescription: "may_act_violation: actor not authorized by subject token",
		});
	});

	it("still refuses the actor an entry of a may_act array with an inherited iss refuses", async () => {
		const entry = Object.create(
			{ iss: "https://another-issuer.example" },
			{ sub: { value: "svc-a", enumerable: true } },
		);
		const h = build((role) =>
			role === "subject"
				? subjectAnswer({ claims: { azp: client.clientId, exp: EXP(), may_act: [entry] } })
				: { sub: "svc-a", claims: { iss: "https://actor-issuer.example" } },
		);

		expect(await h.exchange(WITH_ACTOR)).toEqual({
			status: 400,
			error: "invalid_request",
			errorDescription: "may_act_violation: actor not authorized by subject token",
		});
	});

	it("keeps a may_act member present with no value, which refuses as the original does", async () => {
		// `sub` is present and not a string: the entry matches nothing.
		const mayAct = Object.create({ sub: undefined }, { iss: { value: ISSUER, enumerable: true } });
		const h = build((role) =>
			role === "subject"
				? subjectAnswer({ claims: { azp: client.clientId, exp: EXP(), may_act: mayAct } })
				: { sub: "svc-a", claims: { iss: ISSUER } },
		);

		expect(await h.exchange(WITH_ACTOR)).toMatchObject({
			status: 400,
			errorDescription: "may_act_violation: actor not authorized by subject token",
		});
	});

	it("runs each accessor once when the claims reach themselves, and the copy answers the one value", async () => {
		let reads = 0;
		const exp = EXP();
		const answer = () => {
			const claims: Record<string, unknown> = { azp: client.clientId };
			Object.defineProperty(claims, "exp", {
				get: () => {
					reads += 1;
					return exp;
				},
				enumerable: true,
			});
			claims.self = claims;
			claims.alias = { claims };
			return subjectAnswer({ claims });
		};

		const copy = snapshotValidated(answer());
		if (copy === null) throw new Error("expected a copy");
		expect(reads).toBe(1);
		const self = copy.claims.self as Record<string, unknown>;
		expect(self.exp).toBe(exp);
		expect((self.self as Record<string, unknown>).exp).toBe(exp);

		reads = 0;
		const h = build(answer);
		tokensOf(await h.exchange());
		expect(reads).toBe(1);
	});
});
