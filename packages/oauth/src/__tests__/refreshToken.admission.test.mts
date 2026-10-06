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
 * The refresh grant on session admission (ADR 2026-09-28-session-admission):
 * it admits the verified token's claim (`tokenClaim`: its `sid`, which may be
 * absent, its `sub` and its `amr`) and the live record read by `sid`, and
 * asks the registered requirements about the token's own `amr`, since a
 * token is judged on what it was issued with (the MFA ADR). Admission skips
 * the revocation boundary for a token carrier; it stays `verifyJwt`'s.
 * `unmet`, `reauthenticate` and `step_up` (with `step_up: "<requirement>"`)
 * are `400 invalid_grant`, all answered before the rotation spends the token.
 */

import { createSecretKey } from "node:crypto";
import {
	type AppConfig,
	createInMemorySessionLifecycleStore,
	createInMemorySubjectRevocation,
	createMemoryRefreshTokenFamilyStore,
	createRefreshTokenFamilyRevocation,
	createRefreshTokenFamilyRotation,
	createSymmetricKeyStore,
	type GrantContext,
	type GrantError,
	type GrantPolicyHook,
	type RefreshTokenFamilyRevocation,
	type RefreshTokenFamilyRotation,
	type RequirementInput,
	type RequirementVerdict,
	type SessionLifecycleStore,
	type SessionRequirement,
	type SubjectRevocation,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { resolverForTests } from "@o3co/auth-provider-core/testing";
import { decodeJwt, SignJWT } from "jose";
import { describe, expect, it, vi } from "vitest";
import { createRefreshTokenGrant } from "#/grants/refreshToken.mjs";
import { OAUTH_ADMISSION_ACTIONS } from "./_helpers/admissionActions.mjs";
import { grantSettingsFrom } from "./_helpers/grantSettings.mjs";
import { createMockLogger, type MockLogger } from "./_helpers/mockLogger.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const CLIENT_ID = "client1";
const SID = "sid-1";
const SUBJECT = "u1";
const config = {
	oauth: {
		jwt: { secret: SECRET },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		grants: { refresh_token: { enabled: true } },
	},
} as unknown as AppConfig;

const minutesAgo = (minutes: number): Date => new Date(Date.now() - minutes * 60_000);

const record = (over: Partial<UserSession> = {}): UserSession => ({
	sid: SID,
	sub: SUBJECT,
	authTime: minutesAgo(5),
	createdAt: minutesAgo(5),
	expiresAt: new Date(Date.now() + 3_600_000),
	claims: {},
	amr: ["pwd"],
	authentication: {
		primary: "pwd",
		federation: undefined,
		upstreamAmr: undefined,
		mfaAt: undefined,
	},
	...over,
});

const storeAnswering = (
	impl: (sid: string) => Promise<UserSession | null>,
): UserSessionStore & { get: ReturnType<typeof vi.fn> } =>
	({
		kind: "memory",
		create: vi.fn(async () => {}),
		get: vi.fn(impl),
		delete: vi.fn(async () => {}),
	}) as unknown as UserSessionStore & { get: ReturnType<typeof vi.fn> };

const storeWith = (session: UserSession | null) =>
	storeAnswering(async (sid) => (sid === SID ? session : null));

const fixture = (
	verdict: (input: RequirementInput) => RequirementVerdict,
): SessionRequirement & { readonly inputs: RequirementInput[] } => {
	const inputs: RequirementInput[] = [];
	return {
		name: "fixture",
		reach: new Set(),
		stepUpPage: { url: "/step-up", params: {} },
		remediations: ["fixture.step_up"],
		hintKeys: [],
		inputs,
		async admit(input) {
			inputs.push(input);
			return verdict(input);
		},
	};
};

/** A refresh token as the authorization_code grant mints one: `sid`, `amr`, a family and a jti. */
const refreshToken = (claims: Record<string, unknown> = {}): Promise<string> =>
	new SignJWT({
		sub: SUBJECT,
		scope: "read",
		sid: SID,
		amr: ["pwd"],
		family_id: "fam-1",
		jti: "jti-1",
		...claims,
	})
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
		.setIssuedAt()
		.setIssuer("localhost")
		.setAudience(CLIENT_ID)
		.setExpirationTime("24h")
		.sign(createSecretKey(Buffer.from(SECRET)));

const makeGrant = (opts: {
	userSessionStore?: UserSessionStore;
	sessionLifecycleStore?: SessionLifecycleStore;
	subjectRevocation?: SubjectRevocation;
	requirements?: readonly SessionRequirement[];
	logger?: MockLogger;
	grantPolicy?: GrantPolicyHook;
	/** `revocation: null` wires no `refreshTokenFamilyRevocation`. */
	family?: {
		readonly rotation: RefreshTokenFamilyRotation;
		readonly revocation: RefreshTokenFamilyRevocation | null;
	};
	unknownFamilyPolicy?: "accept" | "reject";
}) => {
	const rotation = vi.fn(
		opts.family?.rotation.rotate ?? (async () => ({ outcome: "rotated" as const })),
	);
	const familyRevocation =
		opts.family?.revocation === undefined
			? ({ revokeFamily: vi.fn(async () => {}) } as never)
			: opts.family.revocation;
	const handler = createRefreshTokenGrant({
		...grantSettingsFrom(config),
		...(opts.unknownFamilyPolicy === undefined
			? {}
			: { unknownFamilyPolicy: opts.unknownFamilyPolicy }),
		keyStore: createSymmetricKeyStore(SECRET),
		refreshTokenFamilyRotation: { register: vi.fn(async () => {}), rotate: rotation },
		...(familyRevocation === null ? {} : { refreshTokenFamilyRevocation: familyRevocation }),
		...(opts.grantPolicy ? { grantPolicy: opts.grantPolicy } : {}),
		sessionRequirementResolver: resolverForTests(opts.requirements ?? [], {
			issuer: "https://issuer.test",
			actions: OAUTH_ADMISSION_ACTIONS,
		}),
		...(opts.userSessionStore ? { userSessionStore: opts.userSessionStore } : {}),
		...(opts.sessionLifecycleStore ? { sessionLifecycleStore: opts.sessionLifecycleStore } : {}),
		...(opts.subjectRevocation ? { subjectRevocation: opts.subjectRevocation } : {}),
		...(opts.logger ? { logger: opts.logger } : {}),
	});
	return { handler, rotation: { rotate: rotation } };
};

const ctx = (token: string): GrantContext => ({
	body: { refresh_token: token },
	session: {},
	issuer: "localhost",
	metadata: {},
	authenticatedClient: { clientId: CLIENT_ID, tokenEndpointAuthMethod: "client_secret_basic" },
});

const refused = async (
	handler: ReturnType<typeof createRefreshTokenGrant>,
	token: string,
): Promise<GrantError & { readonly step_up?: unknown }> => {
	const { result } = await handler.handle(ctx(token));
	expect("error" in result).toBe(true);
	return result as GrantError & { readonly step_up?: unknown };
};

describe("the refresh grant on admission — no requirement registered", () => {
	it("refreshes a token whose sid names a live session, reading it before and after the rotation", async () => {
		const store = storeWith(record());
		const { handler } = makeGrant({ userSessionStore: store });
		const { result } = await handler.handle(ctx(await refreshToken()));
		expect(result.status).toBe(200);
		expect(store.get).toHaveBeenCalledTimes(2);
		if (!("tokens" in result)) throw new Error("expected tokens");
		expect(decodeJwt(result.tokens.access_token).sid).toBe(SID);
	});

	it("refuses a token whose session is gone with 400 invalid_grant session_invalid, before the rotation", async () => {
		const { handler, rotation } = makeGrant({ userSessionStore: storeWith(null) });
		expect(await refused(handler, await refreshToken())).toMatchObject({
			status: 400,
			error: "invalid_grant",
			errorDescription: "session_invalid",
		});
		expect(rotation.rotate).not.toHaveBeenCalled();
	});

	it("refuses a token whose session has no lifecycle record with 400 invalid_grant session_invalid, before the rotation", async () => {
		// A session from before the lifecycle, or one whose record lapsed, reads
		// as closed: a refresh token bound to it stops working.
		const { handler, rotation } = makeGrant({
			userSessionStore: storeWith(record()),
			sessionLifecycleStore: createInMemorySessionLifecycleStore(),
		});
		expect(await refused(handler, await refreshToken())).toMatchObject({
			status: 400,
			error: "invalid_grant",
			errorDescription: "session_invalid",
		});
		expect(rotation.rotate).not.toHaveBeenCalled();
	});

	it("refreshes a token whose session's lifecycle record is active", async () => {
		const sessionLifecycleStore = createInMemorySessionLifecycleStore();
		expect((await sessionLifecycleStore.open(SID, SUBJECT, record().expiresAt)).outcome).toBe(
			"opened",
		);
		const { handler } = makeGrant({
			userSessionStore: storeWith(record()),
			sessionLifecycleStore,
		});
		expect((await handler.handle(ctx(await refreshToken()))).result.status).toBe(200);
	});

	it("skips the read for a token without sid, and for a composition without a store", async () => {
		const store = storeWith(record());
		const withStore = makeGrant({ userSessionStore: store });
		expect(
			(await withStore.handler.handle(ctx(await refreshToken({ sid: undefined })))).result.status,
		).toBe(200);
		expect(store.get).not.toHaveBeenCalled();
		expect((await makeGrant({}).handler.handle(ctx(await refreshToken()))).result.status).toBe(200);
	});

	it("an outage is 503, logged once by admission as session_admission_unavailable", async () => {
		const logger = createMockLogger();
		const { handler, rotation } = makeGrant({
			logger,
			userSessionStore: storeAnswering(async () => {
				throw new Error("redis down");
			}),
		});
		expect(await refused(handler, await refreshToken())).toMatchObject({
			status: 503,
			error: "temporarily_unavailable",
			errorDescription: "session store unavailable",
		});
		expect(logger.error).toHaveBeenCalledTimes(1);
		expect(logger.error).toHaveBeenCalledWith(
			expect.objectContaining({
				store: "user_session",
				action: "oauth.refresh",
				err: expect.anything(),
			}),
			"session_admission_unavailable",
		);
		expect(rotation.rotate).not.toHaveBeenCalled();
	});

	it("the revocation boundary stays verifyJwt's: a token minted after it refreshes even though its session was established before", async () => {
		// Admission skips the boundary for a token carrier: the token's own
		// `iat` is what verifyJwt compares, once per request.
		const revocation = createInMemorySubjectRevocation();
		await revocation.revokeBefore(SUBJECT, minutesAgo(1), new Date(Date.now() + 3_600_000));
		const { handler } = makeGrant({
			userSessionStore: storeWith(record({ authTime: minutesAgo(10) })),
			subjectRevocation: revocation,
		});
		expect((await handler.handle(ctx(await refreshToken()))).result.status).toBe(200);
	});
});

describe("the refresh grant on admission — a requirement's verdicts", () => {
	it("is asked about the token's own amr, with the token carrier, even without a store", async () => {
		const requirement = fixture(() => ({ outcome: "met" }));
		const { handler } = makeGrant({ requirements: [requirement] });
		expect(
			(await handler.handle(ctx(await refreshToken({ amr: ["pwd", "otp"] })))).result.status,
		).toBe(200);
		// Asked before the rotation and again after it.
		expect(requirement.inputs).toHaveLength(2);
		const [input] = requirement.inputs;
		expect(input?.carrier).toBe("token");
		// The action the refresh grant registers, with its grade.
		expect(input?.action).toEqual({ name: "oauth.refresh", grade: "use" });
		expect(input?.action.grade).toBe("use");
		expect(input?.subject).toBe(SUBJECT);
		expect(input?.session).toBeNull();
		expect(input?.authentication?.amr).toEqual(["pwd", "otp"]);
	});

	it("unmet — a password-only token under a requirement that wants more — is 400 invalid_grant, before the rotation", async () => {
		const requirement = fixture((input) =>
			input.authentication?.amr.includes("otp") ? { outcome: "met" } : { outcome: "unmet" },
		);
		const { handler, rotation } = makeGrant({
			userSessionStore: storeWith(record()),
			requirements: [requirement],
		});
		const result = await refused(handler, await refreshToken({ amr: ["pwd"] }));
		expect(result).toMatchObject({ status: 400, error: "invalid_grant" });
		expect(result.step_up).toBeUndefined();
		expect(rotation.rotate).not.toHaveBeenCalled();
		// The same requirement admits a token issued with the second factor.
		expect(
			(await handler.handle(ctx(await refreshToken({ amr: ["pwd", "otp"] })))).result.status,
		).toBe(200);
	});

	it("reauthenticate is 400 invalid_grant", async () => {
		const { handler } = makeGrant({
			userSessionStore: storeWith(record()),
			requirements: [fixture(() => ({ outcome: "reauthenticate" }))],
		});
		expect(await refused(handler, await refreshToken())).toMatchObject({
			status: 400,
			error: "invalid_grant",
		});
	});

	it("step_up over a live session is 400 invalid_grant with step_up naming the requirement", async () => {
		const { handler, rotation } = makeGrant({
			userSessionStore: storeWith(record()),
			requirements: [fixture(() => ({ outcome: "step_up", whenStillUnmet: "unmet" }))],
		});
		expect(await refused(handler, await refreshToken())).toMatchObject({
			status: 400,
			error: "invalid_grant",
			step_up: "fixture",
		});
		expect(rotation.rotate).not.toHaveBeenCalled();
	});

	it("a requirement that throws is 503 temporarily_unavailable", async () => {
		const { handler } = makeGrant({
			userSessionStore: storeWith(record()),
			requirements: [
				fixture(() => {
					throw new Error("policy service down");
				}),
			],
		});
		expect(await refused(handler, await refreshToken())).toMatchObject({
			status: 503,
			error: "temporarily_unavailable",
		});
	});
});

describe("the refresh grant on admission — no requirement registered: the record is read, not only found", () => {
	// With no requirement registered, admission still reads the record the
	// token's `sid` names as it reads every record, not only whether one
	// exists. The bundled stores do not answer an expired record, so they see
	// no difference.
	const refusedBeforeTheRotation = async (session: UserSession) => {
		const { handler, rotation } = makeGrant({ userSessionStore: storeWith(session) });
		expect(await refused(handler, await refreshToken())).toMatchObject({
			status: 400,
			error: "invalid_grant",
			errorDescription: "session_invalid",
		});
		expect(rotation.rotate).not.toHaveBeenCalled();
	};

	it("refuses a record past its expiresAt", async () => {
		await refusedBeforeTheRotation(record({ expiresAt: minutesAgo(1) }));
	});

	it("refuses a record whose authTime is not a valid date", async () => {
		await refusedBeforeTheRotation(record({ authTime: new Date(Number.NaN) }));
	});

	it("refuses a record whose sub is not the token's", async () => {
		await refusedBeforeTheRotation(record({ sub: "someone-else" }));
	});
});

describe("the refresh grant — the subject's revocation and the session are read again before signing", () => {
	const allowAfter = (onEvaluate: () => Promise<void>): GrantPolicyHook => ({
		kind: "slow",
		evaluate: async () => {
			await onEvaluate();
			return { outcome: "allow" };
		},
	});
	const revokeNow = (revocation: SubjectRevocation) =>
		revocation.revokeBefore(SUBJECT, new Date(), new Date(Date.now() + 3_600_000));
	const INVALID_REFRESH_TOKEN = {
		status: 400,
		error: "invalid_grant",
		errorDescription: "invalid refresh_token",
	};
	const SESSION_INVALID = {
		status: 400,
		error: "invalid_grant",
		errorDescription: "session_invalid",
	};

	/** The memory family store with "fam-1" registered at "jti-1", as the authorization_code grant leaves it. */
	const registeredFamily = async () => {
		const refreshTokenFamilyStore = createMemoryRefreshTokenFamilyStore();
		const rotation = createRefreshTokenFamilyRotation({
			refreshTokenFamilyStore,
			accessTokenHorizonMs: 3_600_000,
		});
		const revocation = createRefreshTokenFamilyRevocation({
			refreshTokenFamilyStore,
			accessTokenHorizonMs: 3_600_000,
		});
		await rotation.register("jti-1", "fam-1", Date.now() + 86_400_000);
		return { rotation, revocation };
	};

	/** The family after a refused refresh: revoked, so the spent token rotates nothing. */
	const expectNoUsableFamily = async (family: Awaited<ReturnType<typeof registeredFamily>>) => {
		expect(await family.revocation.isFamilyRevoked("fam-1")).toBe(true);
		expect(await family.rotation.rotate("jti-1", "jti-x", "fam-1", Date.now() + 60_000)).toEqual({
			outcome: "revoked",
		});
	};

	it("a subject revocation landing while the policy evaluates mints nothing, without a store or a sid", async () => {
		const revocation = createInMemorySubjectRevocation();
		const { handler, rotation } = makeGrant({
			subjectRevocation: revocation,
			grantPolicy: allowAfter(() => revokeNow(revocation)),
		});
		const token = await refreshToken({ sid: undefined });
		const during = await refused(handler, token);
		expect(during).toEqual(INVALID_REFRESH_TOKEN);
		expect(rotation.rotate).not.toHaveBeenCalled();
		// The same request once the revocation has landed is refused the same way.
		expect(during).toEqual(
			await refused(makeGrant({ subjectRevocation: revocation }).handler, token),
		);
	});

	it("a subject revocation landing while the policy evaluates mints nothing for a token with a sid and a live session", async () => {
		const revocation = createInMemorySubjectRevocation();
		const { handler, rotation } = makeGrant({
			userSessionStore: storeWith(record()),
			subjectRevocation: revocation,
			grantPolicy: allowAfter(() => revokeNow(revocation)),
		});
		expect(await refused(handler, await refreshToken())).toEqual(INVALID_REFRESH_TOKEN);
		expect(rotation.rotate).not.toHaveBeenCalled();
	});

	it("a session deleted during the rotation mints nothing and leaves no usable family", async () => {
		const family = await registeredFamily();
		let live: UserSession | null = record();
		const { handler } = makeGrant({
			userSessionStore: storeAnswering(async (sid) => (sid === SID ? live : null)),
			family: {
				rotation: {
					register: family.rotation.register,
					rotate: async (...args) => {
						const outcome = await family.rotation.rotate(...args);
						live = null;
						return outcome;
					},
				},
				revocation: family.revocation,
			},
		});
		expect(await refused(handler, await refreshToken())).toEqual(SESSION_INVALID);
		await expectNoUsableFamily(family);
	});

	it("a subject revocation landing during the rotation mints nothing and leaves no usable family, without a store or a sid", async () => {
		const family = await registeredFamily();
		const revocation = createInMemorySubjectRevocation();
		const { handler } = makeGrant({
			subjectRevocation: revocation,
			family: {
				rotation: {
					register: family.rotation.register,
					rotate: async (...args) => {
						const outcome = await family.rotation.rotate(...args);
						await revokeNow(revocation);
						return outcome;
					},
				},
				revocation: family.revocation,
			},
		});
		expect(await refused(handler, await refreshToken({ sid: undefined }))).toEqual(
			INVALID_REFRESH_TOKEN,
		);
		await expectNoUsableFamily(family);
	});

	it("an outage on the revocation read after the policy is 503, mapped as on the first read, before the rotation", async () => {
		const failingOn = (failing: number): SubjectRevocation => {
			let reads = 0;
			return {
				kind: "flaky",
				revokeBefore: async () => {},
				revokedBefore: async () => {
					reads += 1;
					if (reads >= failing) throw new Error("redis down");
					return null;
				},
			};
		};
		const policy = allowAfter(async () => {});
		const second = makeGrant({ subjectRevocation: failingOn(2), grantPolicy: policy });
		const first = makeGrant({ subjectRevocation: failingOn(1), grantPolicy: policy });
		const token = await refreshToken({ sid: undefined });
		const during = await refused(second.handler, token);
		expect(during).toEqual(await refused(first.handler, token));
		expect(during).toEqual({
			status: 503,
			error: "temporarily_unavailable",
			errorDescription: "revocation store unavailable",
		});
		expect(second.rotation.rotate).not.toHaveBeenCalled();
	});

	it("an outage on the session read after the rotation is 503, mapped as on the first read, and leaves no usable family", async () => {
		const family = await registeredFamily();
		let reads = 0;
		const { handler } = makeGrant({
			userSessionStore: storeAnswering(async (sid) => {
				reads += 1;
				if (reads > 1) throw new Error("redis down");
				return sid === SID ? record() : null;
			}),
			family: { rotation: family.rotation, revocation: family.revocation },
		});
		expect(await refused(handler, await refreshToken())).toEqual({
			status: 503,
			error: "temporarily_unavailable",
			errorDescription: "session store unavailable",
		});
		expect(reads).toBe(2);
		await expectNoUsableFamily(family);
	});

	it("an outage on the revocation read after the rotation is 503, mapped as on the first read", async () => {
		let reads = 0;
		const revocation: SubjectRevocation = {
			kind: "flaky",
			revokeBefore: async () => {},
			revokedBefore: async () => {
				reads += 1;
				// Read at verification, after the admission, and after the rotation.
				if (reads > 2) throw new Error("redis down");
				return null;
			},
		};
		const { handler, rotation } = makeGrant({ subjectRevocation: revocation });
		expect(await refused(handler, await refreshToken({ sid: undefined }))).toEqual({
			status: 503,
			error: "temporarily_unavailable",
			errorDescription: "revocation store unavailable",
		});
		expect(rotation.rotate).toHaveBeenCalledTimes(1);
	});

	it("a subject revocation landing while a requirement evaluates mints nothing, before or after the rotation", async () => {
		for (const revokingCall of [1, 2]) {
			const family = await registeredFamily();
			const revocation = createInMemorySubjectRevocation();
			let calls = 0;
			const requirement = fixture(() => ({ outcome: "met" }));
			const { handler } = makeGrant({
				subjectRevocation: revocation,
				requirements: [
					{
						...requirement,
						async admit(input) {
							calls += 1;
							if (calls === revokingCall) await revokeNow(revocation);
							return requirement.admit(input);
						},
					},
				],
				family: { rotation: family.rotation, revocation: family.revocation },
			});
			expect(await refused(handler, await refreshToken({ sid: undefined }))).toEqual(
				INVALID_REFRESH_TOKEN,
			);
			// Before the rotation the family is untouched; after it, revoked.
			expect(await family.revocation.isFamilyRevoked("fam-1")).toBe(revokingCall === 2);
		}
	});

	/** A store whose session is deleted while `rotate` runs, and that rotation. */
	const endedDuringRotation = (
		rotate: RefreshTokenFamilyRotation["rotate"],
	): { store: UserSessionStore; rotation: RefreshTokenFamilyRotation } => {
		let live: UserSession | null = record();
		return {
			store: storeAnswering(async (sid) => (sid === SID ? live : null)),
			rotation: {
				register: async () => {},
				rotate: async (...args) => {
					const outcome = await rotate(...args);
					live = null;
					return outcome;
				},
			},
		};
	};

	it("a refusal after a committed rotation is still answered without a family revocation wired", async () => {
		const family = await registeredFamily();
		const ended = endedDuringRotation(family.rotation.rotate);
		const { handler } = makeGrant({
			userSessionStore: ended.store,
			family: { rotation: ended.rotation, revocation: null },
		});
		expect(await refused(handler, await refreshToken())).toEqual(SESSION_INVALID);
		// The spent token rotates nothing on: it reads as a replay.
		expect(await family.rotation.rotate("jti-1", "jti-x", "fam-1", Date.now() + 60_000)).toEqual(
			expect.objectContaining({ outcome: "replayed" }),
		);
	});

	it("a family revocation that fails after a committed rotation is logged, and the refusal still answered", async () => {
		const family = await registeredFamily();
		const ended = endedDuringRotation(family.rotation.rotate);
		const logger = createMockLogger();
		const { handler } = makeGrant({
			logger,
			userSessionStore: ended.store,
			family: {
				rotation: ended.rotation,
				revocation: {
					revokeFamily: async () => {
						throw new Error("redis down");
					},
					isFamilyRevoked: async () => false,
				},
			},
		});
		expect(await refused(handler, await refreshToken())).toEqual(SESSION_INVALID);
		expect(logger.error).toHaveBeenCalledWith(
			expect.objectContaining({
				store: "refresh_token_family",
				step: "revoke",
				familyId: "fam-1",
				clientId: CLIENT_ID,
				err: expect.anything(),
			}),
			"refresh_token_store_unavailable",
		);
	});

	it("a refusal after an unknown family was accepted revokes nothing, since nothing was committed", async () => {
		const revokeFamily = vi.fn(async () => {});
		const ended = endedDuringRotation(async () => ({ outcome: "unknown_family" }));
		const { handler } = makeGrant({
			unknownFamilyPolicy: "accept",
			userSessionStore: ended.store,
			family: {
				rotation: ended.rotation,
				revocation: { revokeFamily, isFamilyRevoked: async () => false },
			},
		});
		expect(await refused(handler, await refreshToken())).toEqual(SESSION_INVALID);
		expect(revokeFamily).not.toHaveBeenCalled();
	});

	it("a family lifetime the re-checks spend mints nothing", async () => {
		vi.useFakeTimers({ toFake: ["Date"] });
		try {
			let reads = 0;
			const { handler } = makeGrant({
				userSessionStore: storeAnswering(async () => {
					reads += 1;
					// The read after the rotation outlasts what the family has left.
					if (reads === 2) vi.setSystemTime(Date.now() + 10_000);
					return record();
				}),
				family: {
					rotation: {
						register: async () => {},
						rotate: async () => ({ outcome: "rotated", cappedExpiresAtMs: Date.now() + 3_000 }),
					},
					revocation: { revokeFamily: async () => {}, isFamilyRevoked: async () => false },
				},
			});
			expect(await refused(handler, await refreshToken())).toEqual({
				status: 400,
				error: "invalid_grant",
				errorDescription: "refresh token family has reached its lifetime",
			});
			expect(reads).toBe(2);
		} finally {
			vi.useRealTimers();
		}
	});

	it("a refresh nothing revoked still mints, reading the revocation after the policy and after the rotation", async () => {
		const family = await registeredFamily();
		const revocation = createInMemorySubjectRevocation();
		const revokedBefore = vi.spyOn(revocation, "revokedBefore");
		const store = storeWith(record());
		const { handler } = makeGrant({
			userSessionStore: store,
			subjectRevocation: revocation,
			grantPolicy: allowAfter(async () => {}),
			family: { rotation: family.rotation, revocation: family.revocation },
		});
		const { result } = await handler.handle(ctx(await refreshToken()));
		expect(result.status).toBe(200);
		if (!("tokens" in result)) throw new Error("expected tokens");
		expect(decodeJwt(result.tokens.access_token).sid).toBe(SID);
		expect(revokedBefore).toHaveBeenCalledTimes(3);
		expect(store.get).toHaveBeenCalledTimes(2);
		expect(await family.revocation.isFamilyRevoked("fam-1")).toBe(false);
	});
});
