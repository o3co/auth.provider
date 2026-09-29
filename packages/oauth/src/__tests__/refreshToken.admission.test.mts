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
 * The refresh grant on session admission (the session-admission ADR's D8,
 * D9): the verified refresh token's claim (`tokenClaim` — its `sid`, which
 * may be absent, its `sub` and its `amr`) is admitted, the live read by `sid`
 * as before, and the registered requirements asked about the token's own
 * `amr` (the MFA ADR's O3: a token is judged on what it was issued with).
 * The revocation boundary stays `verifyJwt`'s: admission skips it for a
 * token carrier. With no requirement registered nothing changes; with one,
 * `unmet` and `reauthenticate` are `400 invalid_grant`, a `step_up` is
 * `400 invalid_grant` with `step_up: "<requirement>"`, and all are answered
 * before the rotation spends the presented token.
 */

import { createSecretKey } from "node:crypto";
import {
	ADMISSION_ACTIONS,
	type AppConfig,
	createInMemorySubjectRevocation,
	createSymmetricKeyStore,
	type GrantContext,
	type GrantError,
	type RefreshTokenFamilyRotation,
	type RequirementInput,
	type RequirementVerdict,
	type SessionRequirement,
	type SubjectRevocation,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { resolverForTests } from "@o3co/auth-provider-core/testing";
import { decodeJwt, SignJWT } from "jose";
import { describe, expect, it, vi } from "vitest";
import { createRefreshTokenGrant } from "#/grants/refreshToken.mjs";
import { createMockLogger, type MockLogger } from "./_helpers/mockLogger.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const CLIENT_ID = "client1";
const SID = "sid-1";
const SUBJECT = "u1";
const config = {
	oauth: {
		jwt: { secret: SECRET },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400, unknownFamilyPolicy: "reject" },
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
	subjectRevocation?: SubjectRevocation;
	requirements?: readonly SessionRequirement[];
	logger?: MockLogger;
}) => {
	const rotation = {
		register: vi.fn(async () => {}),
		rotate: vi.fn(async () => ({ outcome: "rotated" as const })),
	} as unknown as RefreshTokenFamilyRotation & { rotate: ReturnType<typeof vi.fn> };
	const handler = createRefreshTokenGrant({
		config,
		keyStore: createSymmetricKeyStore(SECRET),
		refreshTokenFamilyRotation: rotation,
		refreshTokenFamilyRevocation: { revokeFamily: vi.fn(async () => {}) } as never,
		sessionRequirementResolver: resolverForTests(opts.requirements ?? [], {
			issuer: "https://issuer.test",
		}),
		...(opts.userSessionStore ? { userSessionStore: opts.userSessionStore } : {}),
		...(opts.subjectRevocation ? { subjectRevocation: opts.subjectRevocation } : {}),
		...(opts.logger ? { logger: opts.logger } : {}),
	});
	return { handler, rotation };
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

describe("the refresh grant on admission — no requirement registered: as before (D9)", () => {
	it("refreshes a token whose sid names a live session, reading it once", async () => {
		const store = storeWith(record());
		const { handler } = makeGrant({ userSessionStore: store });
		const { result } = await handler.handle(ctx(await refreshToken()));
		expect(result.status).toBe(200);
		expect(store.get).toHaveBeenCalledTimes(1);
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

	it("skips the read for a token without sid, and for a composition without a store", async () => {
		const store = storeWith(record());
		const withStore = makeGrant({ userSessionStore: store });
		expect(
			(await withStore.handler.handle(ctx(await refreshToken({ sid: undefined })))).result.status,
		).toBe(200);
		expect(store.get).not.toHaveBeenCalled();
		expect((await makeGrant({}).handler.handle(ctx(await refreshToken()))).result.status).toBe(200);
	});

	it("an outage is 503, logged once by admission — no longer as refresh_token_store_unavailable", async () => {
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
		// Admission skips the boundary for a token carrier (D2, step 4): the
		// token's own `iat` is what verifyJwt compares, once per request.
		const revocation = createInMemorySubjectRevocation();
		await revocation.revokeBefore(SUBJECT, minutesAgo(1), new Date(Date.now() + 3_600_000));
		const { handler } = makeGrant({
			userSessionStore: storeWith(record({ authTime: minutesAgo(10) })),
			subjectRevocation: revocation,
		});
		expect((await handler.handle(ctx(await refreshToken()))).result.status).toBe(200);
	});
});

describe("the refresh grant on admission — a requirement's verdicts (D9)", () => {
	it("is asked about the token's own amr, with the token carrier, even without a store", async () => {
		const requirement = fixture(() => ({ outcome: "met" }));
		const { handler } = makeGrant({ requirements: [requirement] });
		expect(
			(await handler.handle(ctx(await refreshToken({ amr: ["pwd", "otp"] })))).result.status,
		).toBe(200);
		expect(requirement.inputs).toHaveLength(1);
		const [input] = requirement.inputs;
		expect(input?.carrier).toBe("token");
		// The bundled action, the frozen entry itself (the session-admission ADR's D4).
		expect(input?.action).toEqual(ADMISSION_ACTIONS["oauth.refresh"]);
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

describe("the refresh grant on admission — no requirement registered: D2's reading of the record", () => {
	// The one change with no requirement registered: admission reads the
	// record the token's `sid` names as D2's steps 2 and 3 read every record,
	// where the grant only asked whether one existed. The bundled stores do
	// not answer an expired record, so they see no difference.
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
