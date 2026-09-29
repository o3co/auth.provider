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
 * The `session` grant on session admission (see ADR
 * 2026-09-28-session-admission): the cookie is read through `admitSession`
 * with `oauth.session_grant`. A session that cannot mint is `400
 * invalid_grant`, with `step_up: "<requirement>"` beside it when a
 * requirement can be met by a step-up (RFC 6749's vocabulary, so an existing
 * client keeps its mapping); an outage is `503`. `step_up` is pinned on the
 * wire, as `/oauth/token` sends it.
 */

import {
	type AppConfig,
	type ClientRepository,
	type CodeRepository,
	createInMemorySubjectRevocation,
	createSymmetricKeyStore,
	type GrantContext,
	type GrantError,
	type GrantHandler,
	type GrantResult,
	type RequirementInput,
	type RequirementVerdict,
	type SessionRequirement,
	type SubjectRevocation,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { GrantRegistry, resolverForTests } from "@o3co/auth-provider-core/testing";
import express from "express";
import { decodeJwt } from "jose";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createSessionGrant } from "#/grants/session.mjs";
import { createOAuthRouter } from "#/routes.mjs";
import { codeRecord } from "./_helpers/codeRecord.mjs";
import { createMockLogger, type MockLogger } from "./_helpers/mockLogger.mjs";

const SID = "sid-1";
const SUBJECT = "user-1";
const config = {
	oauth: {
		jwt: { issuer: "https://issuer.test", secret: "test-secret" },
		accessToken: { expiresIn: 60 },
		refreshToken: { expiresIn: 86400 },
		grants: { session: { enabled: true } },
	},
	rateLimit: { failMode: "open" },
	endpoints: { login: { url: "/login" } },
} as unknown as AppConfig;
const keyStore = createSymmetricKeyStore("session-admission-test-secret-32-bytes");
const AUTH_CLIENT = {
	clientId: "app",
	tokenEndpointAuthMethod: "none" as const,
	allowedScopes: ["read"],
};

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
	verdict: () => RequirementVerdict,
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
			return verdict();
		},
	};
};

const grant = (opts: {
	userSessionStore?: UserSessionStore;
	subjectRevocation?: SubjectRevocation;
	requirements?: readonly SessionRequirement[];
	logger?: MockLogger;
}) =>
	createSessionGrant({
		config,
		keyStore,
		sessionRequirementResolver: resolverForTests(opts.requirements ?? [], {
			issuer: "https://issuer.test",
		}),
		...(opts.userSessionStore ? { userSessionStore: opts.userSessionStore } : {}),
		...(opts.subjectRevocation ? { subjectRevocation: opts.subjectRevocation } : {}),
		...(opts.logger ? { logger: opts.logger } : {}),
	});

const ctx = (session: Record<string, unknown>): GrantContext => ({
	body: {},
	session,
	issuer: "https://issuer.test",
	metadata: {},
	authenticatedClient: AUTH_CLIENT,
});

const LIVE_COOKIE = { isAuthenticated: true, sid: SID, user: { id: SUBJECT } };

const refused = async (
	handler: ReturnType<typeof createSessionGrant>,
	session: Record<string, unknown> = LIVE_COOKIE,
): Promise<GrantError & { readonly step_up?: unknown }> => {
	const { result } = await handler.handle(ctx(session));
	expect("error" in result).toBe(true);
	return result as GrantError & { readonly step_up?: unknown };
};

describe("the session grant on admission — what the session and its record decide", () => {
	it("the subject-revocation boundary applies when subjectRevocation is wired: 400 invalid_grant", async () => {
		const revocation = createInMemorySubjectRevocation();
		await revocation.revokeBefore(SUBJECT, new Date(), new Date(Date.now() + 3_600_000));
		const result = await refused(
			grant({ userSessionStore: storeWith(record()), subjectRevocation: revocation }),
		);
		expect(result).toMatchObject({
			status: 400,
			error: "invalid_grant",
			errorDescription: "session_invalid",
		});
	});

	it("a session established after the boundary still mints", async () => {
		const revocation = createInMemorySubjectRevocation();
		await revocation.revokeBefore(SUBJECT, minutesAgo(10), new Date(Date.now() + 3_600_000));
		const { result } = await grant({
			userSessionStore: storeWith(record()),
			subjectRevocation: revocation,
		}).handle(ctx(LIVE_COOKIE));
		expect(result.status).toBe(200);
	});

	it("a record past its expiresAt is 400 invalid_grant session_invalid", async () => {
		const result = await refused(
			grant({ userSessionStore: storeWith(record({ expiresAt: minutesAgo(1) })) }),
		);
		expect(result).toMatchObject({
			status: 400,
			error: "invalid_grant",
			errorDescription: "session_invalid",
		});
	});

	it("a cookie without user.id is 400 invalid_grant even without a store (it minted a token with no subject)", async () => {
		const result = await refused(grant({}), { isAuthenticated: true, sid: SID });
		expect(result).toMatchObject({ status: 400, error: "invalid_grant" });
	});

	it("keeps its answers for a dead sid, a missing sid, a mismatched subject and an unauthenticated cookie", async () => {
		expect(await refused(grant({ userSessionStore: storeWith(null) }))).toMatchObject({
			status: 400,
			errorDescription: "session_invalid",
		});
		expect(
			await refused(grant({ userSessionStore: storeWith(record()) }), {
				isAuthenticated: true,
				user: { id: SUBJECT },
			}),
		).toMatchObject({
			status: 400,
			error: "invalid_grant",
			errorDescription: "session identifier (sid) is required",
		});
		expect(
			await refused(grant({ userSessionStore: storeWith(record({ sub: "someone-else" })) })),
		).toMatchObject({ status: 400, errorDescription: "session_invalid" });
		expect(await refused(grant({}), { isAuthenticated: false })).toMatchObject({
			status: 401,
			error: "unauthorized",
		});
	});

	it("an outage is 503, logged once by admission with the action — the grant's own line is gone", async () => {
		const logger = createMockLogger();
		const result = await refused(
			grant({
				logger,
				userSessionStore: storeAnswering(async () => {
					throw new Error("redis down");
				}),
			}),
		);
		expect(result).toMatchObject({
			status: 503,
			error: "temporarily_unavailable",
			errorDescription: "session store unavailable",
		});
		expect(logger.error).toHaveBeenCalledTimes(1);
		expect(logger.error).toHaveBeenCalledWith(
			{
				store: "user_session",
				action: "oauth.session_grant",
				err: expect.objectContaining({ name: "Error" }),
			},
			"session_admission_unavailable",
		);
	});

	it("mints from the admitted record: its sub, its sid and the amr it vouches for", async () => {
		const { result } = await grant({
			userSessionStore: storeWith(record({ amr: ["pwd"] })),
		}).handle(ctx(LIVE_COOKIE));
		expect(result.status).toBe(200);
		if (!("tokens" in result)) throw new Error("expected tokens");
		const claims = decodeJwt(result.tokens.access_token);
		expect(claims.sub).toBe(SUBJECT);
		expect(claims.sid).toBe(SID);
		expect(claims.amr).toEqual(["pwd"]);
	});
});

describe("the session grant on admission — a requirement's verdicts", () => {
	it("asks the requirement with oauth.session_grant, graded use, over the cookie carrier", async () => {
		const requirement = fixture(() => ({ outcome: "met" }));
		const { result } = await grant({
			userSessionStore: storeWith(record()),
			requirements: [requirement],
		}).handle(ctx(LIVE_COOKIE));
		expect(result.status).toBe(200);
		expect(requirement.inputs[0]?.action).toEqual({ name: "oauth.session_grant", grade: "use" });
		expect(requirement.inputs[0]?.carrier).toBe("cookie");
	});

	it("step_up is 400 invalid_grant with step_up naming the requirement", async () => {
		const result = await refused(
			grant({
				userSessionStore: storeWith(record()),
				requirements: [fixture(() => ({ outcome: "step_up", whenStillUnmet: "reauthenticate" }))],
			}),
		);
		expect(result).toMatchObject({ status: 400, error: "invalid_grant", step_up: "fixture" });
	});

	it("unmet and reauthenticate are 400 invalid_grant, with no step_up", async () => {
		for (const outcome of ["unmet", "reauthenticate"] as const) {
			const result = await refused(
				grant({
					userSessionStore: storeWith(record()),
					requirements: [fixture(() => ({ outcome }))],
				}),
			);
			expect(result).toMatchObject({ status: 400, error: "invalid_grant" });
			expect(result.step_up).toBeUndefined();
		}
	});

	it("a requirement that throws is 503 temporarily_unavailable", async () => {
		const result = await refused(
			grant({
				userSessionStore: storeWith(record()),
				requirements: [
					fixture(() => {
						throw new Error("policy service down");
					}),
				],
			}),
		);
		expect(result).toMatchObject({ status: 503, error: "temporarily_unavailable" });
	});
});

describe("the step_up member on the wire (/oauth/token)", () => {
	const buildApp = async (requirements: readonly SessionRequirement[], grant?: GrantHandler) => {
		const client = {
			clientId: "app",
			tokenEndpointAuthMethod: "none" as const,
			allowedRedirectUris: [],
			allowedScopes: ["read"],
			allowedGrantTypes: ["session"],
		};
		const clientRepository: ClientRepository = {
			findById: async (id) => (id === "app" ? client : null),
			authenticate: async () => null,
		};
		const codeRepository: CodeRepository = {
			createCode: async () => codeRecord({ code: "unused", client_id: "app", redirect_uri: "" }),
			findByCode: async () => null,
			consumeByCode: async () => null,
			removeByCode: async () => {},
		};
		const store = storeWith(record());
		const registry = new GrantRegistry();
		registry.register(
			"session",
			grant ??
				createSessionGrant({
					config,
					keyStore,
					userSessionStore: store,
					sessionRequirementResolver: resolverForTests(requirements, {
						issuer: "https://issuer.test",
					}),
				}),
		);
		const { router } = await createOAuthRouter(express, {
			registry,
			config,
			keyStore,
			codeRepository,
			clientRepository,
			userSessionStore: store,
			requirements: resolverForTests(requirements, { issuer: "https://issuer.test" }),
		});
		const app = express();
		app.use((req, _res, next) => {
			req.session = { ...LIVE_COOKIE } as unknown as typeof req.session;
			next();
		});
		app.use("/oauth", router);
		return app;
	};

	const mint = (app: express.Express) =>
		request(app)
			.post("/oauth/token")
			.type("form")
			.send({ grant_type: "session", client_id: "app", scope: "read" });

	it("carries step_up beside error and error_description", async () => {
		const app = await buildApp([
			fixture(() => ({ outcome: "step_up", whenStillUnmet: "reauthenticate" })),
		]);
		const res = await mint(app);
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_grant");
		expect(res.body.step_up).toBe("fixture");
		expect(typeof res.body.error_description).toBe("string");
	});

	it("carries step_up for a requirement named with any of the error-code characters registration admits — deployment:requirement-page", async () => {
		const name = "deployment:requirement-page";
		const app = await buildApp([
			{
				...fixture(() => ({ outcome: "step_up", whenStillUnmet: "reauthenticate" })),
				name,
				remediations: [`${name}.step_up`],
			},
		]);
		const res = await mint(app);
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_grant");
		expect(res.body.step_up).toBe(name);
	});

	const answering = (result: Record<string, unknown>): GrantHandler => ({
		handle: async () => ({ result: result as unknown as GrantResult }),
	});

	it("carries step_up only beside invalid_grant: a grant that sets it on another error does not reach the wire", async () => {
		const app = await buildApp(
			[],
			answering({
				status: 400,
				error: "invalid_request",
				errorDescription: "no",
				step_up: "fixture",
			}),
		);
		const res = await mint(app);
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_request");
		expect(res.body).not.toHaveProperty("step_up");
	});

	it("carries no step_up outside the error-code character set", async () => {
		const app = await buildApp(
			[],
			answering({
				status: 400,
				error: "invalid_grant",
				errorDescription: "no",
				step_up: 'a "quoted" name',
			}),
		);
		const res = await mint(app);
		expect(res.body.error).toBe("invalid_grant");
		expect(res.body).not.toHaveProperty("step_up");
	});

	it("carries no step_up on any other refusal", async () => {
		const app = await buildApp([fixture(() => ({ outcome: "unmet" }))]);
		const res = await mint(app);
		expect(res.status).toBe(400);
		expect(res.body).not.toHaveProperty("step_up");
	});

	it("mints with no requirement registered", async () => {
		const res = await mint(await buildApp([]));
		expect(res.status).toBe(200);
		expect(res.body.access_token).toEqual(expect.any(String));
	});
});
