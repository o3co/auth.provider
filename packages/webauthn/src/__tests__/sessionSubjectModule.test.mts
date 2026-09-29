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
 * `webauthnSessionSubjectModule`: the bridge from the browser's cookie session
 * to `req.webauthnSubject`, which the registration routes require, as a module
 * the deployment installs instead of writing. It reads the session through
 * core's admission as `webauthn.register` (graded `credential_change`). See
 * ADR 2026-09-28-session-admission.
 *
 * Each admission outcome's answer: a subject from the deployment's mapper on
 * `admitted`, `503` on `unavailable`, `403 step_up_required` on `step_up`, and
 * no subject otherwise, so the routes answer their `401`.
 */

import {
	AUDIT_SINK_ABSENCE_POLICY,
	type Logger,
	type RequirementInput,
	type RequirementVerdict,
	type SessionRequirement,
	SUBJECT_REVOCATION_ABSENCE_POLICY,
	type SubjectRevocation,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { resolverForTests } from "@o3co/auth-provider-core/testing";
import express, { type RequestHandler } from "express";
import supertest from "supertest";
import { describe, expect, it, vi } from "vitest";
import type { WebAuthnSubject } from "#/request.mjs";
import { webauthnSessionSubjectModule } from "#/sessionSubject.mjs";

const SUBJECT = "u-1";
const SID = "s-1";
const T0 = Date.now();
/** The issuer the resolver registers each page on, as boot registers it on `oauth.jwt.issuer`. */
const ISSUER = "https://as.example.test";

const live = (over: Partial<UserSession> = {}): UserSession => ({
	sid: SID,
	sub: SUBJECT,
	authTime: new Date(T0 - 60_000),
	createdAt: new Date(T0 - 60_000),
	expiresAt: new Date(T0 + 3_600_000),
	claims: {},
	amr: undefined,
	authentication: undefined,
	...over,
});

/** The cookie session a signed-in browser carries. */
const SIGNED_IN = { sid: SID, isAuthenticated: true, user: { id: SUBJECT } };

/** The deployment's mapper: the opaque subject id as the user handle. */
const bySubject = (session: UserSession): WebAuthnSubject => ({ userId: session.sub });

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

function fixtureRequirement(verdict: RequirementVerdict | Error): {
	requirement: SessionRequirement;
	asked: RequirementInput[];
} {
	const asked: RequirementInput[] = [];
	return {
		asked,
		requirement: {
			name: "fixture",
			reach: new Set<string>(),
			stepUpPage: { url: "/fixture/step-up", params: { requirement: "fixture" } },
			remediations: [],
			hintKeys: [],
			admit: async (input) => {
				asked.push(input);
				if (verdict instanceof Error) throw verdict;
				return verdict;
			},
		},
	};
}

const revocation = (at: Date | Error): SubjectRevocation =>
	({
		kind: "test",
		revokedBefore: vi.fn(async () => {
			if (at instanceof Error) throw at;
			return at;
		}),
		revokeBefore: vi.fn(async () => {}),
	}) as unknown as SubjectRevocation;

interface Setup {
	readonly subjectFor?: (session: UserSession) => WebAuthnSubject;
	readonly session?: Record<string, unknown>;
	readonly record?: UserSession | null | Error;
	readonly requirement?: SessionRequirement;
	readonly subjectRevocation?: SubjectRevocation;
	readonly logger?: ReturnType<typeof spyLogger>;
	/** Leave the store out of the deps, as no composition can (the module requires it). */
	readonly noStore?: boolean;
	/** A subject an earlier middleware set — the deployment's bearer-token bridge, say. */
	readonly preset?: WebAuthnSubject;
}

interface Contribution {
	readonly id: string;
	readonly mountPath: string;
	readonly after?: readonly string[];
	readonly before?: readonly string[];
	readonly handler: RequestHandler;
}

/** The module's one route factory, as the planner calls it. */
const routeFactory = (subjectFor: (session: UserSession) => WebAuthnSubject) => {
	const routes = webauthnSessionSubjectModule({ subjectFor }).contributes?.routes as unknown as
		| ReadonlyArray<(deps: unknown) => Contribution>
		| undefined;
	expect(routes).toHaveLength(1);
	return routes?.[0] as (deps: unknown) => Contribution;
};

/**
 * The route mounted where the planner mounts it, behind a cookie session,
 * in front of two probes standing in for the registration routes: each
 * answers what it found on `req.webauthnSubject`.
 */
function setup(options: Setup = {}) {
	const get = vi.fn(async () => {
		const record = options.record === undefined ? live() : options.record;
		if (record instanceof Error) throw record;
		return record;
	});
	const userSessionStore = {
		kind: "test",
		create: vi.fn(),
		get,
		delete: vi.fn(),
	} as unknown as UserSessionStore;
	const subjectFor = vi.fn(options.subjectFor ?? bySubject);
	const contribution = routeFactory(subjectFor)({
		sessionRequirementResolver: resolverForTests(options.requirement ? [options.requirement] : [], {
			issuer: ISSUER,
		}),
		...(options.noStore ? {} : { userSessionStore }),
		...(options.subjectRevocation ? { subjectRevocation: options.subjectRevocation } : {}),
		...(options.logger ? { logger: options.logger as unknown as Logger } : {}),
	});
	const app = express();
	app.use((req, _res, next) => {
		(req as unknown as { session: unknown }).session = { ...(options.session ?? SIGNED_IN) };
		if (options.preset !== undefined) req.webauthnSubject = options.preset;
		next();
	});
	app.use(contribution.mountPath, contribution.handler);
	const probe: RequestHandler = (req, res) => {
		res.status(200).json({ subject: req.webauthnSubject ?? null });
	};
	app.post("/oauth/webauthn/registration/options", probe);
	app.post("/oauth/webauthn/registration/verify", probe);
	app.get("/oauth/webauthn/registration/options", probe);
	return { app, get, subjectFor };
}

const register = (app: express.Express, route: "options" | "verify" = "options") =>
	supertest(app).post(`/oauth/webauthn/registration/${route}`).send({});

// ---------------------------------------------------------------------------
// The manifest
// ---------------------------------------------------------------------------

describe("webauthnSessionSubjectModule — the manifest", () => {
	const module = webauthnSessionSubjectModule({ subjectFor: bySubject });

	it("requires the resolver and the user-session store — the cookie path it serves is the store-backed one — and not the config: the step-up page comes resolved from registration", () => {
		expect(module.name).toBe("webauthn-session-subject");
		expect([...(module.requires ?? [])].sort()).toEqual(
			["sessionRequirementResolver", "userSessionStore"].sort(),
		);
	});

	it("may be given the revocation boundary, an audit sink and a logger, each absence decided", () => {
		expect([...(module.optional ?? [])].sort()).toEqual(
			["auditSink", "logger", "subjectRevocation"].sort(),
		);
		expect(module.absencePolicies?.subjectRevocation).toBe(SUBJECT_REVOCATION_ABSENCE_POLICY);
		expect(module.absencePolicies?.auditSink).toBe(AUDIT_SINK_ABSENCE_POLICY);
	});

	it("contributes one route at the registration routes' mount path, after the session middleware and before both registration routes", () => {
		const contribution = routeFactory(bySubject)({
			sessionRequirementResolver: resolverForTests([]),
			userSessionStore: {} as never,
		});
		expect(contribution.id).toBe("webauthn-session-subject");
		expect(contribution.mountPath).toBe("/oauth/webauthn/registration");
		expect(contribution.after).toEqual(["session-middleware"]);
		expect([...(contribution.before ?? [])].sort()).toEqual(
			["webauthn-registration-options", "webauthn-registration-verify"].sort(),
		);
	});

	it("refuses, when its route is built, a resolver missing or not the planner's — core's checkResolver, naming the module, as every consumer factory does", () => {
		const factory = routeFactory(bySubject);
		const forged = { get: () => undefined, entries: () => [][Symbol.iterator]() };
		expect(() => factory({ userSessionStore: {} as never })).toThrow(
			/^webauthnSessionSubjectModule: requirements is required/,
		);
		expect(() =>
			factory({ sessionRequirementResolver: forged, userSessionStore: {} as never }),
		).toThrow(
			/^webauthnSessionSubjectModule: requirements must be the sessionRequirementResolver the boot planner built/,
		);
	});

	it("refuses a mapper that is not a function when the module is built", () => {
		expect(() => webauthnSessionSubjectModule({ subjectFor: undefined as never })).toThrow(
			TypeError,
		);
		expect(() => webauthnSessionSubjectModule(undefined as never)).toThrow(TypeError);
	});
});

// ---------------------------------------------------------------------------
// The outcomes
// ---------------------------------------------------------------------------

describe("webauthnSessionSubjectModule — admission's answer, per outcome (webauthn.register)", () => {
	it.each(["options", "verify"] as const)(
		"sets the deployment's subject for an admitted session on registration/%s",
		async (route) => {
			const { app, get, subjectFor } = setup();
			const res = await register(app, route);
			expect(res.status).toBe(200);
			expect(res.body.subject).toEqual({ userId: SUBJECT });
			expect(get).toHaveBeenCalledWith(SID);
			expect(subjectFor).toHaveBeenCalledTimes(1);
			expect(subjectFor.mock.calls[0]?.[0]).toMatchObject({ sid: SID, sub: SUBJECT });
		},
	);

	it("hands the mapper's userName and userDisplayName through", async () => {
		const { app } = setup({
			subjectFor: (session) => ({
				userId: session.sub,
				userName: "alice",
				userDisplayName: "Alice",
			}),
		});
		const res = await register(app);
		expect(res.body.subject).toEqual({
			userId: SUBJECT,
			userName: "alice",
			userDisplayName: "Alice",
		});
	});

	it("copies the subject to its three fields: nothing else the mapper answered reaches the route", async () => {
		const { app } = setup({
			subjectFor: (session) =>
				({ userId: session.sub, email: "alice@example.com" }) as unknown as WebAuthnSubject,
		});
		const res = await register(app);
		expect(res.status).toBe(200);
		expect(res.body.subject).toEqual({ userId: SUBJECT });
	});

	it("sets no subject for a browser that is not signed in, reading no store", async () => {
		const { app, get, subjectFor } = setup({ session: {} });
		const res = await register(app);
		expect(res.status).toBe(200);
		expect(res.body.subject).toBeNull();
		expect(get).not.toHaveBeenCalled();
		expect(subjectFor).not.toHaveBeenCalled();
	});

	it.each([
		["a cookie without user.id", { session: { sid: SID, isAuthenticated: true } }],
		["a cookie without sid", { session: { isAuthenticated: true, user: { id: SUBJECT } } }],
		["a session that is gone", { record: null }],
		["a record past its expiresAt", { record: live({ expiresAt: new Date(T0 - 1000) }) }],
		["a record of another subject", { record: live({ sub: "u-2" }) }],
		["a session the revocation boundary covers", { subjectRevocation: revocation(new Date()) }],
		[
			"a requirement's reauthenticate",
			{ requirement: fixtureRequirement({ outcome: "reauthenticate" }).requirement },
		],
		[
			"a requirement's unmet",
			{ requirement: fixtureRequirement({ outcome: "unmet" }).requirement },
		],
	] satisfies ReadonlyArray<readonly [string, Setup]>)(
		"sets no subject for %s, so the route answers its own 401",
		async (_label, options) => {
			const { app, subjectFor } = setup(options);
			const res = await register(app);
			expect(res.status).toBe(200);
			expect(res.body.subject).toBeNull();
			expect(subjectFor).not.toHaveBeenCalled();
		},
	);

	it.each([
		["a session that is gone", { record: null }],
		["a cookie without user.id", { session: { sid: SID, isAuthenticated: true } }],
		["a session the revocation boundary covers", { subjectRevocation: revocation(new Date()) }],
		[
			"a requirement's reauthenticate",
			{ requirement: fixtureRequirement({ outcome: "reauthenticate" }).requirement },
		],
		[
			"a requirement's unmet",
			{ requirement: fixtureRequirement({ outcome: "unmet" }).requirement },
		],
	] satisfies ReadonlyArray<readonly [string, Setup]>)(
		"clears a subject an earlier middleware set for %s: a dead cookie session registers nothing",
		async (_label, options) => {
			const { app } = setup({ ...options, preset: { userId: "earlier" } });
			const res = await register(app);
			expect(res.status).toBe(200);
			expect(res.body.subject).toBeNull();
		},
	);

	it("leaves a subject an earlier middleware set when the browser is not signed in: the bearer bridge keeps working", async () => {
		const { app, get } = setup({ session: {}, preset: { userId: "bearer-user" } });
		const res = await register(app);
		expect(res.status).toBe(200);
		expect(res.body.subject).toEqual({ userId: "bearer-user" });
		expect(get).not.toHaveBeenCalled();
	});

	it("sets the subject for a session established after the revocation boundary", async () => {
		const { app } = setup({ subjectRevocation: revocation(new Date(T0 - 3_600_000)) });
		expect((await register(app)).body.subject).toEqual({ userId: SUBJECT });
	});

	it("sets no subject when no store reached the route: admission has no record to hand the mapper", async () => {
		const { app, subjectFor } = setup({ noStore: true });
		const res = await register(app);
		expect(res.status).toBe(200);
		expect(res.body.subject).toBeNull();
		expect(subjectFor).not.toHaveBeenCalled();
	});

	it.each([
		[
			"the session store",
			{ record: new Error("session store down") },
			"user_session",
			"session store unavailable",
		],
		[
			"the revocation boundary",
			{ subjectRevocation: revocation(new Error("boundary down")) },
			"revocation_boundary",
			"revocation store unavailable",
		],
		[
			"a requirement",
			{ requirement: fixtureRequirement(new Error("requirement down")).requirement },
			"fixture",
			"session requirement unavailable",
		],
	] satisfies ReadonlyArray<readonly [string, Setup, string, string]>)(
		"answers 503 temporarily_unavailable when %s cannot answer, described by what failed (core's describeAdmissionOutage), logged once by admission, and never reaches the route",
		async (_label, options, store, description) => {
			const logger = spyLogger();
			const { app } = setup({ ...options, logger });
			const res = await register(app);
			expect(res.status).toBe(503);
			expect(res.body).toEqual({
				error: "temporarily_unavailable",
				error_description: description,
			});
			expect(logger.error).toHaveBeenCalledTimes(1);
			expect(logger.error.mock.calls[0]?.[1]).toBe("session_admission_unavailable");
			expect(logger.error.mock.calls[0]?.[0]).toMatchObject({ store, action: "webauthn.register" });
		},
	);

	it("answers a requirement's step-up with 403 step_up_required, the requirement and its page as one absolute URL on the issuer, and never reaches the route", async () => {
		const { app, subjectFor } = setup({
			requirement: fixtureRequirement({ outcome: "step_up", whenStillUnmet: "reauthenticate" })
				.requirement,
		});
		const res = await register(app);
		expect(res.status).toBe(403);
		expect(res.body).toEqual({
			error: "step_up_required",
			error_description: "Registering a passkey requires a step-up first",
			requirement: "fixture",
			// The shape every consumer answers (ADR 2026-09-28-session-admission):
			// the page as registered, resolved on the issuer, its params
			// on the query, no return parameter — the account page knows where it
			// comes back to. The module is handed no config: nothing here reads
			// the issuer.
			page: `${ISSUER}/fixture/step-up?requirement=fixture`,
		});
		expect(subjectFor).not.toHaveBeenCalled();
	});

	it("asks each requirement about webauthn.register, graded credential_change, over the cookie", async () => {
		const fixture = fixtureRequirement({ outcome: "met" });
		const { app } = setup({ requirement: fixture.requirement });
		expect((await register(app)).status).toBe(200);
		expect(fixture.asked).toHaveLength(1);
		expect(fixture.asked[0]).toMatchObject({
			action: { name: "webauthn.register", grade: "credential_change" },
			carrier: "cookie",
			subject: SUBJECT,
			session: { sid: SID, sub: SUBJECT },
		});
	});

	it("admits only the two registration routes' POSTs: nothing else under the path reads a session", async () => {
		const { app, get } = setup();
		const res = await supertest(app).get("/oauth/webauthn/registration/options");
		expect(res.status).toBe(200);
		expect(res.body.subject).toBeNull();
		expect(get).not.toHaveBeenCalled();
	});
});

// ---------------------------------------------------------------------------
// The mapper's answer
// ---------------------------------------------------------------------------

describe("webauthnSessionSubjectModule — the deployment's mapper is held to the subject's shape", () => {
	it.each([
		["not an object", () => "u-1"],
		[
			"a function, even one carrying a userId",
			() => Object.assign(() => undefined, { userId: "u-1" }),
		],
		["null", () => null],
		["without a userId", () => ({})],
		["with an empty userId", () => ({ userId: "" })],
		["with a userId that is not a string", () => ({ userId: 7 })],
		["with a userName that is not a string", () => ({ userId: "u-1", userName: 7 })],
		["with a userDisplayName that is not a string", () => ({ userId: "u-1", userDisplayName: {} })],
		["a promise", async () => ({ userId: "u-1" })],
	] satisfies ReadonlyArray<readonly [string, () => unknown]>)(
		"answers 500 server_error for an answer %s, logged once, and never reaches the route",
		async (_label, answer) => {
			const logger = spyLogger();
			const { app } = setup({
				subjectFor: answer as unknown as (session: UserSession) => WebAuthnSubject,
				logger,
			});
			const res = await register(app);
			expect(res.status).toBe(500);
			expect(res.body).toEqual({
				error: "server_error",
				error_description: "subjectFor did not answer a WebAuthn subject",
			});
			expect(logger.error).toHaveBeenCalledTimes(1);
			expect(logger.error.mock.calls[0]?.[1]).toBe("webauthn_session_subject_invalid");
			expect(logger.error.mock.calls[0]?.[0]).toEqual({ reason: "shape" });
		},
	);

	it("answers 500 server_error for an answer whose field throws when it is read, logged once as a throw", async () => {
		const logger = spyLogger();
		const { app } = setup({
			subjectFor: () =>
				({
					get userId(): string {
						throw new Error("no handle");
					},
				}) as WebAuthnSubject,
			logger,
		});
		const res = await register(app);
		expect(res.status).toBe(500);
		expect(res.body).toEqual({
			error: "server_error",
			error_description: "subjectFor did not answer a WebAuthn subject",
		});
		expect(logger.error).toHaveBeenCalledTimes(1);
		const [context, name] = logger.error.mock.calls[0] as [Record<string, unknown>, string];
		expect(name).toBe("webauthn_session_subject_invalid");
		expect(context.reason).toBe("threw");
		expect(context.err).not.toBeInstanceOf(Error);
	});

	it("answers 500 server_error for a mapper that throws, logged once with the error's projection", async () => {
		const logger = spyLogger();
		const { app } = setup({
			subjectFor: () => {
				throw new Error("no handle for u-1");
			},
			logger,
		});
		const res = await register(app);
		expect(res.status).toBe(500);
		expect(res.body.error).toBe("server_error");
		expect(logger.error).toHaveBeenCalledTimes(1);
		const [context, name] = logger.error.mock.calls[0] as [Record<string, unknown>, string];
		expect(name).toBe("webauthn_session_subject_invalid");
		expect(context.reason).toBe("threw");
		expect(context.err).not.toBeInstanceOf(Error);
		expect(context.err).toMatchObject({ name: "Error" });
	});
});
