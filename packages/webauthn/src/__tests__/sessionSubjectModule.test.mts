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

import { once } from "node:events";
import net, { type AddressInfo } from "node:net";
import {
	AUDIT_SINK_ABSENCE_POLICY,
	createInMemorySessionLifecycleStore,
	type Logger,
	type RequirementInput,
	type RequirementVerdict,
	type SessionLifecycleStore,
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
import {
	SESSION_SUBJECT_ADMISSION_ACTIONS,
	webauthnSessionSubjectModule,
} from "#/sessionSubject.mjs";

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

/**
 * An in-memory lifecycle store holding `SID`'s record, active for `SUBJECT`:
 * a session with no record reads as closed. Opened before its first read.
 */
const openedLifecycleStore = (): SessionLifecycleStore => {
	const store = createInMemorySessionLifecycleStore();
	const opened = store.open(SID, SUBJECT, new Date(Date.now() + 3_600_000));
	return {
		...store,
		read: async (sid) => {
			await opened;
			return store.read(sid);
		},
	};
};

interface Setup {
	readonly subjectFor?: (session: UserSession) => WebAuthnSubject;
	readonly session?: Record<string, unknown>;
	readonly record?: UserSession | null | Error;
	readonly requirement?: SessionRequirement;
	readonly subjectRevocation?: SubjectRevocation;
	/**
	 * Core's session lifecycle port beside the store; by default an in-memory
	 * one holding the session's record, active, as its login opened it; none
	 * when `null`.
	 */
	readonly sessionLifecycleStore?: SessionLifecycleStore | null;
	readonly logger?: ReturnType<typeof spyLogger>;
	/** Leave the store out of the deps, as no composition can (the module requires it). */
	readonly noStore?: boolean;
	/** A subject an earlier middleware set — the deployment's bearer-token bridge, say. */
	readonly preset?: WebAuthnSubject;
	/** A body parser the host installs in front of the provider's routes. */
	readonly upstream?: RequestHandler;
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
			actions: SESSION_SUBJECT_ADMISSION_ACTIONS,
		}),
		...(options.noStore ? {} : { userSessionStore }),
		...(options.subjectRevocation ? { subjectRevocation: options.subjectRevocation } : {}),
		...(options.sessionLifecycleStore === null
			? {}
			: {
					sessionLifecycleStore: options.sessionLifecycleStore ?? openedLifecycleStore(),
				}),
		...(options.logger ? { logger: options.logger as unknown as Logger } : {}),
	});
	const app = express();
	app.use((req, _res, next) => {
		(req as unknown as { session: unknown }).session = { ...(options.session ?? SIGNED_IN) };
		if (options.preset !== undefined) req.webauthnSubject = options.preset;
		next();
	});
	if (options.upstream !== undefined) app.use(options.upstream);
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

	it("registers webauthn.register, graded credential_change: a passkey is a new way into the account", () => {
		expect(module.contributes?.admissionActions).toEqual({
			"webauthn.register": { grade: "credential_change" },
		});
	});

	it("may be given the revocation boundary, the session lifecycle store, an audit sink and a logger, each absence decided", () => {
		expect([...(module.optional ?? [])].sort()).toEqual(
			["auditSink", "logger", "sessionLifecycleStore", "subjectRevocation"].sort(),
		);
		expect(module.absencePolicies?.subjectRevocation).toBe(SUBJECT_REVOCATION_ABSENCE_POLICY);
		expect(module.absencePolicies?.auditSink).toBe(AUDIT_SINK_ABSENCE_POLICY);
	});

	it("contributes one route at the registration routes' mount path, after the session middleware and before both registration routes", () => {
		const contribution = routeFactory(bySubject)({
			sessionRequirementResolver: resolverForTests([], {
				actions: SESSION_SUBJECT_ADMISSION_ACTIONS,
			}),
			userSessionStore: {} as never,
			sessionLifecycleStore: {} as never,
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

	it("refuses, when its route is built, a resolver on which webauthn.register is not registered, naming the module and the action", () => {
		expect(() =>
			routeFactory(bySubject)({
				sessionRequirementResolver: resolverForTests([]),
				userSessionStore: {} as never,
			}),
		).toThrow(
			/^webauthnSessionSubjectModule: admits "webauthn\.register", which no module registers/,
		);
	});

	it("refuses, when its route is built, a user-session store without core's session lifecycle port, naming both slots", () => {
		expect(() => setup({ sessionLifecycleStore: null })).toThrow(
			/^webauthn-session-subject: userSessionStore is wired, but sessionLifecycleStore is not\.[\s\S]*Wire core's session lifecycle: a session-store module that fills sessionLifecycleStore/,
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

	it("sets no subject for a session whose lifecycle record is closing, and sets it while the record is active", async () => {
		const lifecycle = createInMemorySessionLifecycleStore();
		await lifecycle.open(SID, SUBJECT, new Date(Date.now() + 3_600_000));
		const { app, subjectFor } = setup({ sessionLifecycleStore: lifecycle });
		expect((await register(app)).body.subject).not.toBeNull();

		await lifecycle.beginClose(SID, {
			cause: "rp_logout",
			steps: ["tokens"],
			perParticipant: [],
			retainMs: 0,
		});
		subjectFor.mockClear();
		const res = await register(app);
		expect(res.status).toBe(200);
		expect(res.body.subject).toBeNull();
		expect(subjectFor).not.toHaveBeenCalled();
	});

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

	it.each([
		["options", "a body that is not JSON", "{not json", 400],
		[
			"verify",
			"a body over the routes' 100kb limit",
			JSON.stringify({ pad: "x".repeat(110_000) }),
			413,
		],
	] as const)(
		"reads the %s body before the session: %s is refused with no session read",
		async (route, _what, body, status) => {
			const { app, get } = setup();
			const res = await supertest(app)
				.post(`/oauth/webauthn/registration/${route}`)
				.set("Content-Type", "application/json")
				.send(body);
			expect(res.status).toBe(status);
			expect(get).not.toHaveBeenCalled();
		},
	);

	it.each([
		["options", "text/plain", "text/plain"],
		["verify", "a form", "application/x-www-form-urlencoded"],
		["verify", "no content type", undefined],
	] as const)(
		"refuses a %s body sent as %s with 400 invalid_request, with no session read",
		async (route, _what, contentType) => {
			const { app, get } = setup();
			const request = supertest(app).post(`/oauth/webauthn/registration/${route}`);
			if (contentType !== undefined) request.set("Content-Type", contentType);
			else request.unset("Content-Type");
			const res = await request.send(Buffer.from('{"a":1}'));
			expect(res.status).toBe(400);
			expect(res.body).toMatchObject({ error: "invalid_request" });
			expect(get).not.toHaveBeenCalled();
		},
	);

	it("admits a POST with an empty body and no content type", async () => {
		const { app } = setup();
		const res = await supertest(app)
			.post("/oauth/webauthn/registration/options")
			.set("Content-Length", "0");
		expect(res.status).toBe(200);
		expect(res.body.subject).toEqual({ userId: SUBJECT });
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

// ---------------------------------------------------------------------------
// The body's framing
// ---------------------------------------------------------------------------

/**
 * Sends `head` — the request line and headers, without `Host` and
 * `Connection` — then `body`, exactly as given, over a socket; answers the
 * status and the body, parsed when it is JSON.
 */
async function rawPost(app: express.Express, head: readonly string[], body = "") {
	const server = app.listen(0, "127.0.0.1");
	await once(server, "listening");
	try {
		const { port } = server.address() as AddressInfo;
		const socket = net.connect(port, "127.0.0.1");
		await once(socket, "connect");
		socket.write([...head, "Host: 127.0.0.1", "Connection: close", "", ""].join("\r\n") + body);
		const chunks: Buffer[] = [];
		for await (const chunk of socket) chunks.push(chunk as Buffer);
		const text = Buffer.concat(chunks).toString("utf8");
		const payload = text.slice(text.indexOf("\r\n\r\n") + 4);
		let parsed: unknown = payload;
		try {
			parsed = JSON.parse(payload);
		} catch {
			// Not JSON: answered as text.
		}
		return { status: Number(text.split(" ")[1]), body: parsed as Record<string, unknown> };
	} finally {
		server.close();
	}
}

const OPTIONS_LINE = "POST /oauth/webauthn/registration/options HTTP/1.1";
const CHUNKED = "Transfer-Encoding: chunked";

describe("webauthnSessionSubjectModule — the body's framing", () => {
	it.each([
		[
			"a chunked JSON body",
			[OPTIONS_LINE, "Content-Type: application/json", CHUNKED],
			"1\r\n{\r\n1\r\n}\r\n0\r\n\r\n",
		],
		["an empty chunked body with no content type", [OPTIONS_LINE, CHUNKED], "0\r\n\r\n"],
		["Content-Length: 00 with no content type", [OPTIONS_LINE, "Content-Length: 00"], ""],
		["a request with no body framing at all", [OPTIONS_LINE], ""],
		[
			"a JSON body with a charset parameter",
			[OPTIONS_LINE, "Content-Type: application/json; charset=utf-8", "Content-Length: 2"],
			"{}",
		],
	] as const)("admits %s", async (_what, head, body) => {
		const { app, get } = setup();
		const res = await rawPost(app, head, body);
		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(res.body.subject).toEqual({ userId: SUBJECT });
		expect(get).toHaveBeenCalledTimes(1);
	});

	it.each([
		[
			"a body sent as application/*+json, which the routes' parser does not read",
			[OPTIONS_LINE, "Content-Type: application/vnd.example+json", "Content-Length: 2"],
			"{}",
		],
		["a chunked body with no content type", [OPTIONS_LINE, CHUNKED], "2\r\n{}\r\n0\r\n\r\n"],
		[
			"a body with a non-JSON content type",
			[OPTIONS_LINE, "Content-Type: text/plain", "Content-Length: 02"],
			"{}",
		],
	] as const)(
		"refuses %s with 400 invalid_request, with no session read",
		async (_what, head, body) => {
			const { app, get } = setup();
			const res = await rawPost(app, head, body);
			expect(res.status).toBe(400);
			expect(res.body).toMatchObject({ error: "invalid_request" });
			expect(get).not.toHaveBeenCalled();
		},
	);

	it("refuses a chunked body with no content type over the routes' 100kb limit with 413, with no session read", async () => {
		const { app, get } = setup();
		const big = "x".repeat(110_000);
		const res = await rawPost(
			app,
			[OPTIONS_LINE, CHUNKED],
			`${big.length.toString(16)}\r\n${big}\r\n0\r\n\r\n`,
		);
		expect(res.status).toBe(413);
		expect(get).not.toHaveBeenCalled();
	});

	it("leaves a subject an earlier middleware set for an empty chunked request from a browser that is not signed in", async () => {
		const { app, get } = setup({ session: {}, preset: { userId: "bearer-user" } });
		const res = await rawPost(app, [OPTIONS_LINE, CHUNKED], "0\r\n\r\n");
		expect(res.status).toBe(200);
		expect(res.body.subject).toEqual({ userId: "bearer-user" });
		expect(get).not.toHaveBeenCalled();
	});
});

/**
 * A reader the host installs that takes the body to its end, then sets
 * `req.body` to what `parsed` answers, if anything, and marks it read when
 * `mark` is set.
 */
const drainingParser =
	(parsed?: () => unknown, mark = false): RequestHandler =>
	(req, _res, next) => {
		req.on("data", () => {});
		req.on("end", () => {
			if (parsed !== undefined) req.body = parsed();
			if (mark) (req as { _body?: boolean })._body = true;
			next();
		});
	};

const FORM = "application/x-www-form-urlencoded";

describe("webauthnSessionSubjectModule — a body the host's own parser read first", () => {
	it.each([
		[
			"a form body an upstream form parser read",
			express.urlencoded({ extended: true }),
			FORM,
			"a=1&b[c]=2",
		],
		["a form body of separators alone", express.urlencoded({ extended: true }), FORM, "&&&"],
		[
			"a form body of a prototype key",
			express.urlencoded({ extended: true }),
			FORM,
			"__proto__[x]=1",
		],
		["a text body an upstream text parser read", express.text(), "text/plain", "hello"],
		[
			"a multipart body a file-upload parser consumed, leaving an empty object",
			drainingParser(() => ({}), true),
			"multipart/form-data; boundary=x",
			'--x\r\nContent-Disposition: form-data; name="f"; filename="a.txt"\r\n\r\nhello\r\n--x--\r\n',
		],
		[
			"a body a reader drained without setting a body or marking it read",
			drainingParser(),
			"application/octet-stream",
			"hello",
		],
		[
			"a body parsed into an object that inherits a response",
			drainingParser(() => Object.create({ response: { id: "x" } }), true),
			"application/x-custom",
			"hello",
		],
	] as const)(
		"refuses %s with 400 invalid_request, with no session read",
		async (_what, upstream, type, body) => {
			const { app, get } = setup({ upstream });
			const res = await supertest(app)
				.post("/oauth/webauthn/registration/options")
				.set("Content-Type", type)
				.send(body);
			expect(res.status).toBe(400);
			expect(res.body).toMatchObject({ error: "invalid_request" });
			expect(get).not.toHaveBeenCalled();
		},
	);

	it("admits an empty form body an upstream form parser read", async () => {
		const { app } = setup({ upstream: express.urlencoded({ extended: true }) });
		const res = await rawPost(app, [
			OPTIONS_LINE,
			"Content-Type: application/x-www-form-urlencoded",
			"Content-Length: 0",
		]);
		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(res.body.subject).toEqual({ userId: SUBJECT });
	});

	it("refuses an empty chunked body a parser marked read without taking the stream to its end: the framing shows a body", async () => {
		const marksRead: RequestHandler = (req, _res, next) => {
			(req as { _body?: boolean })._body = true;
			req.body = {};
			next();
		};
		const { app, get } = setup({ upstream: marksRead });
		const res = await rawPost(app, [OPTIONS_LINE, `Content-Type: ${FORM}`, CHUNKED], "0\r\n\r\n");
		expect(res.status).toBe(400);
		expect(res.body).toMatchObject({ error: "invalid_request" });
		expect(get).not.toHaveBeenCalled();
	});

	it("refuses an empty chunked form body an upstream form parser read: only framing that shows no body passes", async () => {
		const { app, get } = setup({ upstream: express.urlencoded({ extended: true }) });
		const res = await rawPost(app, [OPTIONS_LINE, `Content-Type: ${FORM}`, CHUNKED], "0\r\n\r\n");
		expect(res.status).toBe(400);
		expect(get).not.toHaveBeenCalled();
	});

	it("admits a form body an upstream form parser read under Content-Length: 00", async () => {
		const { app } = setup({ upstream: express.urlencoded({ extended: true }) });
		const res = await rawPost(app, [OPTIONS_LINE, `Content-Type: ${FORM}`, "Content-Length: 00"]);
		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(res.body.subject).toEqual({ userId: SUBJECT });
	});

	it("admits a JSON body an upstream JSON parser read", async () => {
		const { app } = setup({ upstream: express.json() });
		const res = await supertest(app)
			.post("/oauth/webauthn/registration/options")
			.set("Content-Type", "application/json; charset=utf-8")
			.send('{"a":1}');
		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(res.body.subject).toEqual({ userId: SUBJECT });
	});

	it("answers each of two requests pipelined on one connection", async () => {
		const { app } = setup({ upstream: express.urlencoded({ extended: true }) });
		const server = app.listen(0, "127.0.0.1");
		await once(server, "listening");
		try {
			const { port } = server.address() as AddressInfo;
			const socket = net.connect(port, "127.0.0.1");
			await once(socket, "connect");
			socket.write(
				[
					OPTIONS_LINE,
					"Host: 127.0.0.1",
					CHUNKED,
					"",
					"0",
					"",
					OPTIONS_LINE,
					"Host: 127.0.0.1",
					"Content-Type: application/x-www-form-urlencoded",
					"Content-Length: 3",
					"Connection: close",
					"",
					"a=1",
				].join("\r\n"),
			);
			const chunks: Buffer[] = [];
			for await (const chunk of socket) chunks.push(chunk as Buffer);
			const statuses = [
				...Buffer.concat(chunks)
					.toString("utf8")
					.matchAll(/HTTP\/1\.1 (\d{3})/g),
			].map((match) => match[1]);
			expect(statuses).toEqual(["200", "400"]);
		} finally {
			server.close();
		}
	});
});
