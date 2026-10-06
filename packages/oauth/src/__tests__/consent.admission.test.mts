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
 * `/oauth/consent` on session admission (ADR 2026-09-28-session-admission,
 * D8): both methods read the cookie's session through `admitSession` with
 * `oauth.consent` — liveness and revocation — after the parked request is
 * found and before anything is shown or recorded. A live session whose
 * subject is the parked request's proceeds; every other outcome is
 * `401 login_required`, a requirement's step-up included, because
 * `/authorize` decides again after consent; an outage stays `503`. Every
 * change D8 makes to consent has a test named for it.
 */

import {
	type AuditEvent,
	type AuditSink,
	type ClientRepository,
	type CodeRepository,
	createInMemorySessionLifecycleStore,
	createInMemorySubjectRevocation,
	createMemoryConsentStore,
	createMemoryPendingConsentStore,
	createSymmetricKeyStore,
	type PublicClient,
	type RequirementInput,
	type RequirementVerdict,
	type SessionLifecycleStore,
	type SessionRequirement,
	type SubjectRevocation,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { createTestLoginEntry, resolverForTests } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createOAuthRouter } from "#/routes.mjs";
import { OAUTH_ADMISSION_ACTIONS } from "./_helpers/admissionActions.mjs";
import { authorizationServerRegistry } from "./_helpers/authorizationServerRegistry.mjs";
import { createMockLogger } from "./_helpers/mockLogger.mjs";
import { routerInputsOf } from "./_helpers/sections.mjs";
import { livenessOver } from "./_helpers/sessionLifecycle.mjs";

const CLIENT_ID = "third-party-chat";
const REDIRECT_URI = "https://chat.example/cb";
const ISSUER = "https://issuer.example";
const SID = "sid-1";
const SESSION_ID = "sess-1";
const SUBJECT = "user-1";
const CHALLENGE = "challenge-1";

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
	name: string,
	verdict: () => RequirementVerdict,
): SessionRequirement & { readonly inputs: RequirementInput[] } => {
	const inputs: RequirementInput[] = [];
	return {
		name,
		reach: new Set(),
		stepUpPage: { url: "/step-up", params: {} },
		remediations: [`${name}.step_up`],
		hintKeys: [],
		inputs,
		async admit(input) {
			inputs.push(input);
			return verdict();
		},
	};
};

type Session = Record<string, unknown>;

const makeApp = async (opts: {
	session?: Session;
	userSessionStore?: UserSessionStore;
	subjectRevocation?: SubjectRevocation;
	sessionLifecycleStore?: SessionLifecycleStore;
	requirements?: readonly SessionRequirement[];
	auditSink?: AuditSink;
	/** The parked request's subject; default the cookie's. */
	parkedFor?: string;
}) => {
	const client = {
		clientId: CLIENT_ID,
		tokenEndpointAuthMethod: "none" as const,
		allowedRedirectUris: [REDIRECT_URI],
		allowedScopes: ["read", "write"],
		defaultScopes: ["read"],
		clientName: "Acme Chat",
		firstParty: false,
	} as unknown as PublicClient;
	const clientRepository: ClientRepository = {
		findById: async (id) => (id === CLIENT_ID ? client : null),
		authenticate: async () => null,
	};
	const codeRepository: CodeRepository = {
		createCode: async () => {
			throw new Error("unused");
		},
		findByCode: async () => null,
		consumeByCode: async () => null,
		removeByCode: async () => {},
	};
	const consentStore = createMemoryConsentStore();
	const pendingConsentStore = createMemoryPendingConsentStore();
	const logger = createMockLogger();
	const { router } = await createOAuthRouter(express, {
		loginEntry: createTestLoginEntry(),
		registry: authorizationServerRegistry(),
		...routerInputsOf({
			oauth: { jwt: { issuer: ISSUER }, oidcMode: "dual", grants: {} },
		}),
		clientRepository,
		codeRepository,
		keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
		consentStore,
		pendingConsentStore,
		logger,
		requirements: resolverForTests(opts.requirements ?? [], {
			issuer: ISSUER,
			actions: OAUTH_ADMISSION_ACTIONS,
		}),
		...(opts.userSessionStore
			? {
					userSessionStore: opts.userSessionStore,
					sessionLifecycle: livenessOver(opts.userSessionStore),
				}
			: {}),
		...(opts.subjectRevocation ? { subjectRevocation: opts.subjectRevocation } : {}),
		...(opts.sessionLifecycleStore ? { sessionLifecycleStore: opts.sessionLifecycleStore } : {}),
		...(opts.auditSink ? { auditSink: opts.auditSink } : {}),
	});
	// A request `/authorize` parked for this session, as it parks one.
	const createdAt = Date.now();
	await pendingConsentStore.set({
		challenge: CHALLENGE,
		sessionId: SESSION_ID,
		sub: opts.parkedFor ?? SUBJECT,
		clientId: CLIENT_ID,
		scopes: ["read"],
		grantedScopes: [],
		authorizeUrl: `${ISSUER}/oauth/authorize?client_id=${CLIENT_ID}`,
		redirectUri: REDIRECT_URI,
		state: "xyz",
		createdAt,
		expiresAt: createdAt + 600_000,
	});
	const session: Session = {
		...(opts.session ?? { isAuthenticated: true, user: { id: SUBJECT }, sid: SID }),
	};
	const app = express();
	app.use((req, _res, next) => {
		(req as unknown as { session: Session }).session = session;
		(req as unknown as { sessionID?: string }).sessionID = SESSION_ID;
		next();
	});
	app.use("/oauth", router);
	return { app, logger, consentStore };
};

const show = (app: express.Express, challenge = CHALLENGE) =>
	request(app).get("/oauth/consent").query({ challenge });

const answer = (app: express.Express, decision: "accept" | "deny", challenge = CHALLENGE) =>
	request(app).post("/oauth/consent").type("form").send({ challenge, decision });

const expectLoginRequired = (res: request.Response): void => {
	expect(res.status).toBe(401);
	expect(res.body.error).toBe("login_required");
};

describe("/oauth/consent on admission", () => {
	it("a session whose lifecycle record is closing is not_live: 401 login_required on both methods, its record still there", async () => {
		const live = record();
		const lifecycle = createInMemorySessionLifecycleStore();
		expect((await lifecycle.open(SID, SUBJECT, live.expiresAt)).outcome).toBe("opened");
		const closing = await lifecycle.beginClose(SID, {
			cause: "rp_logout",
			steps: ["held_open"],
			perParticipant: [],
			retainMs: 0,
		});
		expect(closing.outcome).toBe("closing");
		const { app, consentStore } = await makeApp({
			userSessionStore: storeWith(live),
			sessionLifecycleStore: lifecycle,
		});
		expectLoginRequired(await show(app));
		expectLoginRequired(await answer(app, "accept"));
		expect(await consentStore.find(SUBJECT, CLIENT_ID)).toBeNull();
	});

	it("a cookie whose isAuthenticated is not exactly true is refused before anything is read, as every reader reads the flag", async () => {
		const store = storeWith(record());
		const { app } = await makeApp({
			userSessionStore: store,
			session: { isAuthenticated: "true", user: { id: SUBJECT }, sid: SID },
		});
		const res = await show(app);
		expectLoginRequired(res);
		expect(res.body.error_description).toBe("no authenticated session");
		expect(store.get).not.toHaveBeenCalled();
	});

	it("a cookie with isAuthenticated but no sid, while a store is wired, is not_live: 401 login_required on both methods", async () => {
		const store = storeWith(record());
		const { app } = await makeApp({
			userSessionStore: store,
			session: { isAuthenticated: true, user: { id: SUBJECT } },
		});
		expectLoginRequired(await show(app));
		expectLoginRequired(await answer(app, "accept"));
		expect(store.get).not.toHaveBeenCalled();
	});

	it("a cookie without user.id is not_live: 401 login_required on both methods, with no store read", async () => {
		const store = storeWith(record());
		const { app } = await makeApp({
			userSessionStore: store,
			session: { isAuthenticated: true, sid: SID },
		});
		expectLoginRequired(await show(app));
		expectLoginRequired(await answer(app, "accept"));
		expect(store.get).not.toHaveBeenCalled();
	});

	it("a record whose sub differs from the cookie's user.id is not_live: 401 login_required, audited", async () => {
		const events: AuditEvent[] = [];
		const { app } = await makeApp({
			userSessionStore: storeWith(record({ sub: "someone-else" })),
			auditSink: { kind: "recording", record: async (event) => void events.push(event) },
		});
		expectLoginRequired(await show(app));
		expect(events.map((e) => e.type)).toEqual(["session.admission.subject_mismatch"]);
	});

	it("the subject-revocation boundary applies when subjectRevocation is wired: 401 login_required", async () => {
		const revocation = createInMemorySubjectRevocation();
		await revocation.revokeBefore(SUBJECT, new Date(), new Date(Date.now() + 3_600_000));
		const { app } = await makeApp({
			userSessionStore: storeWith(record({ authTime: minutesAgo(5) })),
			subjectRevocation: revocation,
		});
		expectLoginRequired(await show(app));
		expectLoginRequired(await answer(app, "accept"));
	});

	it("a record past its expiresAt is not_live: 401 login_required", async () => {
		const { app } = await makeApp({
			userSessionStore: storeWith(record({ expiresAt: minutesAgo(1) })),
		});
		expectLoginRequired(await show(app));
	});

	it("a store outage stays 503 temporarily_unavailable, logged as admission's line", async () => {
		const { app, logger } = await makeApp({
			userSessionStore: storeAnswering(async () => {
				throw new Error("redis down");
			}),
		});
		const res = await show(app);
		expect(res.status).toBe(503);
		expect(res.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "session store unavailable",
		});
		expect(logger.error).toHaveBeenCalledWith(
			{
				store: "user_session",
				action: "oauth.consent",
				err: expect.objectContaining({ name: "Error" }),
			},
			"session_admission_unavailable",
		);
	});

	it("a live session whose subject the request was parked for is shown the request and can answer it", async () => {
		const store = storeWith(record());
		const { app, consentStore } = await makeApp({ userSessionStore: store });
		const shown = await show(app);
		expect(shown.status).toBe(200);
		expect(shown.body.client_id).toBe(CLIENT_ID);
		const answered = await answer(app, "accept");
		expect(answered.status).toBe(303);
		expect(await consentStore.find(SUBJECT, CLIENT_ID)).toMatchObject({ scopes: ["read"] });
		// One read per request.
		expect(store.get).toHaveBeenCalledTimes(2);
	});

	it("a live session that is not the one the request was parked for is told there is no pending consent", async () => {
		const { app } = await makeApp({ userSessionStore: storeWith(record()), parkedFor: "other" });
		const res = await show(app);
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_request");
	});

	it("still answers a missing challenge 400 and an unauthenticated cookie 401 before any store read", async () => {
		const store = storeWith(record());
		const { app } = await makeApp({
			userSessionStore: store,
			session: { isAuthenticated: false, sid: SID },
		});
		expectLoginRequired(await show(app));
		const authenticated = await makeApp({ userSessionStore: store });
		const res = await request(authenticated.app).get("/oauth/consent");
		expect(res.status).toBe(400);
		expect(store.get).not.toHaveBeenCalled();
	});

	it("without a store, a cookie naming a subject is admitted on its word", async () => {
		const { app } = await makeApp({});
		expect((await show(app)).status).toBe(200);
	});
});

describe("/oauth/consent on admission — a requirement's verdicts", () => {
	it("step_up is 401 login_required, not a trip: /authorize decides again after consent", async () => {
		const requirement = fixture("fixture", () => ({
			outcome: "step_up",
			whenStillUnmet: "reauthenticate",
		}));
		const { app } = await makeApp({
			userSessionStore: storeWith(record()),
			requirements: [requirement],
		});
		expectLoginRequired(await show(app));
		expectLoginRequired(await answer(app, "accept"));
		expect(requirement.inputs[0]?.action).toEqual({ name: "oauth.consent", grade: "use" });
	});

	it("unmet and reauthenticate are 401 login_required", async () => {
		for (const outcome of ["unmet", "reauthenticate"] as const) {
			const { app } = await makeApp({
				userSessionStore: storeWith(record()),
				requirements: [fixture("fixture", () => ({ outcome }))],
			});
			expectLoginRequired(await show(app));
		}
	});

	it("a requirement that throws is 503 temporarily_unavailable", async () => {
		const { app } = await makeApp({
			userSessionStore: storeWith(record()),
			requirements: [
				fixture("fixture", () => {
					throw new Error("policy service down");
				}),
			],
		});
		expect((await show(app)).status).toBe(503);
	});
});

describe("/oauth/consent on admission — the subject is compared after the session is read", () => {
	// Admission reads the session before the cookie's subject is compared
	// with the parked request's, so a dead session or an outage behind a
	// session naming another user is not answered `400`.
	it("a dead session naming another user is 401 login_required, not 400", async () => {
		const { app } = await makeApp({
			userSessionStore: storeWith(null),
			session: { isAuthenticated: true, user: { id: "someone-else" }, sid: SID },
		});
		expectLoginRequired(await show(app));
	});

	it("an outage behind a session naming another user is 503, not 400", async () => {
		const { app } = await makeApp({
			userSessionStore: storeAnswering(async () => {
				throw new Error("redis down");
			}),
			session: { isAuthenticated: true, user: { id: "someone-else" }, sid: SID },
		});
		expect((await show(app)).status).toBe(503);
	});
});
