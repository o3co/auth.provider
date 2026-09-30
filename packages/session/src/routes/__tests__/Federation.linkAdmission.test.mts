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
 * The federation link flow on session admission (ADR
 * 2026-09-28-session-admission, D4 and D8). The `?link=1` start reads the
 * browser's session through `admitSession` as `session.link`, graded
 * `credential_change` so a requirement decides the recent-MFA rule where a
 * step-up has a page to return to, and records the subject beside the `sid`
 * in the transaction. The callback reads the session the start bound as
 * `session.link_callback`, with `linkClaim` over that transaction: a
 * `form_post` callback arrives on a fresh cookie session and has no other
 * binding. Pinned: each outcome's answer, D8's changes (3), (4) and (5) for
 * the start among them, and what the requirements are asked.
 */

import {
	type AuditEvent,
	type AuditSink,
	codeChallenge,
	type FederationProvider,
	type Logger,
	type RequirementInput,
	type RequirementVerdict,
	type SessionRequirement,
	type SubjectRevocation,
	type UserRepository,
	type UserSession,
} from "@o3co/auth-provider-core";
import { resolverForTests } from "@o3co/auth-provider-core/testing";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { SESSION_ADMISSION_ACTIONS } from "#/admissionActions.mjs";
import { FEDERATION_TRANSACTION_KEY_PREFIX } from "#/federations/transaction.mjs";
import {
	buildFederationApp,
	HARNESS_ISSUER,
	HARNESS_TRANSACTION_COOKIE_NAME,
	type HarnessApp,
} from "./federation-harness.mjs";

const QUERY_CALLBACK_URL = "https://app.example.com/session/oauth/federation/test/callback";
const POST_CALLBACK_URL = "https://app.example.com/session/oauth/federation/posting/callback";

/** A query-mode provider, and a form_post one. */
function provider(name: string, responseMode?: "form_post"): FederationProvider {
	return {
		name,
		scope: ["openid"],
		...(responseMode ? { responseMode } : {}),
		buildAuthorizationUrl: ({ state, codeVerifier }) => {
			const url = new URL("https://idp.example.com/authorize");
			url.searchParams.set("state", state);
			url.searchParams.set("code_challenge", codeChallenge(codeVerifier));
			return url;
		},
		exchangeCode: vi.fn(async () => ({
			issuer: "https://idp.example.com",
			sub: "external-42",
			accessToken: "at",
			expiresAt: new Date(Date.now() + 3_600_000),
			scope: "openid",
		})),
	};
}

const providers = new Map([
	["test", provider("test")],
	["posting", provider("posting", "form_post")],
]);
const providerCallbackUrls = new Map([
	["test", QUERY_CALLBACK_URL],
	["posting", POST_CALLBACK_URL],
]);

/** The account the browser is signed in as, and its live record. */
const SUBJECT = "user-1";
const SID = "s-1";
/** One clock reading for the file, so two records built from it are equal. */
const T0 = Date.now();
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

type LinkableRepo = UserRepository & {
	linkFederatedIdentity: ReturnType<typeof vi.fn>;
};

/** A Store that can link, and to which the upstream identity is unknown. */
const linkableRepo = (): LinkableRepo =>
	({
		authenticate: vi.fn(async () => null),
		authenticateByToken: vi.fn(async () => null),
		linkFederatedIdentity: vi.fn(async () => ({ ok: true, user: { id: SUBJECT } })),
	}) as unknown as LinkableRepo;

/** A requirement answering `verdict` for every session it is asked about, recording what it was asked. */
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

/** A boundary stamped at `at`, or a revocation store that cannot answer. */
const revocation = (at: Date | Error): SubjectRevocation =>
	({
		kind: "test",
		revokedBefore: vi.fn(async () => {
			if (at instanceof Error) throw at;
			return at;
		}),
		revokeBefore: vi.fn(async () => {}),
	}) as unknown as SubjectRevocation;

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

const recorder = () => {
	const events: AuditEvent[] = [];
	const sink: AuditSink = {
		kind: "test",
		record: async (event) => {
			events.push(event);
		},
	};
	return { sink, events };
};

interface Setup {
	readonly requirement?: SessionRequirement;
	readonly subjectRevocation?: SubjectRevocation;
	readonly repo?: LinkableRepo;
	readonly logger?: Logger;
	readonly auditSink?: AuditSink;
	/** What the store answers for the session: the live record by default. */
	readonly record?: UserSession | null | Error;
}

function setup(options: Setup = {}): HarnessApp & { repo: LinkableRepo } {
	const repo = options.repo ?? linkableRepo();
	const harness = buildFederationApp({
		providers,
		providerCallbackUrls,
		userRepository: repo,
		requirements: resolverForTests(options.requirement ? [options.requirement] : [], {
			issuer: HARNESS_ISSUER,
			actions: SESSION_ADMISSION_ACTIONS,
		}),
		...(options.subjectRevocation ? { subjectRevocation: options.subjectRevocation } : {}),
		...(options.logger ? { logger: options.logger } : {}),
		...(options.auditSink ? { auditSink: options.auditSink } : {}),
	});
	const record = options.record === undefined ? live() : options.record;
	vi.mocked(harness.userSessionStore.get).mockImplementation(async () => {
		if (record instanceof Error) throw record;
		return record;
	});
	return { ...harness, repo };
}

/** The browser's cookie session, planted under the `sid` cookie `browser`. */
function plant(harness: HarnessApp, data: Record<string, unknown>): void {
	harness.store.set("browser", {
		data,
		cookie: { sameSite: "lax", secure: false, httpOnly: true },
	});
}

/** A link start from this deployment's own page, carrying the planted cookie session. */
const start = (harness: HarnessApp, name = "test") =>
	request(harness.app)
		.get(`/oauth/federation/${name}?link=1`)
		.set("Cookie", "sid=browser")
		.set("Sec-Fetch-Site", "same-origin");

/** What the query-mode start recorded in the browser's session. */
const recordedLink = (harness: HarnessApp): unknown =>
	(harness.store.get("browser")?.data.federation as { link?: unknown } | undefined)?.link;

// ---------------------------------------------------------------------------
// The start
// ---------------------------------------------------------------------------

describe("the ?link=1 start reads the session through admission (session.link)", () => {
	it("records the subject beside the sid when the session is admitted, and sends the browser to the IdP", async () => {
		const harness = setup();
		plant(harness, SIGNED_IN);
		const res = await start(harness);
		expect(res.status).toBe(302);
		expect(recordedLink(harness)).toEqual({ sid: SID, subject: SUBJECT });
		expect(harness.userSessionStore.get).toHaveBeenCalledWith(SID);
	});

	it("records the sid the record was read by — the cookie's — whatever the record says, and the link completes", async () => {
		// A store's record without its own `sid` (the port's field, which a
		// deployment's store may leave out) is still the record of the session
		// the cookie names: the key it was read by is what the callback binds to.
		const { sid: _omitted, ...withoutSid } = live();
		const harness = setup({ record: withoutSid as unknown as UserSession });
		plant(harness, SIGNED_IN);
		expect((await start(harness)).status).toBe(302);
		expect(recordedLink(harness)).toEqual({ sid: SID, subject: SUBJECT });
		const { state } = (harness.store.get("browser")?.data.federation ?? {}) as { state?: string };
		const res = await request(harness.app)
			.get(`/oauth/federation/test/callback?state=${state}&code=c-1`)
			.set("Cookie", "sid=browser");
		expect(res.status).toBe(302);
		expect(harness.repo.linkFederatedIdentity).toHaveBeenCalledWith(
			SUBJECT,
			expect.objectContaining({ provider: "test" }),
		);
		expect(harness.sessionFederationIndex.addFederation).toHaveBeenCalledWith(
			SID,
			"test",
			live().expiresAt,
		);
	});

	it("records the subject in a form_post transaction too", async () => {
		const harness = setup();
		plant(harness, SIGNED_IN);
		const res = await start(harness, "posting");
		expect(res.status).toBe(302);
		const [key] = [...harness.records.keys()];
		expect(key?.startsWith(FEDERATION_TRANSACTION_KEY_PREFIX)).toBe(true);
		const stored = harness.records.get(key as string) as { federation: { link?: unknown } };
		expect(stored.federation.link).toEqual({ sid: SID, subject: SUBJECT });
	});

	it("refuses a browser that is not signed in with 401 login_required, reading no store", async () => {
		const harness = setup();
		plant(harness, {});
		const res = await start(harness);
		expect(res.status).toBe(401);
		expect(res.body).toEqual({
			error: "login_required",
			error_description: "Linking a federated identity requires an authenticated session",
		});
		expect(harness.userSessionStore.get).not.toHaveBeenCalled();
		expect(recordedLink(harness)).toBeUndefined();
	});

	it("refuses a signed-in cookie with no sid, reading no store", async () => {
		const harness = setup();
		plant(harness, { isAuthenticated: true, user: { id: SUBJECT } });
		const res = await start(harness);
		expect(res.status).toBe(401);
		expect(res.body.error).toBe("login_required");
		expect(harness.userSessionStore.get).not.toHaveBeenCalled();
	});

	it("refuses a signed-in cookie without user.id before any store is read", async () => {
		const harness = setup();
		plant(harness, { sid: SID, isAuthenticated: true });
		const res = await start(harness);
		expect(res.status).toBe(401);
		expect(res.body.error).toBe("login_required");
		expect(harness.userSessionStore.get).not.toHaveBeenCalled();
		expect(recordedLink(harness)).toBeUndefined();
	});

	it("refuses a cookie whose UserSession is gone — the start reads the live session now", async () => {
		const harness = setup({ record: null });
		plant(harness, SIGNED_IN);
		const res = await start(harness);
		expect(res.status).toBe(401);
		expect(res.body.error).toBe("login_required");
		expect(recordedLink(harness)).toBeUndefined();
	});

	it("refuses a record past its expiresAt", async () => {
		const harness = setup({ record: live({ expiresAt: new Date(Date.now() - 1000) }) });
		plant(harness, SIGNED_IN);
		const res = await start(harness);
		expect(res.status).toBe(401);
		expect(res.body.error).toBe("login_required");
		expect(recordedLink(harness)).toBeUndefined();
	});

	it("refuses a cookie whose user is not the record's subject, and audits it", async () => {
		const audit = recorder();
		const harness = setup({ record: live({ sub: "user-2" }), auditSink: audit.sink });
		plant(harness, SIGNED_IN);
		const res = await start(harness);
		expect(res.status).toBe(401);
		expect(res.body.error).toBe("login_required");
		expect(recordedLink(harness)).toBeUndefined();
		await vi.waitFor(() => expect(audit.events).toHaveLength(1));
		expect(audit.events[0]).toMatchObject({
			type: "session.admission.subject_mismatch",
			details: { carrier: "cookie", claimedSubject: SUBJECT, recordSubject: "user-2" },
		});
	});

	it("refuses a session the subject-revocation boundary covers, when subjectRevocation is wired", async () => {
		const boundary = revocation(new Date());
		const harness = setup({ subjectRevocation: boundary });
		plant(harness, SIGNED_IN);
		const res = await start(harness);
		expect(res.status).toBe(401);
		expect(res.body.error).toBe("login_required");
		expect(boundary.revokedBefore).toHaveBeenCalledWith(SUBJECT);
		expect(recordedLink(harness)).toBeUndefined();
	});

	it("admits a session established after the boundary", async () => {
		const harness = setup({ subjectRevocation: revocation(new Date(Date.now() - 3_600_000)) });
		plant(harness, SIGNED_IN);
		expect((await start(harness)).status).toBe(302);
		expect(recordedLink(harness)).toEqual({ sid: SID, subject: SUBJECT });
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
		"answers 503 temporarily_unavailable when %s cannot answer, described by what failed (core's describeAdmissionOutage), logged once by admission",
		async (_label, options, store, description) => {
			const logger = spyLogger();
			const harness = setup({ ...options, logger: logger as unknown as Logger });
			plant(harness, SIGNED_IN);
			const res = await start(harness);
			expect(res.status).toBe(503);
			expect(res.body).toEqual({
				error: "temporarily_unavailable",
				error_description: description,
			});
			expect(recordedLink(harness)).toBeUndefined();
			expect(logger.error).toHaveBeenCalledTimes(1);
			expect(logger.error.mock.calls[0]?.[1]).toBe("session_admission_unavailable");
			expect(logger.error.mock.calls[0]?.[0]).toMatchObject({ store, action: "session.link" });
		},
	);

	it("asks each requirement about session.link, graded credential_change, over the cookie", async () => {
		const fixture = fixtureRequirement({ outcome: "met" });
		const harness = setup({ requirement: fixture.requirement });
		plant(harness, SIGNED_IN);
		expect((await start(harness)).status).toBe(302);
		expect(fixture.asked).toHaveLength(1);
		expect(fixture.asked[0]).toMatchObject({
			action: { name: "session.link", grade: "credential_change" },
			carrier: "cookie",
			subject: SUBJECT,
			session: { sid: SID, sub: SUBJECT },
		});
	});

	it("answers a requirement's step-up with 403 step_up_required, the requirement and its page as one absolute URL on the issuer, and records nothing", async () => {
		const fixture = fixtureRequirement({ outcome: "step_up", whenStillUnmet: "reauthenticate" });
		const harness = setup({ requirement: fixture.requirement });
		plant(harness, SIGNED_IN);
		const res = await start(harness);
		expect(res.status).toBe(403);
		expect(res.body).toEqual({
			error: "step_up_required",
			error_description: "Linking a federated identity requires a step-up first",
			requirement: "fixture",
			// The shape every consumer answers (the session-admission ADR's D8, as
			// amended): the page as registered, resolved on the issuer — not on
			// the account page's origin — its params on the query, no return
			// parameter: the page that probed the start knows where it returns.
			// The router's config carries no issuer: nothing here reads one.
			page: `${HARNESS_ISSUER}/fixture/step-up?requirement=fixture`,
		});
		expect(recordedLink(harness)).toBeUndefined();
		expect(harness.records.size).toBe(0);
	});

	it.each([
		["reauthenticate", { outcome: "reauthenticate" }],
		["unmet", { outcome: "unmet" }],
	] satisfies ReadonlyArray<readonly [string, RequirementVerdict]>)(
		"answers a requirement's %s with 401 login_required",
		async (_label, verdict) => {
			const harness = setup({ requirement: fixtureRequirement(verdict).requirement });
			plant(harness, SIGNED_IN);
			const res = await start(harness);
			expect(res.status).toBe(401);
			expect(res.body.error).toBe("login_required");
			expect(recordedLink(harness)).toBeUndefined();
		},
	);

	it.each([
		["a signed-in browser whose session store is down", SIGNED_IN, new Error("session store down")],
		["a browser that is not signed in", {}, undefined],
	] satisfies ReadonlyArray<readonly [string, Record<string, unknown>, Error | undefined]>)(
		"answers link_unsupported before reading the session — a static fault is 400 before 401 or 503: %s",
		async (_label, cookie, down) => {
			const harness = setup({
				repo: {
					authenticate: vi.fn(async () => null),
					authenticateByToken: vi.fn(async () => null),
				} as unknown as LinkableRepo,
				...(down ? { record: down } : {}),
			});
			plant(harness, cookie);
			const res = await start(harness);
			expect(res.status).toBe(400);
			expect(res.body.error).toBe("link_unsupported");
			expect(harness.userSessionStore.get).not.toHaveBeenCalled();
			expect(recordedLink(harness)).toBeUndefined();
		},
	);

	it("reads no session for an ordinary login start", async () => {
		const harness = setup();
		plant(harness, SIGNED_IN);
		const res = await request(harness.app)
			.get("/oauth/federation/test")
			.set("Cookie", "sid=browser");
		expect(res.status).toBe(302);
		expect(harness.userSessionStore.get).not.toHaveBeenCalled();
		expect(recordedLink(harness)).toBeUndefined();
	});
});

// ---------------------------------------------------------------------------
// The callback
// ---------------------------------------------------------------------------

/** The envelope a query-mode start wrote: the intent, bound to the session and its subject. */
const envelope = (link: Record<string, unknown> = { sid: SID, subject: SUBJECT }) => ({
	name: "test",
	state: "st-1",
	codeVerifier: "cv-1",
	link,
});

/** The query-mode callback, on the browser's cookie session holding `envelope`. */
async function callback(harness: HarnessApp, link?: Record<string, unknown>) {
	plant(harness, { ...SIGNED_IN, federation: envelope(link) });
	return request(harness.app)
		.get("/oauth/federation/test/callback?state=st-1&code=c-1")
		.set("Cookie", "sid=browser");
}

describe("the link callback reads the session the start bound through admission (session.link_callback)", () => {
	it("links the identity to the admitted session's subject and attaches the federation to it", async () => {
		const harness = setup();
		const res = await callback(harness);
		expect(res.status).toBe(302);
		expect(harness.userSessionStore.get).toHaveBeenCalledWith(SID);
		expect(harness.repo.linkFederatedIdentity).toHaveBeenCalledWith(
			SUBJECT,
			expect.objectContaining({ provider: "test", sub: "external-42" }),
		);
		expect(harness.sessionFederationIndex.addFederation).toHaveBeenCalledWith(
			SID,
			"test",
			live().expiresAt,
		);
	});

	it("admits a form_post callback arriving on a fresh cookie session, by the transaction's sid and subject", async () => {
		const harness = setup();
		plant(harness, SIGNED_IN);
		const begun = await start(harness, "posting");
		expect(begun.status).toBe(302);
		const cookie = (begun.headers["set-cookie"] as unknown as string[]).find((c) =>
			c.startsWith(`${HARNESS_TRANSACTION_COOKIE_NAME}=`),
		);
		const [key] = [...harness.records.keys()];
		const stored = harness.records.get(key as string) as { federation: { state: string } };
		const res = await request(harness.app)
			.post("/oauth/federation/posting/callback")
			.set("Cookie", (cookie as string).split(";")[0] as string)
			.type("form")
			.send({ state: stored.federation.state, code: "c-1" });
		expect(res.status).toBe(302);
		expect(harness.repo.linkFederatedIdentity).toHaveBeenCalledWith(
			SUBJECT,
			expect.objectContaining({ provider: "posting" }),
		);
	});

	it.each([
		["gone", { record: null }],
		["past its expiresAt", { record: live({ expiresAt: new Date(Date.now() - 1000) }) }],
		["another subject's", { record: live({ sub: "user-2" }) }],
		["covered by the revocation boundary", { subjectRevocation: revocation(new Date()) }],
	] satisfies ReadonlyArray<readonly [string, Setup]>)(
		"refuses a session that is %s with 401 login_required, and links nothing",
		async (_label, options) => {
			const harness = setup(options);
			const res = await callback(harness);
			expect(res.status).toBe(401);
			expect(res.body).toEqual({
				error: "login_required",
				error_description: "Linking a federated identity requires a live session",
			});
			expect(harness.repo.linkFederatedIdentity).not.toHaveBeenCalled();
			expect(harness.sessionFederationIndex.addFederation).not.toHaveBeenCalled();
		},
	);

	it("audits a record whose subject is not the one the start recorded, as a link carrier", async () => {
		const audit = recorder();
		const harness = setup({ record: live({ sub: "user-2" }), auditSink: audit.sink });
		expect((await callback(harness)).status).toBe(401);
		await vi.waitFor(() => expect(audit.events).toHaveLength(1));
		expect(audit.events[0]).toMatchObject({
			type: "session.admission.subject_mismatch",
			details: { sid: SID, carrier: "link", claimedSubject: SUBJECT, recordSubject: "user-2" },
		});
	});

	it("answers a requirement's step-up with 401 login_required: the callback has no page to return to", async () => {
		const fixture = fixtureRequirement({ outcome: "step_up", whenStillUnmet: "reauthenticate" });
		const harness = setup({ requirement: fixture.requirement });
		const res = await callback(harness);
		expect(res.status).toBe(401);
		expect(res.body).toEqual({
			error: "login_required",
			error_description: "Linking a federated identity requires a live session",
		});
		expect(harness.repo.linkFederatedIdentity).not.toHaveBeenCalled();
	});

	it("asks each requirement about session.link_callback, graded use, over the link", async () => {
		const fixture = fixtureRequirement({ outcome: "met" });
		const harness = setup({ requirement: fixture.requirement });
		expect((await callback(harness)).status).toBe(302);
		expect(fixture.asked).toHaveLength(1);
		expect(fixture.asked[0]).toMatchObject({
			action: { name: "session.link_callback", grade: "use" },
			carrier: "link",
			subject: SUBJECT,
			session: { sid: SID, sub: SUBJECT },
		});
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
		"answers 503 temporarily_unavailable when %s cannot answer, described by what failed (core's describeAdmissionOutage), logged once by admission, and asks no Store",
		async (_label, options, store, description) => {
			const logger = spyLogger();
			const harness = setup({ ...options, logger: logger as unknown as Logger });
			const res = await callback(harness);
			expect(res.status).toBe(503);
			expect(res.body).toEqual({
				error: "temporarily_unavailable",
				error_description: description,
			});
			expect(harness.repo.linkFederatedIdentity).not.toHaveBeenCalled();
			expect(logger.error).toHaveBeenCalledTimes(1);
			expect(logger.error.mock.calls[0]?.[1]).toBe("session_admission_unavailable");
			expect(logger.error.mock.calls[0]?.[0]).toMatchObject({
				store,
				action: "session.link_callback",
			});
			expect(JSON.stringify(logger.error.mock.calls[0]?.[0])).not.toContain(SID);
		},
	);

	it("refuses a transaction a start wrote before it recorded the subject, reading no session", async () => {
		// An in-flight link across the upgrade: nothing binds its callback to an
		// account but the sid, and admission's link claim is the sid and the
		// subject together. The user starts the link again.
		const harness = setup();
		const res = await callback(harness, { sid: SID });
		expect(res.status).toBe(401);
		expect(res.body.error).toBe("login_required");
		expect(harness.userSessionStore.get).not.toHaveBeenCalled();
		expect(harness.repo.linkFederatedIdentity).not.toHaveBeenCalled();
	});

	it("still refuses a browser now holding a different authenticated session, before reading one", async () => {
		const harness = setup();
		plant(harness, {
			sid: "s-2",
			isAuthenticated: true,
			user: { id: SUBJECT },
			federation: envelope(),
		});
		const res = await request(harness.app)
			.get("/oauth/federation/test/callback?state=st-1&code=c-1")
			.set("Cookie", "sid=browser");
		expect(res.status).toBe(401);
		expect(res.body).toEqual({
			error: "login_required",
			error_description: "The link was started from a different session",
		});
		expect(harness.userSessionStore.get).not.toHaveBeenCalled();
	});
});
