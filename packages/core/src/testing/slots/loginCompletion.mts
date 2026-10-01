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
 * The contract suite of the `loginCompletion` slot, and its test double.
 * See ADR 2026-09-28-session-admission.
 *
 * `loginCompletionContract(input)` drives a completion over the fake
 * express session of `fake-http.mts` and holds it to what the session
 * package's `establishSession` and `answerInterruption` do:
 *
 * - What core did not build is refused with a `RangeError` before anything
 *   is touched: session, reporter, ceremony, record.
 * - An establishment builds the reporter once, for `{ sid, sub }`, and
 *   saves a regenerated session that `cookieClaim` reads as signed in for
 *   its subject; one record per `sid` answered. The response is the
 *   caller's.
 * - An interruption answers the requirement's `403` (with a fresh token in
 *   `csrfCookieName`, when given), its ceremony opened on the regenerated
 *   session id, saved and not signed in.
 * - An outage (store `create`, cookie `regenerate` / `save`, ceremony
 *   `open`) is reported once, leaves no record and the browser not signed
 *   in; an interruption's is `503 temporarily_unavailable` with no token.
 * - A renewal moves the session it established to a regenerated id, saved
 *   with `isAuthenticated`, `user` and `sid` as they were, a fresh renewal
 *   nonce it answers, and no other field, writing no session record; a
 *   session not signed in stays so. A `regenerate` or `save` that fails, or
 *   a request with no express session, is reported once, saves nothing, and
 *   abandons the request's cookie session. The fake session has no store,
 *   so the suite cannot see the old id destroyed: that is express-session's
 *   regeneration, which the session package's own tests drive.
 *
 * `createRecordingLoginCompletion` keeps that contract with made-up `sid`s
 * and can stand in for a session store that is down. Published on
 * `@o3co/auth-provider-core/testing`.
 */

import assert from "node:assert/strict";
import type { Request, Response } from "express";
import type { CsrfGuard } from "../../browser-session/types.mjs";
import { readAcrTable } from "../../session-admission/acr.mjs";
import {
	admitPrimary,
	cookieClaim,
	isEstablishment,
	isInterruptAdmission,
	passwordPrimary,
} from "../../session-admission/admit.mjs";
import type {
	LoginCompletion,
	LoginEstablishmentReporter,
	LoginEstablishmentResult,
	LoginInterruptionReporter,
	LoginInterruptionResult,
	LoginInterruptionStep,
	SessionRenewalReporter,
	SessionRenewalResult,
	SessionRenewalStep,
} from "../../session-admission/login-completion.mjs";
import type {
	AdmissionDeps,
	Establishment,
	InterruptAdmission,
	InterruptionAnswer,
	RequirementInterruption,
	RequirementVerdict,
	SessionRequirement,
} from "../../session-admission/requirement.mjs";
import type { ContractCase } from "../../session-admission/testing/requirement.contract.mjs";
import { resolverForTests } from "../../session-admission/testing/resolver.mjs";
import { isRenewalNonce, newRenewalNonce } from "../../user-sessions/renewalNonce.mjs";
import {
	type FakeRequestOptions,
	type FakeResponseRecord,
	type FakeSessionRecord,
	fakeRequest,
	fakeResponse,
} from "./fake-http.mjs";

export interface LoginCompletionContractInput {
	/** A fresh completion for each case, over a session store that answers. */
	readonly build: () => LoginCompletion;
	/**
	 * The completion over a session store that is down: establishing must
	 * answer its outage at `create`. Absent for a completion that keeps no
	 * session record.
	 */
	readonly withSessionStoreOutage?: () => LoginCompletion;
	/**
	 * How many session records the store holds that the completion built
	 * last — by `build` or by `withSessionStoreOutage` — writes to: read after
	 * the build, before and after a call. Absent for a completion whose
	 * records the test cannot count.
	 */
	readonly records?: () => number;
	/** The CSRF token's cookie, when the completion answers a `403` with a fresh token: set on the `403`, never on a `503`. */
	readonly csrfCookieName?: string;
}

const SUBJECT = "contract-subject";
const REQUIREMENT = "contract-interrupting";
const ANSWER: InterruptionAnswer = { status: 403, body: { error: "contract_interrupted" } };

const admissionDeps = (requirements: readonly SessionRequirement[]): AdmissionDeps => ({
	userSessionStore: undefined,
	subjectRevocation: undefined,
	requirements: resolverForTests(requirements),
	acrTable: readAcrTable({}),
	logger: undefined,
	auditSink: undefined,
});

const primary = () =>
	passwordPrimary({
		subject: SUBJECT,
		user: { id: SUBJECT, name: "Contract" },
		claims: {},
		authTime: new Date(),
		redirectTo: undefined,
		request: {},
	});

/** A password login no requirement interrupts: the `Establishment` core builds for it. */
async function establishment(): Promise<Establishment> {
	const admission = await admitPrimary(admissionDeps([]), primary());
	assert.equal(admission.outcome, "establish", "core did not establish a login nothing interrupts");
	return (admission as { readonly establishment: Establishment }).establishment;
}

/** A member of a fixture requirement that answers `value`, whatever it is asked. */
const answering =
	<T,>(value: T) =>
	async (): Promise<T> =>
		value;

/** A ceremony that answers the requirement's `403` and notes each session id it is opened on. */
const ceremony =
	(opened: string[]) =>
	async (sessionId: string): Promise<InterruptionAnswer> => {
		opened.push(sessionId);
		return ANSWER;
	};

/** A password login a requirement interrupts, the ceremony `open` stands for. */
async function interruption(
	open: (sessionId: string) => Promise<InterruptionAnswer>,
): Promise<InterruptAdmission> {
	const requirement: SessionRequirement = {
		name: REQUIREMENT,
		reach: new Set(),
		stepUpPage: undefined,
		remediations: [],
		hintKeys: [],
		admit: answering<RequirementVerdict>({ outcome: "met" }),
		admitPrimary: answering<RequirementInterruption>({ open: (sessionId) => open(sessionId) }),
	};
	const admission = await admitPrimary(admissionDeps([requirement]), primary());
	assert.equal(admission.outcome, "interrupt", "core did not interrupt the login");
	return admission as InterruptAdmission;
}

/** The record a reporter for `establishSession` is built for. */
type ReportedRecord = { readonly sid: string | undefined; readonly sub: string };

/** A report a reporter for `establishSession` was given: an outage, a failed rollback step, or a lost index write. */
type EstablishmentReport = readonly [
	kind: "unavailable" | "cleanup" | "index",
	store: string,
	step: string,
];

/** A reporter for `establishSession` that records every record it is built for and every report. */
function establishmentReporter(): {
	readonly reporter: (record: ReportedRecord) => LoginEstablishmentReporter;
	readonly built: ReportedRecord[];
	readonly reports: EstablishmentReport[];
	/** The outages reported, as `[store, step]`. */
	readonly unavailable: () => Array<readonly [string, string]>;
} {
	const built: ReportedRecord[] = [];
	const reports: EstablishmentReport[] = [];
	return {
		built,
		reports,
		unavailable: () =>
			reports.filter(([kind]) => kind === "unavailable").map(([, store, step]) => [store, step]),
		reporter: (record) => {
			built.push({ sid: record?.sid, sub: record?.sub });
			return {
				storeUnavailable: (store, step) => {
					reports.push(["unavailable", store, step]);
				},
				cleanupFailed: (store, step) => {
					reports.push(["cleanup", store, step]);
				},
				subjectIndexWriteFailed: () => {
					reports.push(["index", "subject_session_index", "add_sid"]);
				},
			};
		},
	};
}

/** A reporter for `answerInterruption` that records every report. */
function interruptionReporter(): {
	readonly reporter: LoginInterruptionReporter;
	readonly unavailable: Array<readonly [string, string]>;
} {
	const unavailable: Array<readonly [string, string]> = [];
	return {
		unavailable,
		reporter: {
			storeUnavailable: (store, step) => {
				unavailable.push([store, step]);
			},
		},
	};
}

/** A reporter for `renewSession` that records every report. */
function renewalReporter(): {
	readonly reporter: SessionRenewalReporter;
	readonly unavailable: Array<readonly [string, string]>;
} {
	const unavailable: Array<readonly [string, string]> = [];
	return {
		unavailable,
		reporter: {
			storeUnavailable: (store, step) => {
				unavailable.push([store, step]);
			},
		},
	};
}

/** Fields a renewal must drop: what another flow left on the session beside its signed-in state. */
const BESIDE_SIGNED_IN = Object.freeze({
	redirectTo: "https://rp.contract.test/after",
	parkedByAnotherFlow: "contract-parked",
});

/**
 * A request whose express session carries the signed-in state `completion`
 * established — its own fields, copied from the request it signed in — and
 * fields beside it, on a fake session that fails where `options` says.
 */
async function signedInRequest(
	completion: LoginCompletion,
	options: FakeRequestOptions = {},
): Promise<{
	readonly req: Request;
	readonly session: FakeSessionRecord;
	readonly signedIn: Readonly<Record<string, unknown>>;
}> {
	const signing = fakeRequest();
	const { reporter } = establishmentReporter();
	const result = await completion.establishSession(await establishment(), {
		req: signing.req,
		reporter,
	});
	assert.equal(
		result.outcome,
		"established",
		"the completion did not establish the session to renew",
	);
	const signedIn = Object.freeze({ ...cookieSessionOf(signing.req) });
	const { req, session } = fakeRequest(options);
	Object.assign(cookieSessionOf(req) as CookieSession, signedIn, BESIDE_SIGNED_IN);
	return { req, session, signedIn };
}

/** The express session's id: express-session's field, which core's copy of Express's types does not carry. */
const sessionIdOf = (req: Request): string => (req as unknown as { sessionID: string }).sessionID;

/** Whether core's admission reads the request's cookie as signed in. */
const signedIn = (req: Request): boolean =>
	cookieClaim(req as unknown as Parameters<typeof cookieClaim>[0]).authenticated;

const OUTAGE = new Error("contract: store down");

/** The cases of the `loginCompletion` contract over the completion `input` builds. */
export function loginCompletionContract(
	input: LoginCompletionContractInput,
): readonly ContractCase[] {
	const { build, withSessionStoreOutage, records, csrfCookieName } = input;
	/** The token cookies `record` was set, when the input names the cookie. */
	const tokensSet = (record: FakeResponseRecord): number =>
		csrfCookieName === undefined
			? 0
			: record.cookies.filter((cookie) => cookie.name === csrfCookieName).length;
	const cases: ContractCase[] = [
		{
			name: "establishSession refuses, before the session is touched, an establishment core did not build",
			run: async () => {
				const real = await establishment();
				for (const forged of [{ ...real }, { primary: real.primary }]) {
					const completion = build();
					const before = records?.();
					const { req, session } = fakeRequest();
					const { reporter, built, reports } = establishmentReporter();
					await assert.rejects(
						completion.establishSession(forged as unknown as Establishment, { req, reporter }),
						RangeError,
						"an object shaped like an establishment, or a copy of one, must be refused with a RangeError",
					);
					assert.equal(
						session.regenerated,
						0,
						"the session was regenerated for a forged establishment",
					);
					assert.equal(session.saved, 0, "the session was saved for a forged establishment");
					assert.deepEqual(
						reports,
						[],
						"a forged establishment is the caller's fault, not an outage",
					);
					assert.deepEqual(built, [], "a reporter was built for a forged establishment");
					if (records !== undefined) {
						assert.equal(records(), before, "a forged establishment wrote a session record");
					}
					assert.equal(signedIn(req), false);
				}
			},
		},
		{
			name: "an established login is one admission reads as signed in, for its subject, on a regenerated session saved signed in",
			run: async () => {
				const completion = build();
				const held = records?.();
				const { req, session } = fakeRequest();
				const before = sessionIdOf(req);
				const { reporter, built, reports } = establishmentReporter();
				const result = await completion.establishSession(await establishment(), { req, reporter });
				assert.equal(result.outcome, "established", `answered ${result.outcome}`);
				assert.deepEqual(
					reports,
					[],
					"an established login reported an outage, a failed rollback or a lost index write",
				);
				assert.equal(
					session.regenerated,
					1,
					"the session id is regenerated once: session fixation",
				);
				assert.notEqual(sessionIdOf(req), before, "the session is established on a regenerated id");
				const claim = cookieClaim(req as unknown as Parameters<typeof cookieClaim>[0]);
				assert.equal(claim.authenticated, true, "admission does not read the session as signed in");
				assert.equal(claim.subject, SUBJECT, "the session is signed in for another subject");
				const sid = (result as { readonly sid?: unknown }).sid;
				assert.ok(
					sid === undefined || (typeof sid === "string" && sid.length > 0),
					"an established sid is a non-empty string, or undefined without a session record",
				);
				if (sid !== undefined)
					assert.equal(claim.sid, sid, "the cookie names another session record");
				assert.deepEqual(
					built,
					[{ sid, sub: SUBJECT }],
					"the reporter is built once, for the record the login wrote",
				);
				if (records !== undefined) {
					assert.equal(
						records(),
						(held as number) + (sid === undefined ? 0 : 1),
						"an established login writes one session record when it answers a sid, none otherwise",
					);
				}
				assert.ok(session.saved >= 1, "the session was not saved before the outcome was answered");
				assert.equal(
					cookieClaim({ session: session.lastSaved }).authenticated,
					true,
					"the session saved is not the signed-in one",
				);
			},
		},
		{
			name: "a cookie session that cannot be regenerated or saved is its outage: reported once, never established, the browser not signed in",
			run: async () => {
				const failures: ReadonlyArray<readonly [FakeRequestOptions, string]> = [
					[{ regenerateFails: OUTAGE }, "regenerate"],
					[{ saveFails: OUTAGE }, "save"],
				];
				for (const [options, step] of failures) {
					const completion = build();
					const held = records?.();
					const { req } = fakeRequest(options);
					const { reporter, unavailable } = establishmentReporter();
					const result = await completion.establishSession(await establishment(), {
						req,
						reporter,
					});
					assert.deepEqual(
						result,
						{ outcome: "unavailable", store: "cookie_session", step },
						`a cookie session whose ${step} fails is answered as its outage`,
					);
					assert.deepEqual(
						unavailable(),
						[["cookie_session", step]],
						"the outage is reported once",
					);
					if (records !== undefined) {
						assert.equal(records(), held, `the ${step} failure left a session record behind`);
					}
					assert.equal(
						signedIn(req),
						false,
						`the browser is signed in although the ${step} failed`,
					);
				}
			},
		},
	];
	if (withSessionStoreOutage !== undefined) {
		cases.push({
			name: "a session store that is down is its outage at create: reported once, the cookie session untouched",
			run: async () => {
				const completion = withSessionStoreOutage();
				const held = records?.();
				const { req, session } = fakeRequest();
				const { reporter, unavailable } = establishmentReporter();
				const result = await completion.establishSession(await establishment(), {
					req,
					reporter,
				});
				assert.deepEqual(result, { outcome: "unavailable", store: "user_session", step: "create" });
				assert.deepEqual(
					unavailable(),
					[["user_session", "create"]],
					"the outage is reported once",
				);
				if (records !== undefined) {
					assert.equal(records(), held, "a session-store outage left a session record behind");
				}
				assert.equal(
					session.regenerated,
					0,
					"the cookie session was regenerated with no session record",
				);
				assert.equal(signedIn(req), false);
			},
		});
	}
	cases.push(
		{
			name: "answerInterruption refuses, before the session is touched, an interruption core did not answer",
			run: async () => {
				const opened: string[] = [];
				const real = await interruption(ceremony(opened));
				for (const forged of [
					{ ...real },
					{ outcome: "interrupt", requirement: REQUIREMENT, open: ceremony(opened) },
				]) {
					const { req, session } = fakeRequest();
					const { res, record } = fakeResponse();
					const { reporter, unavailable } = interruptionReporter();
					await assert.rejects(
						build().answerInterruption(forged as unknown as InterruptAdmission, {
							req,
							res,
							reporter,
						}),
						RangeError,
						"an object shaped like an interruption, or a copy of one, must be refused with a RangeError",
					);
					assert.equal(
						session.regenerated,
						0,
						"the session was regenerated for a forged interruption",
					);
					assert.equal(record.ended, false, "a forged interruption was answered");
					assert.deepEqual(unavailable, []);
					assert.deepEqual(opened, [], "a forged interruption's ceremony was opened");
				}
			},
		},
		{
			name: "an interruption is answered with the requirement's 403, its ceremony opened on the regenerated session, saved and not signed in",
			run: async () => {
				const opened: string[] = [];
				const admission = await interruption(ceremony(opened));
				const { req, session } = fakeRequest();
				const before = sessionIdOf(req);
				const { res, record } = fakeResponse();
				const { reporter, unavailable } = interruptionReporter();
				const result: LoginInterruptionResult = await build().answerInterruption(admission, {
					req,
					res,
					reporter,
				});
				assert.deepEqual(result, { outcome: "answered" });
				assert.deepEqual(unavailable, []);
				assert.equal(
					session.regenerated,
					1,
					"the session id is regenerated once before the ceremony",
				);
				assert.deepEqual(
					opened,
					[sessionIdOf(req)],
					"the ceremony is opened once, on the regenerated id",
				);
				assert.notEqual(
					opened[0],
					before,
					"the ceremony is bound to the id from before the password",
				);
				assert.ok(session.saved >= 1, "the session was not saved before the answer");
				assert.equal(record.status, ANSWER.status, "the requirement's status is the answer's");
				assert.deepEqual(record.body, ANSWER.body, "the requirement's body is the answer's");
				assert.equal(signedIn(req), false, "an interrupted login is signed in");
				assert.equal(cookieClaim({ session: session.lastSaved }).authenticated, false);
				if (csrfCookieName !== undefined) {
					assert.equal(
						tokensSet(record),
						1,
						`the 403 carries no fresh token in ${csrfCookieName}: the page cannot post on the regenerated session`,
					);
				}
			},
		},
		{
			name: "an interruption that cannot be answered is 503: the ceremony's outage, or the cookie session's, reported once, the browser not signed in",
			run: async () => {
				const failures: ReadonlyArray<
					readonly [FakeRequestOptions, boolean, string, LoginInterruptionStep]
				> = [
					[{}, true, REQUIREMENT, "open"],
					[{ regenerateFails: OUTAGE }, false, "cookie_session", "regenerate"],
					[{ saveFails: OUTAGE }, false, "cookie_session", "save"],
				];
				for (const [options, ceremonyDown, store, step] of failures) {
					const admission = await interruption(async () => {
						if (ceremonyDown) throw OUTAGE;
						return ANSWER;
					});
					const { req } = fakeRequest(options);
					const { res, record } = fakeResponse();
					const { reporter, unavailable } = interruptionReporter();
					const result = await build().answerInterruption(admission, { req, res, reporter });
					assert.deepEqual(
						result,
						{ outcome: "unavailable", store, step },
						`an interruption whose ${step} fails is answered as ${store}'s outage`,
					);
					assert.deepEqual(unavailable, [[store, step]], "the outage is reported once");
					assert.equal(record.status, 503, `the ${step} failure is not answered 503`);
					assert.equal(
						(record.body as { readonly error?: unknown } | undefined)?.error,
						"temporarily_unavailable",
					);
					assert.equal(tokensSet(record), 0, `the ${step} failure's 503 carries a fresh token`);
					assert.equal(signedIn(req), false);
				}
			},
		},
		{
			name: "renewSession moves a signed-in session to a regenerated id, saved with isAuthenticated, user and sid as they were, a fresh renewal nonce and no other field, writing no session record",
			run: async () => {
				const completion = build();
				const { req, session, signedIn: kept } = await signedInRequest(completion);
				// A nonce an earlier renewal left: the renewal mints another.
				const earlier = newRenewalNonce();
				(cookieSessionOf(req) as CookieSession).renewalNonce = earlier;
				const held = records?.();
				const before = sessionIdOf(req);
				const { reporter, unavailable } = renewalReporter();
				const result: SessionRenewalResult = await completion.renewSession({ req, reporter });
				assert.equal(result.outcome, "renewed", `answered ${result.outcome}`);
				const { renewalNonce } = result as { readonly renewalNonce?: unknown };
				assert.ok(isRenewalNonce(renewalNonce), "the renewal answers no renewal nonce");
				assert.notEqual(renewalNonce, earlier, "the renewal kept the nonce an earlier one left");
				assert.deepEqual(unavailable, [], "a renewal reported an outage");
				assert.equal(session.regenerated, 1, "the session id is regenerated once");
				assert.notEqual(sessionIdOf(req), before, "the session is renewed on the id it had");
				const renewed = { ...kept, renewalNonce };
				assert.deepEqual(
					{ ...cookieSessionOf(req) },
					renewed,
					"the renewed session holds the signed-in state as it was and the nonce answered, and nothing beside them",
				);
				const claim = cookieClaim(req as unknown as Parameters<typeof cookieClaim>[0]);
				assert.equal(
					claim.authenticated,
					true,
					"admission does not read the renewed session as signed in",
				);
				assert.equal(
					claim.subject,
					SUBJECT,
					"the renewed session is signed in for another subject",
				);
				assert.equal(claim.sid, kept.sid, "the renewed session names another session record");
				assert.equal(
					claim.renewalNonce,
					renewalNonce,
					"admission does not read the nonce the renewal answered off the renewed session",
				);
				assert.ok(
					session.saved >= 1,
					"the renewed session was not saved before the outcome was answered",
				);
				assert.deepEqual(session.lastSaved, renewed, "the session saved is not the renewed one");
				if (records !== undefined) {
					assert.equal(records(), held, "a renewal wrote a session record");
				}
				const again = await completion.renewSession({ req, reporter });
				assert.equal(again.outcome, "renewed", `a second renewal answered ${again.outcome}`);
				assert.notEqual(
					(again as { readonly renewalNonce?: unknown }).renewalNonce,
					renewalNonce,
					"two renewals answered one nonce",
				);
			},
		},
		{
			name: "renewSession leaves a session that is not signed in so: no signed-in field is written",
			run: async () => {
				const { req } = fakeRequest();
				const { reporter, unavailable } = renewalReporter();
				const result = await build().renewSession({ req, reporter });
				assert.equal(result.outcome, "renewed", `answered ${result.outcome}`);
				assert.deepEqual(unavailable, []);
				const fields = cookieSessionOf(req) as CookieSession;
				for (const field of ["isAuthenticated", "user", "sid"]) {
					assert.equal(Object.hasOwn(fields, field), false, `the renewal wrote ${field}`);
				}
				assert.equal(signedIn(req), false, "a session not signed in was signed in by a renewal");
			},
		},
		{
			name: "a renewal whose regenerate or save fails, or of a request with no express session, is the cookie session's outage: reported once, nothing saved, the request's cookie session abandoned",
			run: async () => {
				const failures: ReadonlyArray<readonly [FakeRequestOptions, SessionRenewalStep]> = [
					[{ regenerateFails: OUTAGE }, "regenerate"],
					[{ saveFails: OUTAGE }, "save"],
				];
				for (const [options, step] of failures) {
					const completion = build();
					const { req, session } = await signedInRequest(completion, options);
					const { reporter, unavailable } = renewalReporter();
					const result = await completion.renewSession({ req, reporter });
					assert.deepEqual(
						result,
						{ outcome: "unavailable", store: "cookie_session", step },
						`a renewal whose ${step} fails is answered as the cookie session's outage`,
					);
					assert.deepEqual(unavailable, [["cookie_session", step]], "the outage is reported once");
					assert.equal(session.saved, 0, `the ${step} failure saved a session`);
					assert.equal(
						signedIn(req),
						false,
						`the request's cookie session is still signed in after the ${step} failed`,
					);
				}
				const { req } = fakeRequest();
				(req as unknown as { session?: unknown }).session = undefined;
				const { reporter, unavailable } = renewalReporter();
				assert.deepEqual(
					await build().renewSession({ req, reporter }),
					{ outcome: "unavailable", store: "cookie_session", step: "regenerate" },
					"a request with no express session is not the cookie session's outage at regenerate",
				);
				assert.deepEqual(unavailable, [["cookie_session", "regenerate"]]);
			},
		},
	);
	return cases;
}

/** A `LoginCompletion` for tests, that records what it was handed and can stand in for a session store that is down. */
export interface RecordingLoginCompletion extends LoginCompletion {
	/** Every establishment core built that `establishSession` was handed, oldest first. */
	readonly establishments: readonly Establishment[];
	/** Every interruption core answered that `answerInterruption` was handed, oldest first. */
	readonly interruptions: readonly InterruptAdmission[];
	/** The session records it holds: one per login established, none for one rolled back. */
	readonly records: number;
	/** From now on, `establishSession` answers the session store's outage at `create` and writes nothing. */
	failSessionStore(error: unknown): void;
	/** Answer again. */
	recover(): void;
}

/** The express session as the double drives it: express-session's operations, and the fields a login writes. */
interface CookieSession {
	regenerate(done: (err?: unknown) => void): void;
	save(done: (err?: unknown) => void): void;
	[field: string]: unknown;
}

const cookieSessionOf = (req: Request): CookieSession | undefined =>
	(req as unknown as { session?: CookieSession }).session;

/** Runs an express-session operation: whether it failed, and why. */
const sessionOperation = (
	operation: "regenerate" | "save",
	req: Request,
): Promise<{ readonly failed: false } | { readonly failed: true; readonly cause: unknown }> =>
	new Promise((resolve) => {
		try {
			const session = cookieSessionOf(req);
			if (session === undefined) throw new Error("the request has no express session");
			session[operation]((err) => resolve(err ? { failed: true, cause: err } : { failed: false }));
		} catch (cause) {
			resolve({ failed: true, cause });
		}
	});

/** The signed-in state a renewal keeps: what `establishSession` writes and `cookieClaim` reads. */
const SIGNED_IN_FIELDS = ["isAuthenticated", "user", "sid"] as const;

/** Drops the request's cookie session after an outage, so nothing is saved or named by a cookie. */
const abandon = (req: Request): void => {
	(req as unknown as { session?: unknown }).session = undefined;
};

const UNAVAILABLE = Object.freeze({
	error: "temporarily_unavailable",
	error_description: "The login could not be completed. Try again.",
});

export interface RecordingLoginCompletionOptions {
	/** The deployment's CSRF guard: `answerInterruption` issues the `403`'s fresh token through it. */
	readonly csrfGuard?: CsrfGuard;
	/**
	 * `false` for a completion over no session store — the session package's
	 * composition without a `UserSessionStore`: no record is written and no
	 * `sid` answered. A session record per login by default.
	 */
	readonly sessionRecords?: boolean;
}

/**
 * A `LoginCompletion` that keeps the contract over the express session it
 * is handed: `establishSession` counts a session record, regenerates the
 * session, writes the signed-in state and saves it, answering a made-up
 * `sid` — a failure after the record is counted rolls it back;
 * `answerInterruption` regenerates, opens the ceremony on the new id,
 * saves and answers the requirement's `403`, with a fresh token from
 * `options.csrfGuard` when it is given one; `renewSession` regenerates,
 * writes back the signed-in fields the session held and a fresh renewal
 * nonce, and saves.
 */
export function createRecordingLoginCompletion(
	options: RecordingLoginCompletionOptions = {},
): RecordingLoginCompletion {
	let established: readonly Establishment[] = Object.freeze([]);
	let interrupted: readonly InterruptAdmission[] = Object.freeze([]);
	let storeFailure: { readonly error: unknown } | undefined;
	let records = 0;
	let made = 0;
	/** The records a login writes: one, or none over no session store. */
	const writes = options.sessionRecords === false ? 0 : 1;

	return {
		get establishments() {
			return established;
		},
		get interruptions() {
			return interrupted;
		},
		get records() {
			return records;
		},
		failSessionStore(error: unknown): void {
			storeFailure = { error };
		},
		recover(): void {
			storeFailure = undefined;
		},
		async establishSession(establishment, { req, reporter }): Promise<LoginEstablishmentResult> {
			if (!isEstablishment(establishment)) {
				throw new RangeError(
					"establishSession: the establishment must be one admitPrimary, resumePrimary or establishWithoutAsking built",
				);
			}
			established = Object.freeze([...established, establishment]);
			const { subject: sub, user, redirectTo } = establishment.primary;
			made++;
			const sid = writes === 0 ? undefined : `recording-sid-${made}`;
			const report = reporter({ sid, sub });
			if (storeFailure !== undefined) {
				report.storeUnavailable("user_session", "create", storeFailure.error);
				return { outcome: "unavailable", store: "user_session", step: "create" };
			}
			records += writes;
			const regenerated = await sessionOperation("regenerate", req);
			if (regenerated.failed) {
				report.storeUnavailable("cookie_session", "regenerate", regenerated.cause);
				records -= writes;
				abandon(req);
				return { outcome: "unavailable", store: "cookie_session", step: "regenerate" };
			}
			const session = cookieSessionOf(req) as CookieSession;
			session.isAuthenticated = true;
			session.user = user;
			if (sid !== undefined) session.sid = sid;
			if (redirectTo) session.redirectTo = redirectTo;
			const saved = await sessionOperation("save", req);
			if (saved.failed) {
				report.storeUnavailable("cookie_session", "save", saved.cause);
				records -= writes;
				abandon(req);
				return { outcome: "unavailable", store: "cookie_session", step: "save" };
			}
			return { outcome: "established", sid };
		},
		async answerInterruption(admission, { req, res, reporter }): Promise<LoginInterruptionResult> {
			if (!isInterruptAdmission(admission)) {
				throw new RangeError(
					"answerInterruption: the admission must be an interruption admitPrimary or resumePrimary answered",
				);
			}
			interrupted = Object.freeze([...interrupted, admission]);
			const unavailable = (
				store: string,
				step: LoginInterruptionStep,
				cause: unknown,
			): LoginInterruptionResult => {
				reporter.storeUnavailable(store, step, cause);
				abandon(req);
				(res as Response).status(503).json(UNAVAILABLE);
				return { outcome: "unavailable", store, step };
			};
			const regenerated = await sessionOperation("regenerate", req);
			if (regenerated.failed) return unavailable("cookie_session", "regenerate", regenerated.cause);
			let answer: InterruptionAnswer;
			try {
				answer = await admission.open(sessionIdOf(req));
			} catch (cause) {
				return unavailable(admission.requirement, "open", cause);
			}
			const saved = await sessionOperation("save", req);
			if (saved.failed) return unavailable("cookie_session", "save", saved.cause);
			options.csrfGuard?.issue(res);
			res.status(answer.status).json(answer.body);
			return { outcome: "answered" };
		},
		async renewSession({ req, reporter }): Promise<SessionRenewalResult> {
			const renewalNonce = newRenewalNonce();
			const held = cookieSessionOf(req);
			const kept = SIGNED_IN_FIELDS.flatMap((field) =>
				held?.[field] === undefined ? [] : [[field, held[field]] as const],
			);
			const unavailable = (step: SessionRenewalStep, cause: unknown): SessionRenewalResult => {
				reporter.storeUnavailable("cookie_session", step, cause);
				abandon(req);
				return { outcome: "unavailable", store: "cookie_session", step };
			};
			const regenerated = await sessionOperation("regenerate", req);
			if (regenerated.failed) return unavailable("regenerate", regenerated.cause);
			Object.assign(cookieSessionOf(req) as CookieSession, Object.fromEntries(kept), {
				renewalNonce,
			});
			const saved = await sessionOperation("save", req);
			if (saved.failed) return unavailable("save", saved.cause);
			return { outcome: "renewed", renewalNonce };
		},
	};
}
