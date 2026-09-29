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
 * The contract suite of the `loginCompletion` slot (#728; the
 * session-admission ADR's D5) and its test double.
 *
 * `loginCompletionContract(input)` answers one case per rule, as
 * `sessionRequirementContract` does. It drives the completion over the
 * fake request of `fake-http.mts` — an express session with `regenerate`,
 * `save` and `sessionID` — and holds it to what the session package's
 * `establishSession` and `answerInterruption` do.
 *
 * - Each refuses, with a `RangeError`, what core did not build, before the
 *   session is touched: no regeneration, no save, no reporter built, no
 *   ceremony opened, and — with `records` — no session record written.
 * - An establishment builds the caller's reporter once, for the record it
 *   writes (`{ sid, sub }`), and leaves the browser signed in, as core's
 *   admission reads a cookie (`cookieClaim`), for the establishment's
 *   subject, on a regenerated session saved signed in; with `records`, one
 *   record is written when it answers a `sid`. It leaves the response to
 *   its caller.
 * - An interruption is answered with the requirement's `403` — with
 *   `csrfCookieName`, a fresh token set in that cookie (the MFA ADR's D27)
 *   — its ceremony opened on the regenerated session's id, saved and not
 *   signed in.
 * - Every outage — the session store at `create`, the cookie session's
 *   `regenerate` or `save`, the ceremony's `open` — is reported to the
 *   caller's reporter once, never established, and leaves the browser not
 *   signed in; an establishment's leaves no record behind, and an
 *   interruption's is answered `503 temporarily_unavailable` with no token.
 *
 * `createRecordingLoginCompletion` keeps that contract: it counts the
 * session records it would hold (its `sid`s are made up), records what it
 * was handed, issues the `403`'s token through the CSRF guard it is given,
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
} from "../../session-admission/login-completion.mjs";
import type {
	AdmissionDeps,
	Establishment,
	InterruptAdmission,
	InterruptionAnswer,
	SessionRequirement,
} from "../../session-admission/requirement.mjs";
import type { ContractCase } from "../../session-admission/testing/requirement.contract.mjs";
import { resolverForTests } from "../../session-admission/testing/resolver.mjs";
import {
	type FakeRequestOptions,
	type FakeResponseRecord,
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
	 * How many session records the store holds that the completion `build`
	 * returned last writes to — read after `build`, before and after a call.
	 * Absent for a completion whose records the test cannot count.
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
		admit: async () => ({ outcome: "met" }),
		admitPrimary: async () => ({ open: (sessionId) => open(sessionId) }),
	};
	const admission = await admitPrimary(admissionDeps([requirement]), primary());
	assert.equal(admission.outcome, "interrupt", "core did not interrupt the login");
	return admission as InterruptAdmission;
}

/** The record a reporter for `establishSession` is built for. */
type ReportedRecord = { readonly sid: string | undefined; readonly sub: string };

/** A reporter for `establishSession` that records every record it is built for and every report. */
function establishmentReporter(): {
	readonly reporter: (record: ReportedRecord) => LoginEstablishmentReporter;
	readonly built: ReportedRecord[];
	readonly unavailable: Array<readonly [string, string]>;
} {
	const built: ReportedRecord[] = [];
	const unavailable: Array<readonly [string, string]> = [];
	return {
		built,
		unavailable,
		reporter: (record) => {
			built.push({ sid: record?.sid, sub: record?.sub });
			return {
				storeUnavailable: (store, step) => {
					unavailable.push([store, step]);
				},
				cleanupFailed: () => {},
				subjectIndexWriteFailed: () => {},
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
					const { reporter, built, unavailable } = establishmentReporter();
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
						unavailable,
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
				const { reporter, built, unavailable } = establishmentReporter();
				const result = await completion.establishSession(await establishment(), { req, reporter });
				assert.equal(result.outcome, "established", `answered ${result.outcome}`);
				assert.deepEqual(unavailable, [], "an established login reported an outage");
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
					assert.deepEqual(unavailable, [["cookie_session", step]], "the outage is reported once");
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
				const { req, session } = fakeRequest();
				const { reporter, unavailable } = establishmentReporter();
				const result = await withSessionStoreOutage().establishSession(await establishment(), {
					req,
					reporter,
				});
				assert.deepEqual(result, { outcome: "unavailable", store: "user_session", step: "create" });
				assert.deepEqual(unavailable, [["user_session", "create"]], "the outage is reported once");
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
				let opened = 0;
				const real = await interruption(async () => {
					opened++;
					return ANSWER;
				});
				for (const forged of [
					{ ...real },
					{
						outcome: "interrupt",
						requirement: REQUIREMENT,
						open: async () => {
							opened++;
							return ANSWER;
						},
					},
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
					assert.equal(opened, 0, "a forged interruption's ceremony was opened");
				}
			},
		},
		{
			name: "an interruption is answered with the requirement's 403, its ceremony opened on the regenerated session, saved and not signed in",
			run: async () => {
				const opened: string[] = [];
				const admission = await interruption(async (sessionId) => {
					opened.push(sessionId);
					return ANSWER;
				});
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
}

/**
 * A `LoginCompletion` that keeps the contract over the express session it
 * is handed: `establishSession` counts a session record, regenerates the
 * session, writes the signed-in state and saves it, answering a made-up
 * `sid` — a failure after the record is counted rolls it back;
 * `answerInterruption` regenerates, opens the ceremony on the new id,
 * saves and answers the requirement's `403`, with a fresh token from
 * `options.csrfGuard` when it is given one.
 */
export function createRecordingLoginCompletion(
	options: RecordingLoginCompletionOptions = {},
): RecordingLoginCompletion {
	let established: readonly Establishment[] = Object.freeze([]);
	let interrupted: readonly InterruptAdmission[] = Object.freeze([]);
	let storeFailure: { readonly error: unknown } | undefined;
	let records = 0;
	let made = 0;

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
			const sid = `recording-sid-${made}`;
			const report = reporter({ sid, sub });
			if (storeFailure !== undefined) {
				report.storeUnavailable("user_session", "create", storeFailure.error);
				return { outcome: "unavailable", store: "user_session", step: "create" };
			}
			records++;
			const regenerated = await sessionOperation("regenerate", req);
			if (regenerated.failed) {
				report.storeUnavailable("cookie_session", "regenerate", regenerated.cause);
				records--;
				abandon(req);
				return { outcome: "unavailable", store: "cookie_session", step: "regenerate" };
			}
			const session = cookieSessionOf(req) as CookieSession;
			session.isAuthenticated = true;
			session.user = user;
			session.sid = sid;
			if (redirectTo) session.redirectTo = redirectTo;
			const saved = await sessionOperation("save", req);
			if (saved.failed) {
				report.storeUnavailable("cookie_session", "save", saved.cause);
				records--;
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
	};
}
