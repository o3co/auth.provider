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
 * `establishSession` and `answerInterruption` do: each refuses, with a
 * `RangeError` and before the session is touched, what core did not build;
 * an establishment leaves the browser signed in, as core's admission reads
 * a cookie (`cookieClaim`), for the establishment's subject, on a
 * regenerated session saved signed in, and leaves the response to its
 * caller; an interruption is answered with the requirement's `403`, its
 * ceremony opened on the regenerated session's id, saved and not signed in;
 * every outage — the session store at `create`, the cookie session's
 * `regenerate` or `save`, the ceremony's `open` — is reported to the
 * caller's reporter once, never established, and leaves the browser not
 * signed in, an interruption's answered `503 temporarily_unavailable`.
 *
 * `createRecordingLoginCompletion` keeps that contract without a session
 * record of its own (its `sid`s are made up), records what it was handed,
 * and can stand in for a session store that is down. Published on
 * `@o3co/auth-provider-core/testing`.
 */

import assert from "node:assert/strict";
import type { Request, Response } from "express";
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
import { type FakeRequestOptions, fakeRequest, fakeResponse } from "./fake-http.mjs";

export interface LoginCompletionContractInput {
	/** A fresh completion for each case, over a session store that answers. */
	readonly build: () => LoginCompletion;
	/**
	 * The completion over a session store that is down: establishing must
	 * answer its outage at `create`. Absent for a completion that keeps no
	 * session record.
	 */
	readonly withSessionStoreOutage?: () => LoginCompletion;
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

/** A reporter for `establishSession` that records every report. */
function establishmentReporter(): {
	readonly reporter: (record: {
		readonly sid: string | undefined;
		readonly sub: string;
	}) => LoginEstablishmentReporter;
	readonly unavailable: Array<readonly [string, string]>;
} {
	const unavailable: Array<readonly [string, string]> = [];
	return {
		unavailable,
		reporter: () => ({
			storeUnavailable: (store, step) => {
				unavailable.push([store, step]);
			},
			cleanupFailed: () => {},
			subjectIndexWriteFailed: () => {},
		}),
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
	const { build, withSessionStoreOutage } = input;
	const cases: ContractCase[] = [
		{
			name: "establishSession refuses, before the session is touched, an establishment core did not build",
			run: async () => {
				const real = await establishment();
				for (const forged of [{ ...real }, { primary: real.primary }]) {
					const { req, session } = fakeRequest();
					const { reporter, unavailable } = establishmentReporter();
					await assert.rejects(
						build().establishSession(forged as unknown as Establishment, { req, reporter }),
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
					assert.equal(signedIn(req), false);
				}
			},
		},
		{
			name: "an established login is one admission reads as signed in, for its subject, on a regenerated session saved signed in",
			run: async () => {
				const { req, session } = fakeRequest();
				const before = sessionIdOf(req);
				const { reporter, unavailable } = establishmentReporter();
				const result = await build().establishSession(await establishment(), { req, reporter });
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
					const { req } = fakeRequest(options);
					const { reporter, unavailable } = establishmentReporter();
					const result = await build().establishSession(await establishment(), { req, reporter });
					assert.deepEqual(
						result,
						{ outcome: "unavailable", store: "cookie_session", step },
						`a cookie session whose ${step} fails is answered as its outage`,
					);
					assert.deepEqual(unavailable, [["cookie_session", step]], "the outage is reported once");
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
				const real = await interruption(async () => ANSWER);
				for (const forged of [
					{ ...real },
					{ outcome: "interrupt", requirement: REQUIREMENT, open: async () => ANSWER },
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

/**
 * A `LoginCompletion` that keeps the contract over the express session it
 * is handed, without a session record of its own: `establishSession`
 * regenerates the session, writes the signed-in state and saves it,
 * answering a made-up `sid`; `answerInterruption` regenerates, opens the
 * ceremony on the new id, saves and answers the requirement's `403`.
 */
export function createRecordingLoginCompletion(): RecordingLoginCompletion {
	let established: readonly Establishment[] = Object.freeze([]);
	let interrupted: readonly InterruptAdmission[] = Object.freeze([]);
	let storeFailure: { readonly error: unknown } | undefined;
	let records = 0;

	return {
		get establishments() {
			return established;
		},
		get interruptions() {
			return interrupted;
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
			records++;
			const sid = `recording-sid-${records}`;
			const report = reporter({ sid, sub });
			if (storeFailure !== undefined) {
				report.storeUnavailable("user_session", "create", storeFailure.error);
				return { outcome: "unavailable", store: "user_session", step: "create" };
			}
			const regenerated = await sessionOperation("regenerate", req);
			if (regenerated.failed) {
				report.storeUnavailable("cookie_session", "regenerate", regenerated.cause);
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
			res.status(answer.status).json(answer.body);
			return { outcome: "answered" };
		},
	};
}
