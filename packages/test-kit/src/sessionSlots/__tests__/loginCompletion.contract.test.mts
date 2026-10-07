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
 * `loginCompletionContract` run over core's `createRecordingLoginCompletion`,
 * which keeps every case, and the proof that its cases are not vacuous: each
 * way a completion can break the contract fails the case that names it.
 */

import {
	admitPrimary,
	type Establishment,
	type InterruptAdmission,
	isEstablishment,
	isInterruptAdmission,
	type LoginCompletion,
	type LoginEstablishmentCall,
	type LoginEstablishmentResult,
	newRenewalNonce,
	passwordPrimary,
	readAcrTable,
	type SessionRequirement,
} from "@o3co/auth-provider-core";
import {
	createRecordingLoginCompletion,
	createTestCsrfGuard,
	type RecordingLoginCompletion,
	resolverForTests,
} from "@o3co/auth-provider-core/testing";
import type { Request } from "express";
import { describe, expect, expectTypeOf, it } from "vitest";
import { type LoginCompletionContractInput, loginCompletionContract } from "#/index.mjs";

const RULES = {
	forgedEstablishment:
		"establishSession refuses, before the session is touched, an establishment core did not build",
	established:
		"an established login is one admission reads as signed in, for its subject, on a regenerated session saved signed in",
	cookieOutage:
		"a cookie session that cannot be regenerated or saved is its outage: reported once, never established, the browser not signed in",
	storeOutage:
		"a session store that is down is its outage at create: reported once, the cookie session untouched",
	forgedInterruption:
		"answerInterruption refuses, before the session is touched, an interruption core did not answer",
	interrupted:
		"an interruption is answered with the requirement's 403, its ceremony opened on the regenerated session, saved and not signed in",
	interruptionOutage:
		"an interruption that cannot be answered is 503: the ceremony's outage, or the cookie session's, reported once, the browser not signed in",
	renewed:
		"renewSession moves a signed-in session to a regenerated id, saved with isAuthenticated, user and sid as they were, a fresh renewal nonce and no other field, writing no session record",
	notSignedIn:
		"renewSession leaves a session that is not signed in so: no signed-in field is written",
	renewalOutage:
		"a renewal whose regenerate or save fails, or of a request with no express session, is the cookie session's outage: reported once, nothing saved, the request's cookie session abandoned",
} as const;

const withOutage = () => {
	const completion = createRecordingLoginCompletion();
	completion.failSessionStore(new Error("session store down"));
	return completion;
};

/** The deployment's CSRF guard the completions below issue a fresh token through. */
const GUARD = createTestCsrfGuard();

/**
 * The suite's whole input over the recording double: its completions — the
 * ones over a store that answers and the ones over a store that is down —
 * issue a fresh token through `GUARD`, the session records of the one built
 * last are counted, and each is `wrap`ped; `over` replaces any of it.
 */
const inputOver = (
	wrap: (original: RecordingLoginCompletion) => LoginCompletion = (completion) => completion,
	over: Partial<LoginCompletionContractInput> = {},
): LoginCompletionContractInput => {
	let last: RecordingLoginCompletion | undefined;
	return {
		build: () => {
			last = createRecordingLoginCompletion({ csrfGuard: GUARD });
			return wrap(last);
		},
		withSessionStoreOutage: () => {
			last = createRecordingLoginCompletion({ csrfGuard: GUARD });
			last.failSessionStore(new Error("session store down"));
			return wrap(last);
		},
		records: () => last?.records ?? 0,
		csrfCookieName: GUARD.cookieName,
		...over,
	};
};

/** The names of the cases `input` fails. */
const failing = async (input: LoginCompletionContractInput): Promise<string[]> => {
	const failed: string[] = [];
	for (const { name, run } of loginCompletionContract(input)) {
		try {
			await run();
		} catch {
			failed.push(name);
		}
	}
	return failed;
};

/** The double with one of its methods replaced by `change`, which may call the original. */
const broken = (
	change: (original: LoginCompletion) => Partial<LoginCompletion>,
): LoginCompletionContractInput => inputOver((original) => ({ ...original, ...change(original) }));

/** `broken`, with `leak` session records counted beside the double's own. */
const leaking = (
	change: (original: LoginCompletion, leak: () => void) => Partial<LoginCompletion>,
): LoginCompletionContractInput => {
	let leaked = 0;
	const input = inputOver((original) => ({
		...original,
		...change(original, () => {
			leaked++;
		}),
	}));
	const records = input.records as () => number;
	return { ...input, records: () => records() + leaked };
};

const primary = (subject = "user-1") =>
	passwordPrimary({
		subject,
		user: { id: subject },
		claims: {},
		authTime: new Date(),
		redirectTo: undefined,
		request: {},
	});

const deps = (requirements: readonly SessionRequirement[]) => ({
	userSessionStore: undefined,
	sessionLifecycleStore: undefined,
	subjectRevocation: undefined,
	requirements: resolverForTests(requirements),
	acrTable: readAcrTable({}),
	logger: undefined,
	auditSink: undefined,
});

/** The express session's id: express-session's field, which core's copy of Express's types does not carry. */
const sessionIdOf = (req: Request): string => (req as unknown as { sessionID: string }).sessionID;

/** The request's express session, as a broken completion below writes it. */
const sessionOf = (req: Request): Record<string, unknown> =>
	(req as unknown as { session: Record<string, unknown> }).session;

/** One express-session operation on the request's session, rejecting on its failure. */
const operate = (req: Request, operation: "regenerate" | "save"): Promise<void> =>
	new Promise((resolve, reject) => {
		(sessionOf(req)[operation] as (done: (err?: unknown) => void) => void)((err) =>
			err ? reject(err) : resolve(),
		);
	});

describe("loginCompletionContract — its input", () => {
	it("takes an optional records count and an optional CSRF cookie name", () => {
		expectTypeOf<LoginCompletionContractInput["records"]>().toEqualTypeOf<
			(() => number) | undefined
		>();
		expectTypeOf<LoginCompletionContractInput["csrfCookieName"]>().toEqualTypeOf<
			string | undefined
		>();
	});
});

describe("loginCompletionContract — the recording double", () => {
	const cases = loginCompletionContract(inputOver());

	it("names every rule", () => {
		expect(cases.map((c) => c.name)).toEqual([
			RULES.forgedEstablishment,
			RULES.established,
			RULES.cookieOutage,
			RULES.storeOutage,
			RULES.forgedInterruption,
			RULES.interrupted,
			RULES.interruptionOutage,
			RULES.renewed,
			RULES.notSignedIn,
			RULES.renewalOutage,
		]);
	});

	it("leaves the session-store case out for a completion that keeps no session record", () => {
		expect(
			loginCompletionContract({ build: () => createRecordingLoginCompletion() }).map((c) => c.name),
		).not.toContain(RULES.storeOutage);
	});

	it.each(cases)("$name", async ({ run }) => {
		await run();
	});

	it("keeps them over no session store: no sid answered, no record written", async () => {
		expect(
			await failing({
				build: () => createRecordingLoginCompletion({ csrfGuard: GUARD, sessionRecords: false }),
				records: () => 0,
				csrfCookieName: GUARD.cookieName,
			}),
		).toEqual([]);
	});

	it("keeps them with no CSRF guard, and with no records counted", async () => {
		expect(
			await failing({
				build: () => createRecordingLoginCompletion(),
				withSessionStoreOutage: withOutage,
			}),
		).toEqual([]);
	});
});

describe("loginCompletionContract — each way a completion can break it", () => {
	it("accepting an establishment core did not build", async () => {
		expect(
			await failing(
				broken((original) => ({
					establishSession: async (establishment, call) =>
						original.establishSession(
							// Laundered: any object is handed on as if core had built it.
							(await admitPrimary(deps([]), primary(establishment.primary?.subject)).then((a) =>
								a.outcome === "establish" ? a.establishment : establishment,
							)) as Establishment,
							call,
						),
				})),
			),
		).toContain(RULES.forgedEstablishment);
	});

	it("signing the browser in without regenerating the session id", async () => {
		expect(
			await failing(
				broken(() => ({
					establishSession: async (establishment, { req }) => {
						if (!isEstablishment(establishment)) throw new RangeError("not core's");
						sessionOf(req).isAuthenticated = true;
						sessionOf(req).user = establishment.primary.user;
						await operate(req, "save");
						return { outcome: "established", sid: undefined };
					},
				})),
			),
		).toContain(RULES.established);
	});

	it("answering established before the signed-in session is saved, or saving it before signing in", async () => {
		expect(
			await failing(
				broken(() => ({
					establishSession: async (establishment, { req }) => {
						if (!isEstablishment(establishment)) throw new RangeError("not core's");
						await operate(req, "regenerate");
						sessionOf(req).isAuthenticated = true;
						sessionOf(req).user = establishment.primary.user;
						return { outcome: "established", sid: undefined };
					},
				})),
			),
		).toContain(RULES.established);
		expect(
			await failing(
				broken(() => ({
					establishSession: async (establishment, { req }) => {
						if (!isEstablishment(establishment)) throw new RangeError("not core's");
						await operate(req, "regenerate");
						await operate(req, "save");
						sessionOf(req).isAuthenticated = true;
						sessionOf(req).user = establishment.primary.user;
						return { outcome: "established", sid: undefined };
					},
				})),
			),
		).toContain(RULES.established);
	});

	it("signing the browser in for another subject", async () => {
		expect(
			await failing(
				broken(() => ({
					establishSession: async (establishment, { req }) => {
						if (!isEstablishment(establishment)) throw new RangeError("not core's");
						await operate(req, "regenerate");
						sessionOf(req).isAuthenticated = true;
						sessionOf(req).user = { id: "someone-else" };
						await operate(req, "save");
						return { outcome: "established", sid: undefined };
					},
				})),
			),
		).toContain(RULES.established);
	});

	it("answering established when the cookie session could not be saved, or not reporting it", async () => {
		expect(
			await failing(
				broken((original) => ({
					establishSession: async (establishment, call) => {
						const result = await original.establishSession(establishment, call);
						return result.outcome === "unavailable" && result.step === "save"
							? { outcome: "established", sid: undefined }
							: result;
					},
				})),
			),
		).toContain(RULES.cookieOutage);
		expect(
			await failing(
				broken((original) => ({
					establishSession: (establishment, call) =>
						original.establishSession(establishment, {
							...call,
							reporter: (record) => ({ ...call.reporter(record), storeUnavailable: () => {} }),
						}),
				})),
			),
		).toContain(RULES.cookieOutage);
	});

	it("regenerating the cookie session although the session store is down", async () => {
		const regeneratingAnyway = () => {
			const completion = withOutage();
			return {
				...completion,
				establishSession: async (
					establishment: Establishment,
					call: LoginEstablishmentCall,
				): Promise<LoginEstablishmentResult> => {
					await operate(call.req, "regenerate");
					return completion.establishSession(establishment, call);
				},
			};
		};
		expect(
			await failing(inputOver(undefined, { withSessionStoreOutage: regeneratingAnyway })),
		).toContain(RULES.storeOutage);
	});

	it("renewing without regenerating the session id", async () => {
		expect(
			await failing(
				broken(() => ({
					renewSession: async ({ req }) => {
						const renewalNonce = newRenewalNonce();
						const { isAuthenticated, user, sid } = sessionOf(req);
						for (const key of Object.keys(sessionOf(req))) delete sessionOf(req)[key];
						Object.assign(sessionOf(req), { isAuthenticated, user, sid, renewalNonce });
						await operate(req, "save");
						return { outcome: "renewed", renewalNonce };
					},
				})),
			),
		).toContain(RULES.renewed);
	});

	it("carrying a field beside the signed-in state to the new id, or losing one of its three", async () => {
		const renewingWith = (pick: (old: Record<string, unknown>) => Record<string, unknown>) =>
			broken(() => ({
				renewSession: async ({ req }) => {
					const renewalNonce = newRenewalNonce();
					const old = { ...sessionOf(req) };
					await operate(req, "regenerate");
					Object.assign(sessionOf(req), pick(old), { renewalNonce });
					await operate(req, "save");
					return { outcome: "renewed", renewalNonce };
				},
			}));
		expect(await failing(renewingWith(({ renewalNonce: _earlier, ...old }) => old))).toContain(
			RULES.renewed,
		);
		expect(
			await failing(renewingWith(({ isAuthenticated, user }) => ({ isAuthenticated, user }))),
		).toContain(RULES.renewed);
		expect(
			await failing(renewingWith(({ user, sid }) => ({ isAuthenticated: false, user, sid }))),
		).toContain(RULES.renewed);
	});

	it("answering renewed before the renewed session is saved", async () => {
		expect(
			await failing(
				broken(() => ({
					renewSession: async ({ req }) => {
						const renewalNonce = newRenewalNonce();
						const { isAuthenticated, user, sid } = sessionOf(req);
						await operate(req, "regenerate");
						Object.assign(sessionOf(req), { isAuthenticated, user, sid, renewalNonce });
						return { outcome: "renewed", renewalNonce };
					},
				})),
			),
		).toContain(RULES.renewed);
	});

	it("keeping the request's cookie session after a renewal failed, answering renewed, or not reporting it", async () => {
		expect(
			await failing(
				broken(() => ({
					renewSession: async ({ req, reporter }) => {
						const renewalNonce = newRenewalNonce();
						const { isAuthenticated, user, sid } = sessionOf(req);
						try {
							await operate(req, "regenerate");
						} catch (cause) {
							reporter.storeUnavailable("cookie_session", "regenerate", cause);
							return { outcome: "unavailable", store: "cookie_session", step: "regenerate" };
						}
						Object.assign(sessionOf(req), { isAuthenticated, user, sid, renewalNonce });
						try {
							await operate(req, "save");
						} catch (cause) {
							reporter.storeUnavailable("cookie_session", "save", cause);
							return { outcome: "unavailable", store: "cookie_session", step: "save" };
						}
						return { outcome: "renewed", renewalNonce };
					},
				})),
			),
		).toContain(RULES.renewalOutage);
		expect(
			await failing(
				broken((original) => ({
					renewSession: async (call) => {
						const result = await original.renewSession(call);
						return result.outcome === "unavailable"
							? { outcome: "renewed", renewalNonce: newRenewalNonce() }
							: result;
					},
				})),
			),
		).toContain(RULES.renewalOutage);
		expect(
			await failing(
				broken((original) => ({
					renewSession: (call) =>
						original.renewSession({ ...call, reporter: { storeUnavailable: () => {} } }),
				})),
			),
		).toContain(RULES.renewalOutage);
	});

	it("answering a nonce the renewed session does not hold, or keeping the one an earlier renewal left", async () => {
		expect(
			await failing(
				broken((original) => ({
					renewSession: async (call) => {
						const result = await original.renewSession(call);
						return result.outcome === "renewed"
							? { outcome: "renewed", renewalNonce: newRenewalNonce() }
							: result;
					},
				})),
			),
		).toContain(RULES.renewed);
		expect(
			await failing(
				broken(() => ({
					renewSession: async ({ req }) => {
						const { isAuthenticated, user, sid, renewalNonce } = sessionOf(req);
						await operate(req, "regenerate");
						Object.assign(sessionOf(req), { isAuthenticated, user, sid, renewalNonce });
						await operate(req, "save");
						return { outcome: "renewed", renewalNonce: renewalNonce as string };
					},
				})),
			),
		).toContain(RULES.renewed);
	});

	it("writing a session record at a renewal", async () => {
		expect(
			await failing(
				leaking((original, leak) => ({
					renewSession: (call) => {
						leak();
						return original.renewSession(call);
					},
				})),
			),
		).toContain(RULES.renewed);
	});

	it("signing in a session that was not", async () => {
		expect(
			await failing(
				broken((original) => ({
					renewSession: async (call) => {
						const result = await original.renewSession(call);
						if (result.outcome === "renewed") sessionOf(call.req).isAuthenticated = true;
						return result;
					},
				})),
			),
		).toContain(RULES.notSignedIn);
	});

	it("accepting an interruption core did not answer", async () => {
		expect(
			await failing(
				broken(() => ({
					answerInterruption: async (admission, { res }) => {
						res.status(403).json({ error: "whatever" });
						await admission.open("any");
						return { outcome: "answered" };
					},
				})),
			),
		).toContain(RULES.forgedInterruption);
	});

	it("opening the ceremony on the session id from before the password, or not regenerating it", async () => {
		expect(
			await failing(
				broken(() => ({
					answerInterruption: async (admission, { req, res }) => {
						if (!isInterruptAdmission(admission)) throw new RangeError("not core's");
						const before = sessionIdOf(req);
						await operate(req, "regenerate");
						const answer = await admission.open(before);
						await operate(req, "save");
						res.status(answer.status).json(answer.body);
						return { outcome: "answered" };
					},
				})),
			),
		).toContain(RULES.interrupted);
		expect(
			await failing(
				broken(() => ({
					answerInterruption: async (admission, { req, res }) => {
						if (!isInterruptAdmission(admission)) throw new RangeError("not core's");
						const answer = await admission.open(sessionIdOf(req));
						await operate(req, "save");
						res.status(answer.status).json(answer.body);
						return { outcome: "answered" };
					},
				})),
			),
		).toContain(RULES.interrupted);
	});

	it("answering an interruption with anything but the requirement's answer", async () => {
		expect(
			await failing(
				broken(() => ({
					answerInterruption: async (admission, { req, res }) => {
						if (!isInterruptAdmission(admission)) throw new RangeError("not core's");
						await operate(req, "regenerate");
						await admission.open(sessionIdOf(req));
						await operate(req, "save");
						res.status(401).json({ error: "login_required" });
						return { outcome: "answered" };
					},
				})),
			),
		).toContain(RULES.interrupted);
	});

	it("signing an interrupted login in", async () => {
		expect(
			await failing(
				broken((original) => ({
					answerInterruption: async (admission, call) => {
						const result = await original.answerInterruption(admission, call);
						sessionOf(call.req).isAuthenticated = true;
						return result;
					},
				})),
			),
		).toContain(RULES.interrupted);
	});

	it("answering a ceremony that cannot open with something other than a reported 503", async () => {
		expect(
			await failing(
				broken((original) => ({
					answerInterruption: async (admission, call) => {
						const result = await original.answerInterruption(admission, call);
						if (result.outcome === "unavailable") call.res.status(500);
						return result;
					},
				})),
			),
		).toContain(RULES.interruptionOutage);
		expect(
			await failing(
				broken((original) => ({
					answerInterruption: (admission, call) =>
						original.answerInterruption(admission, {
							...call,
							reporter: { storeUnavailable: () => {} },
						}),
				})),
			),
		).toContain(RULES.interruptionOutage);
	});
	it("a forged establishment that writes a record, or builds a reporter, before it is refused", async () => {
		expect(
			await failing(
				leaking((original, leak) => ({
					establishSession: async (establishment, call) => {
						if (!isEstablishment(establishment)) {
							leak();
							throw new RangeError("not core's");
						}
						return original.establishSession(establishment, call);
					},
				})),
			),
		).toContain(RULES.forgedEstablishment);
		expect(
			await failing(
				broken((original) => ({
					establishSession: async (establishment, call) => {
						call.reporter({ sid: undefined, sub: "forged" });
						return original.establishSession(establishment, call);
					},
				})),
			),
		).toContain(RULES.forgedEstablishment);
	});

	it("an established login that writes no record, or two", async () => {
		expect(
			await failing(
				leaking((original, leak) => ({
					establishSession: async (establishment, call) => {
						const result = await original.establishSession(establishment, call);
						if (result.outcome === "established") leak();
						return result;
					},
				})),
			),
		).toContain(RULES.established);
	});

	it("an established login that reports an outage, a failed rollback or a lost index write", async () => {
		for (const report of [
			(reporter: ReturnType<LoginEstablishmentCall["reporter"]>) =>
				reporter.cleanupFailed("user_session", "delete", new Error("x")),
			(reporter: ReturnType<LoginEstablishmentCall["reporter"]>) =>
				reporter.subjectIndexWriteFailed(new Error("x")),
		]) {
			expect(
				await failing(
					broken((original) => ({
						establishSession: (establishment, call) =>
							original.establishSession(establishment, {
								...call,
								reporter: (record) => {
									const reporter = call.reporter(record);
									report(reporter);
									return reporter;
								},
							}),
					})),
				),
			).toContain(RULES.established);
		}
	});

	it("a reporter built for another record, or more than once", async () => {
		expect(
			await failing(
				broken((original) => ({
					establishSession: (establishment, call) =>
						original.establishSession(establishment, {
							...call,
							reporter: (record) => call.reporter({ ...record, sid: "another-sid" }),
						}),
				})),
			),
		).toContain(RULES.established);
		expect(
			await failing(
				broken((original) => ({
					establishSession: (establishment, call) =>
						original.establishSession(establishment, {
							...call,
							reporter: (record) => {
								call.reporter(record);
								return call.reporter(record);
							},
						}),
				})),
			),
		).toContain(RULES.established);
	});

	it("a session-store outage answered after a record was written and left behind", async () => {
		expect(
			await failing(
				leaking((original, leak) => ({
					establishSession: async (establishment, call) => {
						const result = await original.establishSession(establishment, call);
						if (result.outcome === "unavailable" && result.store === "user_session") leak();
						return result;
					},
				})),
			),
		).toContain(RULES.storeOutage);
	});

	it("a cookie-session outage that leaves the session record behind", async () => {
		expect(
			await failing(
				leaking((original, leak) => ({
					establishSession: async (establishment, call) => {
						const result = await original.establishSession(establishment, call);
						if (result.outcome === "unavailable" && result.store === "cookie_session") leak();
						return result;
					},
				})),
			),
		).toContain(RULES.cookieOutage);
	});

	it("a forged interruption whose ceremony is opened before it is refused", async () => {
		expect(
			await failing(
				broken((original) => ({
					answerInterruption: async (admission, call) => {
						if (!isInterruptAdmission(admission)) {
							await (admission as InterruptAdmission).open("forged").catch(() => undefined);
							throw new RangeError("not core's");
						}
						return original.answerInterruption(admission, call);
					},
				})),
			),
		).toContain(RULES.forgedInterruption);
	});

	it("a 403 without the fresh CSRF token, or a fresh token on a 503", async () => {
		expect(
			await failing(
				inputOver(undefined, {
					build: () => createRecordingLoginCompletion(),
					records: undefined,
				}),
			),
		).toContain(RULES.interrupted);
		expect(
			await failing(
				broken((original) => ({
					answerInterruption: async (admission, call) => {
						const result = await original.answerInterruption(admission, call);
						if (result.outcome === "unavailable") GUARD.issue(call.res);
						return result;
					},
				})),
			),
		).toContain(RULES.interruptionOutage);
	});

	it("keeps them when a 503 also clears the token's cookie and marks the response, as Express lets a provider", async () => {
		expect(
			await failing(
				broken((original) => ({
					answerInterruption: async (admission, call) => {
						const result = await original.answerInterruption(admission, call);
						if (result.outcome === "unavailable") {
							call.res.clearCookie(GUARD.cookieName, { path: "/" });
							call.res.vary("Cookie");
							call.res.vary("Origin");
							call.res.append("Cache-Control", "no-store");
							call.res.type("json");
						}
						return result;
					},
				})),
			),
		).toEqual([]);
	});
});
