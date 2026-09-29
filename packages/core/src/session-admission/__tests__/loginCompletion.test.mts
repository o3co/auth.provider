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
 * The `loginCompletion` slot (#728; the session-admission ADR's D5): the
 * session package's `establishSession` and `answerInterruption` as a
 * contract, which a requirement's completion — the MFA package's —
 * requires instead of importing the session package. Its contract suite
 * and the recording double: the double keeps every case, and each way a
 * completion can break the contract fails the case that names it.
 */

import type { Request } from "express";
import { describe, expect, expectTypeOf, it } from "vitest";
import { createApp, defineModule, type ProviderDeps } from "#/index.mjs";
import type { ComponentMap } from "#/modules/manifest/component-map.mjs";
import { readAcrTable } from "#/session-admission/acr.mjs";
import {
	admitPrimary,
	cookieClaim,
	isEstablishment,
	isInterruptAdmission,
	passwordPrimary,
} from "#/session-admission/admit.mjs";
import type {
	LoginCompletion,
	LoginEstablishmentCall,
	LoginEstablishmentResult,
	LoginInterruptionCall,
	LoginInterruptionResult,
} from "#/session-admission/login-completion.mjs";
import type {
	Establishment,
	InterruptAdmission,
	SessionRequirement,
} from "#/session-admission/requirement.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import {
	createRecordingLoginCompletion,
	type LoginCompletionContractInput,
	loginCompletionContract,
	resolverForTests,
} from "#/testing/index.mjs";

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
} as const;

const withOutage = () => {
	const completion = createRecordingLoginCompletion();
	completion.failSessionStore(new Error("session store down"));
	return completion;
};

/** The names of the cases the completion `build` makes fails. */
const failing = async (
	build: LoginCompletionContractInput["build"],
	outage: LoginCompletionContractInput["withSessionStoreOutage"] = withOutage,
): Promise<string[]> => {
	const failed: string[] = [];
	for (const { name, run } of loginCompletionContract({ build, withSessionStoreOutage: outage })) {
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
): (() => LoginCompletion) => {
	return () => {
		const original = createRecordingLoginCompletion();
		return { ...original, ...change(original) };
	};
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
	subjectRevocation: undefined,
	requirements: resolverForTests(requirements),
	acrTable: readAcrTable({}),
	logger: undefined,
	auditSink: undefined,
});

/** A request with an express session, for the double's own tests. */
const requestWithSession = (): Request => {
	const req: Record<string, unknown> = { sessionID: "before", headers: {} };
	const session = (): Record<string, unknown> => {
		const s: Record<string, unknown> = {};
		Object.defineProperties(s, {
			regenerate: {
				value: (done: () => void) => {
					req.sessionID = "after";
					req.session = session();
					done();
				},
			},
			save: { value: (done: () => void) => done() },
		});
		return s;
	};
	req.session = session();
	return req as unknown as Request;
};

const silentReporter = () => ({
	storeUnavailable: () => {},
	cleanupFailed: () => {},
	subjectIndexWriteFailed: () => {},
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

describe("the loginCompletion slot", () => {
	it("is optional, and holds the session package's two login tails as one contract", () => {
		expectTypeOf<ComponentMap["loginCompletion"]>().toEqualTypeOf<LoginCompletion | undefined>();
		expectTypeOf<
			ProviderDeps<"loginCompletion">["loginCompletion"]
		>().toEqualTypeOf<LoginCompletion>();
		expectTypeOf<LoginCompletion["establishSession"]>().toEqualTypeOf<
			(
				establishment: Establishment,
				call: LoginEstablishmentCall,
			) => Promise<LoginEstablishmentResult>
		>();
		expectTypeOf<LoginCompletion["answerInterruption"]>().toEqualTypeOf<
			(
				admission: InterruptAdmission,
				call: LoginInterruptionCall,
			) => Promise<LoginInterruptionResult>
		>();
		// What a caller hands: the request (and for an interruption the response)
		// and its reporter — never a store, a lifetime or a CSRF mechanism, which
		// are the provider's.
		expectTypeOf<keyof LoginEstablishmentCall>().toEqualTypeOf<"req" | "reporter">();
		expectTypeOf<keyof LoginInterruptionCall>().toEqualTypeOf<"req" | "res" | "reporter">();
		expect(true).toBe(true);
	});

	it("is filled by a module, and read by another", async () => {
		const completion = createRecordingLoginCompletion();
		let seen: LoginCompletion | undefined;
		const owner = defineModule({
			name: "test:login-completion-owner",
			provides: { loginCompletion: () => completion },
		});
		const reader = defineModule({
			name: "test:login-completion-reader",
			requires: ["loginCompletion"] as const,
			contributes: {
				routes: [
					(deps) => {
						seen = deps.loginCompletion;
						return {
							id: "test-login-completion-reader",
							mountPath: "/__test_login_completion_reader__",
							handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
						};
					},
				],
			},
		});
		const handle = await createApp({
			modules: [owner, reader],
			bootstrapComponents: {
				config: makeValidCoreConfig(),
				pathResolver: (p: string) => p,
			} as never,
		});
		try {
			expect(seen).toBe(completion);
		} finally {
			await handle.dispose();
		}
	});
});

describe("loginCompletionContract — the recording double", () => {
	const cases = loginCompletionContract({
		build: () => createRecordingLoginCompletion(),
		withSessionStoreOutage: withOutage,
	});

	it("names every rule", () => {
		expect(cases.map((c) => c.name)).toEqual([
			RULES.forgedEstablishment,
			RULES.established,
			RULES.cookieOutage,
			RULES.storeOutage,
			RULES.forgedInterruption,
			RULES.interrupted,
			RULES.interruptionOutage,
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
});

describe("createRecordingLoginCompletion", () => {
	it("records the establishments and interruptions core built that it was handed, oldest first", async () => {
		const completion = createRecordingLoginCompletion();
		const first = await admitPrimary(deps([]), primary("user-1"));
		const second = await admitPrimary(deps([]), primary("user-2"));
		if (first.outcome !== "establish" || second.outcome !== "establish") {
			throw new Error("no requirement interrupts these logins");
		}
		const one = await completion.establishSession(first.establishment, {
			req: requestWithSession(),
			reporter: silentReporter,
		});
		await completion.establishSession(second.establishment, {
			req: requestWithSession(),
			reporter: silentReporter,
		});
		expect(one).toEqual({ outcome: "established", sid: expect.any(String) });
		expect(completion.establishments).toEqual([first.establishment, second.establishment]);
		expect(Object.isFrozen(completion.establishments)).toBe(true);

		const interrupting: SessionRequirement = {
			name: "fixture-interrupting",
			reach: new Set(),
			stepUpPage: undefined,
			remediations: [],
			hintKeys: [],
			admit: async () => ({ outcome: "met" }),
			admitPrimary: async () => ({
				open: async () => ({ status: 403, body: { error: "fixture_required" } }),
			}),
		};
		const interrupted = await admitPrimary(deps([interrupting]), primary());
		if (interrupted.outcome !== "interrupt") throw new Error("the fixture interrupts");
		const res = {
			status() {
				return this;
			},
			json() {
				return this;
			},
		};
		await completion.answerInterruption(interrupted, {
			req: requestWithSession(),
			res: res as never,
			reporter: { storeUnavailable: () => {} },
		});
		expect(completion.interruptions).toEqual([interrupted]);
	});

	it("stands in for a session store that is down until it recovers", async () => {
		const completion = createRecordingLoginCompletion();
		const admission = await admitPrimary(deps([]), primary());
		if (admission.outcome !== "establish") throw new Error("nothing interrupts");
		completion.failSessionStore(new Error("down"));
		const req = requestWithSession();
		expect(
			await completion.establishSession(admission.establishment, { req, reporter: silentReporter }),
		).toEqual({ outcome: "unavailable", store: "user_session", step: "create" });
		expect(cookieClaim(req as never).authenticated).toBe(false);
		completion.recover();
		expect(
			await completion.establishSession(admission.establishment, { req, reporter: silentReporter }),
		).toEqual({ outcome: "established", sid: expect.any(String) });
		expect(cookieClaim(req as never).authenticated).toBe(true);
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
		expect(await failing(() => createRecordingLoginCompletion(), regeneratingAnyway)).toContain(
			RULES.storeOutage,
		);
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
});
