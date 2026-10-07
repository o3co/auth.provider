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
 * The `loginCompletion` slot (the session-admission ADR's D5): the
 * session package's `establishSession` and `answerInterruption` as a
 * contract, which a requirement's completion — the MFA package's —
 * requires instead of importing the session package: the slot's shape, its
 * wiring between modules, and the recording double. The slot's contract
 * suite is the test kit's, and runs over this double there.
 */

import type { Request } from "express";
import { describe, expect, expectTypeOf, it } from "vitest";
import { createApp, defineModule, type ProviderDeps } from "#/index.mjs";
import type { ComponentMap } from "#/modules/manifest/component-map.mjs";
import { readAcrTable } from "#/session-admission/acr.mjs";
import { admitPrimary, cookieClaim, passwordPrimary } from "#/session-admission/admit.mjs";
import type {
	LoginCompletion,
	LoginEstablishmentCall,
	LoginEstablishmentResult,
	LoginInterruptionCall,
	LoginInterruptionResult,
	SessionRenewalCall,
	SessionRenewalResult,
} from "#/session-admission/login-completion.mjs";
import type {
	Establishment,
	InterruptAdmission,
	SessionRequirement,
} from "#/session-admission/requirement.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import {
	createRecordingLoginCompletion,
	createTestCsrfGuard,
	type RecordingLoginCompletion,
	resolverForTests,
} from "#/testing/index.mjs";
import { isRenewalNonce } from "#/user-sessions/renewalNonce.mjs";

/** The deployment's CSRF guard a completion below issues a fresh token through. */
const GUARD = createTestCsrfGuard();

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

/** The request's express session, as the double writes it. */
const sessionOf = (req: Request): Record<string, unknown> =>
	(req as unknown as { session: Record<string, unknown> }).session;

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
		expectTypeOf<LoginCompletion["renewSession"]>().toEqualTypeOf<
			(call: SessionRenewalCall) => Promise<SessionRenewalResult>
		>();
		expectTypeOf<SessionRenewalResult>().toEqualTypeOf<
			| { readonly outcome: "renewed"; readonly renewalNonce: string }
			| {
					readonly outcome: "unavailable";
					readonly store: "cookie_session";
					readonly step: "regenerate" | "save";
			  }
		>();
		expectTypeOf<keyof LoginEstablishmentCall>().toEqualTypeOf<"req" | "reporter">();
		expectTypeOf<keyof SessionRenewalCall>().toEqualTypeOf<"req" | "reporter">();
		expectTypeOf<keyof LoginInterruptionCall>().toEqualTypeOf<"req" | "res" | "reporter">();
		expectTypeOf<RecordingLoginCompletion["records"]>().toEqualTypeOf<number>();
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

	it("holds a session record per login it established, and issues the 403's fresh token through the guard it is given", async () => {
		let issued = 0;
		const guard = {
			...GUARD,
			issue: () => {
				issued++;
				return "token";
			},
		};
		const completion = createRecordingLoginCompletion({ csrfGuard: guard });
		const admission = await admitPrimary(deps([]), primary());
		if (admission.outcome !== "establish") throw new Error("nothing interrupts");
		await completion.establishSession(admission.establishment, {
			req: requestWithSession(),
			reporter: silentReporter,
		});
		completion.failSessionStore(new Error("down"));
		await completion.establishSession(admission.establishment, {
			req: requestWithSession(),
			reporter: silentReporter,
		});
		expect(completion.records).toBe(1);
		expect(issued, "establishSession leaves the token to its caller").toBe(0);
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
		expect(issued, "the 403 carries a fresh token").toBe(1);
	});

	it("keeps the login's redirect_to on the session, and answers a request with no express session as the cookie session's outage", async () => {
		const completion = createRecordingLoginCompletion();
		const admission = await admitPrimary(
			deps([]),
			passwordPrimary({
				subject: "user-1",
				user: { id: "user-1" },
				claims: {},
				authTime: new Date(),
				redirectTo: "https://rp.example.test/after",
				request: {},
			}),
		);
		if (admission.outcome !== "establish") throw new Error("nothing interrupts");
		const req = requestWithSession();
		await completion.establishSession(admission.establishment, { req, reporter: silentReporter });
		expect(sessionOf(req).redirectTo).toBe("https://rp.example.test/after");
		expect(
			await completion.establishSession(admission.establishment, {
				req: { headers: {} } as unknown as Request,
				reporter: silentReporter,
			}),
		).toEqual({ outcome: "unavailable", store: "cookie_session", step: "regenerate" });
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

describe("createRecordingLoginCompletion — renewSession", () => {
	/** A request whose express session is signed in, with a field beside the signed-in state. */
	const signedInRequest = (): Request => {
		const req = requestWithSession();
		Object.assign(sessionOf(req), {
			isAuthenticated: true,
			user: { id: "user-1" },
			sid: "sid-1",
			redirectTo: "https://rp.example.test/after",
		});
		return req;
	};

	it("keeps isAuthenticated, user and sid on the regenerated id with a fresh renewal nonce, and drops the rest", async () => {
		const req = signedInRequest();
		expect(
			await createRecordingLoginCompletion().renewSession({
				req,
				reporter: { storeUnavailable: () => {} },
			}),
		).toEqual({ outcome: "renewed", renewalNonce: expect.any(String) });
		expect(sessionIdOf(req)).toBe("after");
		const { renewalNonce, ...signedIn } = sessionOf(req);
		expect(isRenewalNonce(renewalNonce)).toBe(true);
		expect(signedIn).toEqual({
			isAuthenticated: true,
			user: { id: "user-1" },
			sid: "sid-1",
		});
	});

	it("writes no signed-in field the session did not hold: a session not signed in stays so", async () => {
		const req = requestWithSession();
		await createRecordingLoginCompletion().renewSession({
			req,
			reporter: { storeUnavailable: () => {} },
		});
		expect(Object.keys(sessionOf(req))).toEqual(["renewalNonce"]);
		expect(cookieClaim(req as never).authenticated).toBe(false);
	});

	it("answers a request with no express session as the cookie session's outage at regenerate", async () => {
		const reported: string[] = [];
		expect(
			await createRecordingLoginCompletion().renewSession({
				req: { headers: {} } as unknown as Request,
				reporter: { storeUnavailable: (store, step) => reported.push(`${store}:${step}`) },
			}),
		).toEqual({ outcome: "unavailable", store: "cookie_session", step: "regenerate" });
		expect(reported).toEqual(["cookie_session:regenerate"]);
	});
});
