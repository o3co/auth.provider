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
 * A session's step-up verified (the MFA ADR's F2, D21, D27): a factor the
 * subject holds, challenged and verified on the session's `step_up`
 * transaction through `POST /session/mfa/challenge` and `/verify`, held to
 * the subject lock like a login's, and finished on the session itself — its
 * express id renewed, then the second factor recorded on its `UserSession`
 * with the renewal nonce — never through a login's completion.
 */

import {
	type AppConfig,
	createInMemoryUserSessionStore,
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	defineModule,
	EMAIL_OTP_AMR,
	HARDWARE_KEY_AMR,
	InMemoryUserRepository,
	type LoginCompletion,
	MFA_AMR,
	type MfaFactor,
	type MfaFactorStore,
	type Module,
	newRenewalNonce,
	OTP_AMR,
	PASSWORD_AMR,
	RECOVERY_CODE_AMR,
	type UserRepository,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { createRecordingMailSender } from "@o3co/auth-provider-core/testing";
import { loginCompletionModule } from "@o3co/auth-provider-session";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createRecoveryCodeFactor, generateRecoveryCodes } from "#/recovery/factor.mjs";
import { mfaEmailFactorConfigForTests } from "#/testing/index.mjs";
import {
	ALICE,
	boot,
	configFor,
	directoryEntries,
	disposeAll,
	events,
	login,
	sessionIdSet,
	WitnessingUserRepository,
} from "./moduleHarness.mjs";
import {
	type Agent,
	completeEnrollment,
	contributing,
	cookieSessionTap,
	enrollFromAccount,
	freezeClock,
	loggedText,
	mfaPost,
	readTransaction,
	recordingAuditSink,
	seedFactor,
	seedTotp,
	setsCsrfToken,
	signInWithTotp,
	stepUp,
	suiteSealing,
	T0,
	thawClock,
	totpCode,
	verify,
	wrongCode,
} from "./routesHarness.mjs";

beforeEach(() => freezeClock());
afterEach(async () => {
	await disposeAll();
	thawClock();
});

const UNKNOWN = {
	error: "invalid_request",
	error_description: "Unknown or expired MFA transaction",
};
const UNKNOWN_FACTOR = { error: "invalid_request", error_description: "Unknown second factor" };
const NOT_OPEN = {
	error: "invalid_request",
	error_description: "No enrollment is open in this MFA transaction",
};
const FACTOR_REFUSED = {
	error: "mfa_factor_refused",
	error_description: "This second factor cannot be used: use another",
};

interface Setup {
	readonly mode?: "optional" | "required";
	readonly mfa?: Record<string, unknown>;
	/** The email factor switched on, adding `mfa` as said. */
	readonly email?: { readonly addsMfa: boolean };
	readonly users?: UserRepository;
	readonly userSessionStore?: UserSessionStore;
	readonly extraModules?: readonly Module[];
	/** The login completion in place of the session package's own module. */
	readonly loginCompletion?: Module;
}

/** Boots `optional` (unless `setup` says otherwise) with a recording sender, an audit sink and a witnessing directory. */
async function composed(setup: Setup = {}) {
	const factorStore = createMemoryMfaFactorStore();
	const transactionStore = createMemoryMfaTransactionStore();
	const userSessionStore = (setup.userSessionStore ??
		createInMemoryUserSessionStore()) as ReturnType<typeof createInMemoryUserSessionStore>;
	const users = setup.users ?? new WitnessingUserRepository(directoryEntries());
	const sender = createRecordingMailSender();
	const audit = recordingAuditSink();
	const config = {
		...configFor(setup.mode ?? "optional", setup.mfa ?? {}),
		...(setup.email === undefined
			? {}
			: mfaEmailFactorConfigForTests({ enabled: true, addsMfa: setup.email.addsMfa })),
	} as AppConfig;
	const booted = await boot({
		config,
		factorStore,
		transactionStore,
		userSessionStore,
		auditSink: audit,
		mailSender: sender,
		userRepository: users,
		...(setup.loginCompletion === undefined ? {} : { withoutLoginCompletion: true }),
		extraModules: [
			...(setup.extraModules ?? []),
			...(setup.loginCompletion === undefined ? [] : [setup.loginCompletion]),
		],
	});
	return { ...booted, factorStore, transactionStore, userSessionStore, users, sender, audit };
}

/** The `auth.session` cookie a response sets, as a `Cookie` header carries it. */
const sessionCookie = (res: request.Response): string => {
	const line = ([] as string[])
		.concat(res.headers["set-cookie"] ?? [])
		.find((candidate) => candidate.startsWith("auth.session="));
	if (line === undefined) throw new Error("the response set no session cookie");
	return line.split(";")[0] as string;
};

/** A password sign-in with no second factor asked: the agent, the sid its login wrote, and its session cookie. */
async function signedIn(app: Parameters<typeof login>[0], store: UserSessionStore) {
	const create = vi.spyOn(store, "create");
	const { agent, res } = await login(app);
	expect(res.status, JSON.stringify(res.body)).toBe(200);
	const sid = (create.mock.calls.at(-1)?.[0] as { sid?: unknown } | undefined)?.sid;
	create.mockRestore();
	if (typeof sid !== "string") throw new Error("the login wrote no session");
	return { agent, sid, cookie: sessionCookie(res) };
}

/** `POST /session/mfa<path>` from a browser holding only the cookie session `cookie`, with a CSRF token fetched on it. */
async function postAs(
	app: Parameters<typeof login>[0],
	cookie: string,
	path: string,
	body: Record<string, unknown>,
): Promise<request.Response> {
	const csrf = await request(app).get("/session/csrf").set("Cookie", cookie);
	const csrfCookie = ([] as string[])
		.concat(csrf.headers["set-cookie"] ?? [])
		.map((line) => line.split(";")[0] as string)
		.filter((pair) => !pair.startsWith("auth.session="));
	return request(app)
		.post(`/session/mfa${path}`)
		.set("Cookie", [cookie, ...csrfCookie].join("; "))
		.set(csrf.body.header_name as string, csrf.body.csrf_token as string)
		.send(body);
}

/** Whether the cookie session `cookie` names is admitted as a live signed-in session: a step-up it asks for is not refused 401. */
const admitted = async (app: Parameters<typeof login>[0], cookie: string): Promise<boolean> =>
	(await postAs(app, cookie, "/step-up", {})).status !== 401;

/** A step-up opened in the agent's session: its transaction. */
const openedStepUp = async (agent: Agent): Promise<string> => {
	const res = await stepUp(agent);
	expect(res.status, JSON.stringify(res.body)).toBe(200);
	expect(res.body.email_proof).toBe(false);
	return res.body.transaction as string;
};

/** The session record `sid`, as the store now holds it. */
const stored = async (store: UserSessionStore, sid: string): Promise<UserSession> => {
	const session = await store.get(sid);
	if (session === null) throw new Error("the session is gone");
	return session;
};

/** A recovery-code set of `count` codes as the suite's ring digests them, seeded for alice. */
async function seedRecoveryCodes(factorStore: MfaFactorStore, count = 3) {
	const set = generateRecoveryCodes(
		createRecoveryCodeFactor({ count }),
		suiteSealing().digestsFor("recovery_code"),
	);
	if (set === undefined) throw new Error("no set");
	const record = await seedFactor(factorStore, "recovery_code", set.data);
	return { record, codes: set.codes };
}

/** The session package's login completion, its renewal answering without the renewal nonce it wrote. */
const nonceDropping = (): Module =>
	defineModule({
		name: "test:login-completion-dropping-the-nonce",
		requires: ["sessionCookiePolicy", "userSessionStore", "csrfGuard"],
		optional: ["subjectSessionIndex"],
		provides: {
			loginCompletion: (deps: unknown): LoginCompletion => {
				const real = (
					loginCompletionModule.provides as {
						readonly loginCompletion: (deps: unknown) => LoginCompletion;
					}
				).loginCompletion(deps);
				return {
					establishSession: (...args) => real.establishSession(...args),
					answerInterruption: (...args) => real.answerInterruption(...args),
					renewSession: async (call) => {
						const renewed = await real.renewSession(call);
						return { ...renewed, renewalNonce: undefined } as unknown as typeof renewed;
					},
				};
			},
		} as never,
	});

/** The digest the email factor records for `address`, under the suite's ring. */
const recordedDigest = (address: string) => suiteSealing().digestsFor("email").digest([address]);

describe("a TOTP step-up verified in a password session", () => {
	it("adds the factor's amr and mfa to the session, dated by the verification, its authTime and sid kept, its express id renewed, and answers 200 with a fresh CSRF token", async () => {
		const { app, handle, factorStore, userSessionStore, audit } = await composed();
		const { agent, sid, cookie } = await signedIn(app, userSessionStore);
		const before = await stored(userSessionStore, sid);
		const totp = await seedTotp(factorStore);
		const transaction = await openedStepUp(agent);
		const create = vi.spyOn(userSessionStore, "create");

		const res = await verify(agent, transaction, totp.record.id, totpCode(totp.secret));

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(res.headers["cache-control"]).toBe("no-store");
		expect(res.body).toEqual({ step_up: "verified" });
		const guard = handle.components.csrfGuard;
		if (guard === undefined) throw new Error("no csrf guard");
		expect(setsCsrfToken(res, guard)).toBe(true);
		const renewedId = sessionIdSet(res);
		expect(renewedId).toBeDefined();
		expect(cookie).not.toContain(renewedId as string);
		const after = await stored(userSessionStore, sid);
		expect(after.amr).toEqual([PASSWORD_AMR, OTP_AMR, MFA_AMR]);
		expect(after.authentication?.mfaAt).toEqual(new Date(T0));
		expect(after.authTime).toEqual(before.authTime);
		expect(after.expiresAt).toEqual(before.expiresAt);
		expect(after.renewalNonce).toEqual(expect.any(String));
		expect(create).not.toHaveBeenCalled();
		expect(audit.of("mfa.verified")).toEqual([
			expect.objectContaining({
				subject: ALICE.id,
				details: { kind: "totp", purpose: "step_up" },
			}),
		]);
	});

	it("admits the renewed cookie for mfa.manage, and refuses the old one", async () => {
		const { app, factorStore, userSessionStore } = await composed();
		const { agent, cookie } = await signedIn(app, userSessionStore);
		const totp = await seedTotp(factorStore);
		expect((await enrollFromAccount(agent, "totp")).status).toBe(403);
		const transaction = await openedStepUp(agent);
		expect(await admitted(app, cookie)).toBe(true);

		expect((await verify(agent, transaction, totp.record.id, totpCode(totp.secret))).status).toBe(
			200,
		);

		expect((await enrollFromAccount(agent, "totp")).status).toBe(200);
		expect(await admitted(app, cookie)).toBe(false);
	});

	it("meets mfa.manage under required again once a session's MFA is no longer recent", async () => {
		const { app, factorStore, userSessionStore } = await composed({ mode: "required" });
		const totp = await seedTotp(factorStore);
		const { agent, sid } = await signInWithTotp(app, userSessionStore, totp);
		freezeClock(T0 + 301_000);
		const refused = await enrollFromAccount(agent, "totp");
		expect(refused.status).toBe(403);
		expect(refused.body.error).toBe("step_up_required");
		const transaction = await openedStepUp(agent);

		const res = await verify(agent, transaction, totp.record.id, totpCode(totp.secret, 1));

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect((await stored(userSessionStore, sid)).authentication?.mfaAt).toEqual(
			new Date(T0 + 301_000),
		);
		expect((await enrollFromAccount(agent, "totp")).status).toBe(200);
	});

	it("is spent by its verification: verified again, its transaction is unknown", async () => {
		const { app, factorStore, userSessionStore } = await composed();
		const { agent } = await signedIn(app, userSessionStore);
		const totp = await seedTotp(factorStore);
		const transaction = await openedStepUp(agent);
		expect((await verify(agent, transaction, totp.record.id, totpCode(totp.secret))).status).toBe(
			200,
		);

		const again = await verify(agent, transaction, totp.record.id, totpCode(totp.secret, 1));

		expect(again.status).toBe(400);
		expect(again.body).toEqual(UNKNOWN);
	});
});

describe("the subject lock on a step-up", () => {
	it("answers a held subject's proof 429 mfa_locked with Retry-After, recorded as mfa.locked and mfa.locked.first with the step_up purpose", async () => {
		const { app, factorStore, userSessionStore, audit } = await composed({
			mfa: { lockout: { threshold: 2 } },
		});
		const { agent } = await signedIn(app, userSessionStore);
		const totp = await seedTotp(factorStore);
		const transaction = await openedStepUp(agent);
		for (let n = 0; n < 2; n++) {
			expect(
				(await verify(agent, transaction, totp.record.id, wrongCode(totp.secret))).status,
			).toBe(401);
		}

		const res = await verify(agent, transaction, totp.record.id, totpCode(totp.secret));

		expect(res.status, JSON.stringify(res.body)).toBe(429);
		expect(res.headers["retry-after"]).toMatch(/^[1-9][0-9]*$/);
		expect(res.body).toMatchObject({ error: "mfa_locked", hold: "backoff" });
		const held = { kind: "totp", purpose: "step_up", hold: "backoff" };
		expect(audit.of("mfa.locked")).toEqual([expect.objectContaining({ details: held })]);
		expect(audit.of("mfa.locked.first")).toEqual([
			expect.objectContaining({ details: { ...held, binding: "password" } }),
		]);
		expect(audit.of("mfa.verify.failure")).toEqual([
			expect.objectContaining({ details: expect.objectContaining({ purpose: "step_up" }) }),
			expect.objectContaining({ details: expect.objectContaining({ purpose: "step_up" }) }),
		]);
	});

	it("spends one subject attempt for each of several wrong codes sent at once", async () => {
		const { app, factorStore, transactionStore, userSessionStore } = await composed();
		const { agent } = await signedIn(app, userSessionStore);
		const totp = await seedTotp(factorStore);
		const transaction = await openedStepUp(agent);
		const settle = vi.spyOn(transactionStore, "settleSubjectAttempt");

		const answers = await Promise.all(
			[0, 1, 2].map(() => verify(agent, transaction, totp.record.id, wrongCode(totp.secret))),
		);

		expect(answers.map((res) => res.status)).toEqual([401, 401, 401]);
		expect(settle.mock.calls.map((call) => call[2])).toEqual(["failure", "failure", "failure"]);
	});

	it("settles a right proof whose transaction another verification consumed first as void", async () => {
		const { app, factorStore, transactionStore, userSessionStore } = await composed();
		const { agent } = await signedIn(app, userSessionStore);
		const totp = await seedTotp(factorStore);
		const transaction = await openedStepUp(agent);
		vi.spyOn(transactionStore, "consume").mockResolvedValueOnce(null);
		const settle = vi.spyOn(transactionStore, "settleSubjectAttempt");

		const res = await verify(agent, transaction, totp.record.id, totpCode(totp.secret));

		expect(res.status).toBe(400);
		expect(settle.mock.calls.map((call) => call[2])).toEqual(["void"]);
	});
});

describe("a recovery code at a step-up", () => {
	/** Under required: alice signed in with TOTP at T0, her TOTP then replaced by one whose data does not open, beside a set of codes; the clock past mfa.manage.maxAgeSeconds. */
	async function withCodesOnly() {
		const setup = await composed({ mode: "required" });
		const totp = await seedTotp(setup.factorStore);
		const { agent, sid } = await signInWithTotp(setup.app, setup.userSessionStore, totp);
		await setup.factorStore.remove(ALICE.id, totp.record.id);
		await seedTotp(setup.factorStore, ALICE.id, { sealedFor: "u-someone-else" });
		const codes = await seedRecoveryCodes(setup.factorStore);
		freezeClock(T0 + 301_000);
		return { ...setup, agent, sid, codes };
	}

	it("is accepted under required beside no counting factor that can be used: it adds recovery and mfa, opens no binding, and answers the codes left", async () => {
		const { agent, sid, codes, transactionStore, userSessionStore, audit } = await withCodesOnly();
		expect((await enrollFromAccount(agent, "totp")).body.error).toBe("step_up_required");
		const transaction = await openedStepUp(agent);
		const create = vi.spyOn(transactionStore, "create");

		const res = await verify(agent, transaction, codes.record.id, codes.codes[0]);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(res.body).toEqual({ step_up: "verified", recovery_codes_remaining: 2 });
		const after = await stored(userSessionStore, sid);
		expect(after.amr).toEqual(expect.arrayContaining([RECOVERY_CODE_AMR, MFA_AMR]));
		expect(after.authentication?.mfaAt).toEqual(new Date(T0 + 301_000));
		expect(create).not.toHaveBeenCalled();
		expect(audit.of("mfa.verified").at(-1)).toMatchObject({
			details: { kind: "recovery_code", purpose: "step_up" },
		});
		expect(audit.of("mfa.recovery_code.used")).toEqual([
			expect.objectContaining({
				details: { kind: "recovery_code", purpose: "step_up", remaining: 2 },
			}),
		]);
		expect((await enrollFromAccount(agent, "totp")).status).toBe(200);
	});

	it("records its exempt success, and the session's mfaAt, at the verification's time, however long the request then takes", async () => {
		const { agent, sid, codes, factorStore, transactionStore, userSessionStore } =
			await withCodesOnly();
		const transaction = await openedStepUp(agent);
		const exempt = vi.spyOn(transactionStore, "noteExemptSuccess");
		const update = factorStore.update.bind(factorStore);
		vi.spyOn(factorStore, "update").mockImplementation(async (...args) => {
			freezeClock(T0 + 309_000);
			return update(...args);
		});

		const res = await verify(agent, transaction, codes.record.id, codes.codes[0]);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(exempt).toHaveBeenCalledWith(ALICE.id, T0 + 301_000, expect.anything());
		expect((await stored(userSessionStore, sid)).authentication?.mfaAt).toEqual(
			new Date(T0 + 301_000),
		);
	});
});

describe("an email step-up", () => {
	/** Alice signed in by password, then holding an email factor that recorded `address`'s digest. */
	async function withEmail(addsMfa: boolean, address: string = ALICE.email) {
		const setup = await composed({ email: { addsMfa } });
		const session = await signedIn(setup.app, setup.userSessionStore);
		const record = await seedFactor(setup.factorStore, "email", {
			addressDigest: recordedDigest(address),
		});
		const transaction = await openedStepUp(session.agent);
		return { ...setup, ...session, record, transaction };
	}

	const challenge = (agent: Agent, transaction: string, factorId: string) =>
		mfaPost(agent, "/challenge", { transaction_id: transaction, factor_id: factorId });

	it("mails the code to the session's own address as a login code, and adds email alone", async () => {
		const { agent, sid, record, transaction, sender, userSessionStore, audit } =
			await withEmail(false);

		const challenged = await challenge(agent, transaction, record.id);

		expect(challenged.status, JSON.stringify(challenged.body)).toBe(200);
		expect(challenged.body).toEqual({ sent_to: "a***@example.com", expires_in: 600 });
		expect(sender.sent).toEqual([
			expect.objectContaining({ purpose: "login_code", subject: ALICE.id, to: ALICE.email }),
		]);
		expect(audit.of("mfa.challenge.sent")).toEqual([
			expect.objectContaining({ details: { kind: "email", purpose: "step_up" } }),
		]);
		const res = await verify(agent, transaction, record.id, sender.sent.at(-1)?.code);
		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect((await stored(userSessionStore, sid)).amr).toEqual([PASSWORD_AMR, EMAIL_OTP_AMR]);
	});

	it("adds mfa beside email when the email factor adds it", async () => {
		const { agent, sid, record, transaction, sender, userSessionStore } = await withEmail(true);
		expect((await challenge(agent, transaction, record.id)).status).toBe(200);

		const res = await verify(agent, transaction, record.id, sender.sent.at(-1)?.code);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect((await stored(userSessionStore, sid)).amr).toEqual([
			PASSWORD_AMR,
			EMAIL_OTP_AMR,
			MFA_AMR,
		]);
	});

	it("refuses 403 a factor that recorded another address, recorded as mfa.email_address_mismatch with the step_up purpose, mailing nothing", async () => {
		const { agent, record, transaction, sender, audit } = await withEmail(
			false,
			"someone@example.com",
		);

		const res = await challenge(agent, transaction, record.id);

		expect(res.status).toBe(403);
		expect(res.body).toEqual(FACTOR_REFUSED);
		expect(sender.sent).toEqual([]);
		expect(audit.of("mfa.email_address_mismatch")).toEqual([
			expect.objectContaining({
				subject: ALICE.id,
				details: { kind: "email", purpose: "step_up" },
			}),
		]);
	});
});

describe("what a step_up transaction refuses", () => {
	it("refuses the account-email proof, and an enrollment begun or completed on it, as unknown — spending nothing", async () => {
		const { app, factorStore, transactionStore, userSessionStore } = await composed();
		const totp = await seedTotp(factorStore);
		const { agent } = await signInWithTotp(app, userSessionStore, totp);
		const transaction = await openedStepUp(agent);

		for (const path of ["/challenge", "/verify"]) {
			const res = await mfaPost(agent, path, {
				transaction_id: transaction,
				factor_id: "account-email",
				proof: "0000-0000-0000-0000",
			});
			expect(res.status, path).toBe(400);
			expect(res.body, path).toEqual(UNKNOWN_FACTOR);
		}
		const begun = await mfaPost(agent, "/enrollment", {
			transaction_id: transaction,
			kind: "totp",
		});
		expect(begun.status).toBe(400);
		expect(begun.body).toEqual(NOT_OPEN);
		const completed = await completeEnrollment(agent, transaction, "123456");
		expect(completed.status).toBe(400);
		expect(completed.body).toEqual(NOT_OPEN);
		expect((await transactionStore.get(transaction))?.attempts).toBe(0);
		expect((await readTransaction(agent, transaction)).body.purpose).toBe("step_up");
	});
});

describe("the enrollment witness at a step-up", () => {
	/** A TOTP step-up verified in a password session whose record `change` rewrites as read. */
	async function steppedUp(
		setup: Setup = {},
		change: (session: UserSession) => UserSession = (session) => session,
	) {
		const booted = await composed(setup);
		const { agent } = await signedIn(booted.app, booted.userSessionStore);
		const totp = await seedTotp(booted.factorStore);
		const read = booted.userSessionStore.get.bind(booted.userSessionStore);
		vi.spyOn(booted.userSessionStore, "get").mockImplementation(async (sid) => {
			const session = await read(sid);
			return session === null ? null : change(session);
		});
		const transaction = await openedStepUp(agent);
		const note = vi.spyOn(booted.transactionStore, "noteFirstBinding");
		return {
			...booted,
			note,
			verified: () => verify(agent, transaction, totp.record.id, totpCode(totp.secret)),
		};
	}

	it("notes the first-binding mark, then marks the witness, when the session recorded its User as not enrolled — or recorded nothing", async () => {
		for (const recorded of ["not_enrolled", "nothing"] as const) {
			const { users, note, verified } = await steppedUp({}, (session) => {
				if (recorded === "not_enrolled") return session;
				const { enrollmentFacts: _facts, ...without } = session;
				return without as UserSession;
			});

			const res = await verified();

			expect(res.status, recorded).toBe(200);
			expect(note, recorded).toHaveBeenCalledTimes(1);
			expect((users as WitnessingUserRepository).marks, recorded).toEqual([
				{ subject: ALICE.id, enrolled: true },
			]);
		}
	});

	it("neither notes nor marks when the session recorded its User as enrolled", async () => {
		const { users, note, verified } = await steppedUp({}, (session) => ({
			...session,
			enrollmentFacts: { witness: "enrolled", mailAddress: "address" },
		}));

		expect((await verified()).status).toBe(200);

		expect(note).not.toHaveBeenCalled();
		expect((users as WitnessingUserRepository).marks).toEqual([]);
	});

	it("leaves the witness unmarked when the mark cannot be noted, said at warn, and still steps up", async () => {
		const { users, transactionStore, logger, verified } = await steppedUp();
		vi.spyOn(transactionStore, "noteFirstBinding").mockRejectedValue(new Error("unreachable"));

		expect((await verified()).status).toBe(200);

		expect((users as WitnessingUserRepository).marks).toEqual([]);
		expect(events(logger, "warn")).toContain("mfa_first_binding_unnoted");
	});

	it("says a witness mark that fails at warn, and still steps up", async () => {
		const { users, logger, verified } = await steppedUp();
		(users as WitnessingUserRepository).failWith(new Error("directory down"));

		expect((await verified()).status).toBe(200);

		expect(events(logger, "warn")).toContain("mfa_enrollment_witness_unwritten");
	});

	it("notes nothing for a directory that cannot write the witness", async () => {
		const { note, verified } = await steppedUp({
			users: new InMemoryUserRepository(directoryEntries()),
		});

		expect((await verified()).status).toBe(200);

		expect(note).not.toHaveBeenCalled();
	});
});

describe("what a step-up logs", () => {
	it("never logs the code, the address, the transaction id or the renewal nonce", async () => {
		const { app, factorStore, userSessionStore, logger } = await composed();
		const { agent, sid } = await signedIn(app, userSessionStore);
		const totp = await seedTotp(factorStore);
		const transaction = await openedStepUp(agent);
		const code = totpCode(totp.secret);
		await verify(agent, transaction, totp.record.id, wrongCode(totp.secret));
		expect((await verify(agent, transaction, totp.record.id, code)).status).toBe(200);

		const text = loggedText(logger);
		const nonce = (await stored(userSessionStore, sid)).renewalNonce as string;
		for (const secret of [code, ALICE.email, transaction, nonce]) {
			expect(text).not.toContain(secret);
		}
	});
});

/** Whether the cookie session `cookie` names is signed in as express-session holds it, whatever admission makes of it. */
const signedInAs = async (app: Parameters<typeof login>[0], cookie: string): Promise<boolean> =>
	(await request(app).get("/test-tap").set("Cookie", cookie)).body.authenticated === true;

describe("the step-up's finish", () => {
	/** A TOTP step-up opened in a password session, with the cookie-session tap mounted. */
	async function opened(setup: Setup = {}) {
		const tap = cookieSessionTap();
		const booted = await composed({
			...setup,
			extraModules: [tap.module, ...(setup.extraModules ?? [])],
		});
		const session = await signedIn(booted.app, booted.userSessionStore);
		const totp = await seedTotp(booted.factorStore);
		const transaction = await openedStepUp(session.agent);
		await signedInAs(booted.app, session.cookie);
		const store = tap.tapped.store;
		if (store === undefined) throw new Error("the tap saw no store");
		const recordUnwatched = booted.userSessionStore.recordSecondFactor.bind(
			booted.userSessionStore,
		);
		const record = vi.spyOn(booted.userSessionStore, "recordSecondFactor");
		return {
			...booted,
			...session,
			tap,
			cookieStore: store,
			totp,
			transaction,
			record,
			recordUnwatched,
			verified: () => verify(session.agent, transaction, totp.record.id, totpCode(totp.secret)),
		};
	}

	const SESSION_STORE_UNAVAILABLE = {
		error: "temporarily_unavailable",
		error_description: "Session store unavailable",
	};
	const SERVER_ERROR = {
		error: "server_error",
		error_description: "The step-up could not be recorded",
	};
	const SIGN_IN_AGAIN = {
		error: "server_error",
		error_description: "The session could not be secured: sign in again",
	};

	it("answers 503 and records nothing when the cookie session cannot be regenerated: the old one stands, not stepped up", async () => {
		const { app, sid, cookie, cookieStore, userSessionStore, record, logger, verified } =
			await opened();
		vi.spyOn(cookieStore, "destroy").mockImplementationOnce((_sid, done) =>
			done(new Error("cookie store down")),
		);

		const res = await verified();

		expect(res.status, JSON.stringify(res.body)).toBe(503);
		expect(res.body).toEqual(SESSION_STORE_UNAVAILABLE);
		expect(record).not.toHaveBeenCalled();
		expect((await stored(userSessionStore, sid)).amr).toEqual([PASSWORD_AMR]);
		expect(logger.error).toHaveBeenCalledWith(
			expect.objectContaining({
				route: "verify",
				sid,
				store: "cookie_session",
				step: "regenerate",
			}),
			"mfa_store_unavailable",
		);
		expect(await admitted(app, cookie)).toBe(true);
		expect((await postAs(app, cookie, "/enrollment", { kind: "totp" })).status).toBe(403);
	});

	it("answers 503 and records nothing when the renewed cookie session cannot be saved: the browser is signed out", async () => {
		const { app, sid, cookie, agent, cookieStore, userSessionStore, record, logger, verified } =
			await opened();
		vi.spyOn(cookieStore, "set").mockImplementationOnce((_sid, _session, done) =>
			done(new Error("cookie store down")),
		);

		const res = await verified();

		expect(res.status, JSON.stringify(res.body)).toBe(503);
		expect(res.body).toEqual(SESSION_STORE_UNAVAILABLE);
		expect(record).not.toHaveBeenCalled();
		expect((await stored(userSessionStore, sid)).amr).toEqual([PASSWORD_AMR]);
		expect(logger.error).toHaveBeenCalledWith(
			expect.objectContaining({ route: "verify", sid, store: "cookie_session", step: "save" }),
			"mfa_store_unavailable",
		);
		expect(await admitted(app, cookie)).toBe(false);
		expect((await stepUp(agent)).status).toBe(401);
	});

	it("answers 503 to a session store that cannot record, calling it once: the renewed cookie stands, not stepped up", async () => {
		const { app, sid, userSessionStore, record, logger, verified } = await opened();
		record.mockRejectedValueOnce(new Error("session store down"));

		const res = await verified();

		expect(res.status, JSON.stringify(res.body)).toBe(503);
		expect(res.body).toEqual(SESSION_STORE_UNAVAILABLE);
		expect(record).toHaveBeenCalledTimes(1);
		expect(logger.error).toHaveBeenCalledWith(
			expect.objectContaining({
				route: "verify",
				sid,
				store: "user_session",
				step: "recordSecondFactor",
			}),
			"mfa_store_unavailable",
		);
		expect((await stored(userSessionStore, sid)).amr).toEqual([PASSWORD_AMR]);
		const renewed = sessionCookie(res);
		expect(await admitted(app, renewed)).toBe(true);
		expect((await postAs(app, renewed, "/enrollment", { kind: "totp" })).status).toBe(403);
	});

	it("answers 503 to a session store that answers something that is no session", async () => {
		const { record, verified } = await opened();
		record.mockResolvedValueOnce(true as unknown as UserSession);

		const res = await verified();

		expect(res.status).toBe(503);
		expect(res.body).toEqual(SESSION_STORE_UNAVAILABLE);
		expect(record).toHaveBeenCalledTimes(1);
	});

	it("answers 503 to a session store that answers an object holding the new nonce and nothing of the session, said as the store's outage: the renewed cookie stands, not stepped up", async () => {
		const { app, sid, userSessionStore, record, logger, verified } = await opened();
		record.mockImplementationOnce(
			async (_sid, event) => ({ renewalNonce: event.renewalNonce }) as unknown as UserSession,
		);

		const res = await verified();

		expect(res.status, JSON.stringify(res.body)).toBe(503);
		expect(res.body).toEqual(SESSION_STORE_UNAVAILABLE);
		expect(logger.error).toHaveBeenCalledWith(
			expect.objectContaining({
				route: "verify",
				sid,
				store: "user_session",
				step: "recordSecondFactor",
			}),
			"mfa_store_unavailable",
		);
		expect((await stored(userSessionStore, sid)).amr).toEqual([PASSWORD_AMR]);
		expect((await postAs(app, sessionCookie(res), "/enrollment", { kind: "totp" })).status).toBe(
			403,
		);
	});

	it("answers 503 and records nothing when the renewal answers no renewal nonce, said as the cookie store's outage", async () => {
		const { sid, userSessionStore, record, logger, verified } = await opened({
			loginCompletion: nonceDropping(),
		});

		const res = await verified();

		expect(res.status, JSON.stringify(res.body)).toBe(503);
		expect(res.body).toEqual(SESSION_STORE_UNAVAILABLE);
		expect(record).not.toHaveBeenCalled();
		expect((await stored(userSessionStore, sid)).amr).toEqual([PASSWORD_AMR]);
		expect(logger.error).toHaveBeenCalledWith(
			expect.objectContaining({ route: "verify", sid, store: "cookie_session" }),
			"mfa_store_unavailable",
		);
	});

	it("answers 500 when the store refuses the event as one it cannot record, said as mfa_escalation_invalid", async () => {
		const { record, logger, verified } = await opened();
		record.mockRejectedValueOnce(new RangeError("recordSecondFactor: at is ahead of the clock"));

		const res = await verified();

		expect(res.status).toBe(500);
		expect(res.body).toEqual(SERVER_ERROR);
		expect(record).toHaveBeenCalledTimes(1);
		expect(logger.error).toHaveBeenCalledWith(
			expect.objectContaining({ route: "verify", sub: ALICE.id }),
			"mfa_escalation_invalid",
		);
	});

	it("answers 500, renewing and recording nothing, when what the verification adds is outside the mfa requirement's reach, said as mfa_escalation_invalid", async () => {
		const amrValues = [HARDWARE_KEY_AMR];
		const outside = "x-outside-reach";
		const keyFactor: MfaFactor = {
			kind: "key",
			amrValues,
			amrFor: () => [outside],
			addsMfa: false,
			counting: true,
			guessable: false,
			describe: () => ({}),
			verify: async ({ factor }) => ({ ok: true, factorId: factor.id }),
			beginEnrollment: async () => {
				throw new Error("not enrolled here");
			},
			completeEnrollment: async () => {
				throw new Error("not enrolled here");
			},
		};
		const { agent, sid, factorStore, userSessionStore, record, logger } = await opened({
			extraModules: [contributing(keyFactor)],
		});
		const key = await seedFactor(factorStore, "key", {});
		const transaction = await openedStepUp(agent);
		// The factor now declares a value its reach, sealed at boot, never held.
		amrValues.push(outside);

		const res = await verify(agent, transaction, key.id, "assertion");

		expect(res.status, JSON.stringify(res.body)).toBe(500);
		expect(res.body).toEqual(SERVER_ERROR);
		expect(sessionIdSet(res)).toBeUndefined();
		expect(record).not.toHaveBeenCalled();
		expect((await stored(userSessionStore, sid)).amr).toEqual([PASSWORD_AMR]);
		expect(logger.error).toHaveBeenCalledWith(
			expect.objectContaining({ route: "verify", sub: ALICE.id }),
			"mfa_escalation_invalid",
		);
	});

	it("answers 500 and ends the session when the store answers it without the renewal nonce, said as mfa_escalation_unbound: neither the renewed cookie nor an old one put back is admitted", async () => {
		const { app, cookie, sid, tap, userSessionStore, record, recordUnwatched, logger, verified } =
			await opened();
		record.mockImplementationOnce(async (recorded, event) => {
			const { renewalNonce: _dropped, ...rest } = event;
			return recordUnwatched(recorded, rest);
		});
		const held = request(app)
			.get("/test-tap/hold")
			.set("Cookie", cookie)
			.then((res) => res);
		await tap.held.reached;

		const res = await verified();
		tap.release();
		expect((await held).status).toBe(204);

		expect(res.status).toBe(500);
		expect(res.body).toEqual(SIGN_IN_AGAIN);
		expect(logger.error).toHaveBeenCalledWith(
			expect.objectContaining({ route: "verify", sub: ALICE.id }),
			"mfa_escalation_unbound",
		);
		expect(await userSessionStore.get(sid)).toBeNull();
		expect(await signedInAs(app, cookie)).toBe(true);
		expect(await admitted(app, cookie)).toBe(false);
		expect(await admitted(app, sessionCookie(res))).toBe(false);
	});

	it("still answers 500 when the unbound session cannot be ended, said as the store's outage", async () => {
		const { sid, userSessionStore, record, recordUnwatched, logger, verified } = await opened();
		record.mockImplementationOnce(async (recorded, event) => {
			const { renewalNonce: _dropped, ...rest } = event;
			return recordUnwatched(recorded, rest);
		});
		vi.spyOn(userSessionStore, "delete").mockRejectedValueOnce(new Error("session store down"));

		const res = await verified();

		expect(res.status).toBe(500);
		expect(res.body).toEqual(SIGN_IN_AGAIN);
		expect(logger.error).toHaveBeenCalledWith(
			expect.objectContaining({ route: "verify", sid, store: "user_session", step: "delete" }),
			"mfa_store_unavailable",
		);
	});

	describe("a step-up the session store does not record", () => {
		it("answers 401 when the session is gone by then, the renewed cookie not admitted", async () => {
			const { app, sid, userSessionStore, record, recordUnwatched, verified } = await opened();
			record.mockImplementationOnce(async (...args) => {
				await userSessionStore.delete(sid);
				return recordUnwatched(...args);
			});

			const res = await verified();

			expect(res.status, JSON.stringify(res.body)).toBe(401);
			expect(res.body).toEqual({ error: "login_required", error_description: "Log in again" });
			expect(record).toHaveBeenCalledTimes(1);
			expect(await admitted(app, sessionCookie(res))).toBe(false);
		});

		it("answers 401 when another completion from the same cookie session was recorded first, the renewed cookie not admitted", async () => {
			const { app, sid, record, recordUnwatched, verified } = await opened();
			record.mockImplementationOnce(async (...args) => {
				await recordUnwatched(sid, {
					amr: [OTP_AMR],
					at: new Date(T0),
					renewalNonce: newRenewalNonce(),
				});
				return recordUnwatched(...args);
			});

			const res = await verified();

			expect(res.status, JSON.stringify(res.body)).toBe(401);
			expect(record).toHaveBeenCalledTimes(1);
			expect(await admitted(app, sessionCookie(res))).toBe(false);
		});

		it("answers 401 when the record predates how a session was established, leaving it as it was, the renewed cookie never admitted for mfa.manage", async () => {
			const { app, sid, userSessionStore, record, verified } = await opened();
			const before = await stored(userSessionStore, sid);
			await userSessionStore.delete(sid);
			await userSessionStore.create({
				sid,
				sub: before.sub,
				authTime: before.authTime,
				expiresAt: before.expiresAt,
				claims: before.claims,
				amr: undefined,
				authentication: undefined,
			});

			const res = await verified();

			expect(res.status, JSON.stringify(res.body)).toBe(401);
			expect(record).toHaveBeenCalledTimes(1);
			expect((await stored(userSessionStore, sid)).authentication).toBeUndefined();
			const renewed = sessionCookie(res);
			expect((await postAs(app, renewed, "/enrollment", { kind: "totp" })).status).toBe(401);
		});
	});

	it("records one of two step-ups finished at once from one cookie session: the other is 401, and its renewed cookie is not admitted", async () => {
		const { app, sid, cookie, factorStore, userSessionStore, agent, transaction, totp } =
			await opened();
		const other = await seedTotp(factorStore);
		const second = await openedStepUp(agent);
		const update = factorStore.update.bind(factorStore);
		let release: () => void = () => {};
		let reached: () => void = () => {};
		const gate = new Promise<void>((resolve) => (release = resolve));
		const paused = new Promise<void>((resolve) => (reached = resolve));
		vi.spyOn(factorStore, "update").mockImplementationOnce(async (...args) => {
			reached();
			await gate;
			return update(...args);
		});

		const first = postAs(app, cookie, "/verify", {
			transaction_id: transaction,
			factor_id: totp.record.id,
			proof: totpCode(totp.secret),
		});
		await paused;
		const won = await postAs(app, cookie, "/verify", {
			transaction_id: second,
			factor_id: other.record.id,
			proof: totpCode(other.secret),
		});
		release();
		const lost = await first;

		expect(won.status, JSON.stringify(won.body)).toBe(200);
		expect(lost.status, JSON.stringify(lost.body)).toBe(401);
		expect(await admitted(app, sessionCookie(won))).toBe(true);
		expect(await admitted(app, sessionCookie(lost))).toBe(false);
		expect((await stored(userSessionStore, sid)).amr).toEqual([PASSWORD_AMR, OTP_AMR, MFA_AMR]);
	});

	it("refuses the old cookie session even when a request held on it saves it back after the step-up", async () => {
		const { app, cookie, tap, verified } = await opened();
		const held = request(app)
			.get("/test-tap/hold")
			.set("Cookie", cookie)
			.then((res) => res);
		await tap.held.reached;

		expect((await verified()).status).toBe(200);
		tap.release();
		expect((await held).status).toBe(204);

		expect(await signedInAs(app, cookie)).toBe(true);
		expect(await admitted(app, cookie)).toBe(false);
	});
});
