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
 * `POST /session/mfa/step-up` (the MFA ADR's F2). For a subject that holds
 * no counting factor (its first-binding branch, D24) — the page a first
 * binding's `403 step_up_required` sends the browser to — it opens, or uses,
 * an `enroll` transaction bound to the browser session and its `sid`, owing
 * the account-email proof; the proof, given on it through
 * `POST /session/mfa/challenge` and `/verify`, is recorded for that session
 * alone, for `mfa.manage.maxAgeSeconds`. For a subject holding a record
 * that may count, it opens a `step_up` transaction bound the same way,
 * owing no proof, with the `acr_values` hinted; one with no usable factor
 * is `403 mfa_no_qualifying_factor`, and a session store that cannot record
 * the step-up `401`. A stale sign-in, a session that recorded no facts and
 * no session `401`; a witness that says the subject enrolled beside no
 * counting record `503`.
 */

import {
	createInMemoryUserSessionStore,
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	defineModule,
	type MfaTransactionStore,
	type Module,
	type SessionRequirement,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import {
	createRecordingMailSender,
	type RecordingMailSender,
} from "@o3co/auth-provider-core/testing";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	ALICE,
	boot,
	configFor,
	directoryEntries,
	disposeAll,
	WitnessingUserRepository,
} from "./moduleHarness.mjs";
import {
	completeEnrollment,
	enrollFromAccount,
	freezeClock,
	giveEmailProof,
	mfaPost,
	readTransaction,
	recordingAuditSink,
	STEP_UP_REQUIRED,
	seedFactor,
	seedTotp,
	signIn,
	signInWithTotp,
	stepUp,
	T0,
	thawClock,
	totpProofOf,
	verify,
} from "./routesHarness.mjs";

beforeEach(() => freezeClock());
afterEach(async () => {
	await disposeAll();
	thawClock();
});

const TRANSACTION_ID = /^[A-Za-z0-9_-]{43}$/;
const LOGIN_REQUIRED = { error: "login_required", error_description: "Log in again" };
const UNKNOWN = {
	error: "invalid_request",
	error_description: "Unknown or expired MFA transaction",
};
const UNKNOWN_FACTOR = { error: "invalid_request", error_description: "Unknown second factor" };
const NO_QUALIFYING_FACTOR = {
	error: "mfa_no_qualifying_factor",
	error_description: "No second factor of this account can be used for a step-up",
};

/** Boots `optional` with a recording sender (unless `sender` is `null`) and alice's address. */
async function composed(
	options: {
		readonly mode?: "optional" | "required";
		readonly sender?: RecordingMailSender | null;
		readonly transactionStore?: MfaTransactionStore;
		readonly requireEmailProof?: "when-mail" | "always" | "never";
		readonly extraModules?: readonly Module[];
		readonly expected?: readonly string[];
		readonly userSessionStore?: UserSessionStore;
	} = {},
) {
	const sender = options.sender === undefined ? createRecordingMailSender() : options.sender;
	const factorStore = createMemoryMfaFactorStore();
	const transactionStore = options.transactionStore ?? createMemoryMfaTransactionStore();
	const audit = recordingAuditSink();
	const booted = await boot({
		config: configFor(
			options.mode ?? "optional",
			{ enrollment: { requireEmailProof: options.requireEmailProof ?? "when-mail" } },
			{},
			options.expected,
		),
		...(options.extraModules === undefined ? {} : { extraModules: options.extraModules }),
		factorStore,
		transactionStore,
		auditSink: audit,
		userRepository: new WitnessingUserRepository(directoryEntries()),
		...(sender === null ? {} : { mailSender: sender }),
		...(options.userSessionStore === undefined
			? {}
			: { userSessionStore: options.userSessionStore }),
	});
	return {
		...booted,
		factorStore,
		transactionStore,
		userSessionStore: booted.userSessionStore as UserSessionStore,
		audit,
		sender,
	};
}

/** `store`'s `get`, answering each session as `change` makes it. */
const reading = (store: UserSessionStore, change: (session: UserSession) => UserSession) => {
	const read = store.get.bind(store);
	return vi.spyOn(store, "get").mockImplementation(async (sid) => {
		const session = await read(sid);
		return session === null ? null : change(session);
	});
};

describe("the step-up of a subject with no counting factor", () => {
	it("opens an enroll transaction owing the account-email proof, bound to the browser session, its sid and subject", async () => {
		const { app, transactionStore, userSessionStore } = await composed();
		const { agent, sid } = await signIn(app, userSessionStore);

		const res = await stepUp(agent);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(res.headers["cache-control"]).toBe("no-store");
		expect(res.body).toEqual({
			transaction: expect.stringMatching(TRANSACTION_ID),
			expires_in: 600,
			email_proof: true,
		});
		expect(await transactionStore.get(res.body.transaction as string)).toMatchObject({
			purpose: "enroll",
			subject: ALICE.id,
			sid,
			continuation: undefined,
			enrollment: "required",
			emailProof: "required",
		});
		expect((await readTransaction(agent, res.body.transaction as string)).body).toEqual({
			purpose: "enroll",
			factors: [],
			enrollment: "required",
			email_proof: true,
			expires_in: 600,
			attempts_remaining: 5,
		});
	});

	it("mails the proof to the session's login address, and records it for that session alone, standing mfa.manage.maxAgeSeconds", async () => {
		const { app, transactionStore, userSessionStore, sender, audit } = await composed();
		const { agent, sid } = await signIn(app, userSessionStore);
		const transaction = (await stepUp(agent)).body.transaction as string;

		const challenged = await mfaPost(agent, "/challenge", {
			transaction_id: transaction,
			factor_id: "account-email",
		});
		expect(challenged.status, JSON.stringify(challenged.body)).toBe(200);
		expect(challenged.body).toEqual({ sent_to: "a***@example.com", expires_in: 600 });
		expect(sender?.sent).toEqual([
			expect.objectContaining({
				purpose: "account_email_proof",
				subject: ALICE.id,
				to: ALICE.email,
			}),
		]);
		const verified = await verify(agent, transaction, "account-email", sender?.sent.at(-1)?.code);
		expect(verified.status, JSON.stringify(verified.body)).toBe(200);
		expect(verified.body).toEqual({ email_proof: "verified" });
		expect(await transactionStore.get(transaction)).toMatchObject({
			emailProof: { provedAtMs: T0 },
		});

		expect(await transactionStore.sessionEmailProofAt(ALICE.id, sid, T0)).toBe(T0);
		expect(await transactionStore.sessionEmailProofAt(ALICE.id, sid, T0 + 299_999)).toBe(T0);
		expect(await transactionStore.sessionEmailProofAt(ALICE.id, "another-sid", T0)).toBeNull();
		freezeClock(T0 + 300_000);
		expect(await transactionStore.sessionEmailProofAt(ALICE.id, sid, T0 + 300_000)).toBeNull();
		expect(audit.of("mfa.verified")).toEqual([
			expect.objectContaining({ details: { kind: "account-email", purpose: "enroll" } }),
		]);
	});

	it("admits a first binding in that session once proved, and none in another session of the subject", async () => {
		const { app, userSessionStore, sender } = await composed();
		const { agent } = await signIn(app, userSessionStore);
		const other = await signIn(app, userSessionStore);
		expect((await enrollFromAccount(agent, "totp")).body).toMatchObject(STEP_UP_REQUIRED);
		const transaction = (await stepUp(agent)).body.transaction as string;
		expect((await giveEmailProof(agent, transaction, sender as RecordingMailSender)).status).toBe(
			200,
		);

		expect((await enrollFromAccount(agent, "totp")).status).toBe(200);
		const elsewhere = await enrollFromAccount(other.agent, "totp");
		expect(elsewhere.status).toBe(403);
		expect(elsewhere.body).toMatchObject(STEP_UP_REQUIRED);
	});

	it("asks the proof again when the one given is lost: the first binding is stepped up, and a new proof admits it", async () => {
		const transactionStore = createMemoryMfaTransactionStore();
		let lost = false;
		const answer = transactionStore.sessionEmailProofAt.bind(transactionStore);
		vi.spyOn(transactionStore, "sessionEmailProofAt").mockImplementation(async (...args) =>
			lost ? null : answer(...args),
		);
		const record = transactionStore.recordSessionEmailProof.bind(transactionStore);
		vi.spyOn(transactionStore, "recordSessionEmailProof").mockImplementation(async (...args) => {
			lost = false;
			return record(...args);
		});
		const { app, userSessionStore, sender } = await composed({ transactionStore });
		const { agent } = await signIn(app, userSessionStore);
		const first = (await stepUp(agent)).body.transaction as string;
		expect((await giveEmailProof(agent, first, sender as RecordingMailSender)).status).toBe(200);
		expect((await enrollFromAccount(agent, "totp")).status).toBe(200);

		lost = true;
		expect((await enrollFromAccount(agent, "totp")).body).toMatchObject(STEP_UP_REQUIRED);
		// The transaction whose proof is met is spent for another: a new one is opened.
		const second = await stepUp(agent, first);
		expect(second.status).toBe(200);
		expect(second.body.transaction).not.toBe(first);
		expect(
			(
				await giveEmailProof(
					agent,
					second.body.transaction as string,
					sender as RecordingMailSender,
				)
			).status,
		).toBe(200);
		expect((await enrollFromAccount(agent, "totp")).status).toBe(200);
	});

	it("uses the enrollment's transaction when named: the proof owed on it, the completion then binding by email_proof", async () => {
		const { app, transactionStore, factorStore, userSessionStore, sender } = await composed({
			requireEmailProof: "never",
		});
		const { agent } = await signIn(app, userSessionStore);
		const begun = await enrollFromAccount(agent, "totp");
		expect(begun.status).toBe(200);
		const transaction = begun.body.transaction as string;

		const used = await stepUp(agent, transaction);

		expect(used.status, JSON.stringify(used.body)).toBe(200);
		expect(used.body).toEqual({ transaction, expires_in: 600, email_proof: true });
		expect((await transactionStore.get(transaction))?.emailProof).toBe("required");
		const owed = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));
		expect(owed.status).toBe(403);
		expect(owed.body.error).toBe("mfa_email_proof_required");
		expect((await giveEmailProof(agent, transaction, sender as RecordingMailSender)).status).toBe(
			200,
		);
		const done = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));
		expect(done.status, JSON.stringify(done.body)).toBe(200);
		expect((await factorStore.list(ALICE.id)).find((r) => r.kind === "totp")?.binding).toBe(
			"email_proof",
		);
	});

	it("answers a named transaction that is not this session's as unknown: another session's, one that does not exist, one that is no id", async () => {
		const { app, userSessionStore } = await composed();
		const { agent } = await signIn(app, userSessionStore);
		const other = await signIn(app, userSessionStore);
		const theirs = (await stepUp(other.agent)).body.transaction as string;

		for (const named of [theirs, "A".repeat(43), "not an id"]) {
			const res = await stepUp(agent, named);
			expect(res.status, named).toBe(400);
			expect(res.body, named).toEqual(UNKNOWN);
		}
	});

	it("verifies nothing but the account-email proof on an enroll transaction: a factor named is unknown", async () => {
		const { app, factorStore, userSessionStore } = await composed();
		const { agent } = await signIn(app, userSessionStore);
		const transaction = (await stepUp(agent)).body.transaction as string;
		const recovery = await seedFactor(factorStore, "recovery_code", { codes: [] });

		for (const path of ["/challenge", "/verify"]) {
			const res = await mfaPost(agent, path, {
				transaction_id: transaction,
				factor_id: recovery.id,
				proof: "123456",
			});
			expect(res.status, path).toBe(400);
			expect(res.body, path).toEqual(UNKNOWN_FACTOR);
		}
	});

	it("spends the transaction's attempts on a wrong proof, never the subject lock", async () => {
		const transactionStore = createMemoryMfaTransactionStore();
		const reserveSubject = vi.spyOn(transactionStore, "reserveSubjectAttempt");
		const { app, userSessionStore } = await composed({ transactionStore });
		const { agent } = await signIn(app, userSessionStore);
		const transaction = (await stepUp(agent)).body.transaction as string;
		await mfaPost(agent, "/challenge", { transaction_id: transaction, factor_id: "account-email" });

		const wrong = await verify(agent, transaction, "account-email", "0000-0000-0000-0000");

		expect(wrong.status).toBe(401);
		expect(wrong.body).toMatchObject({ error: "mfa_invalid", attempts_remaining: 4 });
		expect(reserveSubject).not.toHaveBeenCalled();
	});
});

describe("the step-up under required, for a password session without a second factor whose subject holds no counting factor", () => {
	it("is never reached: the requirement sends the session to log in again, where the login binds the first factor — no transaction, no mail", async () => {
		const { app, factorStore, transactionStore, userSessionStore, sender } = await composed({
			mode: "required",
		});
		const seeded = await seedTotp(factorStore);
		const { agent } = await signInWithTotp(app, userSessionStore, seeded);
		// The session as one written before required was switched on, its subject enrolled in nothing.
		await factorStore.remove(ALICE.id, seeded.record.id);
		reading(userSessionStore, (session) => ({
			...session,
			amr: ["pwd"],
			authentication: {
				...(session.authentication as NonNullable<UserSession["authentication"]>),
				mfaAt: undefined,
			},
		}));
		const create = vi.spyOn(transactionStore, "create");

		const enrolled = await enrollFromAccount(agent, "totp");
		expect(enrolled.status).toBe(401);
		expect(enrolled.body).toEqual(LOGIN_REQUIRED);
		const stepped = await stepUp(agent);
		expect(stepped.status).toBe(401);
		expect(stepped.body).toEqual(LOGIN_REQUIRED);
		expect(create).not.toHaveBeenCalled();
		expect(sender?.sent).toEqual([]);
	});
});

describe("the step-up's own step-ups", () => {
	/** A requirement beside mfa that asks every credential_change for a step-up through a page of its own. */
	const insisting = (): Module =>
		defineModule({
			name: "test:insisting-requirement",
			contributes: {
				sessionRequirements: {
					insisting: (): SessionRequirement => ({
						name: "insisting",
						reach: new Set<string>(),
						stepUpPage: { url: "/insist", params: {} },
						remediations: [],
						hintKeys: [],
						admit: async ({ action }) =>
							action.grade === "credential_change"
								? { outcome: "step_up", whenStillUnmet: "reauthenticate" }
								: { outcome: "met" },
					}),
				},
			},
		});

	it("answers another requirement's step-up as that requirement's, opening no proof", async () => {
		const { app, transactionStore, userSessionStore } = await composed({
			sender: null,
			extraModules: [insisting()],
			expected: ["mfa", "insisting"],
		});
		const { agent } = await signIn(app, userSessionStore);
		const create = vi.spyOn(transactionStore, "create");

		const res = await stepUp(agent);

		expect(res.status).toBe(403);
		expect(res.body).toEqual({
			error: "step_up_required",
			error_description: "This action requires a step-up first",
			requirement: "insisting",
			page: "https://auth.example/insist",
		});
		expect(create).not.toHaveBeenCalled();
	});

	it("answers 400 when the body and the MFA-Transaction header name different transactions, opening none", async () => {
		const { app, transactionStore, userSessionStore } = await composed();
		const { agent } = await signIn(app, userSessionStore);
		const named = (await stepUp(agent)).body.transaction as string;
		const create = vi.spyOn(transactionStore, "create");

		const res = await mfaPost(
			agent,
			"/step-up",
			{ transaction_id: named },
			{ "MFA-Transaction": "B".repeat(43) },
		);

		expect(res.status).toBe(400);
		expect(res.body).toEqual(UNKNOWN);
		expect(create).not.toHaveBeenCalled();
	});
});

describe("the step-up of a subject holding a counting factor", () => {
	it("opens a step_up transaction owing no proof, bound to the browser session, its sid and subject, offering the factors", async () => {
		const { app, factorStore, transactionStore, userSessionStore } = await composed();
		const { agent, sid } = await signIn(app, userSessionStore);
		const seeded = await seedTotp(factorStore);

		const res = await stepUp(agent);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(res.headers["cache-control"]).toBe("no-store");
		expect(res.body).toEqual({
			transaction: expect.stringMatching(TRANSACTION_ID),
			expires_in: 600,
			email_proof: false,
		});
		expect(await transactionStore.get(res.body.transaction as string)).toMatchObject({
			purpose: "step_up",
			subject: ALICE.id,
			sid,
			continuation: undefined,
			enrollment: "none",
			emailProof: "not_required",
			acrValues: undefined,
			attempts: 0,
			expiresAtMs: T0 + 600_000,
		});
		expect((await readTransaction(agent, res.body.transaction as string)).body).toEqual({
			purpose: "step_up",
			factors: [{ id: seeded.record.id, kind: "totp" }],
			enrollment: "none",
			email_proof: false,
			expires_in: 600,
			attempts_remaining: 5,
		});
	});

	it("opens one for a session that already holds recent MFA", async () => {
		const { app, factorStore, transactionStore, userSessionStore } = await composed({
			mode: "required",
		});
		const seeded = await seedTotp(factorStore);
		const { agent } = await signInWithTotp(app, userSessionStore, seeded);

		const res = await stepUp(agent);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(res.body.email_proof).toBe(false);
		expect((await transactionStore.get(res.body.transaction as string))?.purpose).toBe("step_up");
	});

	it("answers the session's own step_up transaction again when named, and opens no other", async () => {
		const { app, factorStore, transactionStore, userSessionStore } = await composed();
		const { agent } = await signIn(app, userSessionStore);
		await seedTotp(factorStore);
		const opened = (await stepUp(agent)).body.transaction as string;
		const create = vi.spyOn(transactionStore, "create");

		const again = await stepUp(agent, opened);

		expect(again.status, JSON.stringify(again.body)).toBe(200);
		expect(again.body).toEqual({ transaction: opened, expires_in: 600, email_proof: false });
		expect(create).not.toHaveBeenCalled();
	});

	it("answers a named transaction that is not this session's own step_up as unknown: another session's, its own enroll one, one that does not exist, one that is no id", async () => {
		const { app, factorStore, transactionStore, userSessionStore } = await composed();
		const { agent } = await signIn(app, userSessionStore);
		const other = await signIn(app, userSessionStore);
		// The session's own enroll transaction, opened while the subject held no factor.
		const own = (await stepUp(agent)).body.transaction as string;
		await seedTotp(factorStore);
		const theirs = (await stepUp(other.agent)).body.transaction as string;
		const create = vi.spyOn(transactionStore, "create");

		for (const named of [theirs, own, "A".repeat(43), "not an id"]) {
			const res = await stepUp(agent, named);
			expect(res.status, named).toBe(400);
			expect(res.body, named).toEqual(UNKNOWN);
		}
		expect(create).not.toHaveBeenCalled();
	});

	it("records the acr_values asked as a hint, read strictly: a malformed, overlong or too long a list is recorded as none", async () => {
		const { app, factorStore, transactionStore, userSessionStore } = await composed();
		const { agent } = await signIn(app, userSessionStore);
		await seedTotp(factorStore);
		const opened = async (acrValues: unknown) => {
			const res = await mfaPost(agent, "/step-up", { acr_values: acrValues });
			expect(res.status, JSON.stringify(res.body)).toBe(200);
			return (await transactionStore.get(res.body.transaction as string))?.acrValues;
		};

		expect(await opened("urn:o3co:acr:mfa  urn:example:gold urn:o3co:acr:mfa")).toEqual([
			"urn:o3co:acr:mfa",
			"urn:example:gold",
		]);
		expect(await opened(Array.from({ length: 16 }, (_, n) => `a${n}`).join(" "))).toHaveLength(16);
		expect(await opened("x".repeat(256))).toEqual(["x".repeat(256)]);
		for (const malformed of [
			"urn:o3co:acr:mfa\turn:example:gold",
			'urn:o3co:acr:"mfa"',
			"   ",
			Array.from({ length: 17 }, (_, n) => `a${n}`).join(" "),
			"x".repeat(257),
			["urn:o3co:acr:mfa"],
			42,
		]) {
			expect(await opened(malformed), JSON.stringify(malformed)).toBeUndefined();
		}
	});

	it("answers 403 mfa_no_qualifying_factor, opening nothing, to a subject whose only records are of a kind no installed factor declares, or a TOTP whose data does not open", async () => {
		for (const held of ["retired-kind", "unopenable totp"] as const) {
			const { app, factorStore, transactionStore, userSessionStore } = await composed();
			const { agent } = await signIn(app, userSessionStore);
			if (held === "retired-kind") await seedFactor(factorStore, held, {});
			else await seedTotp(factorStore, ALICE.id, { sealedFor: "u-someone-else" });
			const create = vi.spyOn(transactionStore, "create");

			const res = await stepUp(agent);

			expect(res.status, held).toBe(403);
			expect(res.body, held).toEqual(NO_QUALIFYING_FACTOR);
			expect(create, held).not.toHaveBeenCalled();
		}
	});

	it("offers a usable factor that does not count beside one that cannot be used: recovery codes beside an unopenable TOTP", async () => {
		const { app, factorStore, transactionStore, userSessionStore } = await composed();
		const { agent } = await signIn(app, userSessionStore);
		await seedTotp(factorStore, ALICE.id, { sealedFor: "u-someone-else" });
		const recovery = await seedFactor(factorStore, "recovery_code", { codes: [] });

		const res = await stepUp(agent);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		const listed = (await readTransaction(agent, res.body.transaction as string)).body.factors;
		expect(listed).toEqual(expect.arrayContaining([expect.objectContaining({ id: recovery.id })]));
		expect(await transactionStore.get(res.body.transaction as string)).toMatchObject({
			purpose: "step_up",
		});
	});

	it("answers 401 login_required, opening nothing, when the session store cannot record a step-up — a session with recent MFA included", async () => {
		const { recordSecondFactor: _record, ...legacy } = createInMemoryUserSessionStore();
		const { app, factorStore, transactionStore, userSessionStore } = await composed({
			userSessionStore: { ...legacy, kind: "legacy-sessions" },
		});
		const seeded = await seedTotp(factorStore);
		const { agent } = await signInWithTotp(app, userSessionStore, seeded);
		const create = vi.spyOn(transactionStore, "create");

		const res = await stepUp(agent);

		expect(res.status, JSON.stringify(res.body)).toBe(401);
		expect(res.body).toEqual(LOGIN_REQUIRED);
		expect(create).not.toHaveBeenCalled();
	});
});

describe("the step-up's refusals", () => {
	it("answers 401 login_required without a session, to a sign-in older than mfa.manage.maxAgeSeconds, and to a session that recorded no facts — opening nothing", async () => {
		const { app, transactionStore, userSessionStore } = await composed();
		const create = vi.spyOn(transactionStore, "create");
		expect((await stepUp(request.agent(app))).body).toEqual(LOGIN_REQUIRED);

		const { agent } = await signIn(app, userSessionStore);
		freezeClock(T0 + 301_000);
		const stale = await stepUp(agent);
		expect(stale.status).toBe(401);
		expect(stale.body).toEqual(LOGIN_REQUIRED);

		freezeClock(T0);
		const spy = reading(userSessionStore, (session) => {
			const { enrollmentFacts: _recorded, ...without } = session;
			return without as UserSession;
		});
		const unrecorded = await stepUp(agent);
		expect(unrecorded.status).toBe(401);
		expect(unrecorded.body).toEqual(LOGIN_REQUIRED);
		spy.mockRestore();
		expect(create).not.toHaveBeenCalled();
	});

	it("answers 503 to a session whose login's User said it enrolled while no counting factor is on record — the event recorded — and to a factor store that cannot answer", async () => {
		const { app, factorStore, transactionStore, userSessionStore, audit } = await composed();
		const { agent } = await signIn(app, userSessionStore);
		const create = vi.spyOn(transactionStore, "create");
		const spy = reading(userSessionStore, (session) => ({
			...session,
			enrollmentFacts: { witness: "enrolled", mailAddress: "address" },
		}));

		const inconsistent = await stepUp(agent);

		expect(inconsistent.status).toBe(503);
		expect(inconsistent.body.error).toBe("temporarily_unavailable");
		expect(audit.of("mfa.enrollment_state_inconsistent")).toEqual([
			expect.objectContaining({
				subject: ALICE.id,
				details: { purpose: "session", action: "mfa.manage", witness: "enrolled" },
			}),
		]);
		spy.mockRestore();

		vi.spyOn(factorStore, "list").mockRejectedValue(new Error("factor store unreachable"));
		const outage = await stepUp(agent);
		expect(outage.status).toBe(503);
		expect(outage.body.error).toBe("temporarily_unavailable");
		expect(create).not.toHaveBeenCalled();
	});
});

describe("a proof nobody can give", () => {
	it("is refused 403 at its challenge — no sender, no address, an address the provider cannot read — and the first binding stays stepped up", async () => {
		for (const [label, sender, email] of [
			["no sender", null, ALICE.email],
			["no address", undefined, undefined],
			["unreadable", undefined, "Alice <alice@example.com>"],
		] as const) {
			const entries = directoryEntries();
			const alice = entries.get(ALICE.username);
			if (alice !== undefined) {
				if (email === undefined) delete alice.email;
				else alice.email = email;
			}
			const mail = sender === null ? null : createRecordingMailSender();
			const factorStore = createMemoryMfaFactorStore();
			const booted = await boot({
				config: configFor("optional", { enrollment: { requireEmailProof: "always" } }),
				factorStore,
				userRepository: new WitnessingUserRepository(entries),
				...(mail === null ? {} : { mailSender: mail }),
				...(sender === null ? { config: configFor("optional") } : {}),
			});
			const store = booted.userSessionStore as UserSessionStore;
			if (sender === null) await booted.transactionStore.requireEmailProofAtNextBinding(ALICE.id);
			const { agent } = await signIn(booted.app, store);
			expect((await enrollFromAccount(agent, "totp")).body, label).toMatchObject(STEP_UP_REQUIRED);
			const opened = await stepUp(agent);
			expect(opened.status, label).toBe(200);
			const challenged = await mfaPost(agent, "/challenge", {
				transaction_id: opened.body.transaction,
				factor_id: "account-email",
			});
			expect(challenged.status, label).toBe(403);
			expect(challenged.body.error, label).toBe("mfa_email_proof_unavailable");
			expect((await enrollFromAccount(agent, "totp")).status, label).toBe(403);
		}
	});
});
