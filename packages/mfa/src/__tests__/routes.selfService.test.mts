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
 * Self-service enrollment from the account page (the MFA ADR's F4 steps 2
 * and 3, D12, D24, D25), through the composed application:
 * `POST /session/mfa/enrollment` without a transaction admits the cookie's
 * session as `mfa.manage` and opens an `enroll` transaction bound to the
 * browser session and its `sid`; `POST /session/mfa/enrollment/complete`
 * admits it again and binds. A subject holding a counting factor needs
 * recent MFA and binds by `mfa`; a first binding needs a recent sign-in and
 * the one gate — the account-email proof given in that session, where the
 * gate asks for it — and binds by `password` or `email_proof`, with its
 * recovery codes. The session is left as it was.
 */

import {
	createInMemorySubjectRevocation,
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	type MfaFactorRecord,
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
	csrfOf,
	enrollFromAccount,
	freezeClock,
	giveEmailProof,
	loggedText,
	mfaPost,
	readTransaction,
	recordingAuditSink,
	STEP_UP_REQUIRED,
	seedFactor,
	seedTotp,
	signIn,
	signInWithTotp,
	stepUp,
	storedData,
	suiteSealing,
	T0,
	thawClock,
	totpProofOf,
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
/** What an enrollment in a session is answered when the subject's factors changed under it: the session stands. */
const ENROLLMENT_CONFLICT = {
	error: "mfa_enrollment_conflict",
	error_description: "The account's second factors changed while enrolling: start again",
};
const FACTOR_LIMIT = {
	error: "mfa_factor_limit",
	error_description: "The subject holds as many second factors as it may",
};
const PROOF_UNAVAILABLE = {
	error: "mfa_email_proof_unavailable",
	error_description: "The account-email proof cannot be given for this account",
};

/** An address `normaliseMailAddress` does not read: a display name around it. */
const UNREADABLE = "Alice <alice@example.com>";

/** The directory, alice's address as `address` says: hers, none, or one the provider cannot read. */
function directory(address: "address" | "none" | "unreadable" = "address") {
	const entries = directoryEntries();
	const alice = entries.get(ALICE.username);
	if (alice !== undefined && address === "none") delete alice.email;
	if (alice !== undefined && address === "unreadable") alice.email = UNREADABLE;
	return new WitnessingUserRepository(entries);
}

interface Setup {
	readonly mode?: "optional" | "required";
	readonly sender?: RecordingMailSender | null;
	readonly requireEmailProof?: "when-mail" | "always" | "never";
	readonly address?: "address" | "none" | "unreadable";
	readonly maxFactorsPerSubject?: number;
	readonly subjectRevocation?: ReturnType<typeof createInMemorySubjectRevocation>;
}

/** Boots `mode` (optional by default) with no mail sender unless one is given, and alice's address as `address` says. */
async function composed(setup: Setup = {}) {
	const factorStore = createMemoryMfaFactorStore();
	const transactionStore = createMemoryMfaTransactionStore();
	const audit = recordingAuditSink();
	const users = directory(setup.address);
	const sender = setup.sender ?? null;
	const booted = await boot({
		config: configFor(setup.mode ?? "optional", {
			enrollment: { requireEmailProof: setup.requireEmailProof ?? "when-mail" },
			...(setup.maxFactorsPerSubject === undefined
				? {}
				: { maxFactorsPerSubject: setup.maxFactorsPerSubject }),
		}),
		factorStore,
		transactionStore,
		auditSink: audit,
		userRepository: users,
		...(sender === null ? {} : { mailSender: sender }),
		...(setup.subjectRevocation === undefined
			? {}
			: { subjectRevocation: setup.subjectRevocation }),
	});
	return {
		...booted,
		factorStore,
		transactionStore,
		userSessionStore: booted.userSessionStore as UserSessionStore,
		audit,
		users,
		sender,
	};
}

/** `text` with every run of percent-escapes decoded, as a URI's reader decodes it; a run that is no UTF-8 is kept. */
const percentDecoded = (text: string): string =>
	text.replace(/(?:%[0-9A-Fa-f]{2})+/g, (run) => {
		try {
			return decodeURIComponent(run);
		} catch {
			return run;
		}
	});

/** Alice's records as the factor store holds them, by kind. */
const recordsOf = async (store: { list(subject: string): Promise<readonly MfaFactorRecord[]> }) =>
	Object.fromEntries((await store.list(ALICE.id)).map((record) => [record.kind, record]));

describe("a first factor from the account page, where no proof is asked", () => {
	it("binds TOTP on a recent sign-in: the transaction opened in the session, the factor bound by password with its recovery codes, the witness marked, the session as it was", async () => {
		const { app, factorStore, transactionStore, userSessionStore, audit, users } = await composed();
		const { agent, sid } = await signIn(app, userSessionStore);
		const before = await userSessionStore.get(sid);

		const begun = await enrollFromAccount(agent, "totp");

		expect(begun.status, JSON.stringify(begun.body)).toBe(200);
		expect(begun.headers["cache-control"]).toBe("no-store");
		expect(begun.body).toEqual({
			secret: expect.stringMatching(/^[A-Z2-7]{32}$/),
			otpauth_uri: expect.stringMatching(/^otpauth:\/\/totp\/auth\.example:alice\?/),
			algorithm: "SHA1",
			digits: 6,
			period: 30,
			transaction: expect.stringMatching(TRANSACTION_ID),
			expires_in: 600,
		});
		const transaction = begun.body.transaction as string;
		expect(await transactionStore.get(transaction)).toMatchObject({
			purpose: "enroll",
			subject: ALICE.id,
			sid,
			continuation: undefined,
			enrollment: "required",
			emailProof: "not_required",
			pendingEnrollment: { kind: "totp" },
		});
		expect((await readTransaction(agent, transaction)).body).toEqual({
			purpose: "enroll",
			factors: [],
			enrollment: "required",
			email_proof: false,
			expires_in: 600,
			attempts_remaining: 5,
		});

		const done = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));

		expect(done.status, JSON.stringify(done.body)).toBe(200);
		expect(done.headers["cache-control"]).toBe("no-store");
		expect(done.body).toEqual({
			factor: { id: expect.stringMatching(/^[A-Za-z0-9_-]{22}$/), kind: "totp" },
			recovery_codes: expect.any(Array),
		});
		expect(done.body.recovery_codes).toHaveLength(10);
		const records = await recordsOf(factorStore);
		expect(Object.keys(records).sort()).toEqual(["recovery_code", "totp"]);
		expect(records.totp).toMatchObject({ id: done.body.factor.id, binding: "password" });
		expect(records.recovery_code).toMatchObject({ binding: "password" });
		expect(users.marks).toEqual([{ subject: ALICE.id, enrolled: true }]);
		expect(await transactionStore.get(transaction)).toBeNull();
		expect(await userSessionStore.get(sid)).toEqual(before);
		expect(audit.of("mfa.factor.enrolled")).toEqual([
			expect.objectContaining({
				subject: ALICE.id,
				details: { kind: "totp", purpose: "enroll", binding: "password", by: "user" },
			}),
		]);
		expect(audit.of("mfa.recovery_codes.generated")).toEqual([
			expect.objectContaining({
				details: {
					kind: "recovery_code",
					purpose: "enroll",
					binding: "password",
					by: "user",
					regenerated: false,
				},
			}),
		]);
		expect(audit.of("mfa.verified")).toEqual([]);
	});

	it("answers 401 login_required to a sign-in older than mfa.manage.maxAgeSeconds, opening nothing", async () => {
		const { app, transactionStore, userSessionStore } = await composed();
		const { agent } = await signIn(app, userSessionStore);
		const create = vi.spyOn(transactionStore, "create");
		freezeClock(T0 + 301_000);

		const res = await enrollFromAccount(agent, "totp");

		expect(res.status).toBe(401);
		expect(res.body).toEqual(LOGIN_REQUIRED);
		expect(create).not.toHaveBeenCalled();
	});

	it("answers 401 login_required without a signed-in session, and to one whose subject's sessions were revoked", async () => {
		const subjectRevocation = createInMemorySubjectRevocation();
		const { app, userSessionStore } = await composed({ subjectRevocation });
		const anonymous = request.agent(app);
		expect((await enrollFromAccount(anonymous, "totp")).body).toEqual(LOGIN_REQUIRED);

		const { agent } = await signIn(app, userSessionStore);
		await subjectRevocation.revokeBefore(ALICE.id, new Date(T0 + 1_000), new Date(T0 + 86_400_000));
		const res = await enrollFromAccount(agent, "totp");
		expect(res.status).toBe(401);
		expect(res.body).toEqual(LOGIN_REQUIRED);
	});

	it("answers 401 login_required to a session that recorded no facts: a fresh login records them", async () => {
		const { app, transactionStore, userSessionStore } = await composed();
		const { agent } = await signIn(app, userSessionStore);
		const read = userSessionStore.get.bind(userSessionStore);
		vi.spyOn(userSessionStore, "get").mockImplementation(async (sid) => {
			const session = await read(sid);
			if (session === null) return null;
			const { enrollmentFacts: _recorded, ...without } = session;
			return without as UserSession;
		});
		const create = vi.spyOn(transactionStore, "create");

		const res = await enrollFromAccount(agent, "totp");

		expect(res.status).toBe(401);
		expect(res.body).toEqual(LOGIN_REQUIRED);
		expect(create).not.toHaveBeenCalled();
	});

	it("answers 503 to a session whose login's User said it enrolled, or said nothing readable, while no counting factor is on record — the event recorded, nothing opened", async () => {
		for (const witness of ["enrolled", "malformed"] as const) {
			const { app, transactionStore, userSessionStore, audit } = await composed();
			const { agent } = await signIn(app, userSessionStore);
			const read = userSessionStore.get.bind(userSessionStore);
			vi.spyOn(userSessionStore, "get").mockImplementation(async (sid) => {
				const session = await read(sid);
				return session === null
					? null
					: { ...session, enrollmentFacts: { witness, mailAddress: "address" } };
			});
			const create = vi.spyOn(transactionStore, "create");

			const res = await enrollFromAccount(agent, "totp");

			expect(res.status, witness).toBe(503);
			expect(res.body, witness).toEqual({
				error: "temporarily_unavailable",
				error_description: "session requirement unavailable",
			});
			expect(create, witness).not.toHaveBeenCalled();
			expect(audit.of("mfa.enrollment_state_inconsistent"), witness).toEqual([
				expect.objectContaining({
					subject: ALICE.id,
					details: { purpose: "session", action: "mfa.manage", witness },
				}),
			]);
		}
	});
});

describe("a first factor from the account page, under the gate", () => {
	type Gate = "bind" | "prove" | "unprovable";
	interface Row {
		readonly requireEmailProof: "when-mail" | "always" | "never";
		readonly sender: boolean;
		readonly address: "address" | "none" | "unreadable";
		readonly flag: boolean;
		readonly gate: Gate;
	}
	const rows: readonly Row[] = [
		{
			requireEmailProof: "when-mail",
			sender: true,
			address: "address",
			flag: false,
			gate: "prove",
		},
		{ requireEmailProof: "when-mail", sender: true, address: "none", flag: false, gate: "bind" },
		{
			requireEmailProof: "when-mail",
			sender: true,
			address: "unreadable",
			flag: false,
			gate: "unprovable",
		},
		{
			requireEmailProof: "when-mail",
			sender: false,
			address: "address",
			flag: false,
			gate: "bind",
		},
		{ requireEmailProof: "always", sender: true, address: "address", flag: false, gate: "prove" },
		{ requireEmailProof: "always", sender: true, address: "none", flag: false, gate: "unprovable" },
		{ requireEmailProof: "never", sender: true, address: "address", flag: false, gate: "bind" },
		{ requireEmailProof: "never", sender: true, address: "unreadable", flag: false, gate: "bind" },
		{ requireEmailProof: "never", sender: true, address: "address", flag: true, gate: "prove" },
		{
			requireEmailProof: "when-mail",
			sender: false,
			address: "address",
			flag: true,
			gate: "unprovable",
		},
	];

	it.each(
		rows.map((row) => ({
			...row,
			row: `${row.requireEmailProof}, ${row.sender ? "a sender" : "no sender"}, ${row.address}${row.flag ? ", D25's flag" : ""} → ${row.gate}`,
		})),
	)("$row", async ({ requireEmailProof, sender, address, flag, gate }) => {
		const mail = sender ? createRecordingMailSender() : null;
		const { app, factorStore, transactionStore, userSessionStore } = await composed({
			requireEmailProof,
			sender: mail,
			address,
		});
		if (flag) await transactionStore.requireEmailProofAtNextBinding(ALICE.id);
		const { agent } = await signIn(app, userSessionStore);

		const first = await enrollFromAccount(agent, "totp");
		if (gate === "bind") {
			expect(first.status, JSON.stringify(first.body)).toBe(200);
		} else {
			expect(first.status).toBe(403);
			expect(first.body).toMatchObject(STEP_UP_REQUIRED);
			const opened = await stepUp(agent);
			expect(opened.status, JSON.stringify(opened.body)).toBe(200);
			const transaction = opened.body.transaction as string;
			if (gate === "unprovable") {
				const challenged = await mfaPost(agent, "/challenge", {
					transaction_id: transaction,
					factor_id: "account-email",
				});
				expect(challenged.status).toBe(403);
				expect(challenged.body).toEqual(PROOF_UNAVAILABLE);
				const again = await enrollFromAccount(agent, "totp");
				expect(again.status).toBe(403);
				expect(await factorStore.list(ALICE.id)).toEqual([]);
				return;
			}
			const proof = await giveEmailProof(agent, transaction, mail as RecordingMailSender);
			expect(proof.status, JSON.stringify(proof.body)).toBe(200);
		}
		const begun = gate === "bind" ? first : await enrollFromAccount(agent, "totp");
		expect(begun.status, JSON.stringify(begun.body)).toBe(200);
		const done = await completeEnrollment(
			agent,
			begun.body.transaction as string,
			totpProofOf(begun.body.secret),
		);
		expect(done.status, JSON.stringify(done.body)).toBe(200);
		const records = await recordsOf(factorStore);
		expect(records.totp?.binding).toBe(gate === "prove" ? "email_proof" : "password");
		expect(await transactionStore.emailProofRequiredAtNextBinding(ALICE.id)).toBe(false);
	});

	it("admits the completion again: D25's flag set after the start steps it up, spending nothing, and the proof then given in the session binds by email_proof and clears the flag", async () => {
		const mail = createRecordingMailSender();
		const { app, transactionStore, userSessionStore } = await composed({
			requireEmailProof: "never",
			sender: mail,
		});
		const { agent } = await signIn(app, userSessionStore);
		const begun = await enrollFromAccount(agent, "totp");
		expect(begun.status).toBe(200);
		// Set after the start: the completion is admitted again, and stepped up, spending nothing.
		await transactionStore.requireEmailProofAtNextBinding(ALICE.id);
		const transaction = begun.body.transaction as string;
		const stepped = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));
		expect(stepped.status).toBe(403);
		expect(stepped.body).toMatchObject(STEP_UP_REQUIRED);
		expect(await transactionStore.get(transaction)).toMatchObject({
			attempts: 0,
			pendingEnrollment: { kind: "totp" },
		});
		expect(await transactionStore.emailProofRequiredAtNextBinding(ALICE.id)).toBe(true);

		const opened = await stepUp(agent);
		expect((await giveEmailProof(agent, opened.body.transaction as string, mail)).status).toBe(200);
		const done = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));
		expect(done.status, JSON.stringify(done.body)).toBe(200);
		expect(await transactionStore.emailProofRequiredAtNextBinding(ALICE.id)).toBe(false);
	});
});

describe("the enroll transaction", () => {
	it("is used by the session that opened it alone: another browser of the same account is answered as an unknown transaction", async () => {
		const { app, userSessionStore } = await composed();
		const { agent } = await signIn(app, userSessionStore);
		const other = await signIn(app, userSessionStore);
		const begun = await enrollFromAccount(agent, "totp");
		const transaction = begun.body.transaction as string;

		for (const res of [
			await completeEnrollment(other.agent, transaction, totpProofOf(begun.body.secret)),
			await readTransaction(other.agent, transaction),
		]) {
			expect(res.status).toBe(400);
			expect(res.body).toEqual(UNKNOWN);
		}
	});

	it("is completed only in the session whose sid it recorded", async () => {
		const { app, transactionStore, userSessionStore, factorStore } = await composed();
		const { agent } = await signIn(app, userSessionStore);
		const begun = await enrollFromAccount(agent, "totp");
		const transaction = begun.body.transaction as string;
		const read = transactionStore.get.bind(transactionStore);
		vi.spyOn(transactionStore, "get").mockImplementation(async (id) => {
			const tx = await read(id);
			return tx === null ? null : { ...tx, sid: "another-sid" };
		});

		const res = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));

		expect(res.status).toBe(400);
		expect(res.body).toEqual(UNKNOWN);
		expect(await factorStore.list(ALICE.id)).toEqual([]);
	});

	it("binds nothing beside a record that appeared once the first binding began: a first binding stands only alone, and the session, which stands, is answered 409", async () => {
		const { app, factorStore, userSessionStore, audit, users } = await composed();
		const { agent } = await signIn(app, userSessionStore);
		const begun = await enrollFromAccount(agent, "totp");
		const intruder = (await seedTotp(createMemoryMfaFactorStore())).record;
		const create = factorStore.create.bind(factorStore);
		vi.spyOn(factorStore, "create").mockImplementation(async (record) => {
			await create(record);
			if (record.kind === "totp" && record.id !== intruder.id) await create(intruder);
		});

		const res = await completeEnrollment(
			agent,
			begun.body.transaction as string,
			totpProofOf(begun.body.secret),
		);

		expect(res.status).toBe(409);
		expect(res.body).toEqual(ENROLLMENT_CONFLICT);
		expect((await factorStore.list(ALICE.id)).map((record) => record.kind)).toEqual(["totp"]);
		expect(audit.of("mfa.first_binding_conflict")).toEqual([
			expect.objectContaining({ subject: ALICE.id, details: { kind: "totp", removed: true } }),
		]);
		expect(audit.of("mfa.factor.enrolled")).toEqual([]);
		expect(users.marks).toEqual([]);
	});

	it("never binds a first binding's transaction as another factor: a counting record found at its completion, past admission, refuses it 409 with nothing written", async () => {
		const { app, factorStore, userSessionStore } = await composed();
		const { agent } = await signIn(app, userSessionStore);
		const begun = await enrollFromAccount(agent, "totp");
		const seeded = await seedTotp(createMemoryMfaFactorStore());
		const list = factorStore.list.bind(factorStore);
		const create = vi.spyOn(factorStore, "create");
		// Admission lists first and finds none; every later read finds a counting factor.
		let reads = 0;
		vi.spyOn(factorStore, "list").mockImplementation(async (subject) =>
			reads++ === 0 ? list(subject) : [...(await list(subject)), seeded.record],
		);

		const res = await completeEnrollment(
			agent,
			begun.body.transaction as string,
			totpProofOf(begun.body.secret),
		);

		expect(res.status).toBe(409);
		expect(res.body).toEqual(ENROLLMENT_CONFLICT);
		expect(create).not.toHaveBeenCalled();
	});

	it("refuses a first factor 409 to a subject whose only records do not count, opening nothing", async () => {
		const { app, factorStore, transactionStore, userSessionStore } = await composed();
		const { agent } = await signIn(app, userSessionStore);
		await seedFactor(factorStore, "recovery_code", { codes: [] });
		const create = vi.spyOn(transactionStore, "create");

		const res = await enrollFromAccount(agent, "totp");

		expect(res.status).toBe(409);
		expect(res.body).toEqual(ENROLLMENT_CONFLICT);
		expect(create).not.toHaveBeenCalled();
	});

	it("answers 400 when the body and the MFA-Transaction header name different transactions, opening none", async () => {
		const { app, transactionStore, userSessionStore } = await composed();
		const { agent } = await signIn(app, userSessionStore);
		const begun = await enrollFromAccount(agent, "totp");
		const create = vi.spyOn(transactionStore, "create");

		const res = await mfaPost(
			agent,
			"/enrollment",
			{ kind: "totp", transaction_id: begun.body.transaction },
			{ "MFA-Transaction": "B".repeat(43) },
		);

		expect(res.status).toBe(400);
		expect(res.body).toEqual(UNKNOWN);
		expect(create).not.toHaveBeenCalled();
	});

	it("binds by password where the session's proof reads older than its window — a store answering the epoch — never by email_proof", async () => {
		const { app, factorStore, transactionStore, userSessionStore } = await composed({
			requireEmailProof: "never",
			sender: createRecordingMailSender(),
		});
		vi.spyOn(transactionStore, "sessionEmailProofAt").mockResolvedValue(0);
		const { agent } = await signIn(app, userSessionStore);
		const begun = await enrollFromAccount(agent, "totp");
		const done = await completeEnrollment(
			agent,
			begun.body.transaction as string,
			totpProofOf(begun.body.secret),
		);
		expect(done.status, JSON.stringify(done.body)).toBe(200);
		expect((await recordsOf(factorStore)).totp?.binding).toBe("password");
	});

	it("keeps no address in the pending enrollment, the factor's data, the audit events or the logs — the URI decoded — when the username is the address; the owner's own answer names the account by it", async () => {
		const address = "alice@example.com";
		const entries = directoryEntries();
		entries.delete(ALICE.username);
		entries.set(address, { password: ALICE.password, id: ALICE.id, email: address });
		const factorStore = createMemoryMfaFactorStore();
		const transactionStore = createMemoryMfaTransactionStore();
		const audit = recordingAuditSink();
		const booted = await boot({
			config: configFor("optional"),
			factorStore,
			transactionStore,
			auditSink: audit,
			userRepository: new WitnessingUserRepository(entries),
		});
		const store = booted.userSessionStore as UserSessionStore;
		const { agent } = await signIn(booted.app, store, {
			username: address,
			password: ALICE.password,
		});

		const begun = await enrollFromAccount(agent, "totp");
		expect(begun.status, JSON.stringify(begun.body)).toBe(200);
		expect(decodeURIComponent(begun.body.otpauth_uri as string)).toContain(`:${address}?`);
		const transaction = begun.body.transaction as string;
		const pending = (await transactionStore.get(transaction))?.pendingEnrollment;
		const kept = suiteSealing().openState(
			{ transactionId: transaction, kind: "totp", use: "enrollment" },
			pending?.state as string,
		);
		expect(kept.state).toBe("ok");
		const done = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));
		expect(done.status, JSON.stringify(done.body)).toBe(200);
		const factor = await storedData(factorStore, {
			subject: ALICE.id,
			id: done.body.factor.id as string,
			kind: "totp",
		});

		for (const [where, value] of [
			["the pending enrollment", kept],
			["the factor's data and record", factor],
			["the audit events", audit.events],
			["the logs", loggedText(booted.logger)],
		] as const) {
			expect(percentDecoded(JSON.stringify(value)).toLowerCase(), where).not.toContain(address);
		}
	});
});

describe("another factor from the account page, for a subject holding a counting factor", () => {
	it("is stepped up without a second factor verified in the session: 403 step_up_required, nothing opened", async () => {
		const { app, factorStore, transactionStore, userSessionStore } = await composed();
		const { agent } = await signIn(app, userSessionStore);
		await seedTotp(factorStore);
		const create = vi.spyOn(transactionStore, "create");

		const res = await enrollFromAccount(agent, "totp");

		expect(res.status).toBe(403);
		expect(res.body).toEqual({
			...STEP_UP_REQUIRED,
			error_description: "This action requires a step-up first",
		});
		expect(create).not.toHaveBeenCalled();
	});

	it("binds by mfa with a second factor verified in the session: no recovery codes, no witness mark, the session as it was", async () => {
		const { app, factorStore, transactionStore, userSessionStore, audit, users } = await composed();
		const seeded = await seedTotp(factorStore);
		const { agent, sid } = await signInWithTotp(app, userSessionStore, seeded);
		const before = await userSessionStore.get(sid);
		const marked = users.marks.length;

		const begun = await enrollFromAccount(agent, "totp");
		expect(begun.status, JSON.stringify(begun.body)).toBe(200);
		const transaction = begun.body.transaction as string;
		expect(await transactionStore.get(transaction)).toMatchObject({
			purpose: "enroll",
			enrollment: "allowed",
			sid,
		});
		// It verifies no factor of the subject's: it lists none.
		expect((await readTransaction(agent, transaction)).body).toMatchObject({
			purpose: "enroll",
			factors: [],
			enrollment: "allowed",
		});
		const done = await completeEnrollment(
			agent,
			transaction,
			totpProofOf(begun.body.secret),
			"phone",
		);

		expect(done.status, JSON.stringify(done.body)).toBe(200);
		expect(done.body).toEqual({
			factor: { id: expect.stringMatching(/^[A-Za-z0-9_-]{22}$/), kind: "totp", label: "phone" },
		});
		const totps = (await factorStore.list(ALICE.id)).filter((record) => record.kind === "totp");
		expect(totps.map((record) => record.binding).sort()).toEqual(["mfa", "password"]);
		expect((await factorStore.list(ALICE.id)).some((r) => r.kind === "recovery_code")).toBe(false);
		expect(users.marks).toHaveLength(marked);
		expect(await userSessionStore.get(sid)).toEqual(before);
		expect(audit.of("mfa.factor.enrolled")).toEqual([
			expect.objectContaining({
				details: { kind: "totp", purpose: "enroll", binding: "mfa", by: "user" },
			}),
		]);
		expect(audit.of("mfa.recovery_codes.generated")).toEqual([]);
	});

	it("holds concurrent completions to mfa.maxFactorsPerSubject: at most the limit stands, the rest are answered 409 and leave nothing", async () => {
		const { app, factorStore, userSessionStore } = await composed({ maxFactorsPerSubject: 3 });
		const seeded = await seedTotp(factorStore);
		const { agent } = await signInWithTotp(app, userSessionStore, seeded);
		const begun = [];
		for (let tab = 0; tab < 5; tab++) {
			const res = await enrollFromAccount(agent, "totp");
			expect(res.status, JSON.stringify(res.body)).toBe(200);
			begun.push(res.body as { transaction: string; secret: string });
		}
		// Every read of the records answers late, as a slow store does: each completion reads before the others wrote.
		const list = factorStore.list.bind(factorStore);
		vi.spyOn(factorStore, "list").mockImplementation(async (subject) => {
			const records = await list(subject);
			await new Promise((resolve) => setTimeout(resolve, 25));
			return records;
		});

		const answers = await Promise.all(
			begun.map(({ transaction, secret }) =>
				completeEnrollment(agent, transaction, totpProofOf(secret)),
			),
		);

		const statuses = answers.map((res) => res.status);
		for (const res of answers) {
			expect([200, 409], JSON.stringify(res.body)).toContain(res.status);
			if (res.status === 409) expect(res.body).toEqual(FACTOR_LIMIT);
		}
		const records = await list(ALICE.id);
		expect(records.length).toBeLessThanOrEqual(3);
		const bound = answers.filter((res) => res.status === 200).map((res) => res.body.factor.id);
		expect(records.map((record) => record.id).sort()).toEqual([seeded.record.id, ...bound].sort());
		expect(statuses.filter((status) => status === 409).length).toBeGreaterThanOrEqual(3);
	});

	it("answers 409 mfa_factor_limit once the subject holds mfa.maxFactorsPerSubject records, at the start and at the completion", async () => {
		const { app, factorStore, transactionStore, userSessionStore } = await composed({
			maxFactorsPerSubject: 2,
		});
		const seeded = await seedTotp(factorStore);
		const { agent } = await signInWithTotp(app, userSessionStore, seeded);

		const begun = await enrollFromAccount(agent, "totp");
		expect(begun.status, JSON.stringify(begun.body)).toBe(200);
		await seedFactor(factorStore, "recovery_code", { codes: [] });
		const completed = await completeEnrollment(
			agent,
			begun.body.transaction as string,
			totpProofOf(begun.body.secret),
		);
		expect(completed.status).toBe(409);
		expect(completed.body).toEqual(FACTOR_LIMIT);
		expect(await transactionStore.get(begun.body.transaction as string)).toMatchObject({
			attempts: 0,
		});

		const create = vi.spyOn(transactionStore, "create");
		const refused = await enrollFromAccount(agent, "totp");
		expect(refused.status).toBe(409);
		expect(refused.body).toEqual(FACTOR_LIMIT);
		expect(create).not.toHaveBeenCalled();
		expect(await factorStore.list(ALICE.id)).toHaveLength(2);
	});
});

describe("the account page's calls", () => {
	it("each sit behind the CSRF guard", async () => {
		const { app, userSessionStore } = await composed();
		const { agent } = await signIn(app, userSessionStore);
		for (const path of ["/enrollment", "/step-up"]) {
			const res = await agent.post(`/session/mfa${path}`).send({ kind: "totp" });
			expect(res.status, path).toBe(403);
			expect(res.body.error, path).toBe("access_denied");
		}
		const { header, token } = await csrfOf(agent);
		expect(
			(await agent.post("/session/mfa/enrollment").set(header, token).send({ kind: "totp" }))
				.status,
		).toBe(200);
	});
});
