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
 * A binding after a non-counting proof (the MFA ADR's F3, D24, D25), through
 * the composed application: under `required`, a recovery code verified for a
 * subject with no counting factor it can use consumes the login's
 * transaction, spends the code, and opens a new login transaction named in
 * the `403 mfa_enrollment_required` — `allowed`, bound by `mfa`, beside a
 * record that may count; otherwise `required`, a first binding through the
 * witness check and the one gate, whose recovery codes replace the set.
 */

import {
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	type MfaFactor,
	type MfaFactorStore,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import {
	createRecordingMailSender,
	createTestMfaFactor,
	type RecordingMailSender,
} from "@o3co/auth-provider-core/testing";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createRecoveryCodeFactor, generateRecoveryCodes } from "#/recovery/factor.mjs";
import { mfaRecoveryCodeFactorModule } from "#/recovery/module.mjs";
import {
	ALICE,
	boot,
	configFor,
	directoryEntries,
	disposeAll,
	events,
	WitnessingUserRepository,
} from "./moduleHarness.mjs";
import {
	beginEnrollment,
	beginLogin,
	completeEnrollment,
	contributing,
	freezeClock,
	giveEmailProof,
	loggedText,
	readTransaction,
	recordingAuditSink,
	seedFactor,
	seedTotp,
	storedData,
	suiteSealing,
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
const MFA_UNAVAILABLE = {
	error: "temporarily_unavailable",
	error_description: "MFA temporarily unavailable",
};
const LOGIN_REQUIRED = { error: "login_required", error_description: "Log in again" };
const UNKNOWN_FACTOR = { error: "invalid_request", error_description: "Unknown second factor" };
/** The refusal a code that would open a binding nobody can complete is answered: the code kept. */
const ENROLLMENT_REQUIRED = {
	error: "mfa_enrollment_required",
	error_description: "A second factor that counts must be enrolled",
};

/** An address `normaliseMailAddress` does not read: a display name around it. */
const UNREADABLE = "Alice <alice@example.com>";

interface Setup {
	readonly requireEmailProof?: "when-mail" | "always" | "never";
	readonly sender?: boolean;
	readonly address?: "address" | "unreadable";
	/** What the directory's `mfaEnrolled` says of alice. */
	readonly enrolled?: true | "malformed";
	/** A TOTP record beside the codes that does not open for alice: one that may count. */
	readonly unreadableTotp?: boolean;
	/** A TOTP record beside the codes that alice can use. */
	readonly totp?: boolean;
	readonly count?: number;
	readonly maxFactorsPerSubject?: number;
	/** In place of TOTP, the only counting factor installed beside the recovery codes. */
	readonly countingFactor?: MfaFactor;
}

/** Boots `required` with alice holding a set of recovery codes, and what `setup` adds beside it. */
async function composed(setup: Setup = {}) {
	const factorStore: MfaFactorStore = createMemoryMfaFactorStore();
	const transactionStore = createMemoryMfaTransactionStore();
	const entries = directoryEntries();
	const alice = entries.get(ALICE.username);
	if (alice !== undefined && setup.address === "unreadable") alice.email = UNREADABLE;
	if (alice !== undefined && setup.enrolled !== undefined) {
		alice.mfaEnrolled = setup.enrolled === true ? true : "yes";
	}
	const users = new WitnessingUserRepository(entries);
	const totp = setup.totp
		? await seedTotp(factorStore)
		: setup.unreadableTotp
			? await seedTotp(factorStore, undefined, { sealedFor: "u-bob" })
			: undefined;
	const generated = generateRecoveryCodes(
		createRecoveryCodeFactor({ count: setup.count ?? 3 }),
		suiteSealing().digestsFor("recovery_code"),
	);
	if (generated === undefined) throw new Error("no set");
	const set = {
		record: await seedFactor(factorStore, "recovery_code", generated.data),
		codes: generated.codes,
	};
	const audit = recordingAuditSink();
	const sender: RecordingMailSender | undefined = setup.sender
		? createRecordingMailSender()
		: undefined;
	const booted = await boot({
		config: configFor("required", {
			enrollment: { requireEmailProof: setup.requireEmailProof ?? "when-mail" },
			...(setup.maxFactorsPerSubject === undefined
				? {}
				: { maxFactorsPerSubject: setup.maxFactorsPerSubject }),
		}),
		factorStore,
		transactionStore,
		auditSink: audit,
		userRepository: users,
		...(sender === undefined ? {} : { mailSender: sender }),
		...(setup.countingFactor === undefined
			? {}
			: {
					withoutTotpModule: true,
					extraModules: [mfaRecoveryCodeFactorModule, contributing(setup.countingFactor)],
				}),
	});
	return {
		...booted,
		factorStore,
		transactionStore,
		userSessionStore: booted.userSessionStore as UserSessionStore,
		audit,
		users,
		sender,
		totp,
		set,
	};
}

/** Alice's records, by kind, as the factor store holds them. */
const kindsOf = async (store: MfaFactorStore) =>
	(await store.list(ALICE.id)).map((record) => record.kind).sort();

describe("a recovery code beside a record that may count (allowed)", () => {
	it("consumes the login's transaction, spends the code, and answers a new transaction for a binding beside it: no proof asked", async () => {
		const { app, transactionStore, set, audit } = await composed({ unreadableTotp: true });
		const { agent, transaction } = await beginLogin(app);

		const res = await verify(agent, transaction, set.record.id, set.codes[0]);

		expect(res.status, JSON.stringify(res.body)).toBe(403);
		expect(res.headers["cache-control"]).toBe("no-store");
		expect(res.body).toEqual({
			error: "mfa_enrollment_required",
			transaction: expect.stringMatching(TRANSACTION_ID),
			expires_in: 600,
			hints: { enrollable: ["totp"], email_proof: false },
		});
		const reopened = res.body.transaction as string;
		expect(reopened).not.toBe(transaction);
		expect(await transactionStore.get(transaction)).toBeNull();
		expect(await transactionStore.get(reopened)).toMatchObject({
			purpose: "login",
			subject: ALICE.id,
			enrollment: "allowed",
			emailProof: "not_required",
			attempts: 0,
		});
		expect((await readTransaction(agent, reopened)).body).toMatchObject({
			purpose: "login",
			enrollment: "allowed",
			email_proof: false,
		});
		expect(audit.of("mfa.recovery_code.used").map((event) => event.details)).toEqual([
			{ kind: "recovery_code", purpose: "login", remaining: 2 },
		]);
	});

	it("binds TOTP by mfa on the new transaction, issues no codes, and completes the login", async () => {
		const { app, factorStore, set, audit, userSessionStore } = await composed({
			unreadableTotp: true,
		});
		const create = vi.spyOn(userSessionStore, "create");
		const { agent, transaction } = await beginLogin(app);
		const reopened = (await verify(agent, transaction, set.record.id, set.codes[0])).body
			.transaction as string;

		const begun = await beginEnrollment(agent, reopened, "totp");
		expect(begun.status, JSON.stringify(begun.body)).toBe(200);
		const done = await completeEnrollment(agent, reopened, totpProofOf(begun.body.secret));

		expect(done.status, JSON.stringify(done.body)).toBe(200);
		expect(done.body).toEqual({
			message: "Logged in successfully",
			factor: { id: expect.any(String), kind: "totp" },
		});
		expect(create).toHaveBeenCalledTimes(1);
		const bound = (await factorStore.list(ALICE.id)).filter(
			(record) => record.id === done.body.factor.id,
		);
		expect(bound).toEqual([expect.objectContaining({ kind: "totp", binding: "mfa" })]);
		expect(await kindsOf(factorStore)).toEqual(["recovery_code", "totp", "totp"]);
		expect((await storedData(factorStore, set.record)).data.codes).toHaveLength(2);
		expect(audit.of("mfa.factor.enrolled").map((event) => event.details)).toEqual([
			{ kind: "totp", purpose: "login", binding: "mfa", by: "user" },
		]);
		expect(audit.of("mfa.recovery_codes.generated")).toEqual([]);
	});

	it("refuses, with the code and the transaction kept, a binding beside it when alice is at mfa.maxFactorsPerSubject", async () => {
		const { app, factorStore, transactionStore, set } = await composed({
			unreadableTotp: true,
			maxFactorsPerSubject: 2,
		});
		const { agent, transaction } = await beginLogin(app);

		const res = await verify(agent, transaction, set.record.id, set.codes[0]);

		expect(res.status).toBe(403);
		expect(res.body).toEqual(ENROLLMENT_REQUIRED);
		expect((await storedData(factorStore, set.record)).data.codes).toHaveLength(3);
		expect(await transactionStore.get(transaction)).toMatchObject({ attempts: 0 });
	});

	it("refuses a proof on the reopened transaction: it binds, and spends no other code", async () => {
		const { app, factorStore, transactionStore, set } = await composed({ unreadableTotp: true });
		const { agent, transaction } = await beginLogin(app);
		const reopened = (await verify(agent, transaction, set.record.id, set.codes[0])).body
			.transaction as string;

		const res = await verify(agent, reopened, set.record.id, set.codes[1]);

		expect(res.status).toBe(400);
		expect(res.body).toEqual(UNKNOWN_FACTOR);
		expect((await storedData(factorStore, set.record)).data.codes).toHaveLength(2);
		expect(await transactionStore.get(reopened)).toMatchObject({ attempts: 0 });
	});

	it("records mfa.verified with reopened: true for a code that reopens the login", async () => {
		const { app, set, audit } = await composed({ unreadableTotp: true });
		const { agent, transaction } = await beginLogin(app);

		await verify(agent, transaction, set.record.id, set.codes[0]);

		expect(audit.of("mfa.verified").map((event) => event.details)).toEqual([
			{ kind: "recovery_code", purpose: "login", reopened: true },
		]);
	});

	it("owes no account-email proof for it, D25's flag set or not", async () => {
		const { app, transactionStore, set } = await composed({
			unreadableTotp: true,
			sender: true,
			requireEmailProof: "always",
		});
		await transactionStore.requireEmailProofAtNextBinding(ALICE.id);
		const { agent, transaction } = await beginLogin(app);

		const res = await verify(agent, transaction, set.record.id, set.codes[0]);
		expect(res.body.hints).toEqual({ enrollable: ["totp"], email_proof: false });
		const begun = await beginEnrollment(agent, res.body.transaction as string, "totp");

		expect(begun.status, JSON.stringify(begun.body)).toBe(200);
		expect(await transactionStore.emailProofRequiredAtNextBinding(ALICE.id)).toBe(true);
	});
});

describe("recovery codes alone (required: a first binding)", () => {
	it("asks the account-email proof where the gate does, binds TOTP by email_proof, and replaces the set: regenerated", async () => {
		const { app, factorStore, set, audit, sender, users } = await composed({ sender: true });
		const { agent, transaction } = await beginLogin(app);

		const res = await verify(agent, transaction, set.record.id, set.codes[0]);

		expect(res.status, JSON.stringify(res.body)).toBe(403);
		expect(res.body).toEqual({
			error: "mfa_enrollment_required",
			transaction: expect.stringMatching(TRANSACTION_ID),
			expires_in: 600,
			hints: { enrollable: ["totp"], email_proof: true },
		});
		const reopened = res.body.transaction as string;
		expect((await beginEnrollment(agent, reopened, "totp")).body.error).toBe(
			"mfa_email_proof_required",
		);
		if (sender === undefined) throw new Error("no sender");
		expect((await giveEmailProof(agent, reopened, sender)).status).toBe(200);
		const begun = await beginEnrollment(agent, reopened, "totp");
		const done = await completeEnrollment(agent, reopened, totpProofOf(begun.body.secret));

		expect(done.status, JSON.stringify(done.body)).toBe(200);
		expect(done.body.recovery_codes).toHaveLength(10);
		const records = await factorStore.list(ALICE.id);
		expect(records.map((record) => [record.kind, record.binding]).sort()).toEqual([
			["recovery_code", "email_proof"],
			["totp", "email_proof"],
		]);
		expect(records.some((record) => record.id === set.record.id)).toBe(false);
		expect(audit.of("mfa.recovery_codes.generated").map((event) => event.details)).toEqual([
			{
				kind: "recovery_code",
				purpose: "login",
				binding: "email_proof",
				by: "user",
				regenerated: true,
			},
		]);
		expect(users.marks).toEqual([{ subject: ALICE.id, enrolled: true }]);
	});

	it("binds by password where no proof is asked, and keeps the set that stood beside the new one: kept, said in the audit", async () => {
		const { app, factorStore, set, audit, logger } = await composed({ requireEmailProof: "never" });
		const { agent, transaction } = await beginLogin(app);
		const res = await verify(agent, transaction, set.record.id, set.codes[0]);
		expect(res.body.hints).toEqual({ enrollable: ["totp"], email_proof: false });
		const reopened = res.body.transaction as string;

		const begun = await beginEnrollment(agent, reopened, "totp");
		const done = await completeEnrollment(agent, reopened, totpProofOf(begun.body.secret));

		expect(done.status, JSON.stringify(done.body)).toBe(200);
		expect(done.body.recovery_codes).toHaveLength(10);
		const records = await factorStore.list(ALICE.id);
		expect(records.map((record) => [record.kind, record.binding]).sort()).toEqual([
			["recovery_code", "password"],
			["recovery_code", "password"],
			["totp", "password"],
		]);
		expect(records.some((record) => record.id === set.record.id)).toBe(true);
		expect(audit.of("mfa.recovery_codes.generated").map((event) => event.details)).toEqual([
			{
				kind: "recovery_code",
				purpose: "login",
				binding: "password",
				by: "user",
				regenerated: true,
				unreplaced: true,
				kept: "password_binding",
			},
		]);
		expect(events(logger, "error")).toEqual([]);
	});

	it("leaves the owner's remaining codes usable after a password-bound reopened binding: an old code completes an ordinary MFA login", async () => {
		const { app, set } = await composed({ requireEmailProof: "never" });
		const first = await beginLogin(app);
		const reopened = (await verify(first.agent, first.transaction, set.record.id, set.codes[0]))
			.body.transaction as string;
		const begun = await beginEnrollment(first.agent, reopened, "totp");
		expect(
			(await completeEnrollment(first.agent, reopened, totpProofOf(begun.body.secret))).status,
		).toBe(200);

		const next = await beginLogin(app);
		const res = await verify(next.agent, next.transaction, set.record.id, set.codes[1]);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(res.body).toEqual({ message: "Logged in successfully", recovery_codes_remaining: 1 });
	});

	it("says when the set it replaces could not be removed: unreplaced in the audit, one mfa_recovery_codes_unreplaced line, the old set standing", async () => {
		const { app, factorStore, set, audit, sender, logger } = await composed({ sender: true });
		const { agent, transaction } = await beginLogin(app);
		const reopened = (await verify(agent, transaction, set.record.id, set.codes[0])).body
			.transaction as string;
		if (sender === undefined) throw new Error("no sender");
		await giveEmailProof(agent, reopened, sender);
		const begun = await beginEnrollment(agent, reopened, "totp");
		vi.spyOn(factorStore, "remove").mockRejectedValue(new Error("remove failed"));

		const done = await completeEnrollment(agent, reopened, totpProofOf(begun.body.secret));

		expect(done.status, JSON.stringify(done.body)).toBe(200);
		expect(audit.of("mfa.recovery_codes.generated")[0]?.details).toEqual({
			kind: "recovery_code",
			purpose: "login",
			binding: "email_proof",
			by: "user",
			regenerated: true,
			unreplaced: true,
		});
		expect(events(logger, "error")).toEqual(["mfa_recovery_codes_unreplaced"]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({ sub: ALICE.id });
		expect((await factorStore.list(ALICE.id)).some((record) => record.id === set.record.id)).toBe(
			true,
		);
	});

	it.each([
		["when-mail with a sender and an address", { sender: true }, true],
		["when-mail without a sender", {}, false],
		["never", { requireEmailProof: "never" as const }, false],
		["always", { requireEmailProof: "always" as const, sender: true }, true],
	])(
		"puts the gate's answer in the hints and on the transaction: %s",
		async (_label, setup, asked) => {
			const { app, transactionStore, set } = await composed(setup);
			const { agent, transaction } = await beginLogin(app);

			const res = await verify(agent, transaction, set.record.id, set.codes[0]);

			expect(res.body.hints).toEqual({ enrollable: ["totp"], email_proof: asked });
			expect(await transactionStore.get(res.body.transaction as string)).toMatchObject({
				enrollment: "required",
				emailProof: asked ? "required" : "not_required",
			});
		},
	);

	it("asks the proof under never once D25's flag is set", async () => {
		const { app, transactionStore, set } = await composed({
			requireEmailProof: "never",
			sender: true,
		});
		await transactionStore.requireEmailProofAtNextBinding(ALICE.id);
		const { agent, transaction } = await beginLogin(app);

		const res = await verify(agent, transaction, set.record.id, set.codes[0]);

		expect(res.body.hints).toEqual({ enrollable: ["totp"], email_proof: true });
	});

	it("refuses, with the code and the transaction kept, a first binding whose proof nobody can give, and says why without the address", async () => {
		const { app, factorStore, transactionStore, set, logger } = await composed({
			address: "unreadable",
			requireEmailProof: "always",
			sender: true,
		});
		const { agent, transaction } = await beginLogin(app);

		const res = await verify(agent, transaction, set.record.id, set.codes[0]);

		expect(res.status).toBe(403);
		expect(res.body).toEqual(ENROLLMENT_REQUIRED);
		expect((await storedData(factorStore, set.record)).data.codes).toHaveLength(3);
		expect(await transactionStore.get(transaction)).toMatchObject({ attempts: 0 });
		expect(events(logger, "warn")).toContain("mfa_email_proof_unprovable");
		expect(
			logger.warn.mock.calls.find((call) => call[1] === "mfa_email_proof_unprovable")?.[0],
		).toEqual({ sub: ALICE.id, reason: "unreadable_address" });
		expect(loggedText(logger)).not.toContain("alice@example.com");
	});

	it.each([
		["says alice enrolled", true, "enrolled"],
		["says nothing readable", "malformed", "malformed"],
	] as const)(
		"refuses a witness that %s: 503, mfa.enrollment_state_inconsistent and its log line, with the code and the transaction unspent",
		async (_label, enrolled, witness) => {
			const { app, factorStore, transactionStore, set, audit, totp, logger } = await composed({
				totp: true,
				enrolled,
			});
			const { agent, transaction } = await beginLogin(app);
			// The TOTP record is gone by the time the code is given.
			if (totp === undefined) throw new Error("no TOTP");
			await factorStore.remove(ALICE.id, totp.record.id);

			const res = await verify(agent, transaction, set.record.id, set.codes[0]);

			expect(res.status).toBe(503);
			expect(res.body).toEqual(MFA_UNAVAILABLE);
			expect(audit.of("mfa.enrollment_state_inconsistent")).toEqual([
				expect.objectContaining({
					subject: ALICE.id,
					details: { purpose: "login", witness },
				}),
			]);
			expect(events(logger, "error")).toEqual(["mfa_enrollment_state_inconsistent"]);
			expect(logger.error.mock.calls[0]?.[0]).toEqual({ route: "verify", sub: ALICE.id, witness });
			expect((await storedData(factorStore, set.record)).data.codes).toHaveLength(3);
			expect(await transactionStore.get(transaction)).toMatchObject({ attempts: 0 });
			expect(audit.of("mfa.recovery_code.used")).toEqual([]);
		},
	);

	it("refuses, with the code and the transaction kept, a first binding by password that would pass mfa.maxFactorsPerSubject with the set it keeps", async () => {
		const { app, factorStore, transactionStore, set } = await composed({
			requireEmailProof: "never",
			maxFactorsPerSubject: 2,
		});
		const { agent, transaction } = await beginLogin(app);

		const res = await verify(agent, transaction, set.record.id, set.codes[0]);

		expect(res.status).toBe(403);
		expect(res.body).toEqual(ENROLLMENT_REQUIRED);
		expect((await storedData(factorStore, set.record)).data.codes).toHaveLength(3);
		expect(await transactionStore.get(transaction)).toMatchObject({ attempts: 0 });
	});

	it("does not count the set an email_proof binding replaces: it binds at mfa.maxFactorsPerSubject", async () => {
		const { app, factorStore, set, sender } = await composed({
			sender: true,
			maxFactorsPerSubject: 2,
		});
		const { agent, transaction } = await beginLogin(app);
		const res = await verify(agent, transaction, set.record.id, set.codes[0]);
		expect(res.status, JSON.stringify(res.body)).toBe(403);
		const reopened = res.body.transaction as string;
		if (sender === undefined) throw new Error("no sender");
		await giveEmailProof(agent, reopened, sender);
		const begun = await beginEnrollment(agent, reopened, "totp");

		const done = await completeEnrollment(agent, reopened, totpProofOf(begun.body.secret));

		expect(done.status, JSON.stringify(done.body)).toBe(200);
		expect((await factorStore.list(ALICE.id)).map((record) => record.kind).sort()).toEqual([
			"recovery_code",
			"totp",
		]);
	});

	it("answers 503 with nothing spent when D25's flag cannot be read: no attempt, so retries past mfa.maxAttemptsPerTransaction keep the transaction", async () => {
		const { app, factorStore, transactionStore, set } = await composed();
		vi.spyOn(transactionStore, "emailProofRequiredAtNextBinding").mockRejectedValue(
			new Error("down"),
		);
		const { agent, transaction } = await beginLogin(app);

		for (let n = 0; n < 7; n++) {
			const res = await verify(agent, transaction, set.record.id, set.codes[0]);
			expect(res.status).toBe(503);
		}

		expect((await storedData(factorStore, set.record)).data.codes).toHaveLength(3);
		expect(await transactionStore.get(transaction)).toMatchObject({ attempts: 0 });
	});

	it("answers 503 with nothing spent when no counting factor offers itself to alice, and says so", async () => {
		const refusing = { ...createTestMfaFactor({ kind: "test" }), enrollable: () => false };
		const { app, factorStore, transactionStore, set, logger } = await composed({
			countingFactor: refusing,
		});
		const { agent, transaction } = await beginLogin(app);

		const res = await verify(agent, transaction, set.record.id, set.codes[0]);

		expect(res.status).toBe(503);
		expect(res.body).toEqual(MFA_UNAVAILABLE);
		expect(events(logger, "warn")).toContain("mfa_enrollment_nothing_enrollable");
		expect(
			logger.warn.mock.calls.find((call) => call[1] === "mfa_enrollment_nothing_enrollable")?.[0],
		).toEqual({ kinds: ["test"] });
		expect((await storedData(factorStore, set.record)).data.codes).toHaveLength(3);
		expect(await transactionStore.get(transaction)).toMatchObject({ attempts: 0 });
	});

	it("answers 503 with nothing spent when a factor's enrollable throws, naming the kind", async () => {
		const throwing = {
			...createTestMfaFactor({ kind: "test" }),
			enrollable: () => {
				throw new Error("broken for alice@example.com");
			},
		};
		const { app, factorStore, transactionStore, set, logger } = await composed({
			countingFactor: throwing,
		});
		const { agent, transaction } = await beginLogin(app);

		const res = await verify(agent, transaction, set.record.id, set.codes[0]);

		expect(res.status).toBe(503);
		expect(res.body).toEqual(MFA_UNAVAILABLE);
		expect(events(logger, "error")).toEqual(["mfa_factor_enrollment_unavailable"]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({ route: "verify", kind: "test" });
		expect(loggedText(logger)).not.toContain("alice@example.com");
		expect((await storedData(factorStore, set.record)).data.codes).toHaveLength(3);
		expect(await transactionStore.get(transaction)).toMatchObject({ attempts: 0 });
	});

	it("loses a binding to a counting factor bound at once: its own removed, 401 login_required, mfa.first_binding_conflict", async () => {
		const { app, factorStore, set, audit } = await composed({ requireEmailProof: "never" });
		const { agent, transaction } = await beginLogin(app);
		const reopened = (await verify(agent, transaction, set.record.id, set.codes[0])).body
			.transaction as string;
		const begun = await beginEnrollment(agent, reopened, "totp");
		// Another transaction binds a counting factor while this one completes.
		const other = await seedTotp(createMemoryMfaFactorStore());
		const list = factorStore.list.bind(factorStore);
		let reads = 0;
		vi.spyOn(factorStore, "list").mockImplementation(async (subject) =>
			reads++ === 0 ? list(subject) : [...(await list(subject)), other.record],
		);

		const done = await completeEnrollment(agent, reopened, totpProofOf(begun.body.secret));

		expect(done.status).toBe(401);
		expect(done.body).toEqual(LOGIN_REQUIRED);
		expect(await kindsOf({ list } as MfaFactorStore)).toEqual(["recovery_code"]);
		expect(audit.of("mfa.first_binding_conflict")).toHaveLength(1);
	});
});

describe("the code is spent before the reopen", () => {
	it("spends the transaction, never the code, of a verification that loses the race for it", async () => {
		const { app, factorStore, set } = await composed({ unreadableTotp: true });
		const { agent, transaction } = await beginLogin(app);

		const answers = await Promise.all([
			verify(agent, transaction, set.record.id, set.codes[0]),
			verify(agent, transaction, set.record.id, set.codes[1]),
		]);

		expect(answers.map((res) => res.status).sort()).toEqual([400, 403]);
		expect((await storedData(factorStore, set.record)).data.codes).toHaveLength(2);
	});

	it("answers 503 when the new transaction cannot be opened: the code stays spent, and is said", async () => {
		const { app, factorStore, transactionStore, set, audit, logger } = await composed({
			unreadableTotp: true,
		});
		const { agent, transaction } = await beginLogin(app);
		vi.spyOn(transactionStore, "create").mockRejectedValueOnce(new Error("down"));

		const res = await verify(agent, transaction, set.record.id, set.codes[0]);

		expect(res.status).toBe(503);
		expect(res.body).toEqual(MFA_UNAVAILABLE);
		expect((await storedData(factorStore, set.record)).data.codes).toHaveLength(2);
		expect(audit.of("mfa.recovery_code.used").map((event) => event.details)).toEqual([
			{ kind: "recovery_code", purpose: "login", remaining: 2 },
		]);
		expect(audit.of("mfa.verified").map((event) => event.details)).toEqual([
			{ kind: "recovery_code", purpose: "login", reopened: true },
		]);
		expect(events(logger, "error")).toEqual(["mfa_store_unavailable"]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({
			route: "verify",
			store: "mfa_transaction",
			step: "create",
		});
	});

	it("notes one exempt success for alice", async () => {
		const { app, set, transactionStore } = await composed({ unreadableTotp: true });
		const note = vi.spyOn(transactionStore, "noteExemptSuccess");
		const { agent, transaction } = await beginLogin(app);

		await verify(agent, transaction, set.record.id, set.codes[0]);

		expect(note).toHaveBeenCalledTimes(1);
		expect(note.mock.calls[0]?.[0]).toBe(ALICE.id);
	});
});

describe("a compare-and-set round lost to another write", () => {
	it("completes the login when a counting factor alice can use stands once the round is lost", async () => {
		const { app, factorStore, set } = await composed({ unreadableTotp: true });
		const { agent, transaction } = await beginLogin(app);
		const update = factorStore.update.bind(factorStore);
		let rounds = 0;
		vi.spyOn(factorStore, "update").mockImplementation(async (...args) => {
			if (rounds++ === 0) {
				await seedTotp(factorStore);
				return null;
			}
			return update(...args);
		});

		const res = await verify(agent, transaction, set.record.id, set.codes[0]);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(res.body).toEqual({ message: "Logged in successfully", recovery_codes_remaining: 2 });
	});

	it("plans the binding again over the records read after the round: a first binding once the record that may count is gone", async () => {
		const { app, factorStore, transactionStore, set, totp } = await composed({
			unreadableTotp: true,
			requireEmailProof: "never",
		});
		const { agent, transaction } = await beginLogin(app);
		const update = factorStore.update.bind(factorStore);
		let rounds = 0;
		vi.spyOn(factorStore, "update").mockImplementation(async (...args) => {
			if (rounds++ === 0) {
				if (totp === undefined) throw new Error("no TOTP");
				await factorStore.remove(ALICE.id, totp.record.id);
				return null;
			}
			return update(...args);
		});

		const res = await verify(agent, transaction, set.record.id, set.codes[0]);

		expect(res.status, JSON.stringify(res.body)).toBe(403);
		expect(await transactionStore.get(res.body.transaction as string)).toMatchObject({
			enrollment: "required",
		});
	});
});
