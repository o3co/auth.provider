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
 * A login transaction and its subject's sessions boundary (the MFA ADR's D8
 * and F3), through the composed application: every use of a login's
 * transaction compares its continuation's `authTime` with the boundary
 * (`revokedBefore`, the revocation skew allowed), so a login begun before a
 * revocation or a password change is answered `401 login_required` and
 * spends and binds nothing — its transaction read, a challenge, a
 * verification, the account-email proof, an enrollment's start and
 * completion, and a login reopened after a recovery code alike. A boundary
 * that cannot be read is `503`; with no boundary wired, none is read.
 */

import { randomBytes } from "node:crypto";
import {
	createInMemorySubjectRevocation,
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	type MfaFactorRecord,
	type MfaFactorStore,
	revokeAllForSubject,
	type SubjectRevocation,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import {
	createRecordingMailSender,
	type RecordingMailSender,
} from "@o3co/auth-provider-core/testing";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createRecoveryCodeFactor, generateRecoveryCodes } from "#/recovery/factor.mjs";
import { ALICE, boot, configFor, disposeAll, sessionIdSet } from "./moduleHarness.mjs";
import {
	beginEnrollment,
	beginFirstBinding,
	beginLogin,
	completeEnrollment,
	freezeClock,
	mfaPost,
	readTransaction,
	type SeededTotp,
	seedFactor,
	seedTotp,
	stepUp,
	suiteSealing,
	T0,
	thawClock,
	totpCode,
	totpProofOf,
	verify,
} from "./routesHarness.mjs";

beforeEach(() => freezeClock());
afterEach(async () => {
	await disposeAll();
	thawClock();
});

const LOGIN_REQUIRED = { error: "login_required", error_description: "Log in again" };
const MFA_UNAVAILABLE = {
	error: "temporarily_unavailable",
	error_description: "MFA temporarily unavailable",
};

interface Setup {
	/** The subjects' boundary; an in-memory one by default, none wired when `null`. */
	readonly revocation?: SubjectRevocation | null;
	/** What alice holds: a TOTP factor and a recovery set, the set alone, or nothing. */
	readonly holds?: "totp" | "codes" | "nothing";
	readonly sender?: RecordingMailSender;
}

/** Boots `required` over `setup`, with no proof asked unless a sender is given. */
async function composed(setup: Setup = {}) {
	const factorStore: MfaFactorStore = createMemoryMfaFactorStore();
	const transactionStore = createMemoryMfaTransactionStore();
	const revocation =
		setup.revocation === undefined ? createInMemorySubjectRevocation() : setup.revocation;
	const holds = setup.holds ?? "totp";
	const totp: SeededTotp | undefined = holds === "totp" ? await seedTotp(factorStore) : undefined;
	let set: { readonly record: MfaFactorRecord; readonly codes: readonly string[] } | undefined;
	if (holds !== "nothing") {
		const generated = generateRecoveryCodes(
			createRecoveryCodeFactor({ count: 3 }),
			suiteSealing().digestsFor("recovery_code"),
		);
		if (generated === undefined) throw new Error("no set");
		set = {
			record: await seedFactor(factorStore, "recovery_code", generated.data),
			codes: generated.codes,
		};
	}
	const booted = await boot({
		config: configFor("required", {
			enrollment: { requireEmailProof: setup.sender === undefined ? "never" : "when-mail" },
		}),
		factorStore,
		transactionStore,
		...(revocation === null ? {} : { subjectRevocation: revocation }),
		...(setup.sender === undefined ? {} : { mailSender: setup.sender }),
	});
	return {
		...booted,
		factorStore,
		transactionStore,
		userSessionStore: booted.userSessionStore as UserSessionStore,
		revocation,
		totp,
		set,
	};
}

/** Every session and token of alice's revoked now, as a password change does. */
const revokeAlice = (revocation: SubjectRevocation | null) =>
	revokeAllForSubject({
		subject: ALICE.id,
		watermarkTtlMs: 86_400_000,
		cascadeSession: async () => ({ ok: true }),
		...(revocation === null ? {} : { subjectRevocation: revocation }),
	});

/** Alice's records, each as stored now: what a refusal must leave as it was. */
const snapshot = async (store: MfaFactorStore) => JSON.stringify(await store.list(ALICE.id));

describe("a login begun before its subject's sessions were revoked", () => {
	it("answers 401 login_required to the transaction read, a challenge and every verification, spending no attempt, no code and no factor, writing no session, and saying each at info", async () => {
		const { app, factorStore, transactionStore, userSessionStore, revocation, totp, set, logger } =
			await composed();
		if (totp === undefined || set === undefined) throw new Error("nothing seeded");
		const { agent, transaction } = await beginLogin(app);
		await revokeAlice(revocation);
		const before = await snapshot(factorStore);
		const created = vi.spyOn(userSessionStore, "create");

		const answers = [
			await readTransaction(agent, transaction),
			await mfaPost(agent, "/challenge", {
				transaction_id: transaction,
				factor_id: totp.record.id,
			}),
			await verify(agent, transaction, totp.record.id, totpCode(totp.secret)),
			await verify(agent, transaction, set.record.id, set.codes[0]),
		];

		for (const res of answers) {
			expect(res.status, JSON.stringify(res.body)).toBe(401);
			expect(res.body).toEqual(LOGIN_REQUIRED);
		}
		expect(await snapshot(factorStore)).toBe(before);
		expect(await transactionStore.get(transaction)).toMatchObject({ attempts: 0 });
		expect(created).not.toHaveBeenCalled();
		expect(logger.info.mock.calls.filter((call) => call[1] === "mfa_login_revoked")).toEqual(
			["transaction", "challenge", "verify", "verify"].map((route) => [
				{ sub: ALICE.id, route },
				"mfa_login_revoked",
			]),
		);
	});

	it("answers 401 at a first binding's start and completion, writing no factor and spending no attempt", async () => {
		const { app, factorStore, transactionStore, revocation } = await composed({ holds: "nothing" });
		const { agent, transaction } = await beginFirstBinding(app);
		const begun = await beginEnrollment(agent, transaction, "totp");
		expect(begun.status, JSON.stringify(begun.body)).toBe(200);
		await revokeAlice(revocation);

		const completed = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));
		const started = await beginEnrollment(agent, transaction, "totp");

		for (const res of [completed, started]) {
			expect(res.status, JSON.stringify(res.body)).toBe(401);
			expect(res.body).toEqual(LOGIN_REQUIRED);
		}
		expect(await factorStore.list(ALICE.id)).toEqual([]);
		expect(await transactionStore.get(transaction)).toMatchObject({ attempts: 0 });
	});

	it("answers 401 to the account-email proof the first binding owes, mailing nothing", async () => {
		const sender = createRecordingMailSender();
		const { app, revocation } = await composed({ holds: "nothing", sender });
		const { agent, transaction } = await beginFirstBinding(app);
		await revokeAlice(revocation);

		const challenged = await mfaPost(agent, "/challenge", {
			transaction_id: transaction,
			factor_id: "account-email",
		});
		const verified = await verify(agent, transaction, "account-email", "AAAA-AAAA-AAAA-AAAA");

		for (const res of [challenged, verified]) {
			expect(res.status, JSON.stringify(res.body)).toBe(401);
			expect(res.body).toEqual(LOGIN_REQUIRED);
		}
		expect(sender.sent).toEqual([]);
	});

	it("answers 401 on a login reopened for a binding after a recovery code: the same continuation, nothing bound", async () => {
		const { app, factorStore, revocation, set } = await composed({ holds: "codes" });
		if (set === undefined) throw new Error("nothing seeded");
		const { agent, transaction } = await beginLogin(app);
		const reopened = await verify(agent, transaction, set.record.id, set.codes[0]);
		expect(reopened.status, JSON.stringify(reopened.body)).toBe(403);
		const next = reopened.body.transaction as string;
		const begun = await beginEnrollment(agent, next, "totp");
		expect(begun.status, JSON.stringify(begun.body)).toBe(200);
		await revokeAlice(revocation);

		const res = await completeEnrollment(agent, next, totpProofOf(begun.body.secret));

		expect(res.status, JSON.stringify(res.body)).toBe(401);
		expect(res.body).toEqual(LOGIN_REQUIRED);
		expect((await factorStore.list(ALICE.id)).map((record) => record.kind)).toEqual([
			"recovery_code",
		]);
	});
});

describe("the boundary's edge", () => {
	it("refuses a login authenticated within the revocation skew after the boundary, and completes one authenticated after it", async () => {
		for (const [boundaryMs, status] of [
			[T0 - 1_000, 401],
			[T0 - 1_001, 200],
			[T0 - 60_000, 200],
		] as const) {
			const revocation = createInMemorySubjectRevocation();
			const { app, totp } = await composed({ revocation });
			if (totp === undefined) throw new Error("nothing seeded");
			const { agent, transaction } = await beginLogin(app);
			await revocation.revokeBefore(ALICE.id, new Date(boundaryMs), new Date(T0 + 86_400_000));

			const res = await verify(agent, transaction, totp.record.id, totpCode(totp.secret));

			expect(res.status, `${T0 - boundaryMs} ms: ${JSON.stringify(res.body)}`).toBe(status);
			await disposeAll();
		}
	});

	it("compares in whole seconds, as token verification does: a login in the second the allowance covers is refused, one in the next completes", async () => {
		const boundaryMs = T0 + 100;
		for (const [authMs, status] of [
			[T0 + 1_101, 401],
			[T0 + 1_999, 401],
			[T0 + 2_000, 200],
		] as const) {
			const revocation = createInMemorySubjectRevocation();
			const { app, totp } = await composed({ revocation });
			if (totp === undefined) throw new Error("nothing seeded");
			await revocation.revokeBefore(ALICE.id, new Date(boundaryMs), new Date(T0 + 86_400_000));
			freezeClock(authMs);
			const { agent, transaction } = await beginLogin(app);

			const res = await verify(agent, transaction, totp.record.id, totpCode(totp.secret));

			expect(res.status, `${authMs - boundaryMs} ms: ${JSON.stringify(res.body)}`).toBe(status);
			await disposeAll();
		}
	});

	it("reads the boundary of the login's subject, never another's", async () => {
		const revocation = createInMemorySubjectRevocation();
		const { app, totp } = await composed({ revocation });
		if (totp === undefined) throw new Error("nothing seeded");
		const read = vi.spyOn(revocation, "revokedBefore");
		await revocation.revokeBefore("u-bob", new Date(T0), new Date(T0 + 86_400_000));
		const { agent, transaction } = await beginLogin(app);

		const res = await verify(agent, transaction, totp.record.id, totpCode(totp.secret));

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(read).toHaveBeenCalledWith(ALICE.id);
		expect(read).not.toHaveBeenCalledWith("u-bob");
	});
});

describe("a login transaction carrying no continuation", () => {
	it("cannot show it began after a boundary in force: 401; with none in force it is read as before", async () => {
		for (const [boundaryMs, status] of [
			[T0 - 60_000, 401],
			[undefined, 200],
		] as const) {
			const revocation = createInMemorySubjectRevocation();
			const { app, transactionStore, totp } = await composed({ revocation });
			if (totp === undefined) throw new Error("nothing seeded");
			const { agent, transaction } = await beginLogin(app);
			if (boundaryMs !== undefined) {
				await revocation.revokeBefore(ALICE.id, new Date(boundaryMs), new Date(T0 + 86_400_000));
			}
			const read = transactionStore.get.bind(transactionStore);
			vi.spyOn(transactionStore, "get").mockImplementation(async (id) => {
				const tx = await read(id);
				return tx === null ? null : { ...tx, continuation: undefined };
			});

			const res = await readTransaction(agent, transaction);

			expect(res.status, JSON.stringify(res.body)).toBe(status);
			expect(await read(transaction)).toMatchObject({ attempts: 0 });
			await disposeAll();
		}
	});
});

describe("a boundary that cannot be read", () => {
	it("answers 503, logged once with the store and step, spending nothing — an outage, or an answer that is neither a date nor none", async () => {
		for (const answer of [
			() => Promise.reject(new Error("revocation store unreachable")),
			() => Promise.resolve("yesterday"),
			() => Promise.resolve(new Date(Number.NaN)),
		]) {
			const revocation = createInMemorySubjectRevocation();
			const { app, factorStore, transactionStore, totp, logger } = await composed({ revocation });
			if (totp === undefined) throw new Error("nothing seeded");
			const { agent, transaction } = await beginLogin(app);
			vi.spyOn(revocation, "revokedBefore").mockImplementation(answer as never);
			const before = await snapshot(factorStore);

			const res = await verify(agent, transaction, totp.record.id, totpCode(totp.secret));

			expect(res.status).toBe(503);
			expect(res.body).toEqual(MFA_UNAVAILABLE);
			expect(await snapshot(factorStore)).toBe(before);
			expect(await transactionStore.get(transaction)).toMatchObject({ attempts: 0 });
			const lines = logger.error.mock.calls.filter((call) => call[1] === "mfa_store_unavailable");
			expect(lines).toEqual([
				[
					expect.objectContaining({
						route: "verify",
						store: "revocation_boundary",
						step: "revokedBefore",
					}),
					"mfa_store_unavailable",
				],
			]);
			await disposeAll();
		}
	});
});

describe("no boundary wired", () => {
	it("leaves the login as it was: it completes", async () => {
		const { app, totp } = await composed({ revocation: null });
		if (totp === undefined) throw new Error("nothing seeded");
		const { agent, transaction } = await beginLogin(app);

		const res = await verify(agent, transaction, totp.record.id, totpCode(totp.secret));

		expect(res.status, JSON.stringify(res.body)).toBe(200);
	});
});

describe("a login transaction named at the step-up", () => {
	it("is no step-up's: 400, its subject's boundary read no more than for an unknown transaction", async () => {
		const revocation = createInMemorySubjectRevocation();
		const factorStore = createMemoryMfaFactorStore();
		const generated = generateRecoveryCodes(
			createRecoveryCodeFactor({ count: 3 }),
			suiteSealing().digestsFor("recovery_code"),
		);
		if (generated === undefined) throw new Error("no set");
		const set = await seedFactor(factorStore, "recovery_code", generated.data);
		const booted = await boot({
			config: configFor("optional", { enrollment: { requireEmailProof: "never" } }),
			factorStore,
			subjectRevocation: revocation,
		});
		const begun = await beginLogin(booted.app);
		const login = await booted.transactionStore.get(begun.transaction);
		if (login === null) throw new Error("no login transaction");
		await revocation.revokeBefore(ALICE.id, new Date(T0), new Date(T0 + 86_400_000));
		// A session signed in after the boundary, by a recovery code.
		freezeClock(T0 + 2_000);
		const signed = await beginLogin(booted.app);
		const verified = await verify(signed.agent, signed.transaction, set.id, generated.codes[0]);
		expect(verified.status, JSON.stringify(verified.body)).toBe(200);
		const boundTo = sessionIdSet(verified);
		if (boundTo === undefined) throw new Error("no session set");
		// The login's transaction, bound to that browser's session.
		const named = randomBytes(32).toString("base64url");
		await booted.transactionStore.create({
			...login,
			id: named,
			binding: { kind: "session", id: boundTo },
		});
		const read = vi.spyOn(revocation, "revokedBefore");
		const unknown = await stepUp(signed.agent, "A".repeat(43));
		const readsForUnknown = read.mock.calls.length;
		read.mockClear();

		const res = await stepUp(signed.agent, named);

		expect(unknown.status).toBe(400);
		expect(res.status, JSON.stringify(res.body)).toBe(400);
		expect(res.body).toEqual(unknown.body);
		expect(read.mock.calls.length).toBe(readsForUnknown);
	});
});
