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
 * A subject's first-binding mark (the MFA ADR's D12), through the composed
 * application: a first binding, and a verification that marks the witness,
 * note the mark before they write; a first binding in a session, or at a
 * login, authenticated no later than the mark and the clock skew is
 * refused, so a session or a continuation that recorded `not_enrolled`
 * before the subject enrolled cannot bind over a lost factor store. A mark
 * that cannot be noted refuses the binding, and one that cannot be read
 * refuses it too.
 */

import {
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	DEFAULT_CLOCK_SKEW_MS,
	type MfaFactorStore,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createRecoveryCodeFactor, generateRecoveryCodes } from "#/recovery/factor.mjs";
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
	beginFirstBinding,
	beginLogin,
	completeEnrollment,
	enrollFromAccount,
	freezeClock,
	readTransaction,
	seedFactor,
	seedTotp,
	signIn,
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

/** How long the mark stands under the package's defaults: max(300 s, 2 × 600 s) and twice the skew. */
const LIFETIME_MS = 1_200_000 + 2 * DEFAULT_CLOCK_SKEW_MS;

/** Boots `mode` with no mail sender, so no first binding asks the account-email proof; alice's witness as `enrolled` says. */
async function composed(mode: "optional" | "required", enrolled?: true) {
	const factorStore = createMemoryMfaFactorStore();
	const transactionStore = createMemoryMfaTransactionStore();
	const entries = directoryEntries();
	const alice = entries.get(ALICE.username);
	if (alice !== undefined && enrolled === true) alice.mfaEnrolled = true;
	const users = new WitnessingUserRepository(entries);
	const booted = await boot({
		config: configFor(mode, { enrollment: { requireEmailProof: "never" } }),
		factorStore,
		transactionStore,
		userRepository: users,
	});
	return {
		...booted,
		factorStore,
		transactionStore,
		userSessionStore: booted.userSessionStore as UserSessionStore,
		users,
	};
}

/** The factor store loses every record of alice's. */
async function loseFactors(store: MfaFactorStore): Promise<void> {
	for (const record of await store.list(ALICE.id)) await store.remove(ALICE.id, record.id);
}

/** The Store's witness cleared as well: a Store that keeps none says nothing of the binding. */
const forgetWitness = (users: WitnessingUserRepository) => users.markMfaEnrolled(ALICE.id, false);

/** A first factor bound from the account page of the session `agent` holds. */
async function bindFromAccount(agent: Parameters<typeof enrollFromAccount>[0]) {
	const begun = await enrollFromAccount(agent, "totp");
	expect(begun.status, JSON.stringify(begun.body)).toBe(200);
	return completeEnrollment(
		agent,
		begun.body.transaction as string,
		totpProofOf(begun.body.secret),
	);
}

describe("a first binding in a session after the subject's first binding elsewhere", () => {
	it("is refused to the session that bound, once its factors are lost: 401 login_required, nothing opened", async () => {
		const { app, factorStore, transactionStore, userSessionStore } = await composed("optional");
		const { agent } = await signIn(app, userSessionStore);
		expect((await bindFromAccount(agent)).status).toBe(200);
		await loseFactors(factorStore);
		freezeClock(T0 + 60_000);
		const create = vi.spyOn(transactionStore, "create");

		const res = await enrollFromAccount(agent, "totp");

		expect(res.status).toBe(401);
		expect(res.body).toEqual(LOGIN_REQUIRED);
		expect(create).not.toHaveBeenCalled();
		expect(await factorStore.list(ALICE.id)).toEqual([]);
	});

	it("is refused to a session signed in before another session's first binding, at the start and at a completion begun before it: 401, nothing bound", async () => {
		const { app, factorStore, userSessionStore } = await composed("optional");
		const stale = await signIn(app, userSessionStore);
		const pending = await enrollFromAccount(stale.agent, "totp");
		expect(pending.status, JSON.stringify(pending.body)).toBe(200);
		freezeClock(T0 + 30_000);
		const other = await signIn(app, userSessionStore);
		expect((await bindFromAccount(other.agent)).status).toBe(200);
		await loseFactors(factorStore);
		freezeClock(T0 + 60_000);

		const started = await enrollFromAccount(stale.agent, "totp");
		const completed = await completeEnrollment(
			stale.agent,
			pending.body.transaction as string,
			totpProofOf(pending.body.secret),
		);

		for (const res of [started, completed]) {
			expect(res.status).toBe(401);
			expect(res.body).toEqual(LOGIN_REQUIRED);
		}
		expect(await factorStore.list(ALICE.id)).toEqual([]);
	});

	it("is admitted to a session signed in more than the clock skew after the mark: it binds", async () => {
		const { app, factorStore, userSessionStore, users } = await composed("optional");
		const first = await signIn(app, userSessionStore);
		expect((await bindFromAccount(first.agent)).status).toBe(200);
		await loseFactors(factorStore);
		await forgetWitness(users);
		freezeClock(T0 + DEFAULT_CLOCK_SKEW_MS + 1);
		const fresh = await signIn(app, userSessionStore);

		const res = await bindFromAccount(fresh.agent);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
	});
});

describe("a first binding at a login after the subject's first binding elsewhere", () => {
	it("is refused at the completion of a login begun before it: 401 login_required, nothing bound, nothing spent", async () => {
		const { app, factorStore, transactionStore } = await composed("required");
		const stale = await beginFirstBinding(app);
		const begun = await beginEnrollment(stale.agent, stale.transaction, "totp");
		expect(begun.status, JSON.stringify(begun.body)).toBe(200);
		freezeClock(T0 + 30_000);
		const other = await beginFirstBinding(app);
		const otherBegun = await beginEnrollment(other.agent, other.transaction, "totp");
		const bound = await completeEnrollment(
			other.agent,
			other.transaction,
			totpProofOf(otherBegun.body.secret),
		);
		expect(bound.status, JSON.stringify(bound.body)).toBe(200);
		await loseFactors(factorStore);
		freezeClock(T0 + 60_000);

		const res = await completeEnrollment(
			stale.agent,
			stale.transaction,
			totpProofOf(begun.body.secret),
		);

		expect(res.status).toBe(401);
		expect(res.body).toEqual(LOGIN_REQUIRED);
		expect(await factorStore.list(ALICE.id)).toEqual([]);
		expect(await transactionStore.get(stale.transaction)).toMatchObject({ attempts: 0 });
	});

	it("is refused on a login reopened for a binding after a recovery code, begun before it: 401, nothing bound", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const generated = generateRecoveryCodes(
			createRecoveryCodeFactor({ count: 3 }),
			suiteSealing().digestsFor("recovery_code"),
		);
		if (generated === undefined) throw new Error("no set");
		const set = await seedFactor(factorStore, "recovery_code", generated.data);
		const booted = await boot({
			config: configFor("required", { enrollment: { requireEmailProof: "never" } }),
			factorStore,
		});
		const stale = await beginLogin(booted.app);
		const reopened = await verify(stale.agent, stale.transaction, set.id, generated.codes[0]);
		expect(reopened.status, JSON.stringify(reopened.body)).toBe(403);
		const staleTransaction = reopened.body.transaction as string;
		const begun = await beginEnrollment(stale.agent, staleTransaction, "totp");
		expect(begun.status, JSON.stringify(begun.body)).toBe(200);
		freezeClock(T0 + 30_000);
		const other = await beginLogin(booted.app);
		const otherReopened = await verify(other.agent, other.transaction, set.id, generated.codes[1]);
		const otherTransaction = otherReopened.body.transaction as string;
		const otherBegun = await beginEnrollment(other.agent, otherTransaction, "totp");
		const bound = await completeEnrollment(
			other.agent,
			otherTransaction,
			totpProofOf(otherBegun.body.secret),
		);
		expect(bound.status, JSON.stringify(bound.body)).toBe(200);
		// The counting factor is lost; the recovery sets, which do not count, stay.
		for (const record of await factorStore.list(ALICE.id)) {
			if (record.kind === "totp") await factorStore.remove(ALICE.id, record.id);
		}
		freezeClock(T0 + 60_000);

		const res = await completeEnrollment(
			stale.agent,
			staleTransaction,
			totpProofOf(begun.body.secret),
		);

		expect(res.status).toBe(401);
		expect(res.body).toEqual(LOGIN_REQUIRED);
		expect((await factorStore.list(ALICE.id)).some((record) => record.kind === "totp")).toBe(false);
	});

	it("is admitted at a login authenticated more than the clock skew after the mark: it binds", async () => {
		const { app, factorStore, users } = await composed("required");
		const first = await beginFirstBinding(app);
		const firstBegun = await beginEnrollment(first.agent, first.transaction, "totp");
		expect(
			(
				await completeEnrollment(
					first.agent,
					first.transaction,
					totpProofOf(firstBegun.body.secret),
				)
			).status,
		).toBe(200);
		await loseFactors(factorStore);
		await forgetWitness(users);
		freezeClock(T0 + DEFAULT_CLOCK_SKEW_MS + 1);
		const fresh = await beginFirstBinding(app);
		const begun = await beginEnrollment(fresh.agent, fresh.transaction, "totp");

		const res = await completeEnrollment(
			fresh.agent,
			fresh.transaction,
			totpProofOf(begun.body.secret),
		);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
	});

	it("answers 503 when the mark cannot be read, binding nothing and spending nothing", async () => {
		const { app, factorStore, transactionStore, logger } = await composed("required");
		const { agent, transaction } = await beginFirstBinding(app);
		const begun = await beginEnrollment(agent, transaction, "totp");
		vi.spyOn(transactionStore, "firstBindingAt").mockRejectedValue(
			new Error("transaction store unreachable"),
		);

		const res = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));

		expect(res.status).toBe(503);
		expect(res.body).toEqual(MFA_UNAVAILABLE);
		expect(await factorStore.list(ALICE.id)).toEqual([]);
		expect(await transactionStore.get(transaction)).toMatchObject({ attempts: 0 });
		expect(logger.error.mock.calls).toContainEqual([
			expect.objectContaining({
				route: "enrollment",
				store: "mfa_transaction",
				step: "firstBindingAt",
			}),
			"mfa_store_unavailable",
		]);
	});
});

describe("noting the mark", () => {
	it("notes it at a first binding, before the factor is written, standing max(mfa.manage.maxAgeSeconds, 2 × mfa.transactionTtlSeconds) and twice the clock skew", async () => {
		for (const mode of ["optional", "required"] as const) {
			const { app, factorStore, transactionStore, userSessionStore } = await composed(mode);
			const note = vi.spyOn(transactionStore, "noteFirstBinding");
			const create = vi.spyOn(factorStore, "create");
			let res: Awaited<ReturnType<typeof completeEnrollment>>;
			if (mode === "optional") {
				res = await bindFromAccount((await signIn(app, userSessionStore)).agent);
			} else {
				const { agent, transaction } = await beginFirstBinding(app);
				const begun = await beginEnrollment(agent, transaction, "totp");
				res = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));
			}
			expect(res.status, mode).toBe(200);
			expect(note.mock.calls, mode).toEqual([[ALICE.id, T0, T0 + LIFETIME_MS]]);
			const firstCreate = create.mock.invocationCallOrder[0] as number;
			expect(note.mock.invocationCallOrder[0], mode).toBeLessThan(firstCreate);
			await disposeAll();
		}
	});

	it("notes no mark for a factor bound beside a counting one", async () => {
		const { app, factorStore, transactionStore } = await composed("optional");
		const seeded = await seedTotp(factorStore);
		const { agent, transaction } = await beginLogin(app);
		expect(
			(await verify(agent, transaction, seeded.record.id, totpCode(seeded.secret))).status,
		).toBe(200);
		const note = vi.spyOn(transactionStore, "noteFirstBinding");

		const res = await bindFromAccount(agent);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(note).not.toHaveBeenCalled();
	});

	it("refuses a first binding 503 when the mark cannot be noted — a full or unreachable store — writing no factor, no codes and no witness, the transaction unspent", async () => {
		for (const mode of ["optional", "required"] as const) {
			const { app, factorStore, transactionStore, userSessionStore, users, logger } =
				await composed(mode);
			vi.spyOn(transactionStore, "noteFirstBinding").mockRejectedValue(
				new RangeError("the memory MFA transaction store is full"),
			);
			let agent: Parameters<typeof enrollFromAccount>[0];
			let transaction: string;
			let secret: unknown;
			if (mode === "optional") {
				agent = (await signIn(app, userSessionStore)).agent;
				const begun = await enrollFromAccount(agent, "totp");
				transaction = begun.body.transaction as string;
				secret = begun.body.secret;
			} else {
				const login = await beginFirstBinding(app);
				agent = login.agent;
				transaction = login.transaction;
				secret = (await beginEnrollment(agent, transaction, "totp")).body.secret;
			}

			const res = await completeEnrollment(agent, transaction, totpProofOf(secret));

			expect(res.status, mode).toBe(503);
			expect(res.body, mode).toEqual(MFA_UNAVAILABLE);
			expect(await factorStore.list(ALICE.id), mode).toEqual([]);
			expect(users.marks, mode).toEqual([]);
			expect(await transactionStore.get(transaction), mode).toMatchObject({
				pendingEnrollment: { kind: "totp" },
			});
			expect(logger.error.mock.calls, mode).toContainEqual([
				expect.objectContaining({
					route: "enrollment",
					store: "mfa_transaction",
					step: "noteFirstBinding",
				}),
				"mfa_store_unavailable",
			]);
			if (mode === "optional") {
				expect((await readTransaction(agent, transaction)).status, mode).toBe(200);
			}
			await disposeAll();
		}
	});

	it("notes it before a verification marks the witness of a login whose User does not say it enrolled", async () => {
		const { app, factorStore, transactionStore, users } = await composed("required");
		const seeded = await seedTotp(factorStore);
		const note = vi.spyOn(transactionStore, "noteFirstBinding");
		const mark = vi.spyOn(users, "markMfaEnrolled");
		const { agent, transaction } = await beginLogin(app);

		const res = await verify(agent, transaction, seeded.record.id, totpCode(seeded.secret));

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(note.mock.calls).toEqual([[ALICE.id, T0, T0 + LIFETIME_MS]]);
		expect(users.marks).toEqual([{ subject: ALICE.id, enrolled: true }]);
		expect(note.mock.invocationCallOrder[0]).toBeLessThan(
			mark.mock.invocationCallOrder[0] as number,
		);
	});

	it("notes none for a login whose User says it enrolled", async () => {
		const { app, factorStore, transactionStore } = await composed("required", true);
		const seeded = await seedTotp(factorStore);
		const note = vi.spyOn(transactionStore, "noteFirstBinding");
		const { agent, transaction } = await beginLogin(app);

		const res = await verify(agent, transaction, seeded.record.id, totpCode(seeded.secret));

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(note).not.toHaveBeenCalled();
	});

	it("leaves the witness unmarked, and says so once at warn, when a verification cannot note the mark: the login completes", async () => {
		const { app, factorStore, transactionStore, users, logger } = await composed("required");
		const seeded = await seedTotp(factorStore);
		vi.spyOn(transactionStore, "noteFirstBinding").mockRejectedValue(
			new Error("transaction store unreachable"),
		);
		const { agent, transaction } = await beginLogin(app);

		const res = await verify(agent, transaction, seeded.record.id, totpCode(seeded.secret));

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(users.marks).toEqual([]);
		const lines = logger.warn.mock.calls.filter((call) => call[1] === "mfa_first_binding_unnoted");
		expect(lines).toEqual([
			[
				expect.objectContaining({
					sub: ALICE.id,
					store: "mfa_transaction",
					step: "noteFirstBinding",
				}),
				"mfa_first_binding_unnoted",
			],
		]);
		expect(events(logger, "warn")).not.toContain("mfa_enrollment_witness_unwritten");
	});
});

describe("the mark's lifetime", () => {
	it("ends on the store's clock once its lifetime has passed: the store answers none", async () => {
		const { app, transactionStore, userSessionStore } = await composed("optional");
		expect((await bindFromAccount((await signIn(app, userSessionStore)).agent)).status).toBe(200);
		freezeClock(T0 + LIFETIME_MS - 1);
		expect(await transactionStore.firstBindingAt(ALICE.id, Date.now())).toBe(T0);
		freezeClock(T0 + LIFETIME_MS);
		expect(await transactionStore.firstBindingAt(ALICE.id, Date.now())).toBeNull();
	});
});
