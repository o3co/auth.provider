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
 * The operator reset, `resetMfaForSubject` (`reset.mts`), over core's memory
 * MFA stores and a witnessing directory, and through `mfaResetModule`: the
 * subject's sessions ended first, then — under one lease of the subject's —
 * the lock state reset, every record removed and the witness cleared, in that
 * order; and a factor-set write begun before it binding nothing after it.
 */

import {
	BootError,
	createApp,
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	defineModule,
	type MfaFactorRecord,
	type MfaFactorStore,
	type MfaLockoutPolicy,
	type MfaTransactionStore,
	type Module,
	type SubjectRevocationReport,
	type SubjectRevocationService,
} from "@o3co/auth-provider-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createMfaSubjectLeases } from "#/factorSet.mjs";
import { createMfaReset } from "#/reset.mjs";
import { mfaResetModule } from "#/resetModule.mjs";
import {
	ALICE,
	BOB,
	boot,
	configFor,
	directoryEntries,
	disposeAll,
	events,
	modulesFor,
	refusal,
	WitnessingUserRepository,
} from "./moduleHarness.mjs";
import {
	completeEnrollment,
	enrollFromAccount,
	freezeClock,
	mfaPost,
	newFactorId,
	recordingAuditSink,
	seedTotp,
	signInWithTotp,
	T0,
	thawClock,
	totpProofOf,
} from "./routesHarness.mjs";

beforeEach(() => freezeClock());
afterEach(async () => {
	await disposeAll();
	thawClock();
	vi.restoreAllMocks();
});

/** What a revocation service reports for a subject whose every session ended, or — `complete: false` — one it could not end. */
const revocationReport = (complete = true): SubjectRevocationReport => ({
	sessionsRevoked: ["sid-1"],
	sessionsFailed: complete ? [] : ["sid-2"],
	tokensRevoked: true,
	grantsRequested: false,
	grantsRevoked: [],
	grantsFailed: [],
	grantsRetired: [],
	grantsRetireFailed: [],
	unavailable: [],
	failures: [],
	complete,
	federationGrants: { requested: "revoke", applied: "revoke" },
});

/** A revocation service whose every call reports `complete`. */
const revocationService = (complete = true) => ({
	revokeAllForSubject: vi.fn<SubjectRevocationService["revokeAllForSubject"]>(async () =>
		revocationReport(complete),
	),
});

/** A record of `kind` for alice whose data is `data`: the reset never opens it. */
const recordOf = (
	id: string,
	kind: string,
	data = "sealed-under-a-key-long-retired",
): MfaFactorRecord => ({
	id,
	subject: ALICE.id,
	kind,
	label: undefined,
	binding: "password",
	createdAt: new Date(T0 - 1_000),
	lastUsedAt: undefined,
	version: 0,
	data,
});

const POLICY: MfaLockoutPolicy = {
	threshold: 9,
	baseSeconds: 1,
	maxSeconds: 1,
	memorySeconds: 86_400,
	weeklyBudget: 100,
	hardLimit: 10,
};

/** Alice's run brought to the hard limit on the transaction store: the hard hold fixed. */
async function latch(store: MfaTransactionStore): Promise<void> {
	for (let n = 0; n < 10; n++) {
		const at = n < 9 ? T0 + n : T0 + 10_000;
		const reserved = await store.reserveSubjectAttempt(ALICE.id, at, POLICY);
		if (!reserved.ok) throw new Error(`refused: ${reserved.hold}`);
		await store.settleSubjectAttempt(ALICE.id, reserved.reservation, "failure");
	}
}

/** The reset over memory stores, alice's three kinds of record seeded, and a witnessing directory. */
async function setup(
	options: {
		readonly service?: ReturnType<typeof revocationService>;
		readonly mailWired?: boolean;
		readonly withoutDirectory?: boolean;
		readonly monotonicNow?: () => number;
		readonly transactionStore?: MfaTransactionStore;
		readonly factorStore?: MfaFactorStore;
	} = {},
) {
	const factorStore = options.factorStore ?? createMemoryMfaFactorStore();
	const transactionStore = options.transactionStore ?? createMemoryMfaTransactionStore();
	await factorStore.create(recordOf("totp-retired", "totp"));
	await factorStore.create(recordOf("uninstalled", "a-kind-nobody-installed"));
	await factorStore.create(recordOf("codes", "recovery_code"));
	const users = new WitnessingUserRepository(directoryEntries());
	const service = options.service ?? revocationService();
	const audit = recordingAuditSink();
	const reset = createMfaReset({
		factorStore,
		transactionStore,
		subjectRevocationService: service,
		...(options.withoutDirectory === true ? {} : { userRepository: users }),
		mailWired: options.mailWired ?? true,
		leases: createMfaSubjectLeases({
			store: transactionStore,
			storeTimeoutMs: 1_000,
			...(options.monotonicNow === undefined ? {} : { monotonicNow: options.monotonicNow }),
		}),
		auditSink: audit,
	});
	return { reset, factorStore, transactionStore, users, service, audit };
}

describe("resetMfaForSubject", () => {
	it("ends the sessions, then under one lease sets D25's flag, mints its authorization, resets the lock state, removes every record and clears the witness, then releases the lease — in that order", async () => {
		const { reset, factorStore, transactionStore, users, service } = await setup();
		const order = (mock: { mock: { invocationCallOrder: number[] } }) =>
			mock.mock.invocationCallOrder[0] ?? Number.NaN;
		const flag = vi.spyOn(transactionStore, "requireEmailProofAtNextBinding");
		const acquire = vi.spyOn(transactionStore, "acquireSubjectLease");
		const authorize = vi.spyOn(transactionStore, "authorizeSubjectRecovery");
		const apply = vi.spyOn(transactionStore, "applySubjectRecovery");
		const removeAll = vi.spyOn(factorStore, "removeAllForSubject");
		const mark = vi.spyOn(users, "markMfaEnrolled");
		const releaseLease = vi.spyOn(transactionStore, "releaseSubjectLease");

		const report = await reset.resetMfaForSubject(ALICE.id, { requireEmailProof: true });

		expect(report.complete).toBe(true);
		const steps = [
			service.revokeAllForSubject,
			acquire,
			flag,
			authorize,
			apply,
			removeAll,
			mark,
			releaseLease,
		];
		const called = steps.map(order);
		expect(called.every((at) => Number.isFinite(at))).toBe(true);
		expect([...called].sort((a, b) => a - b)).toEqual(called);
		expect(acquire).toHaveBeenCalledTimes(1);
		expect(releaseLease).toHaveBeenCalledTimes(1);
		expect(apply).toHaveBeenCalledWith(
			ALICE.id,
			expect.objectContaining({ operation: "reset", sid: undefined }),
		);
		expect(mark.mock.calls).toEqual([[ALICE.id, false]]);
	});

	it("removes every record — one sealed under a retired key, one of a kind not installed, a recovery-code set — and leaves another subject's", async () => {
		const { reset, factorStore } = await setup();
		await factorStore.create({ ...recordOf("bobs", "totp"), subject: BOB.id });

		await reset.resetMfaForSubject(ALICE.id);

		expect(await factorStore.list(ALICE.id)).toEqual([]);
		expect(await factorStore.list(BOB.id)).toHaveLength(1);
	});

	it("lifts the hard hold and moves the subject's generation", async () => {
		const { reset, transactionStore } = await setup();
		await latch(transactionStore);

		const report = await reset.resetMfaForSubject(ALICE.id);

		expect(report.generation).toBe(1);
		expect(await transactionStore.subjectGeneration(ALICE.id)).toBe(1);
		expect(
			await transactionStore.reserveSubjectAttempt(ALICE.id, T0 + 20_000, POLICY),
		).toMatchObject({ ok: true });
	});

	it("reports what it did: complete, the sessions' report, the kinds and count removed, the generation, the witness cleared, the lease released as held", async () => {
		const { reset } = await setup();

		const report = await reset.resetMfaForSubject(ALICE.id, { requestedBy: "ticket-42" });

		expect(report).toEqual({
			subject: ALICE.id,
			complete: true,
			requireEmailProof: false,
			sessions: revocationReport(),
			sessionsAgain: revocationReport(),
			removed: { kinds: ["a-kind-nobody-installed", "recovery_code", "totp"], count: 3 },
			generation: 1,
			witness: "cleared",
		});
	});

	it("emits one mfa.reset, and no mfa.lock.recovered", async () => {
		const { reset, audit } = await setup();

		await reset.resetMfaForSubject(ALICE.id, { requireEmailProof: true, requestedBy: "ticket-42" });

		expect(audit.of("mfa.lock.recovered")).toEqual([]);
		expect(audit.of("mfa.reset")).toEqual([
			expect.objectContaining({
				type: "mfa.reset",
				subject: ALICE.id,
				details: {
					by: "operator",
					kinds: ["a-kind-nobody-installed", "recovery_code", "totp"],
					count: 3,
					requireEmailProof: true,
					sessions: true,
					sessionsAgain: true,
					complete: true,
					requestedBy: "ticket-42",
				},
			}),
		]);
	});

	it("completes again when run again: idempotent, the generation moving once more", async () => {
		const { reset } = await setup();
		await reset.resetMfaForSubject(ALICE.id);

		const again = await reset.resetMfaForSubject(ALICE.id);

		expect(again).toMatchObject({
			complete: true,
			removed: { kinds: [], count: 0 },
			generation: 2,
		});
	});

	it("sets D25's flag when asked", async () => {
		const { reset, transactionStore } = await setup();

		await reset.resetMfaForSubject(ALICE.id, { requireEmailProof: true });

		expect(await transactionStore.emailProofRequiredAtNextBinding(ALICE.id)).toBe(true);
	});

	it("refuses requireEmailProof with a RangeError when no mail sender is wired, doing nothing", async () => {
		const { reset, service, factorStore, transactionStore } = await setup({ mailWired: false });
		const flag = vi.spyOn(transactionStore, "requireEmailProofAtNextBinding");

		await expect(reset.resetMfaForSubject(ALICE.id, { requireEmailProof: true })).rejects.toThrow(
			RangeError,
		);

		expect(flag).not.toHaveBeenCalled();
		expect(service.revokeAllForSubject).not.toHaveBeenCalled();
		expect(await factorStore.list(ALICE.id)).toHaveLength(3);
	});

	it("refuses a subject, a federation-grant disposition or a requestedBy it cannot use with a RangeError, doing nothing", async () => {
		const { reset, service } = await setup();
		for (const [subject, request] of [
			["", {}],
			[ALICE.id, { federationGrants: "forget" }],
			[ALICE.id, { requestedBy: "" }],
			[ALICE.id, { requestedBy: "x".repeat(257) }],
		] as const) {
			await expect(reset.resetMfaForSubject(subject, request as never)).rejects.toThrow(RangeError);
		}
		expect(service.revokeAllForSubject).not.toHaveBeenCalled();
	});

	it("hands the federation-grant disposition to the revocation", async () => {
		const { reset, service } = await setup();

		await reset.resetMfaForSubject(ALICE.id, { federationGrants: "keep" });

		expect(service.revokeAllForSubject).toHaveBeenCalledWith({
			subject: ALICE.id,
			federationGrants: "keep",
		});
	});

	it("stops when the sessions could not all be ended: no lease taken, every record left, reported and audited incomplete", async () => {
		const { reset, factorStore, transactionStore, audit } = await setup({
			service: revocationService(false),
		});
		const acquire = vi.spyOn(transactionStore, "acquireSubjectLease");

		const report = await reset.resetMfaForSubject(ALICE.id);

		expect(report).toMatchObject({ complete: false, stoppedAt: "sessions" });
		expect(acquire).not.toHaveBeenCalled();
		expect(await factorStore.list(ALICE.id)).toHaveLength(3);
		expect(audit.of("mfa.reset")[0]?.details).toMatchObject({ complete: false, sessions: false });
	});

	it("stops when the revocation throws, reporting it", async () => {
		const service = revocationService();
		service.revokeAllForSubject.mockRejectedValue(new Error("down"));
		const { reset, factorStore } = await setup({ service });

		const report = await reset.resetMfaForSubject(ALICE.id);

		expect(report).toMatchObject({ complete: false, stoppedAt: "sessions" });
		expect(await factorStore.list(ALICE.id)).toHaveLength(3);
	});

	it("waits for another write's lease to end, never going on without it", async () => {
		const { reset, transactionStore } = await setup();
		const held = await transactionStore.acquireSubjectLease(ALICE.id, {
			ttlMs: 60_000,
			generation: 0,
		});
		if (held.outcome !== "acquired") throw new Error("not held");
		const released = vi.fn();
		const apply = vi.spyOn(transactionStore, "applySubjectRecovery");
		setTimeout(() => {
			released();
			void transactionStore.releaseSubjectLease(ALICE.id, held.token);
		}, 300);

		const report = await reset.resetMfaForSubject(ALICE.id);

		expect(report.complete).toBe(true);
		expect(released).toHaveBeenCalled();
		expect(apply.mock.invocationCallOrder[0]).toBeGreaterThan(
			released.mock.invocationCallOrder[0] as number,
		);
	});

	it("counts its own move of the generation as no overrun: the lease it took is released as held", async () => {
		const { reset, transactionStore } = await setup();
		const releaseLease = vi.spyOn(transactionStore, "releaseSubjectLease");

		const report = await reset.resetMfaForSubject(ALICE.id);

		expect(await releaseLease.mock.results[0]?.value).toBe(true);
		expect(report).not.toHaveProperty("overran");
	});

	it("gives up after its wait when the lease stays held: nothing reset, every record left, reported at the lease", async () => {
		let monotonic = 0;
		const { reset, transactionStore, factorStore } = await setup({
			monotonicNow: () => {
				monotonic += 5_000;
				return monotonic;
			},
		});
		await transactionStore.acquireSubjectLease(ALICE.id, { ttlMs: 60_000, generation: 0 });
		const apply = vi.spyOn(transactionStore, "applySubjectRecovery");

		const report = await reset.resetMfaForSubject(ALICE.id);

		expect(report).toMatchObject({ complete: false, stoppedAt: "lease" });
		expect(apply).not.toHaveBeenCalled();
		expect(await factorStore.list(ALICE.id)).toHaveLength(3);
	});

	it("starts no write with less than one Store call's time of its lease left: nothing reset when the time runs out after the read", async () => {
		let monotonic = 0;
		const { reset, transactionStore, factorStore } = await setup({ monotonicNow: () => monotonic });
		const list = factorStore.list.bind(factorStore);
		vi.spyOn(factorStore, "list").mockImplementation(async (subject) => {
			const listed = await list(subject);
			monotonic = 1e9;
			return listed;
		});
		const authorize = vi.spyOn(transactionStore, "authorizeSubjectRecovery");
		const apply = vi.spyOn(transactionStore, "applySubjectRecovery");

		const report = await reset.resetMfaForSubject(ALICE.id);

		expect(report).toMatchObject({ complete: false, stoppedAt: "lease" });
		expect(authorize).not.toHaveBeenCalled();
		expect(apply).not.toHaveBeenCalled();
		expect(await factorStore.list(ALICE.id)).toHaveLength(3);
	});

	it("starts no removal with less than one Store call's time left once the lock state was reset: stopped at the factors, run again to finish", async () => {
		let monotonic = 0;
		const { reset, transactionStore, factorStore, users } = await setup({
			monotonicNow: () => monotonic,
		});
		const apply = transactionStore.applySubjectRecovery.bind(transactionStore);
		vi.spyOn(transactionStore, "applySubjectRecovery").mockImplementation(async (...args) => {
			const answer = await apply(...args);
			monotonic = 1e9;
			return answer;
		});
		const removeAll = vi.spyOn(factorStore, "removeAllForSubject");

		const report = await reset.resetMfaForSubject(ALICE.id);

		expect(report).toMatchObject({ complete: false, stoppedAt: "factors", generation: 1 });
		expect(report).not.toHaveProperty("removed");
		expect(removeAll).not.toHaveBeenCalled();
		expect(users.marks).toEqual([]);
	});

	it("sets D25's flag under its lease: a binding that held the lease when the reset began cannot clear it", async () => {
		const { reset, transactionStore } = await setup();
		const held = await transactionStore.acquireSubjectLease(ALICE.id, {
			ttlMs: 60_000,
			generation: 0,
		});
		if (held.outcome !== "acquired") throw new Error("not held");
		setTimeout(() => {
			void transactionStore
				.consumeEmailProofRequirement(ALICE.id)
				.then(() => transactionStore.releaseSubjectLease(ALICE.id, held.token));
		}, 200);

		const report = await reset.resetMfaForSubject(ALICE.id, { requireEmailProof: true });

		expect(report.complete).toBe(true);
		expect(await transactionStore.emailProofRequiredAtNextBinding(ALICE.id)).toBe(true);
	});

	it("moves the generation once for each of two resets run at once: each mints its own authorization under its lease", async () => {
		const { reset, transactionStore } = await setup();

		const reports = await Promise.all([
			reset.resetMfaForSubject(ALICE.id),
			reset.resetMfaForSubject(ALICE.id),
		]);

		expect(reports.map((report) => report.complete)).toEqual([true, true]);
		expect(reports.map((report) => report.generation).sort()).toEqual([1, 2]);
		expect(await transactionStore.subjectGeneration(ALICE.id)).toBe(2);
	});

	it("is not complete when the store answers its authorization applied before: nothing removed", async () => {
		const { reset, transactionStore, factorStore } = await setup();
		vi.spyOn(transactionStore, "applySubjectRecovery").mockResolvedValue({
			outcome: "already_applied",
			recoveryId: "an-earlier-one",
			generation: 1,
			hard: false,
		});

		const report = await reset.resetMfaForSubject(ALICE.id);

		expect(report).toMatchObject({ complete: false, stoppedAt: "lock" });
		expect(await factorStore.list(ALICE.id)).toHaveLength(3);
	});

	it("reports and audits nothing removed when it stopped before the removal", async () => {
		const { reset, transactionStore, audit } = await setup();
		vi.spyOn(transactionStore, "applySubjectRecovery").mockRejectedValue(new Error("down"));

		const report = await reset.resetMfaForSubject(ALICE.id);

		expect(report).toMatchObject({ complete: false, stoppedAt: "lock" });
		expect(report).not.toHaveProperty("removed");
		const details = audit.of("mfa.reset")[0]?.details ?? {};
		expect(details).not.toHaveProperty("kinds");
		expect(details).not.toHaveProperty("count");
	});

	it("is not complete when its lease ended before it released it", async () => {
		const { reset, transactionStore } = await setup();
		vi.spyOn(transactionStore, "releaseSubjectLease").mockResolvedValue(false);

		const report = await reset.resetMfaForSubject(ALICE.id);

		expect(report).toMatchObject({ complete: false, overran: true });
	});

	it("ends the sessions again once every record is removed: a session signed in with a factor before its removal does not survive a reset that reports complete", async () => {
		const { reset, factorStore, service } = await setup();
		const removeAll = vi.spyOn(factorStore, "removeAllForSubject");

		const report = await reset.resetMfaForSubject(ALICE.id);

		expect(service.revokeAllForSubject).toHaveBeenCalledTimes(2);
		expect(service.revokeAllForSubject.mock.invocationCallOrder[1]).toBeGreaterThan(
			removeAll.mock.invocationCallOrder[0] as number,
		);
		expect(report).toMatchObject({ complete: true, sessionsAgain: revocationReport() });
	});

	it("is not complete, stopped at the sessions, when the second revocation is not", async () => {
		const service = revocationService();
		service.revokeAllForSubject
			.mockResolvedValueOnce(revocationReport(true))
			.mockResolvedValueOnce(revocationReport(false));
		const { reset, factorStore, audit } = await setup({ service });

		const report = await reset.resetMfaForSubject(ALICE.id);

		expect(report).toMatchObject({ complete: false, stoppedAt: "sessions", generation: 1 });
		expect(await factorStore.list(ALICE.id)).toEqual([]);
		expect(audit.of("mfa.reset")[0]?.details).toMatchObject({
			sessions: true,
			sessionsAgain: false,
			complete: false,
		});
	});

	it("answers an incomplete report, audited, when a revocation answers no report or one whose read throws", async () => {
		for (const answer of [
			null,
			{
				get complete(): boolean {
					throw new Error("a lazy field could not load");
				},
			},
		]) {
			for (const which of [0, 1]) {
				const service = revocationService();
				if (which === 0) service.revokeAllForSubject.mockResolvedValueOnce(answer as never);
				else {
					service.revokeAllForSubject
						.mockResolvedValueOnce(revocationReport())
						.mockResolvedValueOnce(answer as never);
				}
				const { reset, audit } = await setup({ service });

				const report = await reset.resetMfaForSubject(ALICE.id);

				expect(report).toMatchObject({ complete: false, stoppedAt: "sessions" });
				expect(audit.of("mfa.reset")).toHaveLength(1);
			}
		}
	});

	it("still answers its report, counting the records removed, when a record listed has no readable kind", async () => {
		for (const odd of [
			null,
			{
				get kind(): string {
					throw new Error("a lazy field could not load");
				},
			},
		]) {
			const factorStore = createMemoryMfaFactorStore();
			vi.spyOn(factorStore, "list").mockResolvedValue([odd] as never);
			const { reset, audit } = await setup({ factorStore });

			const report = await reset.resetMfaForSubject(ALICE.id);

			expect(report).toMatchObject({ complete: true, removed: { kinds: [], count: 1 } });
			expect(audit.of("mfa.reset")).toHaveLength(1);
		}
	});

	it("takes a lease owner only over a whole Store timeout from 1 ms: one that is no such number is refused", () => {
		for (const storeTimeoutMs of [Number.NaN, 0, -1, 1.5, "1000"]) {
			expect(() =>
				createMfaSubjectLeases({
					store: createMemoryMfaTransactionStore(),
					storeTimeoutMs: storeTimeoutMs as number,
				}),
			).toThrow(RangeError);
		}
	});

	it("stops at D25's flag, or at the lock state, when that write is not answered within a Store call's time", async () => {
		for (const [method, at] of [
			["requireEmailProofAtNextBinding", "email_proof"],
			["authorizeSubjectRecovery", "lock"],
		] as const) {
			const { reset, transactionStore, factorStore } = await setup();
			vi.spyOn(transactionStore, method).mockReturnValue(new Promise<never>(() => {}));

			const report = await reset.resetMfaForSubject(ALICE.id, { requireEmailProof: true });

			expect(report).toMatchObject({ complete: false, stoppedAt: at });
			expect(await factorStore.list(ALICE.id)).toHaveLength(3);
		}
	});

	it("stops at the factors, the witness left, when records still stand after a removal the store answered", async () => {
		const factorStore = createMemoryMfaFactorStore();
		vi.spyOn(factorStore, "removeAllForSubject").mockResolvedValue(undefined);
		const { reset, users } = await setup({ factorStore });

		const report = await reset.resetMfaForSubject(ALICE.id);

		expect(report).toMatchObject({ complete: false, stoppedAt: "factors", generation: 1 });
		expect(report).not.toHaveProperty("removed");
		expect(users.marks).toEqual([]);
	});

	it("reports the records removed as listed, unsorted, when one of several is no record", async () => {
		const factorStore = createMemoryMfaFactorStore();
		vi.spyOn(factorStore, "list")
			.mockResolvedValueOnce([recordOf("totp-a", "totp"), null] as never)
			.mockResolvedValue([]);
		const { reset } = await setup({ factorStore });

		const report = await reset.resetMfaForSubject(ALICE.id);

		expect(report).toMatchObject({ complete: true, removed: { kinds: ["totp"], count: 2 } });
	});

	it("reads the generation again after a pause when it moved before its acquire, and completes", async () => {
		const { reset, transactionStore } = await setup();
		vi.spyOn(transactionStore, "acquireSubjectLease").mockResolvedValueOnce({ outcome: "stale" });

		const report = await reset.resetMfaForSubject(ALICE.id);

		expect(report.complete).toBe(true);
		expect(transactionStore.acquireSubjectLease).toHaveBeenCalledTimes(2);
	});

	it("stops, the witness left, when the records cannot be removed", async () => {
		const factorStore = createMemoryMfaFactorStore();
		vi.spyOn(factorStore, "removeAllForSubject").mockRejectedValue(new Error("down"));
		const { reset, users } = await setup({ factorStore });

		const report = await reset.resetMfaForSubject(ALICE.id);

		expect(report).toMatchObject({ complete: false, stoppedAt: "factors" });
		expect(users.marks).toEqual([]);
	});

	it("reports the witness when it cannot be cleared, and a directory that cannot write it", async () => {
		const failing = await setup();
		failing.users.failWith(new Error("down"));
		expect(await failing.reset.resetMfaForSubject(ALICE.id)).toMatchObject({
			complete: false,
			stoppedAt: "witness",
		});

		const unwritable = await setup({ withoutDirectory: true });
		expect(await unwritable.reset.resetMfaForSubject(ALICE.id)).toMatchObject({
			complete: true,
			witness: "unwritable",
		});
	});
});

/** A module providing `subjectRevocationService` as `service`. */
const providingService = (service: SubjectRevocationService): Module =>
	defineModule({
		name: "test:subject-revocation-service",
		provides: { subjectRevocationService: () => service } as never,
	});

describe("mfaResetModule", () => {
	it("provides mfaReset at boot, over the composition's MFA stores, directory and revocation service", async () => {
		const factorStore = createMemoryMfaFactorStore();
		await seedTotp(factorStore);
		const users = new WitnessingUserRepository(directoryEntries());
		const service = revocationService();
		const { handle } = await boot({
			factorStore,
			userRepository: users,
			extraModules: [mfaResetModule, providingService(service)],
		});
		const components = handle.components as unknown as {
			readonly mfaReset: ReturnType<typeof createMfaReset>;
		};

		const report = await components.mfaReset.resetMfaForSubject(ALICE.id);

		expect(report.complete).toBe(true);
		expect(await factorStore.list(ALICE.id)).toEqual([]);
		expect(users.marks).toEqual([{ subject: ALICE.id, enrolled: false }]);
		expect(service.revokeAllForSubject).toHaveBeenCalledTimes(2);
	});

	it("holds the lease mfaModule's lease owner gives: six of mfa.storeTimeoutMs", async () => {
		const transactionStore = createMemoryMfaTransactionStore();
		const { handle } = await boot({
			config: configFor("required", { storeTimeoutMs: 2_000 }),
			transactionStore,
			extraModules: [mfaResetModule, providingService(revocationService())],
		});
		const acquire = vi.spyOn(transactionStore, "acquireSubjectLease");
		const components = handle.components as unknown as {
			readonly mfaReset: ReturnType<typeof createMfaReset>;
		};

		expect((await components.mfaReset.resetMfaForSubject(ALICE.id)).complete).toBe(true);

		expect(acquire.mock.calls.map(([, request]) => request.ttlMs)).toEqual([12_000]);
	});

	it("is refused at boot without mfaModule, naming the lease owner it requires", async () => {
		const config = configFor("required", {}, {}, []);
		const stores = defineModule({
			name: "test:mfa-stores",
			provides: {
				mfaFactorStore: () => createMemoryMfaFactorStore(),
				mfaTransactionStore: () => createMemoryMfaTransactionStore(),
			} as never,
		});
		let refused: unknown;
		try {
			const handle = await createApp({
				modules: [stores, providingService(revocationService()), mfaResetModule],
				bootstrapComponents: { config, pathResolver: (s: string) => s } as never,
			});
			await handle.dispose();
		} catch (err) {
			refused = err;
		}

		expect(refused).toBeInstanceOf(BootError);
		expect((refused as BootError).message).toContain("mfaSubjectLeases");
	});

	it("serialises a reset behind a removal holding the subject's lease: the lock state is reset only once the removal is done", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const transactionStore = createMemoryMfaTransactionStore();
		const totp = await seedTotp(factorStore);
		await factorStore.create({ ...recordOf(newFactorId(), "recovery_code"), data: "x" });
		const booted = await boot({
			factorStore,
			transactionStore,
			extraModules: [mfaResetModule, providingService(revocationService())],
		});
		const { agent } = await signInWithTotp(booted.app, booted.userSessionStore as never, totp);
		const codes = (await factorStore.list(ALICE.id)).find((r) => r.kind === "recovery_code");
		if (codes === undefined) throw new Error("no set");
		let reached: () => void = () => {};
		const removing = new Promise<void>((resolve) => {
			reached = resolve;
		});
		let open: () => void = () => {};
		const gate = new Promise<void>((resolve) => {
			open = resolve;
		});
		const remove = factorStore.remove.bind(factorStore);
		const removed = vi.fn();
		vi.spyOn(factorStore, "remove").mockImplementation(async (subject, id) => {
			reached();
			await gate;
			await remove(subject, id);
			removed();
		});
		const apply = vi.spyOn(transactionStore, "applySubjectRecovery");
		const components = booted.handle.components as unknown as {
			readonly mfaReset: ReturnType<typeof createMfaReset>;
		};

		const removal = mfaPost(agent, "/factors/remove", { factor_id: codes.id });
		await removing;
		const reset = components.mfaReset.resetMfaForSubject(ALICE.id);
		await new Promise((resolve) => setTimeout(resolve, 300));
		expect(apply).not.toHaveBeenCalled();
		open();

		expect((await removal).status).toBe(200);
		expect((await reset).complete).toBe(true);
		expect(apply.mock.invocationCallOrder[0]).toBeGreaterThan(
			removed.mock.invocationCallOrder[0] as number,
		);
	});

	it("refuses the boot when a composition substitutes the lease owner mfaModule provides", async () => {
		const config = configFor("required");
		const composed = modulesFor({
			config,
			extraModules: [mfaResetModule, providingService(revocationService())],
		});
		let refused: unknown;
		try {
			const handle = await createApp({
				modules: composed.modules,
				bootstrapComponents: { config, pathResolver: (s: string) => s } as never,
				overrideComponents: {
					mfaSubjectLeases: createMfaSubjectLeases({
						store: composed.transactionStore,
						storeTimeoutMs: 1_000,
					}),
				} as never,
			});
			await handle.dispose();
		} catch (err) {
			refused = err;
		}

		expect(refused).toBeInstanceOf(BootError);
		expect((refused as BootError).message).toContain("mfaSubjectLeases");
	});

	it("refuses the boot when the subject revocation service provided is no service", async () => {
		const refused = await refusal({
			extraModules: [
				mfaResetModule,
				defineModule({
					name: "test:subject-revocation-service",
					provides: { subjectRevocationService: () => undefined } as never,
				}),
			],
		});

		expect(refused.message).toContain("mfa-reset");
	});

	it("refuses the boot without a subject revocation service", async () => {
		const refused = await refusal({ extraModules: [mfaResetModule] });

		expect(refused.message).toContain("subjectRevocationService");
	});
});

describe("a factor-set write begun before a reset or a recovery", () => {
	/** Alice signed in with her TOTP factor, a second TOTP enrollment begun from the account page. */
	async function enrollmentBegun() {
		const factorStore = createMemoryMfaFactorStore();
		const transactionStore = createMemoryMfaTransactionStore();
		const totp = await seedTotp(factorStore);
		const booted = await boot({ config: configFor("required"), factorStore, transactionStore });
		const { agent } = await signInWithTotp(app(booted), booted.userSessionStore as never, totp);
		const begun = await enrollFromAccount(agent, "totp");
		expect(begun.status, JSON.stringify(begun.body)).toBe(200);
		return { ...booted, factorStore, transactionStore, agent, begun };
	}
	const app = (booted: { readonly app: Parameters<typeof signInWithTotp>[0] }) => booted.app;

	it("binds nothing after a reset that ended no session of the browser's", async () => {
		const setup = await enrollmentBegun();
		const reset = createMfaReset({
			factorStore: setup.factorStore,
			transactionStore: setup.transactionStore,
			subjectRevocationService: revocationService(),
			mailWired: false,
			leases: createMfaSubjectLeases({ store: setup.transactionStore, storeTimeoutMs: 1_000 }),
		});
		await reset.resetMfaForSubject(ALICE.id);
		const create = vi.spyOn(setup.factorStore, "create");

		const done = await completeEnrollment(
			setup.agent,
			setup.begun.body.transaction as string,
			totpProofOf(setup.begun.body.secret),
		);

		expect(done.status, JSON.stringify(done.body)).not.toBe(200);
		expect(create).not.toHaveBeenCalled();
		expect(await setup.factorStore.list(ALICE.id)).toEqual([]);
	});

	it("is answered 409 mfa_enrollment_conflict, nothing written, when the subject's generation moved since it began", async () => {
		const setup = await enrollmentBegun();
		const lease = await setup.transactionStore.acquireSubjectLease(ALICE.id, {
			ttlMs: 60_000,
			generation: 0,
		});
		if (lease.outcome !== "acquired") throw new Error("not held");
		await setup.transactionStore.authorizeSubjectRecovery(ALICE.id, {
			operation: "reset",
			sid: undefined,
			recoveryId: "moving-the-generation",
			expiresAtMs: Date.now() + 60_000,
		});
		await setup.transactionStore.applySubjectRecovery(ALICE.id, {
			operation: "reset",
			sid: undefined,
			nowMs: Date.now(),
			leaseToken: lease.token,
			sessionsBoundaryMs: undefined,
			guessableBoundSinceMs: undefined,
		});
		await setup.transactionStore.releaseSubjectLease(ALICE.id, lease.token);
		const create = vi.spyOn(setup.factorStore, "create");

		const done = await completeEnrollment(
			setup.agent,
			setup.begun.body.transaction as string,
			totpProofOf(setup.begun.body.secret),
		);

		expect(done.status, JSON.stringify(done.body)).toBe(409);
		expect(done.body.error).toBe("mfa_enrollment_conflict");
		expect(create).not.toHaveBeenCalled();
	});

	it("binds under the subject's lease at the generation its begin read", async () => {
		const setup = await enrollmentBegun();
		const acquire = vi.spyOn(setup.transactionStore, "acquireSubjectLease");
		const create = setup.factorStore.create.bind(setup.factorStore);
		let heldDuringCreate: string | undefined;
		vi.spyOn(setup.factorStore, "create").mockImplementation(async (record) => {
			heldDuringCreate ??= (
				await setup.transactionStore.acquireSubjectLease(ALICE.id, { ttlMs: 1_000, generation: 0 })
			).outcome;
			return create(record);
		});

		const done = await completeEnrollment(
			setup.agent,
			setup.begun.body.transaction as string,
			totpProofOf(setup.begun.body.secret),
		);

		expect(done.status, JSON.stringify(done.body)).toBe(200);
		expect(acquire.mock.calls[0]?.[1]).toMatchObject({ generation: 0 });
		expect(heldDuringCreate).toBe("busy");
	});

	it("is answered 409 mfa_factors_busy with Retry-After while another write holds the lease, nothing written and the transaction standing, and binds once it ends", async () => {
		const setup = await enrollmentBegun();
		const lease = await setup.transactionStore.acquireSubjectLease(ALICE.id, {
			ttlMs: 60_000,
			generation: 0,
		});
		if (lease.outcome !== "acquired") throw new Error("not held");
		const create = vi.spyOn(setup.factorStore, "create");
		const transaction = setup.begun.body.transaction as string;
		const proof = totpProofOf(setup.begun.body.secret);

		const busy = await completeEnrollment(setup.agent, transaction, proof);

		expect(busy.status, JSON.stringify(busy.body)).toBe(409);
		expect(busy.body.error).toBe("mfa_factors_busy");
		expect(Number(busy.headers["retry-after"])).toBeGreaterThanOrEqual(1);
		expect(create).not.toHaveBeenCalled();

		await setup.transactionStore.releaseSubjectLease(ALICE.id, lease.token);
		const done = await completeEnrollment(setup.agent, transaction, proof);
		expect(done.status, JSON.stringify(done.body)).toBe(200);
	});

	it("answers what it wrote, never busy, when the lease's time runs out after the transaction was spent: 503, the overrun said, the transaction gone", async () => {
		const setup = await enrollmentBegun();
		const realNow = performance.now.bind(performance);
		let skew = 0;
		vi.spyOn(performance, "now").mockImplementation(() => realNow() + skew);
		const consume = setup.transactionStore.consume.bind(setup.transactionStore);
		vi.spyOn(setup.transactionStore, "consume").mockImplementation(async (...args) => {
			const consumed = await consume(...args);
			skew = 3_600_000;
			return consumed;
		});
		const create = vi.spyOn(setup.factorStore, "create");
		const transaction = setup.begun.body.transaction as string;
		const proof = totpProofOf(setup.begun.body.secret);

		const done = await completeEnrollment(setup.agent, transaction, proof);

		expect(done.status, JSON.stringify(done.body)).toBe(503);
		expect(create).not.toHaveBeenCalled();
		expect(events(setup.logger, "error")).toContain("mfa_subject_lease_overrun");
		skew = 0;
		expect((await completeEnrollment(setup.agent, transaction, proof)).status).toBe(400);
	});
});
