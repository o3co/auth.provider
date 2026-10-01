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
import { createMfaReset } from "#/reset.mjs";
import { mfaResetModule } from "#/resetModule.mjs";
import {
	ALICE,
	BOB,
	boot,
	configFor,
	directoryEntries,
	disposeAll,
	refusal,
	WitnessingUserRepository,
} from "./moduleHarness.mjs";
import {
	completeEnrollment,
	enrollFromAccount,
	freezeClock,
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
		storeTimeoutMs: 1_000,
		auditSink: audit,
		...(options.monotonicNow === undefined ? {} : { monotonicNow: options.monotonicNow }),
	});
	return { reset, factorStore, transactionStore, users, service, audit };
}

describe("resetMfaForSubject", () => {
	it("ends the sessions, then under one lease resets the lock state, removes every record and clears the witness, then releases the lease — in that order", async () => {
		const { reset, factorStore, transactionStore, users, service } = await setup();
		const order = (mock: { mock: { invocationCallOrder: number[] } }) =>
			mock.mock.invocationCallOrder[0] ?? Number.NaN;
		const flag = vi.spyOn(transactionStore, "requireEmailProofAtNextBinding");
		const acquire = vi.spyOn(transactionStore, "acquireSubjectLease");
		const apply = vi.spyOn(transactionStore, "applySubjectRecovery");
		const removeAll = vi.spyOn(factorStore, "removeAllForSubject");
		const mark = vi.spyOn(users, "markMfaEnrolled");
		const releaseLease = vi.spyOn(transactionStore, "releaseSubjectLease");

		const report = await reset.resetMfaForSubject(ALICE.id, { requireEmailProof: true });

		expect(report.complete).toBe(true);
		const steps = [
			flag,
			service.revokeAllForSubject,
			acquire,
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

	it("sets D25's flag when asked, before the sessions end", async () => {
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
		expect(service.revokeAllForSubject).toHaveBeenCalledTimes(1);
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
			storeTimeoutMs: 1_000,
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

	it("is answered 409 mfa_factors_busy with Retry-After while another write holds the lease, nothing written nor spent, and binds once it ends", async () => {
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
});
