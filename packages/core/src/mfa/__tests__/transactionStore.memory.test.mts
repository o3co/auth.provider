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

import { describe, expect, it } from "vitest";
import { replicaUnsafeReason } from "#/boot/replica-safety.mjs";
import { createApp, defineModule } from "#/index.mjs";
import {
	createMfaTransactionStoreFactory,
	registerBuiltinMfaTransactionStores,
} from "#/mfa/factory.mjs";
import { createMemoryMfaTransactionStore } from "#/mfa/memoryTransactionStore.mjs";
import { memoryMfaTransactionStoreModule } from "#/mfa/module.mjs";
import type {
	MfaLockoutPolicy,
	MfaTransaction,
	MfaTransactionStore,
} from "#/mfa/transactionStore.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import { runMfaEmailProofRequirementContract } from "./emailProofRequirement.contract.mjs";
import { runMfaTransactionStoreContract } from "./transactionStore.contract.mjs";

runMfaTransactionStoreContract(async () => createMemoryMfaTransactionStore());
runMfaEmailProofRequirementContract(async () => createMemoryMfaTransactionStore());

const POLICY: MfaLockoutPolicy = {
	threshold: 5,
	baseSeconds: 900,
	maxSeconds: 86_400,
	memorySeconds: 86_400,
	weeklyBudget: 10,
	hardLimit: 100,
};

const T0 = Date.UTC(2026, 8, 1);
const DAY = 86_400_000;
const WEEK = 7 * DAY;

const TX = (overrides: Partial<MfaTransaction> = {}): MfaTransaction => ({
	id: "tx-1",
	purpose: "login",
	binding: { kind: "session", id: "express-session-1" },
	subject: "user-1",
	sid: undefined,
	continuation: {
		primary: {
			subject: "user-1",
			user: { id: "user-1", groups: ["staff"] },
			claims: { email: "user-1@example.test" },
			recorded: {
				amr: ["pwd"],
				authentication: {
					primary: "pwd",
					federation: undefined,
					upstreamAmr: undefined,
					mfaAt: undefined,
				},
			},
			authTimeMs: T0,
			redirectTo: undefined,
			request: {},
		},
		done: [],
		interruptedBy: "mfa",
	},
	redirectTo: undefined,
	enrollment: "none",
	emailProof: "not_required",
	acrValues: ["urn:o3co:acr:mfa"],
	challenge: undefined,
	pendingEnrollment: undefined,
	attempts: 0,
	createdAtMs: T0,
	expiresAtMs: T0 + 600_000,
	version: 1,
	...overrides,
});

describe("the in-process MfaTransactionStore", () => {
	it("is kind memory", () => {
		expect(createMemoryMfaTransactionStore().kind).toBe("memory");
	});

	it("refuses a consume that names no lease, with a RangeError, clearing nothing", async () => {
		const store = createMemoryMfaTransactionStore();
		await store.requireEmailProofAtNextBinding("user-1");
		await expect(store.consumeEmailProofRequirement("user-1", undefined as never)).rejects.toThrow(
			RangeError,
		);
		expect(await store.emailProofRequiredAtNextBinding("user-1")).toBe(true);
	});

	it("hands out copies: changing a returned transaction changes nothing it holds", async () => {
		const store = createMemoryMfaTransactionStore({ now: () => T0 });
		const written = TX();
		await store.create(written);
		(written.continuation?.primary.user as Record<string, unknown>).id = "someone-else";
		const got = (await store.get("tx-1")) as unknown as {
			continuation: { primary: { user: { groups: string[] } } };
			acrValues: string[];
		};
		got.continuation.primary.user.groups.push("admin");
		got.acrValues.push("urn:other");
		expect(await store.get("tx-1")).toStrictEqual(TX());
	});

	it("expires a transaction on its own clock", async () => {
		let now = T0;
		const store = createMemoryMfaTransactionStore({ now: () => now });
		await store.create(TX());
		now = T0 + 599_999;
		expect(await store.get("tx-1")).not.toBeNull();
		now = T0 + 600_000;
		expect(await store.get("tx-1")).toBeNull();
	});

	it("sweeps expired transactions as it is written to, so an abandoned one does not stay", async () => {
		let now = T0;
		const store = createMemoryMfaTransactionStore({
			now: () => now,
			sweepInterval: 2,
			minSweepIntervalMs: 0,
		});
		await store.create(TX({ id: "abandoned", expiresAtMs: T0 + 1_000 }));
		now = T0 + 2_000;
		await store.create(TX({ id: "a" }));
		expect(store.transactions).toBe(1);
		await store.create(TX({ id: "b" }));
		expect(store.transactions).toBe(2);
	});

	it("expires a session's email proof on its own clock", async () => {
		let now = T0;
		const store = createMemoryMfaTransactionStore({ now: () => now });
		await store.recordSessionEmailProof("user-1", "sid-1", T0, T0 + 300_000);
		now = T0 + 299_999;
		expect(await store.sessionEmailProofAt("user-1", "sid-1", T0)).toBe(T0);
		now = T0 + 300_000;
		expect(await store.sessionEmailProofAt("user-1", "sid-1", T0)).toBeNull();
		expect(store.sessionEmailProofs).toBe(0);
	});

	it("sweeps expired email proofs as it is written to, so an abandoned one does not stay", async () => {
		let now = T0;
		const store = createMemoryMfaTransactionStore({
			now: () => now,
			sweepInterval: 2,
			minSweepIntervalMs: 0,
		});
		await store.recordSessionEmailProof("user-1", "abandoned", T0, T0 + 1_000);
		now = T0 + 2_000;
		await store.create(TX({ id: "a" }));
		expect(store.sessionEmailProofs).toBe(0);
		expect(store.transactions).toBe(1);
	});

	it("expires a subject's first-binding mark on its own clock", async () => {
		let now = T0;
		const store = createMemoryMfaTransactionStore({ now: () => now });
		await store.noteFirstBinding("user-1", T0, T0 + 300_000);
		now = T0 + 299_999;
		expect(await store.firstBindingAt("user-1", T0)).toBe(T0);
		now = T0 + 300_000;
		expect(await store.firstBindingAt("user-1", T0)).toBeNull();
		expect(store.firstBindingMarks).toBe(0);
	});

	it("sweeps expired first-binding marks as it is written to, so an abandoned one does not stay", async () => {
		let now = T0;
		const store = createMemoryMfaTransactionStore({
			now: () => now,
			sweepInterval: 2,
			minSweepIntervalMs: 0,
		});
		await store.noteFirstBinding("abandoned", T0, T0 + 1_000);
		now = T0 + 2_000;
		await store.create(TX({ id: "a" }));
		expect(store.firstBindingMarks).toBe(0);
		expect(store.transactions).toBe(1);
	});

	it("drops a subject's state once nothing in it can matter, and an exempt success adds none", async () => {
		const store = createMemoryMfaTransactionStore();
		const reserved = await store.reserveSubjectAttempt("user-1", T0, POLICY);
		expect(store.subjects).toBe(1);
		if (reserved.ok) await store.settleSubjectAttempt("user-1", reserved.reservation, "void");
		expect(store.subjects).toBe(0);
		await store.noteExemptSuccess("user-1", T0, POLICY);
		expect(store.subjects).toBe(0);
		const failed = await store.reserveSubjectAttempt("user-1", T0, POLICY);
		if (failed.ok) await store.settleSubjectAttempt("user-1", failed.reservation, "failure");
		expect(store.subjects).toBe(1);
		const lease = await store.acquireSubjectLease("user-1", { ttlMs: 60_000, generation: 0 });
		if (lease.outcome !== "acquired") throw new Error("expected a lease");
		await store.authorizeSubjectRecovery("user-1", {
			operation: "reset",
			sid: undefined,
			recoveryId: "reset-1",
			expiresAtMs: Date.now() + 600_000,
		});
		await store.applySubjectRecovery("user-1", {
			operation: "reset",
			sid: undefined,
			nowMs: T0,
			leaseToken: lease.token,
			sessionsBoundaryMs: undefined,
			guessableBoundSinceMs: undefined,
		});
		expect(store.subjects).toBe(0);
	});

	it("keeps a subject's state while a failure stands in its run or its week, and drops it once none does", async () => {
		const store = createMemoryMfaTransactionStore();
		const settle = async (at: number, outcome: "failure" | "success" | "void") => {
			const reserved = await store.reserveSubjectAttempt("user-1", at, POLICY);
			if (!reserved.ok) throw new Error("expected a reservation");
			await store.settleSubjectAttempt("user-1", reserved.reservation, outcome);
		};
		await settle(T0, "success");
		expect(store.subjects).toBe(0);
		await settle(T0, "failure");
		expect(store.subjects).toBe(1);
		// Two weeks on the week has let the failure go, but the consecutive run
		// has not: only a success ends it (the hard limit of the MFA ADR's D21
		// counts it).
		await settle(T0 + 2 * WEEK, "void");
		expect(store.subjects).toBe(1);
		await settle(T0 + 2 * WEEK, "success");
		expect(store.subjects).toBe(0);
	});

	it("forgets a reservation never settled once nothing counts it, so it cannot hold a subject's state forever", async () => {
		// A verification that reserved an attempt and never settled it (a
		// crashed request) stays pending. A later success ends the run up to
		// itself, which takes the reservation out of the run; the week still
		// counts it until it rolls off, and then nothing does.
		const store = createMemoryMfaTransactionStore({ now: () => T0 + 3 * WEEK });
		const abandoned = await store.reserveSubjectAttempt("user-1", T0, POLICY);
		if (!abandoned.ok) throw new Error("expected a reservation");
		const won = await store.reserveSubjectAttempt("user-1", T0 + 1, POLICY);
		if (!won.ok) throw new Error("expected a reservation");
		await store.settleSubjectAttempt("user-1", won.reservation, "success");
		expect(store.subjects).toBe(1);
		// Two weeks on, the week has let it go.
		const later = await store.reserveSubjectAttempt("user-1", T0 + 2 * WEEK, POLICY);
		if (!later.ok) throw new Error("expected a reservation");
		await store.settleSubjectAttempt("user-1", later.reservation, "void");
		expect(store.subjects).toBe(0);
		// Settling the forgotten reservation now changes nothing.
		await store.settleSubjectAttempt("user-1", abandoned.reservation, "failure");
		expect(store.subjects).toBe(0);
	});

	it("sweeps subject state on the latest time a caller passed, never on its own clock", async () => {
		// The port judges the subject state on the callers' time. A store clock
		// that runs ahead must not let the week go early.
		let now = T0;
		const store = createMemoryMfaTransactionStore({
			now: () => now,
			sweepInterval: 1,
			minSweepIntervalMs: 0,
		});
		const oneAWeek: MfaLockoutPolicy = { ...POLICY, weeklyBudget: 1 };
		const reserved = await store.reserveSubjectAttempt("user-1", T0, oneAWeek);
		if (!reserved.ok) throw new Error("expected a reservation");
		await store.settleSubjectAttempt("user-1", reserved.reservation, "failure");
		now = T0 + 30 * DAY;
		await store.create(TX({ id: "sweeps", createdAtMs: now, expiresAtMs: now + 600_000 }));
		const next = await store.reserveSubjectAttempt("user-1", T0 + 1, oneAWeek);
		expect(next).toMatchObject({ ok: false, hold: "weekly" });
	});

	it("keeps a subject held hard through every sweep, after its run was ended and its week let go", async () => {
		let now = T0;
		const store = createMemoryMfaTransactionStore({
			now: () => now,
			sweepInterval: 1,
			minSweepIntervalMs: 0,
		});
		const two: MfaLockoutPolicy = { ...POLICY, threshold: 2, hardLimit: 2 };
		const failed = await store.reserveSubjectAttempt("user-1", T0, two);
		if (!failed.ok) throw new Error("expected a reservation");
		await store.settleSubjectAttempt("user-1", failed.reservation, "failure");
		// The second reservation brings the run to the hard limit; its success
		// ends the run, and the week lets the failure go three weeks on.
		const second = await store.reserveSubjectAttempt("user-1", T0 + 1, two);
		if (!second.ok) throw new Error("expected a reservation");
		await store.settleSubjectAttempt("user-1", second.reservation, "success");
		now = T0 + 3 * WEEK;
		await store.reserveSubjectAttempt("user-2", now, two);
		await store.create(TX({ id: "sweeps", createdAtMs: now, expiresAtMs: now + 600_000 }));
		expect(store.subjects).toBe(2);
		expect(await store.reserveSubjectAttempt("user-1", now, two)).toMatchObject({
			ok: false,
			hold: "hard",
		});
	});

	it("keeps an email-proof requirement through every sweep: it has no expiry", async () => {
		let now = T0;
		const store = createMemoryMfaTransactionStore({
			now: () => now,
			sweepInterval: 1,
			minSweepIntervalMs: 0,
		});
		await store.requireEmailProofAtNextBinding("user-1");
		now = T0 + 400 * DAY;
		await store.reserveSubjectAttempt("user-2", now, POLICY);
		await store.create(TX({ id: "sweeps", createdAtMs: now, expiresAtMs: now + 600_000 }));
		expect(await store.emailProofRequiredAtNextBinding("user-1")).toBe(true);
		// Not lock state: the subject count does not include it.
		expect(store.subjects).toBe(1);
	});

	it("lets no caller far ahead on another subject erase, through the sweep, what a caller on time still counts", async () => {
		// The sweep prunes every subject; the time it prunes at is the latest a
		// caller passed, but never later than the store's own clock.
		const store = createMemoryMfaTransactionStore({ sweepInterval: 1, minSweepIntervalMs: 0 });
		const t = Date.now();
		const oneAWeek: MfaLockoutPolicy = { ...POLICY, weeklyBudget: 1 };
		const reserved = await store.reserveSubjectAttempt("user-1", t, oneAWeek);
		if (!reserved.ok) throw new Error("expected a reservation");
		await store.settleSubjectAttempt("user-1", reserved.reservation, "failure");
		for (const ahead of [t + 10 * DAY, 8.64e15]) {
			await store.reserveSubjectAttempt("user-2", ahead, oneAWeek);
			await store.create(
				TX({ id: `sweeps-${ahead}`, createdAtMs: Date.now(), expiresAtMs: Date.now() + 600_000 }),
			);
		}
		expect(await store.reserveSubjectAttempt("user-1", t + 1, oneAWeek)).toMatchObject({
			ok: false,
			hold: "weekly",
		});
	});
});

describe("memoryMfaTransactionStoreModule", () => {
	it("declares itself replica-unsafe, saying what forks", () => {
		expect(memoryMfaTransactionStoreModule.name).toBe("core-mfa-transaction-store-memory");
		expect(memoryMfaTransactionStoreModule.replicaSafety).toMatchObject({ unsafe: true });
		expect(replicaUnsafeReason(memoryMfaTransactionStoreModule)).toMatch(
			/unknown to the replica that receives the verification/,
		);
		expect(replicaUnsafeReason(memoryMfaTransactionStoreModule)).toMatch(
			/the attempt limits and the lockout are counted per replica/,
		);
		// With a durable factor store beside it, a restart after an operator
		// reset lets a password holder bind without the email proof (the MFA
		// ADR's D25).
		expect(replicaUnsafeReason(memoryMfaTransactionStoreModule)).toMatch(
			/a restart loses the email proof an operator reset required/,
		);
	});

	it("provides an in-process mfaTransactionStore", async () => {
		let seen: MfaTransactionStore | undefined;
		const reader = defineModule({
			name: "test:mfa-transaction-store-reader",
			requires: ["mfaTransactionStore"] as const,
			contributes: {
				routes: [
					(deps) => {
						seen = deps.mfaTransactionStore;
						return {
							id: "test-mfa-transaction-store-reader",
							mountPath: "/__test_mfa_transaction_store_reader__",
							handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
						};
					},
				],
			},
		});
		const handle = await createApp({
			modules: [memoryMfaTransactionStoreModule, reader],
			bootstrapComponents: {
				config: makeValidCoreConfig(),
				pathResolver: (p: string) => p,
			} as never,
		});
		try {
			expect(seen?.kind).toBe("memory");
		} finally {
			await handle.dispose();
		}
	});
});

describe("the MfaTransactionStore adapter factory", () => {
	it("builds the memory adapter by name", async () => {
		const factory = createMfaTransactionStoreFactory();
		registerBuiltinMfaTransactionStores(factory);
		expect((await factory.create({ type: "memory" })).kind).toBe("memory");
	});
});
