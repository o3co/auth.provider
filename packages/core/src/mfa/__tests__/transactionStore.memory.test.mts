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
import { runMfaTransactionStoreContract } from "./transactionStore.contract.mjs";

runMfaTransactionStoreContract(async () => createMemoryMfaTransactionStore());

const POLICY: MfaLockoutPolicy = {
	threshold: 5,
	baseSeconds: 900,
	maxSeconds: 86_400,
	memorySeconds: 86_400,
	weeklyBudget: 10,
	hardLimit: 100,
	trustedBrowsers: 5,
	trustedBrowserDays: 30,
};

const T0 = Date.UTC(2026, 8, 1);
const DAY = 86_400_000;
const WEEK = 7 * DAY;

const TX = (overrides: Partial<MfaTransaction> = {}): MfaTransaction => ({
	id: "tx-1",
	purpose: "login",
	sessionId: "express-session-1",
	subject: "user-1",
	sid: undefined,
	primary: { method: "pwd", authTimeMs: T0 },
	user: { id: "user-1", groups: ["staff"] },
	redirectTo: undefined,
	enrollment: "none",
	emailProof: "not_required",
	acrValues: ["urn:o3co:acr:mfa"],
	challenge: undefined,
	pendingEnrollment: undefined,
	attempts: 0,
	sends: 0,
	lastSentAtMs: undefined,
	createdAtMs: T0,
	expiresAtMs: T0 + 600_000,
	version: 1,
	...overrides,
});

describe("the in-process MfaTransactionStore", () => {
	it("is kind memory", () => {
		expect(createMemoryMfaTransactionStore().kind).toBe("memory");
	});

	it("hands out copies: changing a returned transaction changes nothing it holds", async () => {
		const store = createMemoryMfaTransactionStore({ now: () => T0 });
		const written = TX();
		await store.create(written);
		(written.user as Record<string, unknown>).id = "someone-else";
		const got = (await store.get("tx-1")) as unknown as {
			user: { groups: string[] };
			acrValues: string[];
		};
		got.user.groups.push("admin");
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

	it("drops a subject's state once nothing in it can matter", async () => {
		const store = createMemoryMfaTransactionStore();
		const reserved = await store.reserveSubjectAttempt("user-1", T0, POLICY, undefined);
		expect(store.subjects).toBe(1);
		if (reserved.ok) await store.settleSubjectAttempt("user-1", reserved.reservation, "void");
		expect(store.subjects).toBe(0);
		await store.noteExemptSuccess("user-1", T0, POLICY, undefined);
		expect(store.subjects).toBe(1);
		await store.clearSubjectState("user-1");
		expect(store.subjects).toBe(0);
	});

	it("keeps a subject's state while a failure stands in its run or its week, and drops it once none does", async () => {
		const store = createMemoryMfaTransactionStore();
		const settle = async (at: number, outcome: "failure" | "success" | "void") => {
			const reserved = await store.reserveSubjectAttempt("user-1", at, POLICY, undefined);
			if (!reserved.ok) throw new Error("expected a reservation");
			await store.settleSubjectAttempt("user-1", reserved.reservation, outcome);
		};
		await settle(T0, "success");
		expect(store.subjects).toBe(0);
		await settle(T0, "failure");
		expect(store.subjects).toBe(1);
		// Two weeks on the week has let the failure go, but the consecutive run
		// has not: only a success ends it (D21's hard limit counts it).
		await settle(T0 + 2 * WEEK, "void");
		expect(store.subjects).toBe(1);
		await settle(T0 + 2 * WEEK, "success");
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
		const reserved = await store.reserveSubjectAttempt("user-1", T0, oneAWeek, undefined);
		if (!reserved.ok) throw new Error("expected a reservation");
		await store.settleSubjectAttempt("user-1", reserved.reservation, "failure");
		now = T0 + 30 * DAY;
		await store.create(TX({ id: "sweeps", createdAtMs: now, expiresAtMs: now + 600_000 }));
		const next = await store.reserveSubjectAttempt("user-1", T0 + 1, oneAWeek, undefined);
		expect(next).toMatchObject({ ok: false, hold: "weekly" });
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
		await store.noteExemptSuccess("user-2", now, POLICY, undefined);
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
		const reserved = await store.reserveSubjectAttempt("user-1", t, oneAWeek, undefined);
		if (!reserved.ok) throw new Error("expected a reservation");
		await store.settleSubjectAttempt("user-1", reserved.reservation, "failure");
		for (const ahead of [t + 10 * DAY, 8.64e15]) {
			await store.reserveSubjectAttempt("user-2", ahead, oneAWeek, undefined);
			await store.create(
				TX({ id: `sweeps-${ahead}`, createdAtMs: Date.now(), expiresAtMs: Date.now() + 600_000 }),
			);
		}
		expect(await store.reserveSubjectAttempt("user-1", t + 1, oneAWeek, undefined)).toMatchObject({
			ok: false,
			hold: "weekly",
		});
	});

	it("drops a subject whose only state is a trust that has ended, in the sweep", async () => {
		let now = T0;
		const store = createMemoryMfaTransactionStore({
			now: () => now,
			sweepInterval: 1,
			minSweepIntervalMs: 0,
		});
		await store.noteExemptSuccess("user-1", T0, POLICY, undefined);
		expect(store.subjects).toBe(1);
		// Another subject's call carries the callers' time past the trust's end
		// (trustedBrowserDays, with no failure in the week).
		now = T0 + 31 * DAY;
		await store.noteExemptSuccess("user-2", now, POLICY, undefined);
		await store.create(TX({ id: "sweeps", createdAtMs: now, expiresAtMs: now + 600_000 }));
		expect(store.subjects).toBe(1);
	});
});

describe("memoryMfaTransactionStoreModule", () => {
	it("declares itself replica-unsafe, saying what forks", () => {
		expect(memoryMfaTransactionStoreModule.name).toBe("core-mfa-transaction-store-memory");
		expect(memoryMfaTransactionStoreModule.replicaSafety?.unsafe).toBe(true);
		expect(memoryMfaTransactionStoreModule.replicaSafety?.reason).toMatch(
			/unknown to the replica that receives the verification/,
		);
		expect(memoryMfaTransactionStoreModule.replicaSafety?.reason).toMatch(/per replica/);
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
