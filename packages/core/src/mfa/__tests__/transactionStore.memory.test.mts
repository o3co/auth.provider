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
		const got = (await store.get("tx-1")) as { user: { groups: string[] }; acrValues: string[] };
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
		await store.noteExemptSuccess("user-1", T0, POLICY);
		expect(store.subjects).toBe(1);
		await store.clearSubjectState("user-1");
		expect(store.subjects).toBe(0);
	});

	it("keeps a subject's state while the week still counts a failure, and drops it after", async () => {
		const store = createMemoryMfaTransactionStore();
		const reserved = await store.reserveSubjectAttempt("user-1", T0, POLICY, undefined);
		if (reserved.ok) await store.settleSubjectAttempt("user-1", reserved.reservation, "success");
		expect(store.subjects).toBe(0);
		const failed = await store.reserveSubjectAttempt("user-1", T0, POLICY, undefined);
		if (failed.ok) await store.settleSubjectAttempt("user-1", failed.reservation, "failure");
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
