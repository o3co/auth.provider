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
 * The factor store a bind's writes go through (`MfaFactorSetWrites`): each
 * member held to the lease's time — a read through the lease's read, a write
 * started only while the lease allows one — and otherwise the store's own
 * call, its arguments and its answer passed through unchanged.
 */

import {
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	type MfaFactorRecord,
	type MfaFactorResolver,
	type MfaFactorStore,
	type StoreGeneration,
} from "@o3co/auth-provider-core";
import { describe, expect, it, vi } from "vitest";
import {
	createMfaFactorSet,
	createMfaSubjectLeases,
	leaseMsFor,
	type MfaFactorSetWrites,
} from "#/factorSet.mjs";
import { createMfaEnrollmentWitness } from "#/witness.mjs";
import { suiteSealing } from "./routesHarness.mjs";

const SUBJECT = "u-alice";
const STORE_TIMEOUT_MS = 1_000;
const LEASE_SPENT = "too little of the subject's lease was left to start this write";

const NO_FACTORS: MfaFactorResolver = {
	get: () => undefined,
	entries: () => new Map().entries(),
};

const RECORD: MfaFactorRecord = {
	id: "AAAAAAAAAAAAAAAAAAAAAA",
	subject: SUBJECT,
	kind: "totp",
	label: undefined,
	binding: "password",
	createdAt: new Date(0),
	lastUsedAt: undefined,
	version: 0,
	data: "sealed",
};

/**
 * `body` run with the factor store of a bind's writes, over core's memory
 * stores; `spend()` moves the lease's monotonic clock past its whole time.
 */
async function withinBind(
	factorStore: MfaFactorStore,
	body: (store: MfaFactorSetWrites["factorStore"], spend: () => void) => Promise<void>,
): Promise<void> {
	let nowMs = 0;
	const factorSet = createMfaFactorSet({
		factors: NO_FACTORS,
		factorStore,
		witness: createMfaEnrollmentWitness(undefined),
		leases: createMfaSubjectLeases({
			store: createMemoryMfaTransactionStore(),
			storeTimeoutMs: STORE_TIMEOUT_MS,
			monotonicNow: () => nowMs,
		}),
		sealing: suiteSealing(),
	});
	const start = await factorSet.begin(SUBJECT, "change");
	let ran = false;
	await factorSet.bind(start, SUBJECT, async (writes) => {
		ran = true;
		await body(writes.factorStore, () => {
			nowMs += leaseMsFor(STORE_TIMEOUT_MS);
		});
	});
	expect(ran, "the bind ran its write under the lease").toBe(true);
}

describe("the factor store a bind's writes go through", () => {
	it("reads the set through the lease's read: listVersioned, as list, refused once the lease's time is spent, the store not asked", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const list = vi.spyOn(factorStore, "list");
		const listVersioned = vi.spyOn(factorStore, "listVersioned");
		await withinBind(factorStore, async (store, spend) => {
			spend();
			await expect(store.list(SUBJECT)).rejects.toThrow(LEASE_SPENT);
			await expect(store.listVersioned(SUBJECT)).rejects.toThrow(LEASE_SPENT);
		});
		expect(list).not.toHaveBeenCalled();
		expect(listVersioned).not.toHaveBeenCalled();
	});

	it("starts createIf and removeIf, as create and remove, only while the lease allows a write: refused once it is spent, the store not asked", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const create = vi.spyOn(factorStore, "create");
		const remove = vi.spyOn(factorStore, "remove");
		const createIf = vi.spyOn(factorStore, "createIf");
		const removeIf = vi.spyOn(factorStore, "removeIf");
		await withinBind(factorStore, async (store, spend) => {
			spend();
			await expect(store.create(RECORD)).rejects.toThrow(LEASE_SPENT);
			await expect(store.remove(SUBJECT, RECORD.id)).rejects.toThrow(LEASE_SPENT);
			await expect(store.createIf(RECORD, null)).rejects.toThrow(LEASE_SPENT);
			await expect(store.removeIf(SUBJECT, RECORD.id, "g-read" as StoreGeneration)).rejects.toThrow(
				LEASE_SPENT,
			);
		});
		expect(create).not.toHaveBeenCalled();
		expect(remove).not.toHaveBeenCalled();
		expect(createIf).not.toHaveBeenCalled();
		expect(removeIf).not.toHaveBeenCalled();
		expect(await factorStore.listVersioned(SUBJECT)).toStrictEqual({
			generation: null,
			items: [],
		});
	});

	it("passes listVersioned, createIf and removeIf to the store with the lease's time left, their arguments and answers unchanged", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const listVersioned = vi.spyOn(factorStore, "listVersioned");
		const createIf = vi.spyOn(factorStore, "createIf");
		const removeIf = vi.spyOn(factorStore, "removeIf");
		await withinBind(factorStore, async (store) => {
			expect(await store.listVersioned(SUBJECT)).toStrictEqual({ generation: null, items: [] });
			expect(listVersioned).toHaveBeenCalledExactlyOnceWith(SUBJECT);

			const created = await store.createIf(RECORD, null);
			expect(createIf).toHaveBeenCalledExactlyOnceWith(RECORD, null);
			expect(createIf.mock.calls[0]?.[0]).toBe(RECORD);
			expect(created).toBe(await createIf.mock.results[0]?.value);
			if (created.outcome !== "created") throw new Error("the create was refused");

			const removed = await store.removeIf(SUBJECT, RECORD.id, created.generation);
			expect(removeIf).toHaveBeenCalledExactlyOnceWith(SUBJECT, RECORD.id, created.generation);
			expect(removed).toBe(await removeIf.mock.results[0]?.value);
			expect(removed.outcome).toBe("removed");
		});
	});
});
