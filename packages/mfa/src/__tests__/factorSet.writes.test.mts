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
 * The subject's factor set as a bind's writes change it
 * (`MfaFactorSetWriter`): read once under the lease, right after the
 * acquire; each write held to the lease's time and fenced on that read — a
 * write the store refuses is `changed`, never tried again — and the lease
 * sized as the factor-set writer's issue window.
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
import { OUTSIDE_CONTRACT } from "#/ceremony.mjs";
import {
	checkFactorSetStoreTimeout,
	createMfaFactorSet,
	createMfaSubjectLeases,
	leaseMsFor,
	type MfaFactorSetWriter,
} from "#/factorSet.mjs";
import { createMfaEnrollmentWitness } from "#/witness.mjs";
import { addRecord, suiteSealing } from "./routesHarness.mjs";

const SUBJECT = "u-alice";
const STORE_TIMEOUT_MS = 1_000;
const LEASE_SPENT = "too little of the subject's lease was left to start this write";

const NO_FACTORS: MfaFactorResolver = {
	get: () => undefined,
	entries: () => new Map().entries(),
};

/** A record of the subject's, `id` and created `atMs`. */
const recordOf = (id: string, atMs = 0): MfaFactorRecord => ({
	id: id.padEnd(22, "A"),
	subject: SUBJECT,
	kind: "totp",
	label: undefined,
	binding: "password",
	createdAt: new Date(atMs),
	lastUsedAt: undefined,
	version: 0,
	data: "sealed",
});

const RECORD = recordOf("R");

/** The factor set over `factorStore` and core's memory transaction store, its lease's monotonic clock `clock.nowMs`. */
function factorSetOver(factorStore: MfaFactorStore) {
	const clock = { nowMs: 0 };
	const factorSet = createMfaFactorSet({
		factors: NO_FACTORS,
		factorStore,
		witness: createMfaEnrollmentWitness(undefined),
		leases: createMfaSubjectLeases({
			store: createMemoryMfaTransactionStore(),
			storeTimeoutMs: STORE_TIMEOUT_MS,
			monotonicNow: () => clock.nowMs,
		}),
		sealing: suiteSealing(),
	});
	return { factorSet, clock };
}

/**
 * `body` run with the factor set of a bind's writes over `factorStore`;
 * `spend()` moves the lease's monotonic clock past its whole time.
 */
async function withinBind(
	factorStore: MfaFactorStore,
	body: (factors: MfaFactorSetWriter, spend: () => void) => Promise<void>,
): Promise<void> {
	const { factorSet, clock } = factorSetOver(factorStore);
	const start = await factorSet.begin(SUBJECT, "change");
	let ran = false;
	const bound = await factorSet.bind(start, SUBJECT, async (writes) => {
		ran = true;
		await body(writes.factors, () => {
			clock.nowMs += leaseMsFor(STORE_TIMEOUT_MS);
		});
	});
	expect(ran, `the bind ran its write under the lease: ${JSON.stringify(bound)}`).toBe(true);
}

describe("the subject's factor set a bind's writes go through", () => {
	it("is read once, right after the acquire, through listVersioned — never list — and hands the bind its records oldest first", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const newer = recordOf("B", 2_000);
		const older = recordOf("A", 1_000);
		await addRecord(factorStore, newer);
		await addRecord(factorStore, older);
		const list = vi.spyOn(factorStore, "list");
		const listVersioned = vi.spyOn(factorStore, "listVersioned");

		await withinBind(factorStore, async (factors) => {
			expect(factors.records.map((record) => record.id)).toEqual([older.id, newer.id]);
			expect(factors).not.toHaveProperty("generation");
			expect(JSON.stringify(factors)).not.toContain(
				String((await factorStore.listVersioned(SUBJECT)).generation),
			);
		});

		expect(listVersioned).toHaveBeenNthCalledWith(1, SUBJECT);
		expect(list).not.toHaveBeenCalled();
	});

	it("answers an outage, the bind's write never run and nothing written, when the set cannot be read", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const down = new Error("factor store unreachable");
		vi.spyOn(factorStore, "listVersioned").mockRejectedValue(down);
		const createIf = vi.spyOn(factorStore, "createIf");
		const { factorSet } = factorSetOver(factorStore);
		const write = vi.fn(async () => "wrote");

		const bound = await factorSet.bind(await factorSet.begin(SUBJECT, "change"), SUBJECT, write);

		expect(bound).toEqual({
			outcome: "unavailable",
			store: "mfa_factor",
			step: "list",
			cause: down,
		});
		expect(write).not.toHaveBeenCalled();
		expect(createIf).not.toHaveBeenCalled();
	});

	it("answers an outage for a set read outside its port: a record of another subject", async () => {
		const factorStore = createMemoryMfaFactorStore();
		vi.spyOn(factorStore, "listVersioned").mockResolvedValue({
			items: [{ ...RECORD, subject: "u-bob" }],
			generation: "g-1" as StoreGeneration,
		});
		const { factorSet } = factorSetOver(factorStore);
		const write = vi.fn(async () => "wrote");

		const bound = await factorSet.bind(await factorSet.begin(SUBJECT, "change"), SUBJECT, write);

		expect(bound).toMatchObject({ outcome: "unavailable", store: "mfa_factor", step: "list" });
		expect(write).not.toHaveBeenCalled();
	});

	it("starts create, remove and update only while the lease allows a write: refused once it is spent, the store not asked", async () => {
		const factorStore = createMemoryMfaFactorStore();
		await addRecord(factorStore, RECORD);
		const createIf = vi.spyOn(factorStore, "createIf");
		const removeIf = vi.spyOn(factorStore, "removeIf");
		const update = vi.spyOn(factorStore, "update");
		await withinBind(factorStore, async (factors, spend) => {
			spend();
			await expect(factors.create(recordOf("N"))).rejects.toThrow(LEASE_SPENT);
			await expect(factors.remove(RECORD.id)).rejects.toThrow(LEASE_SPENT);
			await expect(
				factors.update(RECORD.id, 0, { data: "next", label: undefined, lastUsedAt: undefined }),
			).rejects.toThrow(LEASE_SPENT);
		});
		expect(createIf).not.toHaveBeenCalled();
		expect(removeIf).not.toHaveBeenCalled();
		expect(update).not.toHaveBeenCalled();
		expect((await factorStore.list(SUBJECT)).map((record) => record.id)).toEqual([RECORD.id]);
	});

	it("fences each write on the read: the first at the generation read — none for a set never written — each later one at the generation the one before answered", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const createIf = vi.spyOn(factorStore, "createIf");
		const removeIf = vi.spyOn(factorStore, "removeIf");
		const other = recordOf("O");
		await withinBind(factorStore, async (factors) => {
			expect(await factors.create(RECORD)).toBe("created");
			expect(await factors.create(other)).toBe("created");
			expect(await factors.remove(RECORD.id)).toBe("removed");
		});
		expect(createIf.mock.calls[0]).toEqual([RECORD, null]);
		const first = await createIf.mock.results[0]?.value;
		expect(createIf.mock.calls[1]).toEqual([other, first.generation]);
		const second = await createIf.mock.results[1]?.value;
		expect(removeIf.mock.calls[0]).toEqual([SUBJECT, RECORD.id, second.generation]);
		expect((await factorStore.list(SUBJECT)).map((record) => record.id)).toEqual([other.id]);
	});

	it("holds its fence across a record's own update: a write after it still lands", async () => {
		const factorStore = createMemoryMfaFactorStore();
		await withinBind(factorStore, async (factors) => {
			expect(await factors.create(RECORD)).toBe("created");
			expect(
				await factors.update(RECORD.id, 0, {
					data: "next",
					label: undefined,
					lastUsedAt: undefined,
				}),
			).toMatchObject({ id: RECORD.id, version: 1, data: "next" });
			expect(await factors.create(recordOf("N"))).toBe("created");
		});
		expect(await factorStore.list(SUBJECT)).toHaveLength(2);
	});

	it.each([
		["a create", (factors: MfaFactorSetWriter) => factors.create(recordOf("N"))],
		["a removal", (factors: MfaFactorSetWriter) => factors.remove(RECORD.id)],
	])(
		"answers %s changed, nothing written and never tried again, when another write of the set landed since the read: a writer past its lease",
		async (_, write) => {
			const factorStore = createMemoryMfaFactorStore();
			await addRecord(factorStore, RECORD);
			const createIf = vi.spyOn(factorStore, "createIf");
			const removeIf = vi.spyOn(factorStore, "removeIf");
			const stale = recordOf("S");
			await withinBind(factorStore, async (factors) => {
				// A writer that read before this one's lease, and outlived its own, lands now.
				await addRecord(factorStore, stale);
				createIf.mockClear();
				expect(await write(factors)).toBe("changed");
				// Every later write of the set is refused alike.
				expect(await factors.create(recordOf("L"))).toBe("changed");
			});
			expect(createIf.mock.calls.length + removeIf.mock.calls.length).toBe(2);
			expect((await factorStore.list(SUBJECT)).map((record) => record.id).sort()).toEqual(
				[RECORD.id, stale.id].sort(),
			);
		},
	);

	it("answers a set reset since the read changed: a write read before a reset never lands after it", async () => {
		const factorStore = createMemoryMfaFactorStore();
		await addRecord(factorStore, RECORD);
		await withinBind(factorStore, async (factors) => {
			await factorStore.removeAllForSubject(SUBJECT);
			expect(await factors.create(recordOf("N"))).toBe("changed");
			expect(await factors.remove(RECORD.id)).toBe("changed");
		});
		expect(await factorStore.list(SUBJECT)).toEqual([]);
	});

	it("gives two first binders that read a set never written one create: the other is changed", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const answers: string[] = [];
		await withinBind(factorStore, async (one) => {
			// A second binder past its lease read the same never-written set.
			await withinBind(factorStore, async (two) => {
				answers.push(await two.create(recordOf("T")));
			});
			answers.push(await one.create(recordOf("O")));
		});
		expect(answers).toEqual(["created", "changed"]);
		expect((await factorStore.list(SUBJECT)).map((record) => record.id)).toEqual([
			recordOf("T").id,
		]);
	});

	it("rejects a removal the store answers missing for: outside its port, never a removal", async () => {
		const factorStore = createMemoryMfaFactorStore();
		await addRecord(factorStore, RECORD);
		vi.spyOn(factorStore, "removeIf").mockResolvedValue({ outcome: "missing" });
		await withinBind(factorStore, async (factors) => {
			await expect(factors.remove(RECORD.id)).rejects.toBe(OUTSIDE_CONTRACT);
		});
	});

	it("rejects a removal from a set never written without asking the store: it holds no record", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const removeIf = vi.spyOn(factorStore, "removeIf");
		await withinBind(factorStore, async (factors) => {
			await expect(factors.remove(RECORD.id)).rejects.toBe(OUTSIDE_CONTRACT);
		});
		expect(removeIf).not.toHaveBeenCalled();
	});

	it("rejects an answer outside the port, as unknown: never created, never changed", async () => {
		const factorStore = createMemoryMfaFactorStore();
		vi.spyOn(factorStore, "createIf").mockResolvedValue({ outcome: "updated" } as never);
		await withinBind(factorStore, async (factors) => {
			await expect(factors.create(RECORD)).rejects.toBeInstanceOf(TypeError);
		});
	});

	it("refuses a record of another subject before the store is asked", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const createIf = vi.spyOn(factorStore, "createIf");
		await withinBind(factorStore, async (factors) => {
			await expect(factors.create({ ...RECORD, subject: "u-bob" })).rejects.toBeInstanceOf(
				RangeError,
			);
		});
		expect(createIf).not.toHaveBeenCalled();
	});
});

describe("a removal through the factor set", () => {
	it("removes only while the set stands as it read it: a write landing after its read makes it 409-bound changed, nothing removed", async () => {
		const factorStore = createMemoryMfaFactorStore();
		await addRecord(factorStore, RECORD);
		const stale = recordOf("S");
		const read = factorStore.listVersioned.bind(factorStore);
		vi.spyOn(factorStore, "listVersioned").mockImplementationOnce(async (subject) => {
			const answer = await read(subject);
			// A writer past its lease lands between the removal's read and its write.
			await addRecord(factorStore, stale);
			return answer;
		});
		const { factorSet } = factorSetOver(factorStore);

		const removal = await factorSet.remove(
			await factorSet.begin(SUBJECT, "change"),
			SUBJECT,
			RECORD.id,
			() => undefined,
		);

		expect(removal).toEqual({ outcome: "changed" });
		expect((await factorStore.list(SUBJECT)).map((record) => record.id).sort()).toEqual(
			[RECORD.id, stale.id].sort(),
		);
	});

	it("answers an outage, nothing read again, when the store answers missing for a record it read", async () => {
		const factorStore = createMemoryMfaFactorStore();
		await addRecord(factorStore, RECORD);
		vi.spyOn(factorStore, "removeIf").mockResolvedValue({ outcome: "missing" });
		const list = vi.spyOn(factorStore, "list");
		const { factorSet } = factorSetOver(factorStore);

		const removal = await factorSet.remove(
			await factorSet.begin(SUBJECT, "change"),
			SUBJECT,
			RECORD.id,
			() => undefined,
		);

		expect(removal).toEqual({
			outcome: "unavailable",
			store: "mfa_factor",
			step: "remove",
			cause: OUTSIDE_CONTRACT,
		});
		expect(list).not.toHaveBeenCalled();
	});
});

describe("the lease as the factor-set writer's issue window", () => {
	it("stands sixteen Store calls' time: mfa.storeTimeoutMs at most 37 500 ms, so a write is issued at most 600 000 ms after the read it is fenced on", () => {
		expect(leaseMsFor(37_500)).toBe(600_000);
		expect(checkFactorSetStoreTimeout(37_500)).toBe(37_500);
		expect(() => checkFactorSetStoreTimeout(37_501)).toThrow(RangeError);
		expect(leaseMsFor(1_000)).toBe(16 * 1_000);
	});
});
