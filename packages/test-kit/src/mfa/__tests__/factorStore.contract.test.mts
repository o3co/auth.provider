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
 * The factor store's contract suite, run over core's in-process store. Each
 * broken store below is refused by the case that describes what it breaks,
 * so the suite is not vacuous.
 */

import {
	createMemoryMfaFactorStore,
	isMfaFactorId,
	type MfaFactorRecord,
	type MfaFactorStore,
	type StoreGeneration,
} from "@o3co/auth-provider-core";
import { describe, expect, expectTypeOf, it } from "vitest";
import { type ContractCase, type MfaFactorStoreHarness, mfaFactorStoreContract } from "#/index.mjs";

describe("mfaFactorStoreContract over core's in-process store", () => {
	for (const contractCase of mfaFactorStoreContract({
		build: async () => ({ store: createMemoryMfaFactorStore() }),
	})) {
		it(contractCase.name, contractCase.run);
	}
});

const UNREACHABLE_NOT_RUN = "not run: the outage case (unreachable not declared)";
const OUTAGE =
	"rejects every member when it cannot reach its backend, and answers none as no factors, null or done";

/** A store over the same backend that cannot reach it: every member rejects, or, `answers`, the record members answer as if empty. */
function unreachableStore(answers = false): MfaFactorStore {
	const down = async (): Promise<never> => {
		throw new Error("ECONNREFUSED");
	};
	return answers
		? {
				kind: "unreachable-answering",
				list: async () => [],
				listVersioned: down,
				createIf: down,
				removeIf: down,
				update: async () => null,
				removeAllForSubject: down,
			}
		: {
				kind: "unreachable",
				list: down,
				listVersioned: down,
				createIf: down,
				removeIf: down,
				update: down,
				removeAllForSubject: down,
			};
}

const SUCCESSFUL_UPDATE_ALONE =
	"a successful update writes its own record alone: the same id under another subject, and the subject's other factors, stay as they were";

/** Core's in-process store with `change` laid over it. */
function broken(change: (store: MfaFactorStore) => Partial<MfaFactorStore>): MfaFactorStoreHarness {
	const store = createMemoryMfaFactorStore();
	return { store: { ...store, ...change(store) } };
}

/** The names of the cases that refuse the store `build` makes. */
async function refusedBy(build: () => MfaFactorStoreHarness): Promise<string[]> {
	const refused: string[] = [];
	for (const contractCase of mfaFactorStoreContract({ build: async () => build() })) {
		try {
			await contractCase.run();
		} catch {
			refused.push(contractCase.name);
		}
	}
	return refused;
}

describe("the suite refuses a store that breaks the contract", () => {
	it("one that leaves an undefined field out of what it lists", async () => {
		const refused = await refusedBy(() =>
			broken((store) => ({
				list: async (subject) =>
					(await store.list(subject)).map(
						(record) =>
							Object.fromEntries(
								Object.entries(record).filter(([, value]) => value !== undefined),
							) as unknown as MfaFactorRecord,
					),
			})),
		);
		expect(refused).toContain(
			"returns a created record whole, as plain data, its undefined fields named",
		);
	});

	it("one that rewrites data", async () => {
		const refused = await refusedBy(() =>
			broken((store) => ({
				createIf: (record, expected) =>
					store.createIf({ ...record, data: record.data.toUpperCase() }, expected),
			})),
		);
		expect(refused).toContain("keeps data verbatim: the store never reads it");
	});

	it("one that overwrites a duplicate", async () => {
		const refused = await refusedBy(() =>
			broken((store) => ({
				createIf: async (record, expected) => {
					const held = (await store.list(record.subject)).some(({ id }) => id === record.id);
					if (held && expected !== null) {
						const removed = await store.removeIf(record.subject, record.id, expected);
						if (removed.outcome === "removed") return store.createIf(record, removed.generation);
					}
					return store.createIf(record, expected);
				},
			})),
		);
		expect(refused).toContain(
			"refuses a duplicate (subject, id) at the current generation, and keeps the record as it was",
		);
	});

	it("one whose compare-and-set lets every writer win", async () => {
		const refused = await refusedBy(() =>
			broken((store) => ({
				update: async (subject, id, expectedVersion, next) => {
					const written = await store.update(subject, id, expectedVersion, next);
					if (written !== null) return written;
					const current = (await store.list(subject)).find((record) => record.id === id);
					return current === undefined ? null : store.update(subject, id, current.version, next);
				},
			})),
		);
		expect(refused).toContain("lets exactly one of N concurrent updates at one version win");
	});

	it("one that changes a field an update does not carry", async () => {
		const refused = await refusedBy(() =>
			broken((store) => ({
				update: async (subject, id, expectedVersion, next) => {
					const written = await store.update(subject, id, expectedVersion, next);
					return written === null ? null : { ...written, kind: "changed" };
				},
			})),
		);
		expect(refused).toContain(
			"updates at the current version: data, label and lastUsedAt replaced, version + 1, nothing else moved",
		);
	});

	it("one that reaches another subject's record through update", async () => {
		const refused = await refusedBy(() =>
			broken((store) => ({
				update: async (_subject, id, expectedVersion, next) => {
					for (const subject of ["user-1", "user-2"]) {
						const written = await store.update(subject, id, expectedVersion, next);
						if (written !== null) return written;
					}
					return null;
				},
			})),
		);
		expect(refused).toContain("never reaches another subject's record through update");
	});

	it("one whose successful update also writes the same id under another subject", async () => {
		const refused = await refusedBy(() =>
			broken((store) => ({
				update: async (subject, id, expectedVersion, next) => {
					const written = await store.update(subject, id, expectedVersion, next);
					if (written === null) return null;
					for (const other of ["user-1", "user-2"].filter((name) => name !== subject)) {
						const theirs = (await store.list(other)).find((record) => record.id === id);
						if (theirs !== undefined) await store.update(other, id, theirs.version, next);
					}
					return written;
				},
			})),
		);
		expect(refused).toContain(SUCCESSFUL_UPDATE_ALONE);
	});

	it("one whose successful update also writes the subject's other factors", async () => {
		const refused = await refusedBy(() =>
			broken((store) => ({
				update: async (subject, id, expectedVersion, next) => {
					const written = await store.update(subject, id, expectedVersion, next);
					if (written === null) return null;
					for (const sibling of (await store.list(subject)).filter((record) => record.id !== id)) {
						await store.update(subject, sibling.id, sibling.version, next);
					}
					return written;
				},
			})),
		);
		expect(refused).toContain(SUCCESSFUL_UPDATE_ALONE);
	});

	it("one that removes every subject's records", async () => {
		const refused = await refusedBy(() =>
			broken((store) => ({
				removeAllForSubject: async () => {
					await store.removeAllForSubject("user-1");
					await store.removeAllForSubject("user-2");
				},
			})),
		);
		expect(refused).toContain(
			"removes every record of one subject, idempotently, and no other subject's",
		);
	});

	it("one that answers an update at Number.MAX_SAFE_INTEGER with null rather than a RangeError", async () => {
		const refused = await refusedBy(() =>
			broken((store) => ({
				update: async (subject, id, expectedVersion, next) =>
					expectedVersion === Number.MAX_SAFE_INTEGER
						? null
						: store.update(subject, id, expectedVersion, next),
			})),
		);
		expect(refused).toContain(
			"refuses, with a RangeError, an update at Number.MAX_SAFE_INTEGER — the next version would be no safe integer — and changes nothing, whatever the stored version; the update that reaches it passes",
		);
	});
});

describe("the suite's records", () => {
	it("carry ids in the shape the provider makes one, which a Store's wire codec requires", async () => {
		const seen: MfaFactorRecord[] = [];
		const store = createMemoryMfaFactorStore();
		for (const contractCase of mfaFactorStoreContract({
			build: async () => ({
				store: {
					...store,
					createIf: async (record: MfaFactorRecord, expected: StoreGeneration | null) => {
						seen.push(record);
						return store.createIf(record, expected);
					},
				},
			}),
		})) {
			await contractCase.run().catch(() => {});
		}
		expect(seen.length).toBeGreaterThan(0);
		for (const record of seen) expect(isMfaFactorId(record.id), record.id).toBe(true);
	});

	it("are typed as the kit's ContractCase", () => {
		expectTypeOf(
			mfaFactorStoreContract({ build: async () => ({ store: createMemoryMfaFactorStore() }) }),
		).toEqualTypeOf<readonly ContractCase[]>();
	});
});

describe("the suite's outage case", () => {
	it("is named as not run, and runs none, when unreachable is not declared", () => {
		const names = (supports?: { unreachable?: boolean }) =>
			mfaFactorStoreContract({
				build: async () => ({ store: createMemoryMfaFactorStore() }),
				...(supports === undefined ? {} : { supports }),
			}).map((contractCase) => contractCase.name);
		expect(names()).toContain(UNREACHABLE_NOT_RUN);
		expect(names()).not.toContain(OUTAGE);
		expect(names({ unreachable: true })).toContain(OUTAGE);
		expect(names({ unreachable: true })).not.toContain(UNREACHABLE_NOT_RUN);
	});

	it("passes a store whose every member rejects out of reach, and refuses one that answers as if empty", async () => {
		const outage = (answers: boolean) =>
			mfaFactorStoreContract({
				build: async () => ({
					store: createMemoryMfaFactorStore(),
					unreachable: () => unreachableStore(answers),
				}),
				supports: { unreachable: true },
			}).find((contractCase) => contractCase.name === OUTAGE);
		await expect(outage(false)?.run()).resolves.toBeUndefined();
		await expect(outage(true)?.run()).rejects.toThrow();
	});

	it("fails for a harness that declares unreachable and does not give it", async () => {
		const outage = mfaFactorStoreContract({
			build: async () => ({ store: createMemoryMfaFactorStore() }),
			supports: { unreachable: true },
		}).find((contractCase) => contractCase.name === OUTAGE);
		await expect(outage?.run()).rejects.toThrow(/unreachable/);
	});
});

describe("the suite's concurrent cases", () => {
	it("split their writers across the store and the second instance the harness gives", async () => {
		const store = createMemoryMfaFactorStore();
		const used = new Set<string>();
		const tagged = (tag: string): MfaFactorStore => ({
			...store,
			createIf: (record, expected) => {
				used.add(tag);
				return store.createIf(record, expected);
			},
		});
		const race = mfaFactorStoreContract({
			build: async () => ({ store: tagged("store"), second: tagged("second") }),
		}).find(
			(contractCase) =>
				contractCase.name ===
				"lets one of N concurrent creates of one (subject, id) at one generation through",
		);
		await race?.run();
		expect([...used].sort()).toEqual(["second", "store"]);
	});
});

describe("each case", () => {
	it("builds a harness of its own and closes it, whether it passes or fails", async () => {
		let built = 0;
		let closed = 0;
		const cases = mfaFactorStoreContract({
			build: async () => {
				built += 1;
				return {
					store: createMemoryMfaFactorStore(),
					close: async () => {
						closed += 1;
					},
				};
			},
		});
		for (const contractCase of cases) await contractCase.run();
		const building = cases.filter((contractCase) => contractCase.name !== UNREACHABLE_NOT_RUN);
		expect(built).toBe(building.length);
		expect(closed).toBe(building.length);
	});
});
