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
} from "@o3co/auth-provider-core";
import { describe, expect, expectTypeOf, it } from "vitest";
import {
	type ContractCase,
	type MfaFactorStoreHarness,
	mfaFactorStoreContract,
} from "#/index.mjs";

describe("mfaFactorStoreContract over core's in-process store", () => {
	for (const contractCase of mfaFactorStoreContract({
		build: async () => ({ store: createMemoryMfaFactorStore() }),
	})) {
		it(contractCase.name, contractCase.run);
	}
});

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
				create: (record) => store.create({ ...record, data: record.data.toUpperCase() }),
			})),
		);
		expect(refused).toContain("keeps data verbatim: the store never reads it");
	});

	it("one that overwrites a duplicate", async () => {
		const refused = await refusedBy(() =>
			broken((store) => ({
				create: async (record) => {
					await store.remove(record.subject, record.id);
					await store.create(record);
				},
			})),
		);
		expect(refused).toContain("refuses a duplicate (subject, id), and keeps the record as it was");
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

	it("one that updates at Number.MAX_SAFE_INTEGER", async () => {
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
					create: async (record: MfaFactorRecord) => {
						seen.push(record);
						await store.create(record);
					},
				},
			}),
		})) {
			await contractCase.run().catch(() => {});
		}
		expect(seen.length).toBeGreaterThan(0);
		for (const record of seen) expect(isMfaFactorId(record.id), record.id).toBe(true);
	});

	it("are run as core's ContractCase, which the kit re-exports", () => {
		expectTypeOf(
			mfaFactorStoreContract({ build: async () => ({ store: createMemoryMfaFactorStore() }) }),
		).toEqualTypeOf<readonly ContractCase[]>();
		expect(true).toBe(true);
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
		expect(built).toBe(cases.length);
		expect(closed).toBe(cases.length);
	});
});
