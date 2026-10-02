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
 * The factor set's conditional-write binding, run over core's in-process
 * store, and the proof that it is not vacuous: a model store, correct with
 * no fault, and with each fault the bug class a real Store can have. Each
 * fault is refused by the case that names its class.
 *
 * The concurrent faults force their interleaving with explicit barriers, so
 * each schedule is the one the fault needs, every run:
 *
 * - check-then-write: every write of one batch of calls checks first, then
 *   all of them write (the batch's start, then a rendezvous of its checks);
 * - a torn snapshot: a read pauses between its two halves until the write
 *   started beside it has committed.
 *
 * They prove the cases catch each class for the schedule forced. They do not
 * prove a database's isolation: that is the Store's own run of the binding,
 * on its backend, with `second` a second instance.
 */

import { createHash, randomUUID } from "node:crypto";
import {
	type ConditionalCreateAnswer,
	type ConditionalSetRemoveAnswer,
	createMemoryMfaFactorStore,
	isMfaFactorId,
	type MfaFactorRecord,
	type MfaFactorStore,
	type StoreGeneration,
} from "@o3co/auth-provider-core";
import { describe, expect, expectTypeOf, it } from "vitest";
import {
	type ContractCase,
	type MfaFactorStoreContractInput,
	mfaFactorStoreConditionalContract,
} from "#/index.mjs";

/** An input over one store per case, no second instance and no outage: one process is one instance. */
const over = (build: () => MfaFactorStore): MfaFactorStoreContractInput => ({
	build: async () => ({ store: build() }),
});

const UNREACHABLE_NOT_RUN = "not run: the outage case (unreachable not declared)";

describe("mfaFactorStoreConditionalContract over core's in-process store", () => {
	// No second: the memory store is one process by contract, so this run
	// proves no fence across processes. No unreachable: it has no backend.
	for (const contractCase of mfaFactorStoreConditionalContract(over(createMemoryMfaFactorStore))) {
		it(contractCase.name, contractCase.run);
	}
});

type Fault =
	| "none"
	| "check-then-write"
	| "digest-generation"
	| "reset-deletes-set"
	| "update-moves-generation"
	| "torn-list-records-first"
	| "torn-list-generation-first"
	| "missing-moves-generation"
	| "create-upserts-held-id";

const copyOf = (record: MfaFactorRecord): MfaFactorRecord => ({
	...record,
	createdAt: new Date(record.createdAt.getTime()),
	lastUsedAt: record.lastUsedAt === undefined ? undefined : new Date(record.lastUsedAt.getTime()),
});

/** Resolves once every call made in the current synchronous batch has started. */
const batchStarted = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));

/** A store of factor sets, correct with `none`, and with any other fault broken in that one way. */
function modelStore(fault: Fault): MfaFactorStore {
	const sets = new Map<
		string,
		{ readonly records: Map<string, MfaFactorRecord>; generation: StoreGeneration }
	>();

	// The torn snapshot's barrier: a read's second half waits for the commit
	// of a write started beside it, or, with none, for its batch to run.
	const commitWaiters: Array<() => void> = [];
	const nextCommitOrIdle = (): Promise<void> =>
		new Promise((resolve) => {
			commitWaiters.push(resolve);
			setImmediate(resolve);
		});

	// The check-then-write barrier: a write waits, once it has checked, until
	// every write in flight has checked.
	let inFlight = 0;
	let checked = 0;
	const checkWaiters: Array<() => void> = [];
	const everyWriteChecked = (): Promise<void> => {
		checked += 1;
		if (checked < inFlight) return new Promise((resolve) => checkWaiters.push(resolve));
		for (const waiter of checkWaiters.splice(0)) waiter();
		return Promise.resolve();
	};

	const fresh = (records: Map<string, MfaFactorRecord>): StoreGeneration =>
		(fault === "digest-generation"
			? createHash("sha256")
					.update(JSON.stringify([...records.values()].map((r) => [r.id, r.data]).sort()))
					.digest("base64url")
			: randomUUID()) as StoreGeneration;

	/** One membership write: `change`, then a new generation, then the commit is told. */
	const write = (
		subject: string,
		change: (records: Map<string, MfaFactorRecord>) => void,
	): StoreGeneration => {
		const set = sets.get(subject) ?? {
			records: new Map<string, MfaFactorRecord>(),
			generation: "" as StoreGeneration,
		};
		change(set.records);
		set.generation = fresh(set.records);
		sets.set(subject, set);
		for (const waiter of commitWaiters.splice(0)) waiter();
		return set.generation;
	};

	/** `check`'s refusal, or `apply`: in one step, or, with check-then-write, apart. */
	const fenced = async <T,>(check: () => T | undefined, apply: () => T): Promise<T> => {
		if (fault !== "check-then-write") return check() ?? apply();
		inFlight += 1;
		try {
			await batchStarted();
			const refusal = check();
			await everyWriteChecked();
			return refusal ?? apply();
		} finally {
			inFlight -= 1;
			checked -= 1;
		}
	};

	const itemsOf = (subject: string): MfaFactorRecord[] =>
		[...(sets.get(subject)?.records.values() ?? [])].map(copyOf);
	const generationOf = (subject: string): StoreGeneration | null =>
		sets.get(subject)?.generation ?? null;

	return {
		kind: `model:${fault}`,
		list: async (subject) => itemsOf(subject),
		listVersioned: async (subject) => {
			if (fault === "torn-list-records-first") {
				const items = itemsOf(subject);
				await nextCommitOrIdle();
				return { generation: generationOf(subject), items };
			}
			if (fault === "torn-list-generation-first") {
				const generation = generationOf(subject);
				await nextCommitOrIdle();
				return { generation, items: itemsOf(subject) };
			}
			return { generation: generationOf(subject), items: itemsOf(subject) };
		},
		createIf: (record, expected) =>
			fenced<ConditionalCreateAnswer>(
				() => {
					const set = sets.get(record.subject);
					const atExpected = expected === null ? set === undefined : set?.generation === expected;
					const held = set?.records.has(record.id) === true && fault !== "create-upserts-held-id";
					return atExpected && !held ? undefined : ({ outcome: "conflict" } as const);
				},
				() => ({
					outcome: "created" as const,
					generation: write(record.subject, (records) => records.set(record.id, copyOf(record))),
				}),
			),
		removeIf: (subject, id, expected) =>
			fenced<ConditionalSetRemoveAnswer>(
				() => {
					const set = sets.get(subject);
					if (set === undefined) return { outcome: "missing" } as const;
					if (set.generation !== expected) return { outcome: "conflict" } as const;
					if (set.records.has(id)) return undefined;
					if (fault === "missing-moves-generation") write(subject, () => {});
					return { outcome: "missing" } as const;
				},
				() => ({
					outcome: "removed" as const,
					generation: write(subject, (records) => records.delete(id)),
				}),
			),
		create: async (record) => {
			if (sets.get(record.subject)?.records.has(record.id) === true) {
				throw new Error("held");
			}
			write(record.subject, (records) => records.set(record.id, copyOf(record)));
		},
		update: async (subject, id, expectedVersion, next) => {
			const set = sets.get(subject);
			const current = set?.records.get(id);
			if (set === undefined || current === undefined || current.version !== expectedVersion) {
				return null;
			}
			const written: MfaFactorRecord = {
				...current,
				data: next.data,
				label: next.label,
				lastUsedAt: next.lastUsedAt,
				version: current.version + 1,
			};
			set.records.set(id, written);
			if (fault === "update-moves-generation") set.generation = fresh(set.records);
			return copyOf(written);
		},
		remove: async (subject, id) => {
			if (sets.get(subject)?.records.has(id) === true) {
				write(subject, (records) => records.delete(id));
			}
		},
		removeAllForSubject: async (subject) => {
			if (fault === "reset-deletes-set") {
				sets.delete(subject);
				return;
			}
			write(subject, (records) => records.clear());
		},
	};
}

/** A store over the same backend that cannot reach it: every member rejects, or, `answers`, answers as if empty. */
function unreachableStore(answers = false): MfaFactorStore {
	const down = async (): Promise<never> => {
		throw new Error("ECONNREFUSED");
	};
	if (!answers) {
		return {
			kind: "unreachable",
			list: down,
			listVersioned: down,
			createIf: down,
			removeIf: down,
			create: down,
			update: down,
			remove: down,
			removeAllForSubject: down,
		};
	}
	return {
		kind: "unreachable-answering",
		list: async () => [],
		listVersioned: async () => ({ generation: null, items: [] }),
		createIf: async () => ({ outcome: "conflict" }),
		removeIf: async () => ({ outcome: "missing" }),
		create: down,
		update: async () => null,
		remove: async () => {},
		removeAllForSubject: down,
	};
}

/** The names of the cases that refuse the store `build` makes, beside an unreachable one that rejects. */
async function refusedBy(
	build: () => MfaFactorStore,
	unreachable: () => MfaFactorStore = () => unreachableStore(),
): Promise<string[]> {
	const refused: string[] = [];
	for (const contractCase of mfaFactorStoreConditionalContract({
		build: async () => ({ store: build(), unreachable }),
		supports: { unreachable: true },
	})) {
		try {
			await contractCase.run();
		} catch {
			refused.push(contractCase.name);
		}
	}
	return refused;
}

const CASE = {
	firstBindings:
		"lets exactly one of two concurrent first bindings through, one from each instance",
	heldId:
		"a create of an id the set holds, at the current generation, is a conflict that changes nothing",
	outage:
		"rejects every set member when it cannot reach its backend, and answers none as an empty set, missing or conflict",
	reset: "a reset leaves the set at a new generation, so a first binding after it is a conflict",
	update: "an update keeps the set's generation, and a write at it still lands",
	twoRemovals:
		"two removals of different records at one generation, one from each instance: one removed, the other a conflict that keeps its record",
	manyCreates:
		"concurrent creates of different records at one generation: exactly one created, the set one larger",
	removalRacingCreate:
		"a removal racing a create at one generation: exactly one wins, and the set is the winner's",
	aba: "a set taken back to the same records answers conflict at the generation read before it, and no generation repeats",
	resetFences:
		"a reset fences every write read before it, and leaves a set never written at a generation",
	missing:
		"missing writes nothing: the generation stays and a write at it lands; an absent set answers missing to a removal and conflict to a create",
	snapshot:
		"a snapshot read beside a create is one snapshot: without the record its generation is fenced, with it the create's generation",
} as const;

describe("the binding refuses a store that breaks the factor set's fence", () => {
	it("passes the model store with no fault, and a store without the set's members fails every case", async () => {
		expect(await refusedBy(() => modelStore("none"))).toEqual([]);
		expect(await refusedBy(createMemoryMfaFactorStore)).toEqual([]);
		const plain = createMemoryMfaFactorStore();
		const withoutMembers: MfaFactorStore = {
			kind: plain.kind,
			list: (subject) => plain.list(subject),
			create: (record) => plain.create(record),
			update: (subject, id, version, next) => plain.update(subject, id, version, next),
			remove: (subject, id) => plain.remove(subject, id),
			removeAllForSubject: (subject) => plain.removeAllForSubject(subject),
		};
		const cases = mfaFactorStoreConditionalContract({
			build: async () => ({ store: withoutMembers }),
			supports: { unreachable: true },
		});
		expect(await refusedBy(() => withoutMembers)).toEqual(
			cases.map((contractCase) => contractCase.name),
		);
	});

	it("(a) one that checks, then writes after an await: two writers both pass the check", async () => {
		const refused = await refusedBy(() => modelStore("check-then-write"));
		expect(refused).toEqual(
			expect.arrayContaining([
				CASE.firstBindings,
				CASE.twoRemovals,
				CASE.manyCreates,
				CASE.removalRacingCreate,
			]),
		);
	});

	it("(b) one whose generation is a digest of the set: it repeats when the set does", async () => {
		expect(await refusedBy(() => modelStore("digest-generation"))).toContain(CASE.aba);
	});

	it("(c) one whose reset deletes the set", async () => {
		const refused = await refusedBy(() => modelStore("reset-deletes-set"));
		expect(refused).toEqual(expect.arrayContaining([CASE.reset, CASE.resetFences]));
	});

	it("(d) one whose update moves the set's generation", async () => {
		expect(await refusedBy(() => modelStore("update-moves-generation"))).toContain(CASE.update);
	});

	it("(e) one whose snapshot reads the records, then the generation, apart", async () => {
		expect(await refusedBy(() => modelStore("torn-list-records-first"))).toContain(CASE.snapshot);
	});

	it("(e) one whose snapshot reads the generation, then the records, apart", async () => {
		expect(await refusedBy(() => modelStore("torn-list-generation-first"))).toContain(
			CASE.snapshot,
		);
	});

	it("one whose create of a held id, at the current generation, overwrites it", async () => {
		expect(await refusedBy(() => modelStore("create-upserts-held-id"))).toContain(CASE.heldId);
	});

	it("one that answers, out of reach, as if the set were empty", async () => {
		expect(
			await refusedBy(
				() => modelStore("none"),
				() => unreachableStore(true),
			),
		).toEqual([CASE.outage]);
	});

	it("(f) one whose removal of a record not there moves the generation", async () => {
		expect(await refusedBy(() => modelStore("missing-moves-generation"))).toContain(CASE.missing);
	});
});

describe("the binding's records", () => {
	it("carry ids in the shape the provider makes one, which a Store's wire codec requires", async () => {
		const seen: MfaFactorRecord[] = [];
		const watched = (): MfaFactorStore => {
			const store = createMemoryMfaFactorStore();
			return {
				...store,
				createIf: (record, expected) => {
					seen.push(record);
					return store.createIf?.(record, expected) ?? Promise.reject(new Error("no createIf"));
				},
			};
		};
		for (const contractCase of mfaFactorStoreConditionalContract(over(watched))) {
			await contractCase.run();
		}
		expect(seen.length).toBeGreaterThan(0);
		for (const record of seen) expect(isMfaFactorId(record.id), record.id).toBe(true);
	});

	it("are typed as core's ContractCase, which the kit re-exports", () => {
		expectTypeOf(mfaFactorStoreConditionalContract(over(createMemoryMfaFactorStore))).toEqualTypeOf<
			readonly ContractCase[]
		>();
	});
});

describe("each case", () => {
	it("builds a harness of its own and closes it, whether it passes or fails", async () => {
		let built = 0;
		let closed = 0;
		const counting = (store: () => MfaFactorStore): MfaFactorStoreContractInput => ({
			build: async () => {
				built += 1;
				return {
					store: store(),
					close: async () => {
						closed += 1;
					},
				};
			},
		});
		const cases = mfaFactorStoreConditionalContract(counting(createMemoryMfaFactorStore));
		for (const contractCase of cases) await contractCase.run();
		const failing = mfaFactorStoreConditionalContract(
			counting(() => ({ ...createMemoryMfaFactorStore(), listVersioned: undefined })),
		);
		for (const contractCase of failing) await contractCase.run().catch(() => {});
		const building = (list: readonly ContractCase[]): number =>
			list.filter((contractCase) => contractCase.name !== UNREACHABLE_NOT_RUN).length;
		expect(built).toBe(building(cases) + building(failing));
		expect(closed).toBe(built);
	});

	it("names the outage case as not run, and runs none, when unreachable is not declared", async () => {
		const names = mfaFactorStoreConditionalContract(over(createMemoryMfaFactorStore)).map(
			(contractCase) => contractCase.name,
		);
		expect(names).toContain(UNREACHABLE_NOT_RUN);
		expect(names).not.toContain(CASE.outage);
		const declared = mfaFactorStoreConditionalContract({
			build: async () => ({
				store: createMemoryMfaFactorStore(),
				unreachable: () => unreachableStore(),
			}),
			supports: { unreachable: true },
		}).map((contractCase) => contractCase.name);
		expect(declared).toContain(CASE.outage);
		expect(declared).not.toContain(UNREACHABLE_NOT_RUN);
	});

	it("fails the outage case of a harness that declares unreachable and does not give it", async () => {
		const outage = mfaFactorStoreConditionalContract({
			build: async () => ({ store: createMemoryMfaFactorStore() }),
			supports: { unreachable: true },
		}).find((contractCase) => contractCase.name === CASE.outage);
		await expect(outage?.run()).rejects.toThrow(/unreachable/);
	});

	it("splits a race across the store and the second instance the harness gives", async () => {
		const store = createMemoryMfaFactorStore();
		const used = new Set<string>();
		const tagged = (tag: string): MfaFactorStore => ({
			...store,
			removeIf: (subject, id, expected) => {
				used.add(tag);
				return store.removeIf?.(subject, id, expected) ?? Promise.reject(new Error("none"));
			},
		});
		const race = mfaFactorStoreConditionalContract({
			build: async () => ({ store: tagged("store"), second: tagged("second") }),
		}).find((contractCase) => contractCase.name === CASE.twoRemovals);
		await race?.run();
		expect([...used].sort()).toEqual(["second", "store"]);
	});
});
