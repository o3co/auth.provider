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
 * fault is refused by the case that names its class, the generic suite's
 * or the factor set's own.
 *
 * The model keeps an emptied set's tombstone deadline on a clock of its own,
 * which `forceExpire` moves past every deadline: the hook judges and deletes
 * nothing, so what expires is the model's doing.
 *
 * The concurrent faults force their interleaving with explicit barriers, so
 * each schedule is the one the fault needs:
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
	BUNDLED_STORE_WRITE_LIFETIME_MS,
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
	conditionalSetContract,
	type MfaFactorStoreContractInput,
	type MfaFactorStoreHarness,
	mfaFactorStoreConditionalContract,
	mfaFactorStoreContract,
} from "#/index.mjs";

/** An input over one store per case, no second instance, no outage and no expiry. */
const over = (build: () => MfaFactorStore): MfaFactorStoreContractInput => ({
	build: async () => ({ store: build() }),
});

/** Core's in-process store on a clock of its own, which `forceExpire` moves on by the write-lifetime bound. */
const memoryOnItsClock = (): MfaFactorStoreHarness => {
	let nowMs = Date.parse("2026-10-02T00:00:00.000Z");
	return {
		store: createMemoryMfaFactorStore({ now: () => nowMs }),
		forceExpire: async () => {
			nowMs += BUNDLED_STORE_WRITE_LIFETIME_MS;
		},
	};
};

const isNotRun = (contractCase: ContractCase): boolean => contractCase.name.startsWith("not run:");

/**
 * `store` with `members` taken away. Without one of the factor set's members
 * it is outside the port's type, as a store written in JavaScript can be,
 * which the binding refuses when it runs; `create` and `remove` are optional.
 */
const without = (
	store: MfaFactorStore,
	...members: readonly ("listVersioned" | "createIf" | "removeIf" | "create" | "remove")[]
): MfaFactorStore =>
	Object.fromEntries(
		Object.entries(store).filter(([name]) => !(members as readonly string[]).includes(name)),
	) as unknown as MfaFactorStore;

describe("mfaFactorStoreConditionalContract over core's in-process store", () => {
	// No second: the memory store is one process by contract, so this run
	// proves no fence across processes. No unreachable: it has no backend.
	for (const contractCase of mfaFactorStoreConditionalContract({
		build: async () => memoryOnItsClock(),
		supports: { forceExpire: true },
	})) {
		it(contractCase.name, contractCase.run);
	}
});

/** Core's in-process store on its own clock, without the port's optional unconditional `create` and `remove`. */
const memoryWithoutUnconditional = (): MfaFactorStoreHarness => {
	const harness = memoryOnItsClock();
	return { ...harness, store: without(harness.store, "create", "remove") };
};

describe("mfaFactorStoreConditionalContract over a store without the unconditional create and remove", () => {
	for (const contractCase of mfaFactorStoreConditionalContract({
		build: async () => memoryWithoutUnconditional(),
		supports: { forceExpire: true },
	})) {
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
	| "create-upserts-held-id"
	| "counter-generation"
	| "reset-of-empty-keeps-generation"
	| "removed-answers-another-generation"
	| "tombstone-never-expires"
	| "reset-tombstone-never-expires"
	| "expiry-kept-after-write"
	| "recreate-answers-another-generation"
	| "race-winner-stale-generation";

/** A model store and its `forceExpire`. */
interface Model {
	readonly store: MfaFactorStore;
	readonly forceExpire: (subject: string) => Promise<void>;
}

/** How long an emptied set's tombstone stands, on the model's clock. */
const TOMBSTONE_MS = 1_000;

const copyOf = (record: MfaFactorRecord): MfaFactorRecord => ({
	...record,
	createdAt: new Date(record.createdAt.getTime()),
	lastUsedAt: record.lastUsedAt === undefined ? undefined : new Date(record.lastUsedAt.getTime()),
});

/** Resolves once every call made in the current synchronous batch has started. */
const batchStarted = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));

/** A store of factor sets, correct with `none`, and with any other fault broken in that one way. */
function modelStore(fault: Fault): Model {
	interface FactorSet {
		readonly records: Map<string, MfaFactorRecord>;
		generation: StoreGeneration;
		/** Writes since the set was made: a counter's generation. */
		writes: number;
		/** When the tombstone expires, on the model's clock; none while the set holds a record. */
		deadline: number | undefined;
	}
	const sets = new Map<string, FactorSet>();
	const purged = new Set<string>();
	let nowMs = 0;

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

	/** `subject`'s set, unless its tombstone is past its deadline, which drops it. */
	const live = (subject: string): FactorSet | undefined => {
		const set = sets.get(subject);
		if (
			set === undefined ||
			fault === "tombstone-never-expires" ||
			set.deadline === undefined ||
			set.deadline > nowMs
		) {
			return set;
		}
		sets.delete(subject);
		purged.add(subject);
		return undefined;
	};

	const fresh = (set: FactorSet): StoreGeneration => {
		set.writes += 1;
		if (fault === "counter-generation") return String(set.writes) as StoreGeneration;
		return (
			fault === "digest-generation"
				? createHash("sha256")
						.update(JSON.stringify([...set.records.values()].map((r) => [r.id, r.data]).sort()))
						.digest("base64url")
				: randomUUID()
		) as StoreGeneration;
	};

	/** One membership write: `change`, then a new generation and the deadline, then the commit is told. */
	const write = (
		subject: string,
		change: (records: Map<string, MfaFactorRecord>) => void,
	): StoreGeneration => {
		const set = live(subject) ?? {
			records: new Map<string, MfaFactorRecord>(),
			generation: randomUUID() as StoreGeneration,
			writes: 0,
			deadline: undefined,
		};
		change(set.records);
		set.generation = fresh(set);
		if (set.records.size === 0) set.deadline = nowMs + TOMBSTONE_MS;
		else if (fault !== "expiry-kept-after-write") set.deadline = undefined;
		sets.set(subject, set);
		for (const waiter of commitWaiters.splice(0)) waiter();
		return set.generation;
	};

	// Conditional writes started so far: one started while another is in
	// flight contends with it.
	let conditionalStarts = 0;

	/**
	 * `check`'s refusal, or `apply`: in one step, or, with check-then-write,
	 * apart. With race-winner-stale-generation, a write that lands while
	 * another conditional write starts answers the generation `subject`'s set
	 * was at before it.
	 */
	const fenced = async <T extends { readonly outcome: string }>(
		subject: string,
		check: () => T | undefined,
		apply: () => T,
	): Promise<T> => {
		if (fault === "race-winner-stale-generation") {
			conditionalStarts += 1;
			const mine = conditionalStarts;
			const refusal = check();
			if (refusal !== undefined) return refusal;
			const prior = live(subject)?.generation ?? (randomUUID() as StoreGeneration);
			const answer = apply();
			await batchStarted();
			return conditionalStarts > mine ? { ...answer, generation: prior } : answer;
		}
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
		[...(live(subject)?.records.values() ?? [])].map(copyOf);
	const generationOf = (subject: string): StoreGeneration | null =>
		live(subject)?.generation ?? null;

	const store: MfaFactorStore = {
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
				record.subject,
				() => {
					const set = live(record.subject);
					const atExpected = expected === null ? set === undefined : set?.generation === expected;
					const held = set?.records.has(record.id) === true && fault !== "create-upserts-held-id";
					return atExpected && !held ? undefined : ({ outcome: "conflict" } as const);
				},
				() => {
					const generation = write(record.subject, (records) =>
						records.set(record.id, copyOf(record)),
					);
					return {
						outcome: "created" as const,
						generation:
							fault === "recreate-answers-another-generation" && purged.has(record.subject)
								? (randomUUID() as StoreGeneration)
								: generation,
					};
				},
			),
		removeIf: (subject, id, expected) =>
			fenced<ConditionalSetRemoveAnswer>(
				subject,
				() => {
					const set = live(subject);
					if (set === undefined) return { outcome: "missing" } as const;
					if (set.generation !== expected) return { outcome: "conflict" } as const;
					if (set.records.has(id)) return undefined;
					if (fault === "missing-moves-generation") write(subject, () => {});
					return { outcome: "missing" } as const;
				},
				() => {
					const generation = write(subject, (records) => records.delete(id));
					return {
						outcome: "removed" as const,
						generation:
							fault === "removed-answers-another-generation"
								? (randomUUID() as StoreGeneration)
								: generation,
					};
				},
			),
		create: async (record) => {
			if (live(record.subject)?.records.has(record.id) === true) {
				throw new Error("held");
			}
			write(record.subject, (records) => records.set(record.id, copyOf(record)));
		},
		update: async (subject, id, expectedVersion, next) => {
			const set = live(subject);
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
			if (fault === "update-moves-generation") set.generation = fresh(set);
			return copyOf(written);
		},
		remove: async (subject, id) => {
			if (live(subject)?.records.has(id) === true) {
				write(subject, (records) => records.delete(id));
			}
		},
		removeAllForSubject: async (subject) => {
			if (fault === "reset-deletes-set") {
				sets.delete(subject);
				return;
			}
			if (fault === "reset-of-empty-keeps-generation" && live(subject)?.records.size === 0) {
				return;
			}
			write(subject, (records) => records.clear());
			const reset = sets.get(subject);
			if (fault === "reset-tombstone-never-expires" && reset !== undefined) {
				reset.deadline = undefined;
			}
		},
	};
	return {
		store,
		// Moves the clock past every deadline; judges and deletes nothing.
		forceExpire: async () => {
			nowMs += TOMBSTONE_MS;
		},
	};
}

/**
 * How a store out of reach answers: `rejects`, every member, as it must; the
 * others, broken: `answers-empty` as if the set were empty, `lists-undefined`
 * a versioned listing of `undefined`, `update-resolves` an update of `null`,
 * every other member rejecting.
 */
type Outage = "rejects" | "answers-empty" | "lists-undefined" | "update-resolves";

/** A store over the same backend that cannot reach it, answering as `outage` says. */
function unreachableStore(outage: Outage = "rejects"): MfaFactorStore {
	const down = async (): Promise<never> => {
		throw new Error("ECONNREFUSED");
	};
	if (outage !== "answers-empty") {
		return {
			kind: `unreachable:${outage}`,
			list: down,
			listVersioned: outage === "lists-undefined" ? async () => undefined as never : down,
			createIf: down,
			removeIf: down,
			create: down,
			update: outage === "update-resolves" ? async () => null : down,
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

/** The names of the cases that refuse the harness `build` makes, beside an unreachable store that rejects. */
async function refusedBy(
	build: () => Omit<MfaFactorStoreHarness, "unreachable">,
	unreachable: () => MfaFactorStore = () => unreachableStore(),
): Promise<string[]> {
	const refused: string[] = [];
	for (const contractCase of mfaFactorStoreConditionalContract({
		build: async () => ({ ...build(), unreachable }),
		supports: { unreachable: true, forceExpire: true },
	})) {
		try {
			await contractCase.run();
		} catch {
			refused.push(contractCase.name);
		}
	}
	return refused;
}

/** The generic suite's cases a fault below is refused by, and the factor set's own. */
const CASE = {
	firstCreates: "of two concurrent first creates through two instances, exactly one is created",
	resetAbsent:
		"a reset of a set never written leaves it empty at a generation, so a first create then answers conflict",
	lastMember:
		"removing the last member keeps the set, empty, at the new generation removed answers",
	twoRemovals:
		"of two concurrent removals of different members at one generation through two instances, exactly one is removed",
	manyCreates:
		"of concurrent creates of different members at one generation, exactly one is created",
	removalRacingCreate:
		"a removal racing a create at one generation, either started first: exactly one wins",
	resetEmpty:
		"a reset of a set already empty moves its generation: the emptying one then answers conflict",
	resetAfterRead: "a reset after a read moves the generation: the read one then answers conflict",
	aba: "a member removed and created again with the same bytes leaves no generation repeated, and the first answers conflict",
	missing:
		"removing a member not held answers missing, keeps the generation, and the generation still writes",
	snapshot:
		"a versioned set read is one snapshot: read with a concurrent create, its members and generation are both before or both after",
	held: "a create of a member already held, at the current generation, answers conflict and changes nothing",
	updateMember: "a member's own update changes that member and keeps the set's generation",
	tombstoneExpired:
		"an emptied set whose tombstone expired reads as absent, and a write with no read after the expiry finds it absent",
	heldSet:
		"a set that holds a member does not expire, one revived from its tombstone included: the clock moved past every deadline leaves it as it was",
	recreate:
		"a set created again after its tombstone expired is at a generation it is then read at, never one seen before",
	outage: "a store that cannot reach its backend rejects every member",
	update: "an update keeps the set's generation, and a write at it still lands",
	legacy:
		"where the store still provides create and remove: create refuses a held id and keeps the record and the generation; remove is idempotent and moves the generation only when it removes",
	tombstone:
		"a tombstone stands: a late first binding and a late write at a generation read before the reset are refused, and write nothing",
	unconditional:
		"every unconditional membership write that changes the members moves the generation: the old one then answers conflict",
	race: "the winner of a race answers the generation the set is then read at: two first bindings, two removals, many creates, a removal and a create, split across both instances",
	resetExpiry:
		"a reset's tombstone expires: a set reset, and a set never written reset, read as absent once the clock passes the deadline, and a re-create repeats neither tombstone's generation",
} as const;

describe("the binding refuses a store that breaks the factor set's fence", () => {
	it("passes the model store with no fault, and a store without the set's members fails every case", async () => {
		expect(await refusedBy(() => modelStore("none"))).toEqual([]);
		expect(await refusedBy(memoryOnItsClock)).toEqual([]);
		const withoutMembers = without(
			createMemoryMfaFactorStore(),
			"listVersioned",
			"createIf",
			"removeIf",
		);
		const cases = mfaFactorStoreConditionalContract({
			build: async () => ({ store: withoutMembers }),
			supports: { unreachable: true, forceExpire: true },
		});
		expect(await refusedBy(() => ({ store: withoutMembers, forceExpire: async () => {} }))).toEqual(
			cases.map((contractCase) => contractCase.name),
		);
	});

	it("runs the unconditional cases over create and remove only when the store has them", async () => {
		const unreachableWithout = () => without(unreachableStore(), "create", "remove");
		expect(await refusedBy(memoryWithoutUnconditional, unreachableWithout)).toEqual([]);
		const createRefusing = (): MfaFactorStoreHarness => {
			const harness = memoryOnItsClock();
			const create = async (): Promise<void> => {
				throw new Error("refused");
			};
			return { ...harness, store: { ...harness.store, create } };
		};
		expect(await refusedBy(createRefusing)).toContain(CASE.unconditional);
		const removeIgnoring = (): MfaFactorStoreHarness => {
			const harness = memoryOnItsClock();
			const remove = async (): Promise<void> => {};
			return { ...harness, store: { ...harness.store, remove } };
		};
		expect(await refusedBy(removeIgnoring)).toContain(CASE.unconditional);
	});

	it("holds a store's own create and remove to their promises when it still provides them", async () => {
		const createOverwriting = (): MfaFactorStoreHarness => {
			const harness = memoryOnItsClock();
			const { store } = harness;
			const create = async (record: MfaFactorRecord): Promise<void> => {
				await store.remove?.(record.subject, record.id);
				await store.create?.(record);
			};
			return { ...harness, store: { ...store, create } };
		};
		expect(await refusedBy(createOverwriting)).toContain(CASE.legacy);
		expect(await refusedBy(memoryOnItsClock)).not.toContain(CASE.legacy);
	});

	const faults: ReadonlyArray<readonly [string, Fault, readonly string[]]> = [
		[
			"one that checks, then writes after an await: two writers both pass the check",
			"check-then-write",
			[CASE.firstCreates, CASE.twoRemovals, CASE.manyCreates, CASE.removalRacingCreate],
		],
		[
			"one whose generation is a digest of the set: it repeats when the set does",
			"digest-generation",
			[CASE.aba],
		],
		[
			"one whose reset deletes the set",
			"reset-deletes-set",
			[CASE.resetAbsent, CASE.resetAfterRead, CASE.tombstone],
		],
		[
			"one whose update moves the set's generation",
			"update-moves-generation",
			[CASE.updateMember, CASE.update],
		],
		[
			"one whose snapshot reads the records, then the generation, apart",
			"torn-list-records-first",
			[CASE.snapshot],
		],
		[
			"one whose snapshot reads the generation, then the records, apart",
			"torn-list-generation-first",
			[CASE.snapshot],
		],
		[
			"one whose create of a held id, at the current generation, overwrites it",
			"create-upserts-held-id",
			[CASE.held],
		],
		[
			"one whose generation is a counter, which repeats once its tombstone is purged",
			"counter-generation",
			[CASE.recreate],
		],
		[
			"one whose reset of an emptied set keeps its generation",
			"reset-of-empty-keeps-generation",
			[CASE.resetEmpty],
		],
		[
			"one whose removal answers a generation other than the one it wrote",
			"removed-answers-another-generation",
			[CASE.lastMember],
		],
		[
			"one whose create after a purge answers a generation other than the one it wrote",
			"recreate-answers-another-generation",
			[CASE.recreate],
		],
		["one whose tombstone never expires", "tombstone-never-expires", [CASE.tombstoneExpired]],
		[
			"one whose tombstone never expires when a reset left it",
			"reset-tombstone-never-expires",
			[CASE.resetExpiry],
		],
		[
			"one that keeps a tombstone's deadline on a set written to after it",
			"expiry-kept-after-write",
			[CASE.heldSet],
		],
		[
			"one whose removal of a record not there moves the generation",
			"missing-moves-generation",
			[CASE.missing],
		],
	];

	for (const [what, fault, refusing] of faults) {
		it(what, async () => {
			expect(await refusedBy(() => modelStore(fault))).toEqual(
				expect.arrayContaining([...refusing]),
			);
		});
	}

	it("one whose race winner answers a stale generation under contention, refused by the race case alone", async () => {
		expect(await refusedBy(() => modelStore("race-winner-stale-generation"))).toEqual([CASE.race]);
	});

	const outages: ReadonlyArray<readonly [string, Outage]> = [
		["one that answers, out of reach, as if the set were empty", "answers-empty"],
		["one that answers, out of reach, a versioned listing of undefined", "lists-undefined"],
		["one whose update, out of reach, resolves", "update-resolves"],
	];
	for (const [what, outage] of outages) {
		it(what, async () => {
			expect(
				await refusedBy(
					() => modelStore("none"),
					() => unreachableStore(outage),
				),
			).toEqual([CASE.outage]);
		});
	}
});

describe("the binding", () => {
	it("is the generic set suite, every case of it run, then the factor set's own", () => {
		const generic = conditionalSetContract<MfaFactorRecord>({
			build: async () => {
				throw new Error("never built");
			},
			items: () => [],
			idOf: (record) => record.id,
			scopeOf: (record) => record.subject,
			mutate: () => {},
			supports: {
				forceExpire: true,
				unreachable: true,
				updateMember: true,
				list: true,
				unconditional: true,
			},
		}).map((contractCase) => contractCase.name);
		const names = mfaFactorStoreConditionalContract({
			build: async () => ({ store: createMemoryMfaFactorStore() }),
			supports: { unreachable: true, forceExpire: true },
		}).map((contractCase) => contractCase.name);
		expect(generic.filter((name) => name.startsWith("not run:"))).toEqual([]);
		expect(names).toEqual([
			...generic,
			CASE.update,
			CASE.legacy,
			CASE.tombstone,
			CASE.race,
			CASE.resetExpiry,
		]);
	});

	it("calls the harness's hooks on the harness, so one that uses this keeps working", async () => {
		class Harness implements MfaFactorStoreHarness {
			private nowMs = Date.parse("2026-10-02T00:00:00.000Z");
			private readonly down = unreachableStore();
			readonly store = createMemoryMfaFactorStore({ now: () => this.nowMs });
			closed = false;
			unreachable(): MfaFactorStore {
				return this.down;
			}
			async forceExpire(): Promise<void> {
				this.nowMs += BUNDLED_STORE_WRITE_LIFETIME_MS;
			}
			async close(): Promise<void> {
				this.closed = true;
			}
		}
		const built: Harness[] = [];
		const input: MfaFactorStoreContractInput = {
			build: async () => {
				const harness = new Harness();
				built.push(harness);
				return harness;
			},
			supports: { unreachable: true, forceExpire: true },
		};
		for (const contractCase of [
			...mfaFactorStoreConditionalContract(input),
			...mfaFactorStoreContract(input),
		]) {
			await contractCase.run();
		}
		expect(built.length).toBeGreaterThan(0);
		expect(built.every((harness) => harness.closed)).toBe(true);
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
					return store.createIf(record, expected);
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
			counting(() => without(createMemoryMfaFactorStore(), "listVersioned")),
		);
		for (const contractCase of failing) await contractCase.run().catch(() => {});
		const building = (list: readonly ContractCase[]): number =>
			list.filter((contractCase) => !isNotRun(contractCase)).length;
		expect(built).toBe(building(cases) + building(failing));
		expect(closed).toBe(built);
	});

	it("names in passing cases the cases a hook not declared leaves out, and runs none of them", async () => {
		const names = (supports?: MfaFactorStoreContractInput["supports"]) =>
			mfaFactorStoreConditionalContract({
				build: async () => ({ store: createMemoryMfaFactorStore() }),
				...(supports === undefined ? {} : { supports }),
			}).map((contractCase) => contractCase.name);
		const expiry = [CASE.tombstoneExpired, CASE.heldSet, CASE.recreate, CASE.resetExpiry];
		const notRun = (cases: readonly string[]) =>
			cases.filter((name) => name.startsWith("not run:"));
		const none = names();
		expect(notRun(none)).toEqual([
			"not run: the tombstone expiry case (supports.forceExpire not declared)",
			"not run: the held-set expiry case (supports.forceExpire not declared)",
			"not run: the re-create after expiry case (supports.forceExpire not declared)",
			"not run: the outage case (supports.unreachable not declared)",
			"not run: the reset tombstone expiry case (supports.forceExpire not declared)",
		]);
		for (const name of [...expiry, CASE.outage]) expect(none).not.toContain(name);
		expect(none).toContain(CASE.tombstone);
		expect(notRun(names({ forceExpire: true }))).toEqual([
			"not run: the outage case (supports.unreachable not declared)",
		]);
		const both = names({ unreachable: true, forceExpire: true });
		expect(notRun(both)).toEqual([]);
		for (const name of [...expiry, CASE.outage]) expect(both).toContain(name);
		for (const marker of mfaFactorStoreConditionalContract(over(createMemoryMfaFactorStore)).filter(
			isNotRun,
		)) {
			await expect(marker.run()).resolves.toBeUndefined();
		}
	});

	it("fails each expiry case of a harness that declares forceExpire and does not give it", async () => {
		const cases = mfaFactorStoreConditionalContract({
			build: async () => ({ store: createMemoryMfaFactorStore() }),
			supports: { forceExpire: true },
		});
		for (const name of [CASE.tombstoneExpired, CASE.resetExpiry]) {
			const expired = cases.find((contractCase) => contractCase.name === name);
			await expect(expired?.run(), name).rejects.toThrow(/forceExpire/);
		}
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
				return store.removeIf(subject, id, expected);
			},
		});
		const race = mfaFactorStoreConditionalContract({
			build: async () => ({ store: tagged("store"), second: tagged("second") }),
		}).find((contractCase) => contractCase.name === CASE.twoRemovals);
		await race?.run();
		expect([...used].sort()).toEqual(["second", "store"]);
	});
});
