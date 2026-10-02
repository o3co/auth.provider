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
 * The generic conditional-write suites, run over a reference record store and
 * a reference set store, and over each of them broken one way at a time:
 * every rule the suites hold a store to has a broken store the case for that
 * rule refuses, so no case is vacuous. Each reference store serves two
 * instances over one backend, as two connections would, keeps retention
 * deadlines on a clock of its own, which `forceExpire` moves past every
 * deadline, and judges expiry itself.
 */

import { createHash } from "node:crypto";
import {
	type ConditionalCreateAnswer,
	type ConditionalRemoveAnswer,
	type ConditionalReplaceAnswer,
	type ConditionalSetRemoveAnswer,
	newStoreGeneration,
	type StoreGeneration,
	type Versioned,
	type VersionedSet,
} from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import {
	type ConditionalRecordContractInput,
	type ConditionalRecordHarness,
	type ConditionalRecordTarget,
	type ConditionalSetContractInput,
	type ConditionalSetHarness,
	type ConditionalSetTarget,
	type ContractCase,
	conditionalRecordContract,
	conditionalSetContract,
} from "#/index.mjs";

/** The names of the cases that fail. */
async function refusedBy(cases: readonly ContractCase[]): Promise<string[]> {
	const refused: string[] = [];
	for (const contractCase of cases) {
		try {
			await contractCase.run();
		} catch {
			refused.push(contractCase.name);
		}
	}
	return refused;
}

/** One microtask: the gap a store with an `await` in a step it must make atomic leaves open. */
const gap = (): Promise<void> => Promise.resolve();

const outage = (): Promise<never> => Promise.reject(new Error("unreachable"));

// ---------------------------------------------------------------------------
// The record store
// ---------------------------------------------------------------------------

interface Value {
	name: string;
	at: Date;
}

const VALUES = (): readonly [Value, Value] => [
	{ name: "first", at: new Date("2026-10-01T00:00:00.000Z") },
	{ name: "second", at: new Date("2026-10-02T00:00:00.000Z") },
];

/** Changes each mutable part on its own, leaving a part that is frozen. */
const MUTATE = (value: Value): void => {
	try {
		value.name = "mutated";
	} catch {
		// A frozen copy.
	}
	value.at.setTime(0);
};

/** How a record store is broken: each flag breaks one rule. */
interface RecordFaults {
	/** A versioned read of a key never written answers a value. */
	readonly absentAnswersValue?: boolean;
	/** A value is kept without one of its fields. */
	readonly lossy?: boolean;
	/** A replace answers updated and keeps the generation. */
	readonly replaceKeepsGeneration?: boolean;
	/** A replace never checks the generation. */
	readonly replaceIgnoresExpected?: boolean;
	/** A replace of an absent key creates it. */
	readonly createOnMissing?: boolean;
	/** A removal never checks the generation. */
	readonly removeIgnoresExpected?: boolean;
	/** The generation is a counter that restarts when the key is created again. */
	readonly counter?: boolean;
	/** The generation is a digest of the value. */
	readonly digest?: boolean;
	/** A replace skips the lock the other writes take: its check and its write are apart. */
	readonly replaceSkipsLock?: boolean;
	/** A removal skips the lock the other writes take: its check and its write are apart. */
	readonly removeSkipsLock?: boolean;
	/** The unconditional delete skips the lock the other writes take. */
	readonly deleteSkipsLock?: boolean;
	/** The unconditional delete rejects the first value, so it races only with the second. */
	readonly deleteRefusesFirst?: boolean;
	/** The unconditional delete rewrites the record at a new generation and keeps it. */
	readonly deleteRewrites?: boolean;
	/** The unconditional put writes the value outside the lock, then moves the generation under it. */
	readonly putTorn?: boolean;
	/** Reads drop an expired record, and writes do not check expiry. */
	readonly writesIgnoreExpiry?: boolean;
	/** The second instance answers a versioned read from its own cache. */
	readonly secondCaches?: boolean;
	/** Not a fault: every value read is frozen, and its own copy. */
	readonly frozen?: boolean;
	/**
	 * Not a fault: a write that fails its check labels its answer from a read
	 * taken before it waited for the lock, as one SQL statement with a CTE
	 * does: `conflict` if that read saw the record, `missing` if not.
	 */
	readonly labelsFromSnapshot?: boolean;
	/** A value read is frozen, and shares its date with what is stored. */
	readonly frozenSharesDate?: boolean;
	/** An unconditional write keeps the generation when the value changes. */
	readonly legacyKeepsGenerationOnChange?: boolean;
	/** The unreachable target names no unconditional write. */
	readonly unreachableDropsWrites?: boolean;
	/** An unconditional write keeps the generation. */
	readonly legacyKeepsGeneration?: boolean;
	/** A versioned read takes the value and the generation apart, with an `await` between. */
	readonly tornRead?: "value-first" | "generation-first";
	/** A replace that answers conflict writes anyway. */
	readonly writeOnConflict?: boolean;
	/** A removal of an absent key answers an outcome outside the type. */
	readonly malformedMissing?: boolean;
	/** A value is stored and answered as the caller's own object. */
	readonly alias?: boolean;
	/** A create over a live record keeps its generation. */
	readonly createKeepsGeneration?: boolean;
	/** The store ignores its own deadline. */
	readonly deadlineIgnored?: boolean;
	/** An outage is answered as absent. */
	readonly outageAsMissing?: boolean;
}

/** A record's retention, on the backend's clock. */
const RECORD_TTL_MS = 60_000;

interface RecordEntry {
	value: Value;
	generation: StoreGeneration;
	/** When the record expires, on the backend's clock. */
	deadline: number;
}

/** A lock per key, as a row lock would be: `body` runs once every earlier holder of `key` is done. */
function keyLocks() {
	const tails = new Map<string, Promise<void>>();
	return async <R,>(key: string, body: () => Promise<R>): Promise<R> => {
		const before = tails.get(key) ?? Promise.resolve();
		let release = (): void => {};
		const held = new Promise<void>((resolve) => {
			release = resolve;
		});
		const tail = before.then(() => held);
		tails.set(key, tail);
		await before;
		try {
			return await body();
		} finally {
			release();
			if (tails.get(key) === tail) tails.delete(key);
		}
	};
}

/** A record backend, and a target over it per call to `target`. */
function recordBackend(faults: RecordFaults = {}) {
	const entries = new Map<string, RecordEntry>();
	const counters = new Map<string, number>();
	const locked = keyLocks();
	let now = 0;
	/** Runs `body` under `key`'s lock, unless the write skips it. */
	const serialised = <R,>(key: string, body: () => Promise<R>, skips = false): Promise<R> =>
		skips ? body() : locked(key, body);
	const copy = (value: Value): Value =>
		faults.alias === true
			? value
			: faults.lossy === true
				? ({ name: value.name } as Value)
				: { name: value.name, at: new Date(value.at.getTime()) };
	const issue = (key: string, value: Value): StoreGeneration => {
		if (faults.counter === true) {
			const next = (counters.get(key) ?? 0) + 1;
			counters.set(key, next);
			return `c${next}` as StoreGeneration;
		}
		if (faults.digest === true) {
			return createHash("sha256")
				.update(JSON.stringify(value))
				.digest("hex")
				.slice(0, 32) as StoreGeneration;
		}
		return newStoreGeneration();
	};
	const drop = (key: string): void => {
		entries.delete(key);
		counters.delete(key);
	};
	/** Writes `value` at a new generation: a replace keeps the record's deadline, a create starts one. */
	const write = (key: string, value: Value, creates = false): StoreGeneration => {
		const generation = issue(key, value);
		const held = creates ? undefined : entries.get(key)?.deadline;
		const deadline = held ?? now + RECORD_TTL_MS;
		entries.set(key, { value: copy(value), generation, deadline });
		return generation;
	};
	/** The record, unless it is past its deadline: a read drops it, and so does a write unless writes ignore expiry. */
	const live = (key: string, forWrite: boolean): RecordEntry | undefined => {
		const entry = entries.get(key);
		if (entry === undefined || faults.deadlineIgnored === true || entry.deadline > now)
			return entry;
		if (forWrite && faults.writesIgnoreExpiry === true) return entry;
		drop(key);
		return undefined;
	};
	/** How a write that fails its check answers: by what it found, or by a read taken before the lock. */
	const refusal = (key: string) => {
		const seen = faults.labelsFromSnapshot === true ? live(key, false) !== undefined : undefined;
		return (found: "missing" | "conflict"): { outcome: "missing" | "conflict" } => ({
			outcome: seen === undefined ? found : seen ? "conflict" : "missing",
		});
	};
	const out = (value: Value): Value =>
		faults.frozenSharesDate === true
			? Object.freeze({ ...value })
			: faults.frozen === true
				? Object.freeze(copy(value))
				: copy(value);

	const target = (instance: number): ConditionalRecordTarget<Value> => {
		const cache = new Map<string, Versioned<Value>>();
		const read = async (key: string): Promise<Versioned<Value> | null> => {
			const entry = live(key, false);
			if (entry === undefined) {
				return faults.absentAnswersValue === true
					? { value: VALUES()[0], generation: newStoreGeneration() }
					: null;
			}
			if (faults.tornRead === "value-first") {
				const value = out(entry.value);
				await gap();
				const current = entries.get(key);
				return current === undefined ? null : { value, generation: current.generation };
			}
			if (faults.tornRead === "generation-first") {
				const generation = entry.generation;
				await gap();
				const current = entries.get(key);
				return current === undefined ? null : { value: out(current.value), generation };
			}
			return { value: out(entry.value), generation: entry.generation };
		};
		return {
			create: (key, value) =>
				serialised(key, async () => {
					const held = live(key, true);
					if (faults.createKeepsGeneration === true && held !== undefined) {
						entries.set(key, { ...held, value: copy(value) });
						return;
					}
					write(key, value, true);
				}),
			async getVersioned(key) {
				if (faults.secondCaches === true && instance === 1) {
					const cached = cache.get(key);
					if (cached !== undefined) return cached;
					const fresh = await read(key);
					if (fresh !== null) cache.set(key, fresh);
					return fresh;
				}
				return read(key);
			},
			replaceIf: (key, expected, value) => {
				const refused = refusal(key);
				return serialised(
					key,
					async (): Promise<ConditionalReplaceAnswer> => {
						const entry = live(key, true);
						if (entry === undefined) {
							if (faults.createOnMissing === true)
								return { outcome: "updated", generation: write(key, value) };
							return refused("missing");
						}
						if (entry.generation !== expected && faults.replaceIgnoresExpected !== true) {
							if (faults.writeOnConflict === true) write(key, value);
							return refused("conflict");
						}
						// A round trip inside the step, as a transaction's would be.
						await gap();
						if (faults.replaceKeepsGeneration === true) {
							entries.set(key, { ...entry, value: copy(value) });
							return { outcome: "updated", generation: entry.generation };
						}
						return { outcome: "updated", generation: write(key, value) };
					},
					faults.replaceSkipsLock,
				);
			},
			removeIf: (key, expected) => {
				const refused = refusal(key);
				return serialised(
					key,
					async (): Promise<ConditionalRemoveAnswer> => {
						const entry = live(key, true);
						if (entry === undefined) {
							return faults.malformedMissing === true
								? ({ outcome: "absent" } as unknown as ConditionalRemoveAnswer)
								: refused("missing");
						}
						if (entry.generation !== expected && faults.removeIgnoresExpected !== true) {
							return refused("conflict");
						}
						await gap();
						drop(key);
						return { outcome: "removed" };
					},
					faults.removeSkipsLock,
				);
			},
			unconditional: {
				put: async (key, value) => {
					const held = entries.get(key);
					if (faults.putTorn === true && held !== undefined) {
						held.value = copy(value);
						await serialised(key, async () => {
							const current = entries.get(key);
							if (current !== undefined) current.generation = issue(key, current.value);
						});
						return;
					}
					return serialised(key, async () => {
						const held = live(key, true);
						const keeps =
							faults.legacyKeepsGeneration === true ||
							(faults.legacyKeepsGenerationOnChange === true &&
								held !== undefined &&
								held.value.name !== value.name);
						if (keeps && held !== undefined) {
							entries.set(key, { ...held, value: copy(value) });
							return;
						}
						write(key, value, true);
					});
				},
				delete: (key, value) => {
					if (faults.deleteRefusesFirst === true && value.name === VALUES()[0].name) {
						return outage();
					}
					return serialised(
						key,
						async () => {
							const held = entries.get(key);
							if (faults.deleteRewrites === true && held !== undefined) write(key, held.value);
							else drop(key);
						},
						faults.deleteSkipsLock,
					);
				},
			},
		};
	};

	const unreachable = (): ConditionalRecordTarget<Value> =>
		faults.outageAsMissing === true
			? {
					create: outage,
					getVersioned: async () => null,
					replaceIf: async () => ({ outcome: "missing" }),
					removeIf: async () => ({ outcome: "missing" }),
					unconditional: { put: outage, delete: outage },
				}
			: {
					create: outage,
					getVersioned: outage,
					replaceIf: outage,
					removeIf: outage,
					unconditional:
						faults.unreachableDropsWrites === true ? {} : { put: outage, delete: outage },
				};

	return {
		target,
		/** Moves the clock past every deadline the store set; judges and deletes nothing. */
		forceExpire: async (_key: string) => {
			now += RECORD_TTL_MS;
		},
		unreachable,
	};
}

/** A harness over a fresh backend: two instances, and every hook. */
function recordHarness(faults: RecordFaults = {}): ConditionalRecordHarness<Value> {
	const backend = recordBackend(faults);
	return {
		store: backend.target(0),
		second: backend.target(1),
		forceExpire: backend.forceExpire,
		unreachable: backend.unreachable,
	};
}

const recordInput = (faults: RecordFaults = {}): ConditionalRecordContractInput<Value> => ({
	build: async () => recordHarness(faults),
	values: VALUES,
	mutate: MUTATE,
	removals: ["delete"],
	supports: { forceExpire: true, unreachable: true, unconditional: true },
});

describe("conditionalRecordContract over the reference record store", () => {
	for (const contractCase of conditionalRecordContract(recordInput())) {
		it(contractCase.name, contractCase.run);
	}
});

const RECORD = {
	absent: "a versioned read of a key never written answers null",
	created: "a created record is read back whole, at a well-formed generation",
	replace:
		"a replace at the current generation answers updated, at a new generation the record is then read at",
	stale: "a replace at a stale generation answers conflict and changes nothing",
	neverCreates:
		"a replace never creates: an absent key and a removed one answer missing and stay absent",
	remove:
		"a removal answers removed at the current generation, conflict at a stale one, and missing for an absent key",
	aba: "a record removed and created again with the same value is at a new generation, and the old one answers conflict",
	sameValue: "a replace with the same value still issues a new generation",
	race: "of concurrent replaces at one generation through two instances, exactly one is updated",
	removeRace:
		"of concurrent removals at one generation through two instances, exactly one is removed",
	mixedRace:
		"a replace racing a removal at one generation, either started first: exactly one wins, and the record is what the winner left",
	unconditional:
		"every unconditional write, a byte-identical rewrite included, moves or ends the generation: the old one then answers conflict or missing",
	unconditionalRace:
		"an unconditional write racing a replace at one generation, either started first, is serialised with it: a removal leaves the record absent, and no replace outlives the write",
	snapshot:
		"a versioned read is one snapshot: read with a concurrent replace, its value and generation are both before or both after",
	nothingWritten:
		"missing and conflict write nothing: the current generation still writes afterwards",
	readers: "every answer is one core's readers accept",
	overwrite:
		"a create over a live record, as a relink does, issues a new generation, the same value included, and the old one answers conflict",
	crossInstance:
		"a write through one instance is read through the other at the generation it answered, and the old generation conflicts there",
	alias: "the store keeps its own copy: changing a value written or read changes nothing stored",
	expiry:
		"an expired record reads as gone, and answers missing to a replace and to a removal made with no read after the expiry",
	outage:
		"a store that cannot reach its backend rejects every member, never answering null or missing",
} as const;

describe("conditionalRecordContract refuses a record store that breaks a rule", () => {
	const cases: ReadonlyArray<readonly [string, RecordFaults, string]> = [
		["a read of an absent key that answers a value", { absentAnswersValue: true }, RECORD.absent],
		["a store that drops a field", { lossy: true }, RECORD.created],
		["a replace that keeps the generation", { replaceKeepsGeneration: true }, RECORD.replace],
		["a replace that ignores the generation", { replaceIgnoresExpected: true }, RECORD.stale],
		["a replace that creates on missing", { createOnMissing: true }, RECORD.neverCreates],
		["a removal that ignores the generation", { removeIgnoresExpected: true }, RECORD.remove],
		["a counter that restarts at a re-create", { counter: true }, RECORD.aba],
		["a digest of the value", { digest: true }, RECORD.aba],
		["a digest of the value, on a same-value replace", { digest: true }, RECORD.sameValue],
		["a replace that skips the lock", { replaceSkipsLock: true }, RECORD.race],
		[
			"a replace that skips the lock, against a removal",
			{ replaceSkipsLock: true },
			RECORD.mixedRace,
		],
		[
			"a removal that skips the lock, against a replace",
			{ removeSkipsLock: true },
			RECORD.mixedRace,
		],
		[
			"a removal that skips the lock, against a removal",
			{ removeSkipsLock: true },
			RECORD.removeRace,
		],
		[
			"an unconditional delete that skips the lock, against a replace",
			{ deleteSkipsLock: true },
			RECORD.unconditionalRace,
		],
		[
			"an unconditional delete that skips the lock and refuses the first value",
			{ deleteSkipsLock: true, deleteRefusesFirst: true },
			RECORD.unconditionalRace,
		],
		[
			"an unconditional delete that keeps the record",
			{ deleteRewrites: true },
			RECORD.unconditional,
		],
		[
			"an unconditional put that writes the value before it takes the lock",
			{ putTorn: true },
			RECORD.unconditionalRace,
		],
		["writes that do not check expiry", { writesIgnoreExpiry: true }, RECORD.expiry],
		["a second instance that reads from a cache", { secondCaches: true }, RECORD.crossInstance],
		[
			"an unconditional write that keeps the generation",
			{ legacyKeepsGeneration: true },
			RECORD.unconditional,
		],
		["a read of the value, then the generation", { tornRead: "value-first" }, RECORD.snapshot],
		["a read of the generation, then the value", { tornRead: "generation-first" }, RECORD.snapshot],
		["a replace that writes on conflict", { writeOnConflict: true }, RECORD.nothingWritten],
		["an answer outside the type", { malformedMissing: true }, RECORD.readers],
		["a value shared with the caller", { alias: true }, RECORD.alias],
		[
			"a frozen value that shares its date with the store",
			{ frozenSharesDate: true },
			RECORD.alias,
		],
		[
			"an unconditional write that keeps the generation when the value changes",
			{ legacyKeepsGenerationOnChange: true },
			RECORD.unconditional,
		],
		["an unreachable target that names no write", { unreachableDropsWrites: true }, RECORD.outage],
		[
			"a create in place that keeps the generation",
			{ createKeepsGeneration: true },
			RECORD.overwrite,
		],
		["a store that ignores its own deadline", { deadlineIgnored: true }, RECORD.expiry],
		["an outage answered as absent", { outageAsMissing: true }, RECORD.outage],
	];
	for (const [what, faults, refusing] of cases) {
		it(`${what}: refused by "${refusing}"`, async () => {
			expect(await refusedBy(conditionalRecordContract(recordInput(faults)))).toContain(refusing);
		});
	}

	it("a store that answers frozen values passes every case", async () => {
		expect(await refusedBy(conditionalRecordContract(recordInput({ frozen: true })))).toEqual([]);
	});

	it("a store whose losing write labels its answer from a read taken before its lock passes every case", async () => {
		expect(
			await refusedBy(conditionalRecordContract(recordInput({ labelsFromSnapshot: true }))),
		).toEqual([]);
	});

	it("every case of the suite refuses one of the broken stores", () => {
		const named = conditionalRecordContract(recordInput())
			.map((contractCase) => contractCase.name)
			.filter((name) => !name.startsWith("not run:"));
		expect(new Set(cases.map(([, , refusing]) => refusing))).toEqual(new Set(named));
	});
});

describe("conditionalRecordContract's declared hooks", () => {
	const names = (input: Partial<ConditionalRecordContractInput<Value>>) =>
		conditionalRecordContract({ ...recordInput(), ...input }).map(
			(contractCase) => contractCase.name,
		);

	it("leaves out the cases of an undeclared hook, and names what was not run", async () => {
		const cases = conditionalRecordContract({
			build: async () => ({ store: recordBackend().target(0) }),
			values: VALUES,
		});
		const listed = cases.map((contractCase) => contractCase.name);
		expect(listed).not.toContain(RECORD.expiry);
		expect(listed).not.toContain(RECORD.outage);
		expect(listed).not.toContain(RECORD.alias);
		expect(listed).toEqual(
			expect.arrayContaining([
				"not run: the expiry case (supports.forceExpire not declared)",
				"not run: the outage case (supports.unreachable not declared)",
				"not run: the unconditional-write case (supports.unconditional not declared)",
				"not run: the unconditional-write race case (supports.unconditional not declared)",
				"not run: the aliasing case (no mutate given)",
			]),
		);
		expect(listed).not.toContain(RECORD.unconditional);
		expect(listed).not.toContain(RECORD.unconditionalRace);
		expect(await refusedBy(cases)).toEqual([]);
	});

	it("fails the case of a hook declared and missing from the harness", async () => {
		const cases = conditionalRecordContract({
			...recordInput(),
			build: async () => ({ store: recordBackend().target(0) }),
		});
		expect(await refusedBy(cases)).toEqual([RECORD.expiry, RECORD.outage]);
		expect(names({ supports: {} })).not.toContain(RECORD.expiry);
	});

	it("fails the unconditional-write case when it is declared and the target names no write", async () => {
		const cases = conditionalRecordContract({
			...recordInput(),
			build: async () => ({
				...recordHarness(),
				store: { ...recordBackend().target(0), unconditional: {} },
			}),
		});
		const refused = await refusedBy(cases);
		expect(refused).toContain(RECORD.unconditional);
		expect(refused).toContain(RECORD.unconditionalRace);
	});
});

// ---------------------------------------------------------------------------
// The set store
// ---------------------------------------------------------------------------

interface Item {
	readonly scope: string;
	readonly id: string;
	data: string;
}

const ITEMS = (scope: string, n: number): readonly Item[] =>
	Array.from({ length: n }, (_, i) => ({ scope, id: `item-${i}`, data: `data-${i}` }));

/** Changes an item's data, leaving a frozen item. */
const MUTATE_ITEM = (item: Item): void => {
	try {
		item.data = "mutated";
	} catch {
		// A frozen copy.
	}
};

/** How a set store is broken: each flag breaks one rule. */
interface SetFaults {
	/** A set never written answers a generation. */
	readonly absentAnswersGeneration?: boolean;
	/** A create's check and its write are apart, with an `await` between. */
	readonly createCheckThenWrite?: boolean;
	/** A removal's check and its write are apart, with an `await` between. */
	readonly removeCheckThenWrite?: boolean;
	/** A reset of a set already empty changes nothing. */
	readonly resetEmptyNoop?: boolean;
	/** A reset clears the members, then moves the generation, in two steps. */
	readonly resetTwoSteps?: boolean;
	/** A member's own update changes nothing. */
	readonly updateNoop?: boolean;
	/** A member is stored and answered as the caller's own object. */
	readonly alias?: boolean;
	/** Reads drop an expired set, and writes do not check expiry. */
	readonly writesIgnoreExpiry?: boolean;
	/** A removal does not check expiry. */
	readonly removeIgnoresExpiry?: boolean;
	/** The unreachable target names no unconditional write. */
	readonly unreachableDropsWrites?: boolean;
	/** The second instance answers a versioned read from its own cache. */
	readonly secondCaches?: boolean;
	/** The plain listing leaves a member out. */
	readonly listDisagrees?: boolean;
	/** Not a fault: every member read is frozen. */
	readonly frozen?: boolean;
	/** Not a fault: every other read lists the members in reverse. */
	readonly reordered?: boolean;
	/** A reset deletes the set, leaving no tombstone. */
	readonly resetDeletes?: boolean;
	/** A reset empties the set and keeps its generation. */
	readonly resetKeepsGeneration?: boolean;
	/** A member's own update moves the set's generation. */
	readonly updateMoves?: boolean;
	/** A create never checks the generation. */
	readonly createIgnoresExpected?: boolean;
	/** Removing the last member deletes the set. */
	readonly lastRemovalDeletes?: boolean;
	/** The generation is a digest of the members. */
	readonly digest?: boolean;
	/** Removing a member not held moves the generation. */
	readonly absentMemberMoves?: boolean;
	/** A create with a generation, against an absent set, creates it. */
	readonly absentSetCreates?: boolean;
	/** A versioned read takes the members and the generation apart, with an `await` between. */
	readonly tornRead?: "items-first" | "generation-first";
	/** The versioned read lists a reserved entry as a member. */
	readonly leaksReserved?: boolean;
	/** An unconditional membership write keeps the generation. */
	readonly legacyKeepsGeneration?: boolean;
	/** A removal of a member not held answers an outcome outside the type. */
	readonly malformedMissing?: boolean;
	/** A create of a held id overwrites it. */
	readonly upsertHeld?: boolean;
	/** The store ignores its own deadline. */
	readonly deadlineIgnored?: boolean;
	/** A set revived from its tombstone keeps the tombstone's deadline. */
	readonly revivedKeepsDeadline?: boolean;
	/** The generation is a counter per scope that restarts once the set expires. */
	readonly counterRestarts?: boolean;
	/** A create after the set expired answers the generation the set had before, not the one it issued. */
	readonly recreateAnswersStale?: boolean;
	/** An outage is answered as an empty set. */
	readonly outageAsMissing?: boolean;
}

/** An emptied set's retention, on the backend's clock. */
const TOMBSTONE_MS = 60_000;

interface SetEntry {
	generation: StoreGeneration;
	readonly members: Map<string, Item>;
	/** When an emptied set's tombstone expires, on the backend's clock; none while it holds a member. */
	deadline?: number;
}

/** A set backend, and a target over it per call to `target`. */
function setBackend(faults: SetFaults = {}) {
	const sets = new Map<string, SetEntry>();
	const counters = new Map<string, number>();
	const expired = new Map<string, StoreGeneration>();
	let now = 0;
	const issue = (members: ReadonlyMap<string, Item>, scope = ""): StoreGeneration => {
		if (faults.counterRestarts === true) {
			const next = (counters.get(scope) ?? 0) + 1;
			counters.set(scope, next);
			return `c${next}` as StoreGeneration;
		}
		return faults.digest === true
			? (createHash("sha256")
					.update(JSON.stringify([...members.values()].sort((a, b) => (a.id < b.id ? -1 : 1))))
					.digest("hex")
					.slice(0, 32) as StoreGeneration)
			: newStoreGeneration();
	};
	const keep = (item: Item): Item => (faults.alias === true ? item : { ...item });
	/** After a membership write: an emptied set starts its tombstone's deadline; one holding a member has none. */
	const retain = (entry: SetEntry): void => {
		if (entry.members.size === 0) entry.deadline = now + TOMBSTONE_MS;
		else if (faults.revivedKeepsDeadline !== true) entry.deadline = undefined;
	};
	const add = (item: Item): StoreGeneration => {
		const held = live(item.scope, true);
		const entry = held ?? { generation: newStoreGeneration(), members: new Map() };
		const before = held !== undefined ? undefined : expired.get(item.scope);
		entry.members.set(item.id, keep(item));
		entry.generation = issue(entry.members, item.scope);
		retain(entry);
		sets.set(item.scope, entry);
		return faults.recreateAnswersStale === true && before !== undefined ? before : entry.generation;
	};
	/** The set, unless its tombstone is past its deadline: a read drops it, and so does a write unless writes ignore expiry. */
	const live = (scope: string, forWrite: boolean): SetEntry | undefined => {
		const entry = sets.get(scope);
		if (
			entry === undefined ||
			faults.deadlineIgnored === true ||
			entry.deadline === undefined ||
			entry.deadline > now
		) {
			return entry;
		}
		if (forWrite && faults.writesIgnoreExpiry === true) return entry;
		expired.set(scope, entry.generation);
		sets.delete(scope);
		counters.delete(scope);
		return undefined;
	};
	const out = (item: Item): Item =>
		faults.alias === true
			? item
			: faults.frozen === true
				? Object.freeze({ ...item })
				: { ...item };

	const target = (instance: number): ConditionalSetTarget<Item> => {
		const cache = new Map<string, VersionedSet<Item>>();
		let reads = 0;
		const ordered = (items: Item[]): Item[] => {
			if (faults.reordered !== true) return items;
			reads += 1;
			return reads % 2 === 0 ? items.reverse() : items;
		};
		const read = async (scope: string): Promise<VersionedSet<Item>> => {
			const entry = live(scope, false);
			if (entry === undefined) {
				return {
					items: [],
					generation: faults.absentAnswersGeneration === true ? newStoreGeneration() : null,
				};
			}
			const items = (): Item[] =>
				ordered([
					...[...(sets.get(scope)?.members.values() ?? [])].map(out),
					...(faults.leaksReserved === true ? [{ scope, id: "~g", data: "" }] : []),
				]);
			if (faults.tornRead === "items-first") {
				const listed = items();
				await gap();
				return { items: listed, generation: sets.get(scope)?.generation ?? null };
			}
			if (faults.tornRead === "generation-first") {
				const generation = entry.generation;
				await gap();
				return { items: items(), generation };
			}
			return { items: items(), generation: entry.generation };
		};
		return {
			async listVersioned(scope) {
				if (faults.secondCaches === true && instance === 1) {
					const cached = cache.get(scope);
					if (cached !== undefined) return cached;
					const fresh = await read(scope);
					cache.set(scope, fresh);
					return fresh;
				}
				return read(scope);
			},
			async list(scope) {
				const members = [...(live(scope, false)?.members.values() ?? [])].map(out);
				return faults.listDisagrees === true ? members.slice(1) : members;
			},
			async createIf(item, expected): Promise<ConditionalCreateAnswer> {
				const entry = live(item.scope, true);
				if (expected === null && entry !== undefined && faults.createIgnoresExpected !== true) {
					return { outcome: "conflict" };
				}
				if (expected !== null) {
					if (entry === undefined && faults.absentSetCreates !== true)
						return { outcome: "conflict" };
					if (
						entry !== undefined &&
						entry.generation !== expected &&
						faults.createIgnoresExpected !== true
					) {
						return { outcome: "conflict" };
					}
				}
				if (entry?.members.has(item.id) === true && faults.upsertHeld !== true)
					return { outcome: "conflict" };
				if (faults.createCheckThenWrite === true) await gap();
				return { outcome: "created", generation: add(item) };
			},
			async removeIf(scope, id, expected): Promise<ConditionalSetRemoveAnswer> {
				const entry = faults.removeIgnoresExpiry === true ? sets.get(scope) : live(scope, true);
				if (entry === undefined) return { outcome: "missing" };
				if (entry.generation !== expected) return { outcome: "conflict" };
				if (!entry.members.has(id)) {
					if (faults.absentMemberMoves === true) entry.generation = newStoreGeneration();
					return faults.malformedMissing === true
						? ({ outcome: "absent" } as unknown as ConditionalSetRemoveAnswer)
						: { outcome: "missing" };
				}
				if (faults.removeCheckThenWrite === true) await gap();
				entry.members.delete(id);
				entry.generation = issue(entry.members, scope);
				retain(entry);
				if (faults.lastRemovalDeletes === true && entry.members.size === 0) sets.delete(scope);
				return { outcome: "removed", generation: entry.generation };
			},
			async reset(scope) {
				const entry = live(scope, true);
				if (faults.resetEmptyNoop === true && entry !== undefined && entry.members.size === 0)
					return;
				if (faults.resetDeletes === true) {
					sets.delete(scope);
					return;
				}
				if (faults.resetKeepsGeneration === true && entry !== undefined) {
					entry.members.clear();
					retain(entry);
					return;
				}
				if (faults.resetTwoSteps === true && entry !== undefined) {
					entry.members.clear();
					await gap();
					entry.generation = newStoreGeneration();
					retain(entry);
					return;
				}
				const emptied: SetEntry = { generation: newStoreGeneration(), members: new Map() };
				retain(emptied);
				sets.set(scope, emptied);
			},
			async updateMember(scope, id) {
				const entry = live(scope, true);
				const member = entry?.members.get(id);
				if (entry === undefined || member === undefined) throw new Error("no such member");
				if (faults.updateNoop !== true)
					entry.members.set(id, { ...member, data: `${member.data}+` });
				if (faults.updateMoves === true) entry.generation = newStoreGeneration();
			},
			unconditional: {
				async create(item) {
					const entry = live(item.scope, true);
					if (entry?.members.has(item.id) === true) throw new Error("held");
					if (faults.legacyKeepsGeneration === true && entry !== undefined) {
						entry.members.set(item.id, keep(item));
						retain(entry);
						return;
					}
					add(item);
				},
				async remove(item) {
					const entry = live(item.scope, true);
					if (entry === undefined || !entry.members.delete(item.id)) return;
					if (faults.legacyKeepsGeneration !== true)
						entry.generation = issue(entry.members, item.scope);
					retain(entry);
				},
			},
		};
	};

	const unreachable = (): ConditionalSetTarget<Item> =>
		faults.outageAsMissing === true
			? {
					listVersioned: async () => ({ items: [], generation: null }),
					list: async () => [],
					createIf: outage,
					removeIf: async () => ({ outcome: "missing" }),
					reset: outage,
					updateMember: outage,
					unconditional: { create: outage, remove: outage },
				}
			: {
					listVersioned: outage,
					list: outage,
					createIf: outage,
					removeIf: outage,
					reset: outage,
					updateMember: outage,
					unconditional:
						faults.unreachableDropsWrites === true ? {} : { create: outage, remove: outage },
				};

	return {
		target,
		/** Moves the clock past every deadline the store set; judges and deletes nothing. */
		forceExpire: async (_scope: string) => {
			now += TOMBSTONE_MS;
		},
		unreachable,
	};
}

/** A harness over a fresh backend: two instances, and every hook. */
function setHarness(faults: SetFaults = {}): ConditionalSetHarness<Item> {
	const backend = setBackend(faults);
	return {
		store: backend.target(0),
		second: backend.target(1),
		forceExpire: backend.forceExpire,
		unreachable: backend.unreachable,
	};
}

const setInput = (faults: SetFaults = {}): ConditionalSetContractInput<Item> => ({
	build: async () => setHarness(faults),
	items: ITEMS,
	idOf: (item) => item.id,
	scopeOf: (item) => item.scope,
	mutate: MUTATE_ITEM,
	supports: {
		forceExpire: true,
		unreachable: true,
		updateMember: true,
		list: true,
		unconditional: true,
	},
});

describe("conditionalSetContract over the reference set store", () => {
	for (const contractCase of conditionalSetContract(setInput())) {
		it(contractCase.name, contractCase.run);
	}
});

const SET = {
	absent: "a set never written answers no items and a null generation",
	firstRace: "of two concurrent first creates through two instances, exactly one is created",
	resetAbsent:
		"a reset of a set never written leaves it empty at a generation, so a first create then answers conflict",
	update: "a member's own update changes that member and keeps the set's generation",
	stale: "a create at a stale generation answers conflict and adds nothing",
	last: "removing the last member keeps the set, empty, at the new generation removed answers",
	removeRace:
		"of two concurrent removals of different members at one generation through two instances, exactly one is removed",
	createRace:
		"of concurrent creates of different members at one generation, exactly one is created",
	mixedRace: "a removal racing a create at one generation, either started first: exactly one wins",
	resetRace:
		"a reset racing a create or a removal at one generation, either started first, is serialised with it: the set ends empty, at a generation neither the read nor the write answered",
	resetEmpty:
		"a reset of a set already empty moves its generation: the emptying one then answers conflict",
	aba: "a member removed and created again with the same bytes leaves no generation repeated, and the first answers conflict",
	reset: "a reset after a read moves the generation: the read one then answers conflict",
	absentMember:
		"removing a member not held answers missing, keeps the generation, and the generation still writes",
	absentSet:
		"against an absent set, a removal with a generation answers missing and a create with one answers conflict",
	snapshot:
		"a versioned set read is one snapshot: read with a concurrent create, its members and generation are both before or both after",
	membersAlone: "the versioned read lists the members alone",
	agree: "the plain listing agrees with the versioned read",
	crossInstance:
		"a write through one instance is read through the other at the generation it answered, and the old generation conflicts there",
	unconditional:
		"every unconditional membership write that changes the members moves the generation: the old one then answers conflict",
	readers: "every answer is one core's readers accept",
	held: "a create of a member already held, at the current generation, answers conflict and changes nothing",
	tombstone:
		"an emptied set whose tombstone expired reads as absent, and a write with no read after the expiry finds it absent",
	outage: "a store that cannot reach its backend rejects every member",
	heldSet:
		"a set that holds a member does not expire, one revived from its tombstone included: the clock moved past every deadline leaves it as it was",
	alias: "the store keeps its own copy: changing a member written or read changes nothing stored",
	recreate:
		"a set created again after its tombstone expired is at a generation it is then read at, never one seen before",
} as const;

describe("conditionalSetContract refuses a set store that breaks a rule", () => {
	const cases: ReadonlyArray<readonly [string, SetFaults, string]> = [
		[
			"a set never written that answers a generation",
			{ absentAnswersGeneration: true },
			SET.absent,
		],
		[
			"a create's check apart from its write, on first creates",
			{ createCheckThenWrite: true },
			SET.firstRace,
		],
		["a reset that leaves no tombstone", { resetDeletes: true }, SET.resetAbsent],
		["a member's update that moves the generation", { updateMoves: true }, SET.update],
		["a member's update that changes nothing", { updateNoop: true }, SET.update],
		[
			"a reset in two steps, clearing the members before it moves the generation",
			{ resetTwoSteps: true },
			SET.resetRace,
		],
		["a member shared with the caller", { alias: true }, SET.alias],
		["a create that ignores the generation", { createIgnoresExpected: true }, SET.stale],
		["a removal of the last member that deletes the set", { lastRemovalDeletes: true }, SET.last],
		[
			"a removal's check apart from its write, on removals",
			{ removeCheckThenWrite: true },
			SET.removeRace,
		],
		[
			"a create's check apart from its write, on creates",
			{ createCheckThenWrite: true },
			SET.createRace,
		],
		[
			"a removal's check apart from its write, against a create",
			{ removeCheckThenWrite: true },
			SET.mixedRace,
		],
		[
			"a create's check apart from its write, against a removal",
			{ createCheckThenWrite: true },
			SET.mixedRace,
		],
		["a reset of an empty set that changes nothing", { resetEmptyNoop: true }, SET.resetEmpty],
		["writes that do not check expiry", { writesIgnoreExpiry: true }, SET.tombstone],
		["a removal that does not check expiry", { removeIgnoresExpiry: true }, SET.tombstone],
		["an unreachable target that names no write", { unreachableDropsWrites: true }, SET.outage],
		["a second instance that reads from a cache", { secondCaches: true }, SET.crossInstance],
		["a plain listing that leaves a member out", { listDisagrees: true }, SET.agree],
		["a digest of the members", { digest: true }, SET.aba],
		["a reset that keeps the generation", { resetKeepsGeneration: true }, SET.reset],
		[
			"a removal of a member not held that moves the generation",
			{ absentMemberMoves: true },
			SET.absentMember,
		],
		[
			"a create with a generation that creates an absent set",
			{ absentSetCreates: true },
			SET.absentSet,
		],
		["a read of the members, then the generation", { tornRead: "items-first" }, SET.snapshot],
		["a read of the generation, then the members", { tornRead: "generation-first" }, SET.snapshot],
		["a versioned read that lists a reserved entry", { leaksReserved: true }, SET.membersAlone],
		[
			"an unconditional write that keeps the generation",
			{ legacyKeepsGeneration: true },
			SET.unconditional,
		],
		["an answer outside the type", { malformedMissing: true }, SET.readers],
		["a create that overwrites a held id", { upsertHeld: true }, SET.held],
		["a store that ignores its own deadline", { deadlineIgnored: true }, SET.tombstone],
		["an outage answered as an empty set", { outageAsMissing: true }, SET.outage],
		[
			"a set revived from its tombstone that keeps the tombstone's deadline",
			{ revivedKeepsDeadline: true },
			SET.heldSet,
		],
		["a counter that restarts once the set expires", { counterRestarts: true }, SET.recreate],
		[
			"a create after expiry that answers the expired generation",
			{ recreateAnswersStale: true },
			SET.recreate,
		],
	];
	for (const [what, faults, refusing] of cases) {
		it(`${what}: refused by "${refusing}"`, async () => {
			expect(await refusedBy(conditionalSetContract(setInput(faults)))).toContain(refusing);
		});
	}

	it("a store that answers frozen members passes every case", async () => {
		expect(await refusedBy(conditionalSetContract(setInput({ frozen: true })))).toEqual([]);
	});

	it("a store that lists its members in another order on each read passes every case", async () => {
		expect(await refusedBy(conditionalSetContract(setInput({ reordered: true })))).toEqual([]);
	});

	it("every case of the suite refuses one of the broken stores", () => {
		const named = conditionalSetContract(setInput())
			.map((contractCase) => contractCase.name)
			.filter((name) => !name.startsWith("not run:"));
		expect(new Set(cases.map(([, , refusing]) => refusing))).toEqual(new Set(named));
	});
});

describe("conditionalSetContract's declared hooks", () => {
	it("leaves out the cases of an undeclared hook, and names what was not run", async () => {
		const cases = conditionalSetContract({ ...setInput(), supports: undefined });
		const listed = cases.map((contractCase) => contractCase.name);
		expect(listed).not.toContain(SET.tombstone);
		expect(listed).not.toContain(SET.outage);
		expect(listed).toEqual(
			expect.arrayContaining([
				"not run: the tombstone expiry case (supports.forceExpire not declared)",
				"not run: the held-set expiry case (supports.forceExpire not declared)",
				"not run: the re-create after expiry case (supports.forceExpire not declared)",
				"not run: the outage case (supports.unreachable not declared)",
				"not run: the member-update case (supports.updateMember not declared)",
				"not run: the plain-listing case (supports.list not declared)",
				"not run: the unconditional-write case (supports.unconditional not declared)",
			]),
		);
		for (const name of [SET.update, SET.agree, SET.unconditional])
			expect(listed).not.toContain(name);
		expect(await refusedBy(cases)).toEqual([]);
		const withoutMutate = conditionalSetContract({ ...setInput(), mutate: undefined }).map(
			(contractCase) => contractCase.name,
		);
		expect(withoutMutate).toContain("not run: the aliasing case (no mutate given)");
		expect(withoutMutate).not.toContain(SET.alias);
	});

	it("fails a case whose items answer an item of another scope", async () => {
		const cases = conditionalSetContract({
			...setInput(),
			items: (scope, n) => ITEMS(`${scope}-elsewhere`, n),
		});
		const first = cases.find((contractCase) => contractCase.name === SET.firstRace);
		await expect(first?.run()).rejects.toThrow(/an item of another scope/);
	});

	it("fails the case of a hook declared and missing from the harness", async () => {
		const cases = conditionalSetContract({
			...setInput(),
			build: async () => ({ store: setBackend().target(0) }),
		});
		expect(await refusedBy(cases)).toEqual([SET.tombstone, SET.heldSet, SET.recreate, SET.outage]);
	});

	it("fails the case of a member declared and missing from the target", async () => {
		const { updateMember: _update, list: _list, ...rest } = setBackend().target(0);
		const cases = conditionalSetContract({
			...setInput(),
			build: async () => ({ ...setHarness(), store: { ...rest, unconditional: {} } }),
		});
		const refused = await refusedBy(cases);
		for (const name of [SET.update, SET.agree, SET.unconditional]) expect(refused).toContain(name);
	});
});
