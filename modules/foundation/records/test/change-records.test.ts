import { randomBytes } from "node:crypto";
import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type Json, type Space, type Store, spaces, store } from "@mod/store";
import { simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
import { changeRecords, type Place, pairedRecordsAcross, recordsIn } from "../src/records.ts";
import { memoryRecords } from "../src/testing.ts";

const runtime = quietRuntime({
	clock: { now: () => 1_800_000_000_000 },
	random: { bytes: (n) => new Uint8Array(n) },
});
const guarantees = ["no-eviction", "durable", "replicated"] as const;
const lists: Space = { name: "many-lists", guarantees: [...guarantees] };
const items: Space = { name: "many-items", guarantees: [...guarantees] };
const opened = contract<Store>("test.store");

type List = { readonly ids: readonly string[] };
type Item = { readonly owner: string; readonly gone?: true };

/** A simulated store over two spaces of one guarantee, a place in each, and their records. */
async function open() {
	const simulated = simulatedStore();
	const app = await assemble({
		modules: [
			simulated.module,
			defineModule({ name: "user", takes: [store] }, (m) => [
				m.contribute(spaces).by(() => lists),
				m.contribute(spaces).by(() => items),
				m.provide(opened).by((c) => c.get(store)),
			]),
		],
		config: kernelConfig(),
		runtime,
	});
	const s = app.get(opened);
	const random = { bytes: (n: number) => new Uint8Array(randomBytes(n)) };
	const listPlace: Place = { store: s, space: lists, random };
	const itemPlace: Place = { store: s, space: items, random };
	return {
		simulated,
		s,
		listPlace,
		itemPlace,
		listRecords: recordsIn<List>(listPlace),
		itemRecords: recordsIn<Item>(itemPlace),
		at: (place: Place, key: string) => ({ place, key }),
	};
}

/** A list and the items it names, as a reset reads them: the list emptied, its owner's items marked gone. */
const clearing = (owner: string) => ({
	watch: ([list]: readonly (Json | undefined)[]) => (list as List | undefined)?.ids ?? [],
	decide: ([list]: readonly (Json | undefined)[], found: readonly (Json | undefined)[]) => ({
		targets: [list === undefined ? undefined : { value: { ids: [] } }],
		watched: found.map((item) =>
			(item as Item | undefined)?.owner === owner ? { value: { owner, gone: true } } : undefined,
		),
	}),
});

it("writes a record and the records it names, watched, as one", async () => {
	const { listPlace, itemPlace, listRecords, itemRecords, at } = await open();
	await listRecords.create("ann", { ids: ["i1", "i2", "i3"] }, "endless");
	await itemRecords.create("i1", { owner: "ann" }, "endless");
	await itemRecords.create("i2", { owner: "bob" }, "endless");
	const { watch, decide } = clearing("ann");
	const changed = await changeRecords({
		targets: [at(listPlace, "ann")],
		watch: (read) => watch(read).map((key) => at(itemPlace, key)),
		decide,
	});
	expect(changed.targets).toEqual([{ before: { ids: ["i1", "i2", "i3"] }, after: { ids: [] } }]);
	expect(changed.watched).toEqual([
		{ before: { owner: "ann" }, after: { owner: "ann", gone: true } },
		{ before: { owner: "bob" }, after: { owner: "bob" } },
		{ before: undefined, after: undefined },
	]);
	expect(await listRecords.read("ann")).toEqual({ ids: [] });
	expect(await itemRecords.read("i1")).toEqual({ owner: "ann", gone: true });
	expect(await itemRecords.read("i2")).toEqual({ owner: "bob" });
});

it("writes 101 records as one, each held by a condition of the one write", async () => {
	const { simulated, listPlace, itemPlace, listRecords, itemRecords, at } = await open();
	const ids = Array.from({ length: 100 }, (_, n) => `m${n}`);
	await listRecords.create("cid", { ids }, "endless");
	for (const id of ids) await itemRecords.create(id, { owner: "cid" }, "endless");
	// Another writer changes the last item before the write: all is read again, and decided again.
	simulated.beforeNext("batchAcross", lists.name, async () => {
		await itemRecords.change("m99", () => ({ value: { owner: "dee" } }));
	});
	let decisions = 0;
	const { watch, decide } = clearing("cid");
	await changeRecords({
		targets: [at(listPlace, "cid")],
		watch: (read) => watch(read).map((key) => at(itemPlace, key)),
		decide: (read, found) => {
			decisions += 1;
			return decide(read, found);
		},
	});
	expect(decisions).toBe(2);
	expect(await listRecords.read("cid")).toEqual({ ids: [] });
	expect(await itemRecords.read("m0")).toEqual({ owner: "cid", gone: true });
	expect(await itemRecords.read("m99")).toEqual({ owner: "dee" });
});

it("reads the watch again after a race on what it watched, and holds what nothing writes", async () => {
	const { simulated, listPlace, itemPlace, listRecords, itemRecords, at } = await open();
	await listRecords.create("eve", { ids: ["e1"] }, "endless");
	await itemRecords.create("e1", { owner: "eve" }, "endless");
	await itemRecords.create("e2", { owner: "eve" }, "endless");
	// The list names one more item before the write: the watch, read again, names it too.
	simulated.beforeNext("batchAcross", lists.name, async () => {
		await listRecords.change("eve", () => ({ value: { ids: ["e1", "e2"] } }));
	});
	const named: string[][] = [];
	const { watch, decide } = clearing("eve");
	await changeRecords({
		targets: [at(listPlace, "eve")],
		watch: (read) => {
			const keys = watch(read);
			named.push([...keys]);
			return keys.map((key) => at(itemPlace, key));
		},
		decide,
	});
	expect(named).toEqual([["e1"], ["e1", "e2"]]);
	expect(await itemRecords.read("e2")).toEqual({ owner: "eve", gone: true });
	// Deciding to write nothing still holds what was read: a race first makes it decide again.
	await itemRecords.create("e3", { owner: "fay" }, "endless");
	simulated.beforeNext("batchAcross", items.name, async () => {
		await itemRecords.change("e3", () => ({ value: { owner: "gus" } }));
	});
	const seen: unknown[] = [];
	const kept = await changeRecords({
		targets: [at(itemPlace, "e3")],
		decide: ([item]) => {
			seen.push(item);
			return {};
		},
	});
	expect(seen).toEqual([{ owner: "fay" }, { owner: "gus" }]);
	expect(kept.targets).toEqual([{ before: { owner: "gus" }, after: { owner: "gus" } }]);
});

it("takes effect once where its answer was lost and is sent again under its mark", async () => {
	const { simulated, listPlace, itemPlace, listRecords, itemRecords, at } = await open();
	await listRecords.create("hal", { ids: ["h1"] }, "endless");
	await itemRecords.create("h1", { owner: "hal" }, "endless");
	simulated.loseNextReply();
	let decisions = 0;
	const { watch, decide } = clearing("hal");
	const changed = await changeRecords({
		targets: [at(listPlace, "hal")],
		watch: (read) => watch(read).map((key) => at(itemPlace, key)),
		decide: (read, found) => {
			decisions += 1;
			return decide(read, found);
		},
	});
	expect(decisions).toBe(1);
	expect(changed.watched).toEqual([
		{ before: { owner: "hal" }, after: { owner: "hal", gone: true } },
	]);
});

it("reads a record named twice once, writing it from one naming, and refuses two writes of it", async () => {
	const { s, itemPlace, itemRecords, at } = await open();
	await itemRecords.create("j1", { owner: "jo" }, "endless");
	const sent: number[] = [];
	const batchAcross = s.batchAcross?.bind(s);
	const counting: Place = {
		...itemPlace,
		store: new Proxy(s, {
			get: (target, name) =>
				name === "batchAcross"
					? (...args: Parameters<NonNullable<Store["batchAcross"]>>) => {
							sent.push(args[0].length);
							return batchAcross?.(...args);
						}
					: Reflect.get(target, name),
		}),
	};
	const changed = await changeRecords({
		targets: [at(counting, "j1")],
		watch: () => [at(counting, "j1")],
		decide: ([item], [again]) => {
			expect(again).toEqual(item);
			return { watched: [{ value: { owner: "kim" } }] };
		},
	});
	expect(sent).toEqual([1]);
	expect(changed.targets).toEqual([{ before: { owner: "jo" }, after: { owner: "kim" } }]);
	expect(await itemRecords.read("j1")).toEqual({ owner: "kim" });
	await expect(
		changeRecords({
			targets: [at(itemPlace, "j1")],
			watch: () => [at(itemPlace, "j1")],
			decide: () => ({
				targets: [{ value: { owner: "lou" } }],
				watched: [{ value: { owner: "max" } }],
			}),
		}),
	).rejects.toThrow();
	await expect(
		changeRecords({ targets: [at(itemPlace, "a"), at(itemPlace, "a")], decide: () => ({}) }),
	).rejects.toThrow();
	await expect(changeRecords({ targets: [], decide: () => ({}) })).rejects.toThrow();
});

it("pairs records of two places to change as one, apart by place, and refuses through the caller where the store cannot", async () => {
	const { listPlace, itemPlace, listRecords, itemRecords } = await open();
	// One key in both places: each place keeps its own.
	await listRecords.create("k", { ids: ["k"] }, "endless");
	await itemRecords.create("k", { owner: "ned" }, "endless");
	const refusals: string[] = [];
	const refuse = (where: string, reason: string): never => {
		refusals.push(`${where}: ${reason}`);
		throw new Error(reason);
	};
	const paired = pairedRecordsAcross<List, Item>(listPlace, itemPlace, "user", refuse);
	const changed = await paired.changeRecords(
		{ first: ["k"], second: [] },
		{
			watch: ({ first: [list] }) => ({ second: [...(list?.ids ?? [])] }),
			decide: ({ second: [item] }) => ({
				first: [{ value: { ids: [] } }],
				second: [item && { value: { ...item, gone: true as const } }],
			}),
		},
	);
	expect(changed).toEqual({
		first: [{ before: { ids: ["k"] }, after: { ids: [] } }],
		second: [{ before: { owner: "ned" }, after: { owner: "ned", gone: true } }],
	});
	expect([await listRecords.read("k"), await itemRecords.read("k")]).toEqual([
		{ ids: [] },
		{ owner: "ned", gone: true },
	]);
	const { batchAcross: _, ...lacking } = listPlace.store;
	expect(() =>
		pairedRecordsAcross({ ...listPlace, store: lacking as Store }, itemPlace, "user", refuse),
	).toThrow();
	// Two stores, or spaces of other guarantees, are refused at build too, before any change.
	const another = { ...listPlace.store } as Store;
	expect(() =>
		pairedRecordsAcross(listPlace, { ...itemPlace, store: another }, "user", refuse),
	).toThrow();
	const loose: Space = { name: "many-items", guarantees: ["no-eviction"] };
	expect(() =>
		pairedRecordsAcross(listPlace, { ...itemPlace, space: loose }, "user", refuse),
	).toThrow();
	expect(refusals).toEqual([
		"user: its store writes no records of two partitions as one",
		"user: its two places are on two stores, which write nothing of both as one",
		"user: its two spaces declare other guarantees, so a fault could keep one and drop the other",
	]);
});

it("changes records of the stand-in as one, the watched ones too, as records does", async () => {
	const { records } = memoryRecords<{ ids?: string[]; owner?: string }>(() => 0, {
		shards: 1,
		perShard: 1,
	});
	await records.create("ola", { ids: ["o1", "o2"] }, "endless");
	await records.create("o1", { owner: "ola" }, "endless");
	const changed = await records.changeRecords(["ola"], {
		watch: ([list]) => list?.ids ?? [],
		decide: ([list], found) => ({
			targets: [list && { value: { ids: [] } }],
			watched: found.map((item) => item && { value: { owner: "gone" } }),
		}),
	});
	expect(changed.watched).toEqual([
		{ before: { owner: "ola" }, after: { owner: "gone" } },
		{ before: undefined, after: undefined },
	]);
	expect(await records.read("ola")).toEqual({ ids: [] });
	await expect(records.changeRecords(["p", "p"], { decide: () => ({}) })).rejects.toThrow();
});

it("keeps in the stand-in the record as read before the decision, its end too, though the end passes as it decides", async () => {
	let clock = 0;
	const { records } = memoryRecords<{ n: number }>(() => clock, { shards: 1, perShard: 1 });
	await records.create("q", { n: 1 }, 1000);
	const changed = await records.changeRecords(["q"], {
		watch: () => ["q"],
		decide: ([held], [again]) => {
			expect([held, again]).toEqual([{ n: 1 }, { n: 1 }]);
			clock += 2000;
			// Changed keeping its lifetime: it ends when the record read ended.
			return { targets: [{ value: { n: 2 } }] };
		},
	});
	expect(changed).toEqual({
		targets: [{ before: { n: 1 }, after: { n: 2 } }],
		watched: [{ before: { n: 1 }, after: { n: 2 } }],
	});
	expect(await records.read("q")).toBeUndefined();
});

it("gives a record the stand-in changes a lifetime of 1 ms at least, as records does", async () => {
	const { records } = memoryRecords<{ n: number }>(() => 0, { shards: 1, perShard: 1 });
	await records.changeRecords(["r"], {
		decide: () => ({ targets: [{ value: { n: 1 }, lifetimeMs: 0 }] }),
	});
	// The clock stands still: the record lives its 1 ms, as the store keeps a write's least lifetime.
	expect(await records.read("r")).toEqual({ n: 1 });
});
