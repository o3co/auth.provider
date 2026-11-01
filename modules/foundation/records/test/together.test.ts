import { randomBytes } from "node:crypto";
import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type Space, type Store, spaces, store } from "@mod/store";
import { simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
import {
	changesTogether,
	changeTogether,
	type Place,
	pairedRecordsIn,
	recordsIn,
} from "../src/records.ts";
import { memoryRecords } from "../src/testing.ts";

const runtime = quietRuntime({
	clock: { now: () => 1_800_000_000_000 },
	random: { bytes: (n) => new Uint8Array(n) },
});
const guarantees = ["no-eviction", "durable", "replicated"] as const;
const lists: Space = { name: "together-lists", guarantees: [...guarantees] };
const claims: Space = { name: "together-claims", guarantees: [...guarantees] };
const opened = contract<Store>("test.store");

/** A simulated store over two spaces of one guarantee, a place in each, and their records. */
async function open() {
	const simulated = simulatedStore();
	const app = await assemble({
		modules: [
			simulated.module,
			defineModule({ name: "user", replicaSafe: true, takes: [store] }, (m) => [
				m.contribute(spaces).by(() => lists),
				m.contribute(spaces).by(() => claims),
				m.provide(opened).by((c) => c.get(store)),
			]),
		],
		config: kernelConfig(),
		runtime,
	});
	const s = app.get(opened);
	const random = { bytes: (n: number) => new Uint8Array(randomBytes(n)) };
	const listPlace: Place = { store: s, space: lists, random };
	const claimPlace: Place = { store: s, space: claims, random };
	return {
		simulated,
		s,
		listPlace,
		claimPlace,
		listRecords: recordsIn<{ ids: string[] }>(listPlace),
		claimRecords: recordsIn<{ owner: string }>(claimPlace),
	};
}

it("writes two records of two spaces at once, each from what it held", async () => {
	const { listPlace, claimPlace, listRecords, claimRecords } = await open();
	await listRecords.create("ann", { ids: ["one"] }, "endless");
	const changed = await changeTogether<{ ids: string[] }, { owner: string }>({
		first: { place: listPlace, key: "ann" },
		second: { place: claimPlace, key: "value-1" },
		decide: (list, claim) => ({
			first: { value: { ids: [...(list?.ids ?? []), "two"] } },
			second: claim === undefined ? { value: { owner: "ann" }, lifetimeMs: "endless" } : undefined,
		}),
	});
	expect(changed).toEqual({
		first: { before: { ids: ["one"] }, after: { ids: ["one", "two"] } },
		second: { before: undefined, after: { owner: "ann" } },
	});
	expect(await listRecords.read("ann")).toEqual({ ids: ["one", "two"] });
	expect(await claimRecords.read("value-1")).toEqual({ owner: "ann" });
});

it("writes nothing where the decision keeps both, and answers what each holds", async () => {
	const { listPlace, claimPlace, listRecords } = await open();
	await listRecords.create("bob", { ids: ["one"] }, "endless");
	const kept = await changeTogether<{ ids: string[] }, { owner: string }>({
		first: { place: listPlace, key: "bob" },
		second: { place: claimPlace, key: "value-2" },
		decide: () => ({}),
	});
	expect(kept).toEqual({
		first: { before: { ids: ["one"] }, after: { ids: ["one"] } },
		second: { before: undefined, after: undefined },
	});
});

it("decides again on what is there after another writer changes either record first", async () => {
	const { simulated, listPlace, claimPlace, listRecords, claimRecords } = await open();
	await listRecords.create("cid", { ids: [] }, "endless");
	simulated.beforeNext("batchAcross", lists.name, async () => {
		await claimRecords.create("value-3", { owner: "dee" }, "endless");
	});
	let decisions = 0;
	const changed = await changeTogether<{ ids: string[] }, { owner: string }>({
		first: { place: listPlace, key: "cid" },
		second: { place: claimPlace, key: "value-3" },
		decide: (list, claim) => {
			decisions += 1;
			if (claim !== undefined) return {};
			return {
				first: { value: { ids: [...(list?.ids ?? []), "f"] } },
				second: { value: { owner: "cid" }, lifetimeMs: "endless" },
			};
		},
	});
	expect(decisions).toBe(2);
	expect(changed.second.after).toEqual({ owner: "dee" });
	expect(await listRecords.read("cid")).toEqual({ ids: [] });
});

it("holds the record the decision watched: changed by another writer meanwhile, it is read again and decided on", async () => {
	const { simulated, listPlace, claimPlace, listRecords, claimRecords } = await open();
	await claimRecords.create("value-4", { owner: "eve" }, "endless");
	await listRecords.create("eve", { ids: [] }, "endless");
	await listRecords.create("fay", { ids: [] }, "endless");
	// The claim's owner lists the claimed id just before the write: the claim is not stale then.
	simulated.beforeNext("batchAcross", lists.name, async () => {
		await listRecords.change("eve", () => ({ value: { ids: ["value-4"] } }));
	});
	const watchedSeen: unknown[] = [];
	const changed = await changeTogether<{ ids: string[] }, { owner: string }>({
		first: { place: listPlace, key: "fay" },
		second: { place: claimPlace, key: "value-4" },
		watch: (_list, claim) => (claim ? [{ place: listPlace, key: claim.owner }] : []),
		decide: (list, claim, [owner]) => {
			watchedSeen.push(owner);
			const stale =
				claim !== undefined && !(owner as { ids: string[] } | undefined)?.ids.includes("value-4");
			if (claim !== undefined && !stale) return {};
			return {
				first: { value: { ids: [...(list?.ids ?? []), "value-4"] } },
				second: { value: { owner: "fay" }, lifetimeMs: "endless" },
			};
		},
	});
	expect(watchedSeen).toEqual([{ ids: [] }, { ids: ["value-4"] }]);
	expect(changed.second.after).toEqual({ owner: "eve" });
	expect(await listRecords.read("fay")).toEqual({ ids: [] });
});

it("watches the owner a racing writer gave the claim, reading it, and keeps both records where that owner holds the value", async () => {
	const { simulated, listPlace, claimPlace, listRecords, claimRecords } = await open();
	// Ida's claim is stale (her list lacks the value) when read; before the write, Jon takes it, and his list holds it.
	await claimRecords.create("value-9", { owner: "ida" }, "endless");
	await listRecords.create("ida", { ids: [] }, "endless");
	await listRecords.create("jon", { ids: ["value-9"] }, "endless");
	await listRecords.create("kay", { ids: [] }, "endless");
	simulated.beforeNext("batchAcross", lists.name, async () => {
		await claimRecords.change("value-9", () => ({ value: { owner: "jon" } }));
	});
	const watchedKeys: string[][] = [];
	const owners: unknown[] = [];
	const changed = await changeTogether<{ ids: string[] }, { owner: string }>({
		first: { place: listPlace, key: "kay" },
		second: { place: claimPlace, key: "value-9" },
		watch: (_list, claim) => {
			const keys = claim ? [claim.owner] : [];
			watchedKeys.push(keys);
			return keys.map((key) => ({ place: listPlace, key }));
		},
		decide: (list, claim, [owner]) => {
			owners.push(owner);
			const stale =
				claim !== undefined && !(owner as { ids: string[] } | undefined)?.ids.includes("value-9");
			if (claim !== undefined && !stale) return {};
			return {
				first: { value: { ids: [...(list?.ids ?? []), "value-9"] } },
				second: { value: { owner: "kay" }, lifetimeMs: "endless" },
			};
		},
	});
	expect(watchedKeys).toEqual([["ida"], ["jon"]]);
	expect(owners).toEqual([{ ids: [] }, { ids: ["value-9"] }]);
	expect(changed.second).toEqual({ before: { owner: "jon" }, after: { owner: "jon" } });
	expect([await listRecords.read("kay"), await listRecords.read("jon")]).toEqual([
		{ ids: [] },
		{ ids: ["value-9"] },
	]);
	expect(await claimRecords.read("value-9")).toEqual({ owner: "jon" });
});

it("reads a watched record that is the first or second once, holding it by one condition", async () => {
	const { s, listPlace, claimPlace, listRecords, claimRecords } = await open();
	await listRecords.create("gus", { ids: ["value-5"] }, "endless");
	await claimRecords.create("value-5", { owner: "gus" }, "endless");
	const sent: number[] = [];
	const batchAcross = s.batchAcross?.bind(s);
	const counting: Place = {
		...listPlace,
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
	const changed = await changeTogether<{ ids: string[] }, { owner: string }>({
		first: { place: counting, key: "gus" },
		second: { place: { ...claimPlace, store: counting.store }, key: "value-5" },
		watch: (_list, claim) => (claim ? [{ place: counting, key: claim.owner }] : []),
		decide: (list, _claim, [owner]) => {
			expect(owner).toEqual(list);
			return {};
		},
	});
	expect(changed.first.after).toEqual({ ids: ["value-5"] });
	expect(sent).toEqual([2]);
});

it("removes a record where the decision removes it, and sets a lifetime only where it gives one", async () => {
	const { listPlace, claimPlace, listRecords, claimRecords } = await open();
	await listRecords.create("hal", { ids: ["value-6"] }, "endless");
	await claimRecords.create("value-6", { owner: "hal" }, "endless");
	const changed = await changeTogether<{ ids: string[] }, { owner: string }>({
		first: { place: listPlace, key: "hal" },
		second: { place: claimPlace, key: "value-6" },
		decide: () => ({ first: { value: { ids: [] } }, second: { remove: true } }),
	});
	expect(changed.second).toEqual({ before: { owner: "hal" }, after: undefined });
	expect(await claimRecords.read("value-6")).toBeUndefined();
	expect(await listRecords.read("hal")).toEqual({ ids: [] });
});

it("takes effect once where its answer was lost and is sent again under its mark", async () => {
	const { simulated, listPlace, claimPlace, listRecords } = await open();
	await listRecords.create("ivy", { ids: [] }, "endless");
	simulated.loseNextReply();
	let decisions = 0;
	const changed = await changeTogether<{ ids: string[] }, { owner: string }>({
		first: { place: listPlace, key: "ivy" },
		second: { place: claimPlace, key: "value-7" },
		decide: (list) => {
			decisions += 1;
			return {
				first: { value: { ids: [...(list?.ids ?? []), "x"] } },
				second: { value: { owner: "ivy" }, lifetimeMs: "endless" },
			};
		},
	});
	expect(decisions).toBe(1);
	expect(changed.first.after).toEqual({ ids: ["x"] });
	expect(await listRecords.read("ivy")).toEqual({ ids: ["x"] });
});

it("refuses two places on two stores, one key named twice, and a store without a batch across", async () => {
	const { listPlace, claimPlace } = await open();
	const other = await open();
	const keep = () => ({});
	await expect(
		changeTogether({
			first: { place: listPlace, key: "a" },
			second: { place: other.claimPlace, key: "b" },
			decide: keep,
		}),
	).rejects.toThrow();
	await expect(
		changeTogether({
			first: { place: listPlace, key: "a" },
			second: { place: listPlace, key: "a" },
			decide: keep,
		}),
	).rejects.toThrow();
	const { batchAcross: _, ...lacking } = listPlace.store;
	const without = lacking as Store;
	expect([changesTogether(listPlace.store), changesTogether(without)]).toEqual([true, false]);
	await expect(
		changeTogether({
			first: { place: { ...listPlace, store: without }, key: "a" },
			second: { place: { ...claimPlace, store: without }, key: "b" },
			decide: keep,
		}),
	).rejects.toThrow();
});

it("changes two records of the stand-in as one, with the records it watched, as records does", async () => {
	const { records } = memoryRecords<{ ids?: string[]; owner?: string }>(() => 0, {
		shards: 1,
		perShard: 1,
	});
	await records.create("jo", { ids: [] }, "endless");
	await records.create("value-8", { owner: "kim" }, "endless");
	await records.create("kim", { ids: [] }, "endless");
	const changed = await records.changeTogether("jo", "value-8", {
		watch: (_list, claim) => (claim?.owner ? [claim.owner] : []),
		decide: (list, claim, [owner]) => {
			const stale = claim !== undefined && !owner?.ids?.includes("value-8");
			if (claim !== undefined && !stale) return {};
			return {
				first: { value: { ids: [...(list?.ids ?? []), "value-8"] } },
				second: { value: { owner: "jo" }, lifetimeMs: "endless" },
			};
		},
	});
	expect(changed.second).toEqual({ before: { owner: "kim" }, after: { owner: "jo" } });
	expect(await records.read("jo")).toEqual({ ids: ["value-8"] });
	const kept = await records.changeTogether("jo", "value-9", {
		decide: () => ({ second: { remove: true } }),
	});
	expect(kept.second).toEqual({ before: undefined, after: undefined });
	await expect(records.changeTogether("jo", "jo", { decide: () => ({}) })).rejects.toThrow();
});

it("pairs records of one place to change two as one, and refuses through the caller where the store cannot", async () => {
	const { listPlace, listRecords } = await open();
	await listRecords.create("lou", { ids: [] }, "endless");
	const refusals: string[] = [];
	const refuse = (where: string, reason: string): never => {
		refusals.push(`${where}: ${reason}`);
		throw new Error(reason);
	};
	const paired = pairedRecordsIn<{ ids: string[] }>(listPlace, "user", refuse);
	const changed = await paired.changeTogether("lou", "max", {
		watch: () => [],
		decide: () => ({ second: { value: { ids: ["m"] } } }),
	});
	expect(changed.second).toEqual({ before: undefined, after: { ids: ["m"] } });
	expect(await listRecords.read("max")).toEqual({ ids: ["m"] });
	const { batchAcross: _, ...lacking } = listPlace.store;
	expect(() =>
		pairedRecordsIn({ ...listPlace, store: lacking as Store }, "user", refuse),
	).toThrow();
	expect(refusals).toEqual(["user: its store writes no records of two partitions as one"]);
});
