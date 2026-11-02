import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { memoryRecords } from "@mod/records/testing";
import { expect, it } from "vitest";
import { type StoredSelection, selectionRecords } from "../src/store.ts";
import { claimsSelectionInMemory, selectionRecordsContract } from "../src/testing.ts";

selectionRecordsContract("records stand-in", async () => {
	let now = 0;
	const { records } = memoryRecords<StoredSelection>(() => now, { shards: 1, perShard: 1 });
	return {
		records: { save: records.create, read: records.read },
		advance: (ms) => {
			now += ms;
		},
	};
});

selectionRecordsContract("in-memory stand-in", async () => {
	let now = 0;
	const stand = claimsSelectionInMemory();
	await assemble({
		modules: [stand.module],
		config: kernelConfig(),
		runtime: quietRuntime({ clock: { now: () => now } }),
	});
	return {
		records: stand.records,
		advance: (ms) => {
			now += ms;
		},
	};
});

it("hands the composition its records through what a test wraps them in, on the composition's clock", async () => {
	const seen: string[] = [];
	const stand = claimsSelectionInMemory({
		around: (records) => ({
			save: async (name, kept, ms) => {
				seen.push(name);
				return records.save(name, kept, ms);
			},
			read: records.read,
		}),
	});
	let now = 0;
	const app = await assemble({
		modules: [stand.module],
		config: kernelConfig(),
		runtime: quietRuntime({ clock: { now: () => now } }),
	});
	const kept = { format: 1 } as unknown as StoredSelection;
	await app.get(selectionRecords).save("c.one", kept, 1000);
	expect(seen).toEqual(["c.one"]);
	expect(await stand.records.read("c.one")).toEqual(kept);
	now = 1000;
	expect(await app.get(selectionRecords).read("c.one")).toBeUndefined();
});
