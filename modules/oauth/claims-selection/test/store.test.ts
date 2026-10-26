import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { memoryRecords } from "@mod/records/testing";
import type { StoredSelection } from "../src/store.ts";
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
