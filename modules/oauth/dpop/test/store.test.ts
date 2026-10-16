import { memoryRecords } from "@mod/records/testing";
import { spentProofsContract } from "../src/testing.ts";

spentProofsContract("records stand-in", async () => {
	let now = 0;
	const stand = memoryRecords<true>(() => now, { shards: 1, perShard: 1 });
	return {
		spent: { save: (name, lifetimeMs) => stand.records.create(name, true, lifetimeMs) },
		advance: (ms) => {
			now += ms;
		},
	};
});
