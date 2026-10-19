import { memoryRecords } from "@mod/records/testing";
import type { StoredReauth } from "../src/contract.ts";
import { reauthStoreContract } from "../src/testing.ts";

reauthStoreContract("records stand-in", async () => {
	let now = 0;
	const stand = memoryRecords<StoredReauth>(() => now, { shards: 1, perShard: 1 });
	return {
		reauths: { save: stand.records.create, update: stand.records.change },
		advance: (ms) => {
			now += ms;
		},
		raceNextUpdate: (_name, change) => stand.raceNextChange(change),
	};
});
