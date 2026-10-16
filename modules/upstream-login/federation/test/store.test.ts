import { memoryRecords } from "@mod/records/testing";
import type { StoredTransaction } from "../src/store.ts";
import { transactionStoreContract } from "../src/testing.ts";

transactionStoreContract("records stand-in", async () => {
	let now = 0;
	const stand = memoryRecords<StoredTransaction>(() => now, { shards: 1, perShard: 1 });
	return {
		transactions: {
			save: stand.records.create,
			update: stand.records.change,
			remove: stand.records.remove,
		},
		advance: (ms) => {
			now += ms;
		},
		raceNextUpdate: (_name, change) => stand.raceNextChange(change),
	};
});
