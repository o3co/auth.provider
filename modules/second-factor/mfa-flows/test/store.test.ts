import { memoryRecords } from "@mod/records/testing";
import { type StoredTransaction, transactionsPerHolder } from "../src/store.ts";
import { transactionListingsContract, transactionStoreContract } from "../src/testing.ts";
import { memoryTransactions } from "./stores.ts";

transactionStoreContract("records stand-in", async () => {
	let now = 0;
	const stand = memoryTransactions(() => now);
	return {
		transactions: stand.transactions,
		advance: (ms) => {
			now += ms;
		},
		raceNextUpdate: (_key, change) => stand.raceNextChange(change),
	};
});

transactionListingsContract("records stand-in", async () => {
	let now = 0;
	const stand = memoryRecords<StoredTransaction>(() => now, { shards: 1, perShard: 1 });
	return {
		listings: stand.keyedSets(transactionsPerHolder),
		advance: (ms) => {
			now += ms;
		},
	};
});
