import { memoryRecords } from "@mod/records/testing";
import type { StoredTransaction } from "../src/store.ts";
import { transactionListingsContract, transactionStoreContract } from "../src/testing.ts";
import { memoryTransactions } from "./stores.ts";

/** The live transactions a holder keeps here, as mfa-flows-store keeps them by default. */
const perHolder = 5;

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
		listings: stand.keyedSets(perHolder),
		cap: perHolder,
		advance: (ms) => {
			now += ms;
		},
	};
});
