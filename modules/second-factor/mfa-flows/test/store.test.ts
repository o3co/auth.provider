import { transactionStoreContract } from "../src/testing.ts";
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
