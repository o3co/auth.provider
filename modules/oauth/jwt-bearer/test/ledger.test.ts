import { jtiLedgerContract, memoryJtiLedger } from "../src/testing.ts";

jtiLedgerContract("memory", async () => {
	let now = 0;
	return {
		ledger: memoryJtiLedger("https://idp.example", () => now),
		advance: (ms) => {
			now += ms;
		},
	};
});
