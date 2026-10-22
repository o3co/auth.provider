import { factorStoreContract } from "../src/testing.ts";
import { memoryFactors } from "./stores.ts";

factorStoreContract("records stand-in writing a list and its claim in two steps", async () => {
	let now = 0;
	const stand = memoryFactors(() => now, { together: false });
	return {
		factors: stand.factors,
		advance: (ms) => {
			now += ms;
		},
		raceNextUpdate: (_key, change) => stand.raceNextChange(change),
	};
});

factorStoreContract("records stand-in writing a list and a claim together", async () => {
	let now = 0;
	const stand = memoryFactors(() => now, { together: true });
	return {
		factors: stand.factors,
		advance: (ms) => {
			now += ms;
		},
		raceNextUpdate: (_key, change) => stand.raceNextChange(change),
	};
});
