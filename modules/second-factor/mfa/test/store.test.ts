import { factorStoreContract } from "../src/testing.ts";
import { memoryFactors } from "./stores.ts";

factorStoreContract("records stand-in", async () => {
	let now = 0;
	const stand = memoryFactors(() => now);
	return {
		factors: stand.factors,
		advance: (ms) => {
			now += ms;
		},
		raceNextUpdate: (_key, change) => stand.raceNextChange(change),
	};
});
