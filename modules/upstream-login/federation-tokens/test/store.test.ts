import { upstreamTokenStoreContract } from "../src/testing.ts";
import { memoryStores } from "./stores.ts";

upstreamTokenStoreContract("records stand-in", async () => {
	let now = 0;
	const stand = memoryStores(() => now);
	return {
		records: stand.records,
		locks: stand.locks,
		advance: (ms) => {
			now += ms;
		},
		raceNextUpdate: (_session, change) => stand.raceNext(change),
	};
});
