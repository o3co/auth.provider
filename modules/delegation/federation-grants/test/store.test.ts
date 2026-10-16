import { grantStoreContract, refreshLockStoreContract } from "../src/testing.ts";
import { memoryStores } from "./stores.ts";

grantStoreContract("records stand-in", async () => {
	let now = 0;
	const stand = memoryStores(() => now, 3);
	return {
		grants: stand.grants,
		steps: stand.steps,
		pending: stand.pending,
		subjects: stand.subjects,
		cap: 3,
		advance: (ms) => {
			now += ms;
		},
		raceNextChange: (_id, change) => stand.raceNext(change),
	};
});

refreshLockStoreContract("records stand-in", async () => {
	let now = 0;
	const stand = memoryStores(() => now);
	return {
		locks: stand.lockStore,
		advance: (ms) => {
			now += ms;
		},
	};
});
