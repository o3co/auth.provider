import { challengeStoreContract, passkeyStoreContract } from "../src/testing.ts";
import { memoryStores } from "./stores.ts";

passkeyStoreContract("records stand-in", async () => {
	let now = 0;
	const stand = memoryStores(() => now);
	return {
		passkeys: stand.passkeys,
		advance: (ms) => {
			now += ms;
		},
		raceNextUpdate: (_key, change) => stand.raceSubjects(change),
	};
});

challengeStoreContract("records stand-in", async () => {
	let now = 0;
	const stand = memoryStores(() => now);
	return {
		challenges: stand.challenges,
		advance: (ms) => {
			now += ms;
		},
	};
});
