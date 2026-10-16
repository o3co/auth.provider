import { crowdingFor, memoryRecords } from "@mod/records/testing";
import type { StoredSession } from "../src/store.ts";
import { sessionStoreContract } from "../src/testing.ts";

sessionStoreContract("records stand-in", async () => {
	let now = 0;
	const size = { shards: 4, perShard: 5 };
	const kept = memoryRecords<StoredSession>(() => now, size);
	const index = memoryRecords<string>(() => now, size);
	return {
		sessions: {
			save: kept.records.create,
			read: kept.records.read,
			update: kept.records.change,
		},
		cookies: {
			save: index.records.create,
			read: index.records.read,
			remove: index.records.remove,
		},
		closings: kept.deferred,
		subjects: kept.keyedSets(size.perShard),
		advance: (ms) => {
			now += ms;
		},
		raceNextUpdate: (_handle, change) => kept.raceNextChange(change),
		crowd: { limit: size.perShard, handles: crowdingFor(size).jobs },
	};
});
