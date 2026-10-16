import { crowdingFor, memoryRecords } from "@mod/records/testing";
import type { StoredFamily, StoredLink, StoredRedemption } from "../src/store.ts";
import { refreshStoreContract } from "../src/testing.ts";

refreshStoreContract("records stand-in", async () => {
	let now = 0;
	const size = { shards: 4, perShard: 5 };
	const kept = memoryRecords<StoredFamily>(() => now, size);
	const marks = memoryRecords<StoredRedemption>(() => now, size);
	const links = memoryRecords<StoredLink>(() => now, size);
	const caps = { sessionFamilies: 4, issuedAccess: 6 };
	return {
		families: { save: kept.records.create, read: kept.records.read, update: kept.records.change },
		redemptions: { save: marks.records.create, read: marks.records.read },
		sessionFamilies: memoryRecords<never>(() => now, size).keyedSets(caps.sessionFamilies),
		issuedAccess: memoryRecords<never>(() => now, size).keyedSets(caps.issuedAccess),
		tokenFamilies: { save: links.records.create, read: links.records.read },
		settles: kept.deferred,
		caps,
		advance: (ms) => {
			now += ms;
		},
		raceNextUpdate: (_id, change) => kept.raceNextChange(change),
		crowd: { limit: size.perShard, ids: crowdingFor(size).jobs },
	};
});
