import { memoryRecords } from "@mod/records/testing";
import { revokedTokensContract } from "../src/testing.ts";

revokedTokensContract("records stand-in", async () => {
	let now = 0;
	const stand = memoryRecords<true>(() => now, { shards: 1, perShard: 1 });
	return {
		revoked: {
			save: (id, lifetimeMs) => stand.records.create(id, true, lifetimeMs),
			holds: async (id) => (await stand.records.read(id)) !== undefined,
		},
		advance: (ms) => {
			now += ms;
		},
	};
});
