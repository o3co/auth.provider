import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { memoryRecords } from "@mod/records/testing";
import { askStore, grantStore, type StoredAsk, type StoredGrant } from "../src/store.ts";
import { askStoreContract, consentStoresOn, grantStoreContract } from "../src/testing.ts";

let now = 0;
const runtime = quietRuntime({ clock: { now: () => now } });
const advance = (ms: number) => {
	now += ms;
};

async function standIn() {
	const size = { shards: 1, perShard: 1 };
	const grants = memoryRecords<StoredGrant>(() => now, size);
	const asks = memoryRecords<StoredAsk>(() => now, size);
	const modules = [consentStoresOn({ grants, asks })];
	const app = await assemble({ modules, config: kernelConfig(), runtime });
	return { app, grants, asks };
}

grantStoreContract("records stand-in", async () => {
	const { app, grants } = await standIn();
	return {
		records: app.get(grantStore),
		advance,
		raceNextUpdate: (_key, change) => grants.raceNextChange(change),
	};
});

askStoreContract("records stand-in", async () => {
	const { app, asks } = await standIn();
	return {
		records: app.get(askStore),
		advance,
		raceNextUpdate: (_key, change) => asks.raceNextChange(change),
	};
});
