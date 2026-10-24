import { defineModule } from "@mod/kernel";
import { memoryRecords } from "@mod/records/testing";
import { pendingNotices, sessionClients } from "../src/store.ts";

/** rp-logout's stores on the records stand-in, at most `cap` clients to a session, on the given clock. */
export function memoryStores(now: () => number, cap = 4) {
	const stand = memoryRecords<string>(now, { shards: 4, perShard: 100 });
	const clients = stand.keyedSets(cap);
	const module = defineModule({ name: "rp-logout-stores", takes: [] }, (m) => [
		m.provide(sessionClients).by(() => clients),
		m.provide(pendingNotices).by(() => stand.deferred),
	]);
	return { module, clients, notices: stand.deferred, size: cap };
}
