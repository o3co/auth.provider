import { defineModule } from "@mod/kernel";
import { unavailableSwitch } from "@mod/kernel/testing";
import { memoryRecords } from "@mod/records/testing";
import {
	type RefreshLocks,
	refreshLocks,
	type StoredUpstreamTokens,
	type UpstreamTokenStore,
	upstreamTokenStore,
} from "../src/store.ts";

/** federation-tokens' stores on the records stand-in, on the given clock; the records behind a switch. */
export function memoryStores(now: () => number = () => 0) {
	const size = { shards: 1, perShard: 1 };
	const stand = memoryRecords<StoredUpstreamTokens>(now, size);
	// Locks see real time pass on top of the test's clock, as a store's do: a lock let go ends a millisecond later.
	const started = Date.now();
	const lockStand = memoryRecords<string>(() => now() + (Date.now() - started), size);
	/** Every value the store was given, as written. */
	const given: unknown[] = [];
	const down = unavailableSwitch<UpstreamTokenStore>("records");
	/** What runs as a save begins, before it lands. */
	const during = { save: async () => {} };
	const records: UpstreamTokenStore = down.wrap({
		save: async (session, record, lifetimeMs) => {
			await during.save();
			given.push(record);
			return stand.records.create(session, record, lifetimeMs);
		},
		read: stand.records.read,
		update: async (session, change) =>
			stand.records.change(session, (record) => {
				const changed = change(record);
				if (changed) given.push(changed.value);
				return changed;
			}),
		remove: stand.records.remove,
		// One session a page, so a walk must go on by its cursor.
		scan: async (cursor) => {
			const keys = (await stand.records.scan()).keys.toSorted();
			const at = cursor === undefined ? 0 : keys.indexOf(cursor) + 1;
			const page = keys.slice(at, at + 1);
			const last = page[0];
			return at + 1 < keys.length && last !== undefined
				? { keys: page, cursor: last }
				: { keys: page };
		},
	});
	const locks: RefreshLocks = {
		hold: (name, mark, lifetimeMs) => lockStand.records.create(name, mark, lifetimeMs),
		update: lockStand.records.change,
	};
	const module = defineModule(
		{ name: "federation-tokens-stores", replicaSafe: false, takes: [] },
		(m) => [
			m.provide(upstreamTokenStore).by(() => records),
			m.provide(refreshLocks).by(() => locks),
		],
	);
	return { module, records, locks, down, given, during, raceNext: stand.raceNextChange };
}
