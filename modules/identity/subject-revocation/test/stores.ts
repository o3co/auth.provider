import { unavailableSwitch } from "@mod/kernel/testing";
import { memoryRecords } from "@mod/records/testing";
import type { BoundaryStore, StoredBoundary } from "../src/store.ts";

/**
 * subject-revocation's store interface on the records stand-in, behind a switch: its clock is the
 * host's given, else none, moved on by hand; each write hands its deadline, as records does.
 */
export function memoryBoundaries(host: () => number = () => 0) {
	let now = 0;
	const kept = memoryRecords<StoredBoundary>(() => host() + now, { shards: 1, perShard: 1 });
	const down = unavailableSwitch<BoundaryStore>("boundary store");
	const boundaries = down.wrap({
		save: (subject, record) => kept.records.create(subject, record, "endless"),
		read: kept.records.read,
		update: (subject, change) =>
			kept.records.change(subject, (record, write) => ({ value: change(record, write) })),
	});
	const advanceStore = (ms: number) => {
		now += ms;
	};
	return { boundaries, kept, down, advanceStore };
}
