import { unavailableSwitch } from "@mod/kernel/testing";
import { memoryRecords } from "@mod/records/testing";
import type { BoundaryStore, StoredBoundary } from "../src/store.ts";

/** subject-revocation's store interface on the records stand-in, its clock moved by hand, behind a switch. */
export function memoryBoundaries() {
	let now = 0;
	const kept = memoryRecords<StoredBoundary>(() => now, { shards: 1, perShard: 1 });
	const down = unavailableSwitch<BoundaryStore>("boundary store");
	const boundaries = down.wrap({
		save: (subject, record) => kept.records.create(subject, record, "endless"),
		read: kept.records.read,
		update: (subject, change) =>
			kept.records.change(subject, (record) => ({ value: change(record) })),
	});
	const advanceStore = (ms: number) => {
		now += ms;
	};
	return { boundaries, kept, down, advanceStore };
}
