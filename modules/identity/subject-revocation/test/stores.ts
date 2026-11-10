import { Unavailable } from "@mod/kernel";
import { unavailableSwitch } from "@mod/kernel/testing";
import { memoryRecords } from "@mod/records/testing";
import type { BoundaryStore, StoredBoundary, StoredReceipt } from "../src/store.ts";

/**
 * subject-revocation's store interface on the records stand-in, behind a switch: its clock is the
 * host's given, else none, moved on by hand; each write hands its deadline, as records does. It
 * fences and tells whether erasure is enabled unless told not to; `erasure` turns the mark on, or
 * makes it unreadable while the rest answers.
 */
export function memoryBoundaries(
	host: () => number = () => 0,
	has: { readonly fence?: boolean; readonly erasureEnabled?: boolean } = {},
) {
	let now = 0;
	const kept = memoryRecords<StoredBoundary>(() => host() + now, { shards: 1, perShard: 1 });
	const receipts = new Map<string, StoredReceipt>();
	const erasure = { on: false, unreadable: false };
	let raceNextFence: ((record: StoredBoundary) => StoredBoundary) | undefined;
	const fence: BoundaryStore["fence"] = async (subject, receiptId, allowed) => {
		for (;;) {
			const record = await kept.records.read(subject);
			const made = allowed(record);
			const race = raceNextFence;
			if (race && record !== undefined) {
				raceNextFence = undefined;
				await kept.records.change(subject, (held) => ({ value: race(held) }));
				continue;
			}
			const before = receipts.get(receiptId);
			if (made !== undefined) receipts.set(receiptId, made.value);
			return { before, after: receipts.get(receiptId) };
		}
	};
	const erasureEnabled = async () => {
		if (erasure.unreadable) throw new Unavailable("erasure mark");
		return erasure.on;
	};
	const down = unavailableSwitch<BoundaryStore>("boundary store");
	const boundaries = down.wrap({
		save: (subject, record) => kept.records.create(subject, record, "endless"),
		read: kept.records.read,
		update: (subject, change) =>
			kept.records.change(subject, (record, write) => ({ value: change(record, write) })),
		...(has.fence === false ? {} : { fence }),
		...(has.erasureEnabled === false ? {} : { erasureEnabled }),
	});
	const advanceStore = (ms: number) => {
		now += ms;
	};
	const raceFence = (change: (record: StoredBoundary) => StoredBoundary) => {
		raceNextFence = change;
	};
	return { boundaries, kept, down, advanceStore, receipts, erasure, raceFence };
}
