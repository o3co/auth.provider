import type { SelectionRecords } from "../store.ts";

/** Why the store's set of ports cannot be used, or none: the one statement of the set, as the card gives it. */
export function portsRefused(records: SelectionRecords): string | undefined {
	if ((records.erase === undefined) !== (records.migrate === undefined)) {
		return "the selection store offers part of its erase and migrate: both, or neither";
	}
	return undefined;
}

/** The store's erasure ports, where it offers both, each called on the store; none otherwise. */
export function portsOf(records: SelectionRecords) {
	const { erase, migrate } = records;
	if (!erase || !migrate) return undefined;
	return {
		erase: (...args: Parameters<typeof erase>) => erase.apply(records, args),
		migrate: (...args: Parameters<typeof migrate>) => migrate.apply(records, args),
	};
}
