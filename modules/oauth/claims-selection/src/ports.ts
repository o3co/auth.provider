import type { SelectionRecords } from "./store.ts";

/** Why the store's set of ports cannot be used, or none: the one statement of the set, as the card gives it. */
export function portsRefused(records: SelectionRecords): string | undefined {
	if ((records.create === undefined) === (records.save === undefined)) {
		return "the selection store offers both or neither of save and create: exactly one";
	}
	if ((records.erase === undefined) !== (records.migrate === undefined)) {
		return "the selection store offers part of its erase and migrate: both, or neither";
	}
	return undefined;
}
