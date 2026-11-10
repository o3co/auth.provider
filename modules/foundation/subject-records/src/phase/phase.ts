import type { Control, StoreControl } from "@mod/store";
import type { Phase } from "../index/index.ts";

const mark = "subject-records.phase";

/**
 * The phase records are in, kept as a mark of the store's control record: `indexed` where the mark
 * holds it, in any epoch; `reader` where it does not, which no write makes. Read once as a process
 * starts, and monotone. Written only under the maintenance key, by the one who holds the store's
 * upkeep, from what `write` answers.
 */
export const subjectRecordsPhase = Object.freeze({
	mark,
	read: async (control: StoreControl): Promise<Phase> =>
		(await control.control()).marks[mark]?.value === "indexed" ? "indexed" : "reader",
	/** The mark that turns records indexed; `not-in-maintenance` outside the maintenance key. */
	write: (
		control: Control,
	):
		| { readonly kind: "write"; readonly name: string; readonly value: "indexed" }
		| { readonly kind: "not-in-maintenance" } =>
		control.maintenance
			? { kind: "write", name: mark, value: "indexed" }
			: { kind: "not-in-maintenance" },
});
