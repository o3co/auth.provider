import { changesTogether } from "@mod/records";
import type { Control, Store, StoreControl } from "@mod/store";
import type { Phase } from "../index/index.ts";

const mark = "subject-records.phase";

const read = async (control: StoreControl): Promise<Phase> =>
	(await control.control()).marks[mark]?.value === "indexed" ? "indexed" : "reader";

/**
 * The phase records are in, kept as a mark of the store's control record: `indexed` where the mark
 * holds it, in any epoch; `reader` where it does not, which no write makes. Read once as a process
 * starts, and monotone. Written only under the maintenance key, by the one who holds the store's
 * upkeep, from what `write` answers.
 */
export const subjectRecordsPhase = Object.freeze({
	mark,
	read,
	/** As `read`, where a store adapter may offer no control: none is `reader`; a read that fails, fails. */
	readFrom: async (control: StoreControl | undefined): Promise<Phase> =>
		control === undefined ? "reader" : read(control),
	/**
	 * The mark that turns records indexed, for the store whose control record `control` is:
	 * `not-in-maintenance` outside the maintenance key, then `not-paired` where the store writes no
	 * records of two partitions as one, which indexed records need, so every next start would refuse.
	 */
	write: (
		control: Control,
		store: Store,
	):
		| { readonly kind: "write"; readonly name: string; readonly value: "indexed" }
		| { readonly kind: "not-in-maintenance" }
		| { readonly kind: "not-paired" } => {
		if (!control.maintenance) return { kind: "not-in-maintenance" };
		if (!changesTogether(store)) return { kind: "not-paired" };
		return { kind: "write", name: mark, value: "indexed" };
	},
});
