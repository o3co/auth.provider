import type { Control, StoreControl } from "@mod/store";
import type { Phase } from "../index/index.ts";

const mark = "subject-records.phase";

/** The phase a control record holds: `indexed` where its mark says so, in any epoch; else `reader`. */
const phaseOf = (control: Control): Phase =>
	control.marks[mark]?.value === "indexed" ? "indexed" : "reader";

/**
 * The phase records are in, kept as a mark of the store's control record. Read once as a process
 * starts, and monotone: `indexed`, once written in any epoch, stays. Written only under the
 * maintenance key, by the one who holds the store's upkeep, from what `write` answers.
 */
export const subjectRecordsPhase = Object.freeze({
	mark,
	read: async (control: StoreControl): Promise<Phase> => phaseOf(await control.control()),
	/**
	 * The mark to write for `phase`: `not-in-maintenance` outside the maintenance key, and
	 * `stays-indexed` for `reader` once indexed, which the read would never see.
	 */
	write: (
		control: Control,
		phase: Phase,
	):
		| { readonly kind: "write"; readonly name: string; readonly value: Phase }
		| { readonly kind: "not-in-maintenance" }
		| { readonly kind: "stays-indexed" } => {
		if (!control.maintenance) return { kind: "not-in-maintenance" };
		if (phase === "reader" && phaseOf(control) === "indexed") return { kind: "stays-indexed" };
		return { kind: "write", name: mark, value: phase };
	},
});
