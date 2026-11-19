import { changesTogether } from "@mod/records";
import type { Control, Store, StoreControl } from "@mod/store";
import type { Phase } from "../index/index.ts";

const mark = "subject-records.phase";

/** The phase as one process reads it once and keeps it, as `subjectRecordsPhase.once` gives it. */
export interface PhaseOnce {
	read(): Promise<Phase>;
}

const read = async (control: StoreControl): Promise<Phase> =>
	(await control.control()).marks[mark]?.value === "indexed" ? "indexed" : "reader";

/**
 * The phase records are in, kept as a mark of the store's control record: `indexed` where the mark
 * holds it, in any epoch; `reader` where it does not, which no write makes. Monotone. A process
 * keeps the first reading that answers (`once`), so it turns indexed only by a start after the
 * mark. Written only under the maintenance key, by the one who holds the store's upkeep, from what
 * `write` answers.
 */
const subjectRecordsPhaseOnce = (control: StoreControl | undefined): PhaseOnce => {
	let phase: Phase | undefined;
	return {
		read: async () => {
			phase ??= control === undefined ? "reader" : await read(control);
			return phase;
		},
	};
};

/** The mark that turns records indexed, decided for the store whose control record `control` is. */
const write = (
	control: Control,
	store: Store,
):
	| { readonly kind: "write"; readonly name: string; readonly value: "indexed" }
	| { readonly kind: "not-in-maintenance" }
	| { readonly kind: "not-paired" } => {
	if (!control.maintenance) return { kind: "not-in-maintenance" };
	if (!changesTogether(store)) return { kind: "not-paired" };
	return { kind: "write", name: mark, value: "indexed" };
};

export const subjectRecordsPhase = Object.freeze({
	mark,
	read,
	/**
	 * The phase as one process reads it once and keeps it, monotone: while the store cannot answer,
	 * `read` throws Unavailable and the next call reads again, so a store's blip refuses no start.
	 * With no control (a store adapter that offers none), `reader`.
	 */
	once: subjectRecordsPhaseOnce,
	/**
	 * The mark that turns records indexed, for the store whose control record `control` is:
	 * `not-in-maintenance` outside the maintenance key, then `not-paired` where the store writes no
	 * records of two partitions as one, which indexed records need, so every next start would refuse.
	 */
	write,
	/**
	 * Writes that mark through `markWith`, the holder of the store's upkeep's own write, where `write`
	 * decides it: `written` once it is written, or `write`'s refusal, with nothing written.
	 */
	writeWith: async (
		control: Control,
		store: Store,
		markWith: (name: string, value: "indexed") => Promise<unknown>,
	): Promise<
		| { readonly kind: "written" }
		| { readonly kind: "not-in-maintenance" }
		| { readonly kind: "not-paired" }
	> => {
		const decided = write(control, store);
		if (decided.kind !== "write") return decided;
		await markWith(decided.name, decided.value);
		return { kind: "written" };
	},
});
