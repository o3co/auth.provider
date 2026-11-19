import type { ErasureJournal } from "@mod/erasure-journal";
import type { Clock } from "@mod/kernel";
import type { ErasureMaintenance } from "../maintenance/maintenance.ts";
import { type StepAnswer, underKeyAndAlone } from "../step/step.ts";

/** Another command holds the journal; `holder` is the medium's text for the operator, never parsed. */
export type Busy = { readonly kind: "busy"; readonly holder: string };

/** What keeps a command from its body: the journal held by another, or the step's refusal. */
export type Kept = Busy | Exclude<StepAnswer, { readonly kind: "under-key" }>;

/**
 * Runs a command's body in the frame every command under the maintenance key runs in: it takes
 * the journal's hold, runs the step, runs the body with the epoch the step answers, and releases
 * the hold, also where the step or the body throws. Where another holds the journal, it answers
 * `busy` and calls nothing more; where the step answers anything but `under-key`, that answer, and
 * the body never runs.
 */
export async function inFrame<T>(
	parts: {
		readonly journal: ErasureJournal;
		readonly maintenance: ErasureMaintenance;
		readonly clock: Clock;
	},
	way: "entering" | "passing",
	body: (epoch: string) => Promise<T>,
): Promise<Kept | T> {
	const hold = await parts.journal.hold();
	if (hold.kind === "busy") return { kind: "busy", holder: hold.holder };
	try {
		const step = await underKeyAndAlone(parts.maintenance, way, parts.clock);
		if (step.kind !== "under-key") return step;
		return await body(step.epoch);
	} finally {
		await hold.release();
	}
}
