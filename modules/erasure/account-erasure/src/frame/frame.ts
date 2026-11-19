import type { ErasureJournal } from "@mod/erasure-journal";
import { type Clock, isUnavailable } from "@mod/kernel";
import type { ErasureMaintenance } from "../maintenance/maintenance.ts";
import { type StepAnswer, underKeyAndAlone } from "../step/step.ts";

/** The journal is held; `holder` is the medium's text for the operator, never parsed. */
export type Busy = { readonly kind: "busy"; readonly holder: string };

/** The step's refusal: any answer but `under-key`. */
export type Refused = Exclude<StepAnswer, { readonly kind: "under-key" }>;

/** What keeps a command from its body: the journal held, or the step's refusal. */
export type Kept = Busy | Refused;

/** An answer that stands, given where the hold's release then failed (unavailable): the hold may be left. */
export type HoldLeft<A> = { readonly kind: "hold-left"; readonly answer: A };

/**
 * Runs a command's body in the frame every command under the maintenance key runs in: it takes
 * the journal's hold, runs the step, runs the body with the epoch the step answers, and asks its
 * release once, also where the step or the body throws. Where the journal is held, it answers
 * `busy` and calls nothing more; where the step answers anything but `under-key`, that answer, and
 * the body never runs. Where the release is unavailable, an answer is given as `hold-left` and a
 * throw is thrown as it was; anything else the release throws is thrown in place of an answer.
 */
export async function inFrame<T>(
	parts: {
		readonly journal: ErasureJournal;
		readonly maintenance: ErasureMaintenance;
		readonly clock: Clock;
	},
	way: "entering" | "passing",
	body: (epoch: string) => Promise<T>,
): Promise<Kept | T | HoldLeft<Refused | T>> {
	const hold = await parts.journal.hold();
	if (hold.kind === "busy") return { kind: "busy", holder: hold.holder };
	let answer: Refused | T;
	try {
		const step = await underKeyAndAlone(parts.maintenance, way, parts.clock);
		answer = step.kind === "under-key" ? await body(step.epoch) : step;
	} catch (error) {
		// The first failure stands: whatever the release then throws, the step's or the body's throw is thrown.
		await hold.release().catch(() => undefined);
		throw error;
	}
	try {
		await hold.release();
	} catch (error) {
		if (isUnavailable(error)) return { kind: "hold-left", answer };
		throw error;
	}
	return answer;
}
