import { type Clock, isUnavailable } from "@mod/kernel";
import type { ErasureMaintenance } from "../maintenance/maintenance.ts";

/** The mark holding when `erasure-enter` was last shown alone under the present epoch's key. */
export const entryTimeMark = "account-erasure.entered";

/** What the store showed that keeps a command from running alone. */
export type NotAlone =
	| { readonly kind: "accompanied"; readonly count: number }
	| { readonly kind: "unchecked"; readonly reasons: readonly string[] };

/** What the read after entering showed in place of `alone`: not alone, or no answer. */
export type NotShownAlone = NotAlone | { readonly kind: "unavailable" };

/** The step's answer: under the key and alone, with the epoch, or why not. */
export type StepAnswer =
	| { readonly kind: "under-key"; readonly epoch: string }
	| NotAlone
	| { readonly kind: "not-in-maintenance" }
	| {
			readonly kind: "entered-not-shown-alone";
			readonly epoch: string;
			readonly found: NotShownAlone;
			readonly wayOn: string;
	  };

const wayOn: Record<NotShownAlone["kind"], string> = {
	accompanied: "stop that client and run erasure-enter again",
	unchecked: "run erasure-enter again once every server answers",
	unavailable: "run erasure-enter again once every server answers",
};

/** The read after entering: its answer, or `unavailable` where it gives none; any other throw is thrown. */
async function shownAfterEntering(maintenance: ErasureMaintenance) {
	try {
		return await maintenance.alone();
	} catch (error) {
		if (isUnavailable(error)) return { kind: "unavailable" } as const;
		throw error;
	}
}

/**
 * Brings a command under the maintenance key, alone, or refuses it. `entering` is `erasure-enter`'s
 * alone: it reads `alone()`, enters, reads it again, and once shown alone writes the entry-time
 * mark. `passing` is every other command's: it
 * never enters, and refuses where the key is not held or the store is not alone. A call that is
 * unavailable stops the step as thrown, and the step calls nothing after it, apart from the read
 * after entering: the key is set by then, so that one answers.
 */
export async function underKeyAndAlone(
	maintenance: ErasureMaintenance,
	way: "entering" | "passing",
	clock: Clock,
): Promise<StepAnswer> {
	if (way === "passing") {
		const { epoch, maintenance: held } = await maintenance.record();
		if (!held || epoch === null) return { kind: "not-in-maintenance" };
		const seen = await maintenance.alone();
		return seen.kind === "alone" ? { kind: "under-key", epoch } : seen;
	}
	const before = await maintenance.alone();
	if (before.kind !== "alone") return before;
	const { epoch } = await maintenance.enter();
	const after = await shownAfterEntering(maintenance);
	if (after.kind !== "alone") {
		return { kind: "entered-not-shown-alone", epoch, found: after, wayOn: wayOn[after.kind] };
	}
	// Shown alone under the new key: its entry time, in this epoch, on the tool host's clock.
	await maintenance.mark(entryTimeMark, clock.now());
	return { kind: "under-key", epoch };
}
