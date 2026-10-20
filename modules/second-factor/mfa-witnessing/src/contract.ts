import { contract } from "@mod/kernel";

/** What filling a subject's mark found: `marked` set one, `held` found one, `none` found neither factor nor mark, `inconsistent` a mark beside nothing counting (left as it is). */
export type Backfilled = "marked" | "held" | "none" | "inconsistent";

/** Fills the witness's mark of a subject that holds a counting factor and carries none, as one enrolled before the witness was composed. */
export interface WitnessBackfill {
	settle(subject: string): Promise<Backfilled>;
}

export const witnessBackfill = contract<WitnessBackfill>("mfa-witnessing.backfill");
