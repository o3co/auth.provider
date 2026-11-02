import { contract } from "@mod/kernel";

/** What filling a subject's mark found: `marked` set one, `held` found one, `none` found neither passkey nor mark, `pending` only pending ones written (the mark as it is), `inconsistent` a mark beside nothing written (left as it is). */
export type Backfilled = "marked" | "held" | "none" | "pending" | "inconsistent";

/** Fills the witness's mark of a subject that holds a passkey and carries none, as one registered before the witness was composed. */
export interface PasskeyBackfill {
	settle(subject: string): Promise<Backfilled>;
}

export const passkeyBackfill = contract<PasskeyBackfill>("passkey-witnessing.backfill");
