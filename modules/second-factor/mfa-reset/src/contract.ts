import { contract } from "@mod/kernel";

/** What a reset removed: how many factors, and their kinds. */
export interface Removed {
	readonly count: number;
	readonly kinds: readonly string[];
}

/**
 * How a reset run ended. Done: every step ran. Stopped: a step was unavailable, at `sessions` (the
 * first boundary, or the second), `factors` (their removal) or `lock` (the lockout's release), and
 * running it again finishes it. `removed` is given where the factors' removal answered before the run
 * stopped: never at `factors`, always at `lock`, and at `sessions` only for the second boundary.
 * Without it, whether the factors went is not known: a removal that failed may have taken them all,
 * as `mfa` removes the records before the witness's mark.
 */
export type ResetOutcome =
	| { readonly kind: "done"; readonly removed: number; readonly kinds: readonly string[] }
	| { readonly kind: "stopped"; readonly at: "sessions" | "factors"; readonly removed?: never }
	| { readonly kind: "stopped"; readonly at: "sessions" | "lock"; readonly removed: Removed };

/** An operator's reset of a subject's second factors, for the embedder that has verified who asks. */
export interface MfaReset {
	/** Answers how many factors went; rejects as unavailable when a step cannot be done, and running it again finishes it. */
	reset(subject: string, options?: { readonly requestedBy?: string }): Promise<number>;
	/** Answers how the run ended; throws a step's failure that is not unavailable, and a malformed input. */
	run(subject: string, options?: { readonly requestedBy?: string }): Promise<ResetOutcome>;
}

export const mfaReset = contract<MfaReset>("mfa-reset.reset");
