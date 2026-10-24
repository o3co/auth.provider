import { contract, extensionPoint } from "@mod/kernel";

/** What a reset removed: how many factors, and their kinds. */
export interface Removed {
	readonly count: number;
	readonly kinds: readonly string[];
}

/**
 * How a reset run ended. Done: every step ran, with each part's count by its name (none where none is
 * composed). Stopped: a step was unavailable, at `sessions` (the first boundary, or the second),
 * `factors` (their removal), `parts` (a part's removal) or `lock` (the lockout's release), and running
 * it again finishes it. `removed` is given where the factors' removal answered before the run
 * stopped: never at `factors`, always at `parts` and `lock`, and at `sessions` only for the second
 * boundary.
 * Without it, whether the factors went is not known: a removal that failed may have taken them all,
 * as `mfa` removes the records before the witness's mark.
 */
export type ResetOutcome =
	| {
			readonly kind: "done";
			readonly removed: number;
			readonly kinds: readonly string[];
			readonly parts: Readonly<Record<string, number>>;
	  }
	| { readonly kind: "stopped"; readonly at: "sessions" | "factors"; readonly removed?: never }
	| {
			readonly kind: "stopped";
			readonly at: "sessions" | "parts" | "lock";
			readonly removed: Removed;
	  };

/** An operator's reset of a subject's second factors, for the embedder that has verified who asks. */
export interface MfaReset {
	/** Answers how the run ended; throws a step's failure that is not unavailable, and a malformed input. */
	run(subject: string, options?: { readonly requestedBy?: string }): Promise<ResetOutcome>;
}

export const mfaReset = contract<MfaReset>("mfa-reset.reset");

/** A part of a subject's reset: what a module holds that the reset removes beside the second factors. */
export interface ResetPart {
	/** What it removes, in its own words; the audit names it. */
	readonly name: string;
	/**
	 * Removes what it holds for the subject, inside the reset's boundaries; never moves one. Done with
	 * how many went, or stopped where its store was unavailable; throws any other failure. Run again,
	 * it finishes what a stopped run left, done with none where nothing is left.
	 */
	remove(
		subject: string,
	): Promise<{ readonly kind: "done"; readonly removed: number } | { readonly kind: "stopped" }>;
}

/** The parts a reset removes, one per name: two of one name refuse boot. */
export const resetParts = extensionPoint<ResetPart>("mfa-reset.parts", {
	multiplicity: "keyed",
	keyOf: (part) => part.name,
});
