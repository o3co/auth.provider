import { contract } from "@mod/kernel";

/**
 * How a passkey reset ended. Done: every step ran. Stopped: the first step that was unavailable, at
 * `sessions` (the first boundary, or the second) or `passkeys` (their removal), and running it again
 * finishes it. `removed` is given where the removal answered before the run stopped: never at
 * `passkeys`, and at `sessions` only for the second boundary. Without it, whether the list went is
 * not known: a removal that failed may have written it, as the witness's mark goes after the list.
 */
export type PasskeyResetOutcome =
	| { readonly kind: "done"; readonly removed: number }
	| { readonly kind: "stopped"; readonly at: "sessions" | "passkeys"; readonly removed?: never }
	| { readonly kind: "stopped"; readonly at: "sessions"; readonly removed: number };

/** An operator's reset of a subject's passkeys, for the embedder that has verified who asks. */
export interface PasskeyReset {
	/**
	 * Moves the subject's revocation boundary, empties its passkey list, and moves the boundary again.
	 * Answers how the run ended; throws a step's failure that is not unavailable, and a malformed input.
	 */
	reset(subject: string, options?: { readonly requestedBy?: string }): Promise<PasskeyResetOutcome>;
}

export const passkeyReset = contract<PasskeyReset>("passkey-reset.reset");

/** The passkeys' step alone, for a reset that moves the boundaries itself (`mfa-reset`'s parts). Never moves a boundary. */
export interface PasskeyResetPart {
	/** Done with how many list entries it took off, or stopped where their removal was unavailable; throws any other failure. */
	passkeys(
		subject: string,
	): Promise<{ readonly kind: "done"; readonly removed: number } | { readonly kind: "stopped" }>;
}

/** Taken by the bridge that runs it under `mfa-reset`'s boundaries alone. */
export const passkeyResetPart = contract<PasskeyResetPart>("passkey-reset.part", {
	takenBy: ["mfa-reset-passkeys"],
});
