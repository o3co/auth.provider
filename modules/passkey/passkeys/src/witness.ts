import { extensionPoint } from "@mod/kernel";

/**
 * Who remembers, apart from the passkey store, that a subject holds a passkey: an outside ledger, so
 * losing the store never reads as holding none. Per subject its calls are linearizable, an answered
 * write lasts, and an answer is never older than the last answered write; where it cannot keep that,
 * or cannot tell, it throws Unavailable, never a default.
 */
export interface PasskeyWitness {
	/** Whether the subject carries the mark. */
	read(subject: string): Promise<boolean>;
	/** Sets the mark to `token` unless one is set, at once; whether the mark is `token`'s after. The same token answers alike however often. */
	enroll(subject: string, token: string): Promise<boolean>;
	/** Removes the mark only where it is `token`'s, as one atomic step; any other mark, and none, stay as they are. */
	withdraw(subject: string, token: string): Promise<void>;
	/** The mark's token, whoever set it; none where no mark is set. Kept as `read` is, never behind an answered write. */
	markedWith(subject: string): Promise<string | undefined>;
}

/** At most one witness: passkeys refuses to start with two. */
export const passkeyWitnesses = extensionPoint<PasskeyWitness>("passkeys.witnesses", {
	multiplicity: "many",
});
