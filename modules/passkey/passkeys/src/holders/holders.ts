import type { Asked, PasskeyHolders, PasskeyWitnessing } from "../contract.ts";
import type { Emptied, KeptPasskeys } from "../records.ts";

export type { Asked } from "../contract.ts";

export interface HolderParts {
	readonly records: KeptPasskeys;
	/** Where one is contributed, it keeps the witness's mark in line; none leaves the store alone to tell. */
	readonly witnessing: PasskeyWitnessing | undefined;
	/** A new holder's handle, for a reset of a subject that has none. */
	readonly handle: () => string;
}

/** The subjects' holdings, and the settle that asks the witnessing where passkeys settles. */
export function holdersOver(p: HolderParts) {
	const holds = async (subject: string) => (await p.records.listed(subject)).length > 0;
	/**
	 * Asks the witnessing, if any, to bring the mark in line: after a write that emptied the list
	 * (`emptied`), with what that write left, read anew; otherwise with whether the subject holds a
	 * passkey, read anew. Answers whether it holds, as the read the mark agreed with saw it, or as the
	 * store alone tells without a witnessing.
	 */
	const settle = async (subject: string, at: Asked, emptied?: Emptied): Promise<boolean> => {
		const witnessing = p.witnessing;
		const holding = () => holds(subject);
		if (witnessing === undefined) return holding();
		if (emptied === undefined) return witnessing.settle(subject, at, holding);
		await witnessing.emptied(subject, at, () => p.records.afterRemoval(subject, emptied), holding);
		// After an emptying write no caller reads the answer: it tells nothing of the mark.
		return false;
	};
	const holders: PasskeyHolders = {
		// What the settle saw, the mark agreeing: never a read of the passkeys alone after it.
		held: (subject) => settle(subject, "held"),
		cleared: async (subject) => {
			const { removed, emptied } = await p.records.cleared(subject, p.handle());
			// A reset ends the mark whatever the list held: a mark beside none is what it mends.
			await settle(subject, "reset", emptied);
			return { removed };
		},
		settle: async (subject) => {
			await settle(subject, "settle");
		},
		witnessed: p.witnessing !== undefined,
	};
	return { holders, settle };
}
