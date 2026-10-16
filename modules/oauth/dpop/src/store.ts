import { contract } from "@mod/kernel";

/** Where the proofs already used are kept, by a name for the key and `jti`. Throws Unavailable when it cannot tell. */
export interface SpentProofs {
	/** Keeps the name for its lifetime, unless it is kept already. */
	save(name: string, lifetimeMs: number): Promise<"created" | "exists">;
}

export const spentProofs = contract<SpentProofs>("dpop.spent-proofs");

/** A proof whose use was lost could be used again by whoever saw it, with the key's token. */
export const spentProofsNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
} as const;
