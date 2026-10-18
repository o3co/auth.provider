import { contract } from "@mod/kernel";

/** Where the assertions already used are kept, by a name for the issuer and `jti`. Throws Unavailable when it cannot tell. */
export interface SpentAssertions {
	/** Keeps the name for its lifetime, unless it is kept already. */
	save(name: string, lifetimeMs: number): Promise<"created" | "exists">;
}

export const spentAssertions = contract<SpentAssertions>("jwt-bearer.spent-assertions");

/** An assertion whose use was lost could be exchanged again, by whoever saw it. */
export const spentAssertionsNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
} as const;
