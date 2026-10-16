import { contract } from "@mod/kernel";

/** Where the assertions already used are kept, by a name for the client and `jti`. Throws Unavailable when it cannot tell. */
export interface SpentAssertions {
	/** Keeps the name for its lifetime, unless it is kept already. */
	save(name: string, lifetimeMs: number): Promise<"created" | "exists">;
}

export const spentAssertions = contract<SpentAssertions>("client-assertion.spent-assertions");

/** An assertion whose use was lost could be used again, as the client, by whoever saw it. */
export const spentAssertionsNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
} as const;
