import { contract } from "@mod/kernel";

/** Where the access tokens revoked before their end are kept, by their id. Throws Unavailable when it cannot tell. */
export interface RevokedTokens {
	/** Keeps the id for its lifetime, unless it is kept already. */
	save(id: string, lifetimeMs: number): Promise<"created" | "exists">;
	/** Whether the id is kept. */
	holds(id: string): Promise<boolean>;
}

export const revokedTokens = contract<RevokedTokens>("tokens.revoked-tokens");

/** A revocation that was lost would let the token be used again until its end. */
export const revokedTokensNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
} as const;
