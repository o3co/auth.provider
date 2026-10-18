import { contract } from "@mod/kernel";

/** The id_tokens taken, each once, by kind. Every call throws Unavailable when the place cannot tell. */
export interface UsedIdTokens {
	/** Keeps the name under its kind for `lifetimeMs`, unless the kind holds it: created the first time, exists while held. */
	save(kind: string, name: string, lifetimeMs: number): Promise<"created" | "exists">;
}

export const usedIdTokens = contract<UsedIdTokens>("exchange-id-tokens.used");

/** Losing a record would let an id_token be exchanged twice. */
export const usedIdTokensNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
} as const;
