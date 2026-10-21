import { type Clock, contract } from "@mod/kernel";

/** Where the access tokens revoked before their end are kept, by their id. Throws Unavailable when it cannot tell. */
export interface RevokedTokens {
	/** Keeps the id for its lifetime, unless it is kept already. */
	save(id: string, lifetimeMs: number): Promise<"created" | "exists">;
	/** Whether the id is kept. */
	holds(id: string): Promise<boolean>;
}

export const revokedTokens = contract<RevokedTokens>("token-denylist.revoked-tokens");

/** A revocation that was lost would let the token be used again until its end. */
export const revokedTokensNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
} as const;

/** A revocation's answer: revoked, past the allowance and so nothing to revoke, or no store to keep it. */
export type Revoked =
	| { readonly kind: "revoked" }
	| { readonly kind: "invalid" }
	| { readonly kind: "unsupported" };

/** Kept past the token's expiry by this much, so clock differences never let it back early. */
export const denylistAllowanceMs = 60_000;

/** The access tokens revoked before their end; without a store, nothing can be revoked. */
export interface Denylist {
	readonly revocable: boolean;
	/** Revokes the token by its id until its expiry plus the allowance. */
	revoke(id: string, expiresAt: number): Promise<Revoked>;
	/** Whether the token was revoked. */
	holds(id: string): Promise<boolean>;
}

export function denylistOver(store: RevokedTokens | undefined, clock: Clock): Denylist {
	return {
		revocable: store !== undefined,
		revoke: async (id, expiresAt) => {
			if (!store) return { kind: "unsupported" };
			// Relative, since the store judges expiry by its own clock; the allowance covers clocks apart.
			const left = expiresAt - clock.now() + denylistAllowanceMs;
			if (left <= 0) return { kind: "invalid" };
			// Kept already is revoked already: the same token always ends at the same time.
			await store.save(id, left);
			return { kind: "revoked" };
		},
		holds: async (id) => (store ? store.holds(id) : false),
	};
}
