import type { Clock } from "@mod/kernel";
import type { Revocation } from "../contract.ts";
import type { RevokedTokens } from "../store.ts";

/** Kept past the token's expiry by this much, so clock differences never let it back early. */
export const denylistAllowanceMs = 60_000;

/** The access tokens revoked before their end; without a store, nothing can be revoked. */
export interface Denylist {
	readonly revocable: boolean;
	/** Revokes the token by its id until its expiry plus the allowance. */
	revoke(id: string, expiresAt: number): Promise<Revocation>;
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
