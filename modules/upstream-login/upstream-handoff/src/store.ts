import { contract } from "@mod/kernel";

declare const stored: unique symbol;
/** A held login as the store keeps it: the store never reads it, and only this package opens it. */
export type StoredHeldLogin = { readonly [stored]: true };

/** Where held logins are kept, by their carry, never kept in clear. Every call throws Unavailable when the place cannot tell. */
export interface HeldLoginStore {
	/** Keeps a new record for its lifetime, unless the carry holds one already. */
	save(carry: string, record: StoredHeldLogin, lifetimeMs: number): Promise<"created" | "exists">;
	/** Changes the record from what it holds; `change` reruns on a race, so it is pure. Nothing when gone. */
	update(
		carry: string,
		change: (record: StoredHeldLogin) => { readonly value: StoredHeldLogin } | undefined,
	): Promise<{ readonly before: StoredHeldLogin; readonly after: StoredHeldLogin } | undefined>;
	remove(carry: string): Promise<void>;
}

export const heldLoginStore = contract<HeldLoginStore>("upstream-handoff.held-login-store");

/** A taken held login back after a failover could hand its tokens over twice. */
export const heldLoginStoreNeeds = {
	survivesFailover: true,
	/** Names derive from the carry, so the place never keeps it in clear. */
	namesFromSecret: true,
} as const;
