import { contract } from "@mod/kernel";

declare const stored: unique symbol;
/** A re-authentication's record as the store keeps it: the store never reads it, and only authorize opens it. */
export type StoredReauth = { readonly [stored]: true };

/** Where re-authentications are kept, by their name, an unguessable value never kept in clear. Every call throws Unavailable when the place cannot tell. */
export interface ReauthStore {
	/** Keeps a new record for its lifetime, unless the name holds one already. */
	save(name: string, record: StoredReauth, lifetimeMs: number): Promise<"created" | "exists">;
	/** Changes the record from what it holds; `change` reruns on a race, so it is pure. Nothing when gone. */
	update(
		name: string,
		change: (record: StoredReauth) => { readonly value: StoredReauth } | undefined,
	): Promise<{ readonly before: StoredReauth; readonly after: StoredReauth } | undefined>;
}

export const reauthStore = contract<ReauthStore>("authorize.reauth-store");

/**
 * A re-authentication taken once that came back would count twice; one lost to memory only sends
 * the browser to log in again.
 */
export const reauthStoreNeeds = {
	survivesCrash: true,
	survivesFailover: true,
	/** Names derive from the unguessable value, so the place never keeps it in clear. */
	namesFromSecret: true,
} as const;
