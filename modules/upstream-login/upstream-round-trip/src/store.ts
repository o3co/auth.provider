import { contract } from "@mod/kernel";

declare const stored: unique symbol;
/** A round trip as the store keeps it: the store never reads it, and only this package opens it. */
export type StoredRoundTrip = { readonly [stored]: true };

/** Where round trips are kept, by their cookie, never kept in clear. Every call throws Unavailable when the place cannot tell. */
export interface RoundTripStore {
	/** Keeps a new record for its lifetime, unless the cookie holds one already. */
	save(cookie: string, record: StoredRoundTrip, lifetimeMs: number): Promise<"created" | "exists">;
	/** Changes the record from what it holds; `change` reruns on a race, so it is pure. Nothing when gone. */
	update(
		cookie: string,
		change: (record: StoredRoundTrip) => { readonly value: StoredRoundTrip } | undefined,
	): Promise<{ readonly before: StoredRoundTrip; readonly after: StoredRoundTrip } | undefined>;
}

export const roundTripStore = contract<RoundTripStore>("upstream-round-trip.store");

/** A taken round trip back after a failover could be taken twice; a lost one only starts again. */
export const roundTripStoreNeeds = {
	survivesFailover: true,
	/** Names derive from the cookie, so the place never keeps it in clear. */
	namesFromSecret: true,
} as const;
