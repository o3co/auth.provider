import type { Walk } from "@mod/erasure-extensions";
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
	/**
	 * Once, under the maintenance key: hands `visit` each round trip a walk of the store meets, until
	 * `visit` answers false; optional. `walked` when every record was handed over; `stopped` where
	 * `visit` stopped it; `unfinished` with why where the walk could not finish, which tells nothing of
	 * the records it did not reach. TODO(0.22): goes with the legacy reading (a 0.19 link's subject).
	 */
	walk?(
		walk: Walk,
		visit: (record: StoredRoundTrip) => Promise<boolean> | boolean,
		signal: AbortSignal,
	): Promise<RoundTripsWalked>;
}

/** A walk of the round trips: all of them handed over, stopped by its visitor, or not finished. */
export type RoundTripsWalked =
	| { readonly kind: "walked" }
	| { readonly kind: "stopped" }
	| {
			readonly kind: "unfinished";
			readonly reason: "walk-unsteady" | "aborted" | "unavailable";
	  };

export const roundTripStore = contract<RoundTripStore>("upstream-round-trip.store");

/** A taken round trip back after a failover could be taken twice; a lost one only starts again. */
export const roundTripStoreNeeds = {
	survivesFailover: true,
	/** Names derive from the cookie, so the place never keeps it in clear. */
	namesFromSecret: true,
} as const;
