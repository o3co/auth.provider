import { contract } from "@mod/kernel";
import type { RoundTrips } from "./round-trips.ts";

export type { Begun, Carried, RoundTrips, Taken } from "./round-trips.ts";
export {
	type RoundTripStore,
	roundTripStore,
	roundTripStoreNeeds,
	type StoredRoundTrip,
} from "./store.ts";

/** Round trips to upstreams, made and taken once by this package's rules. */
export const roundTrips = contract<RoundTrips>("upstream-round-trip.round-trips");
