import { defineModule } from "@mod/kernel";
import { secretRecordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store } from "@mod/store";
import {
	roundTripStore,
	type roundTripStoreNeeds,
	type StoredRoundTrip,
} from "@mod/upstream-round-trip";

/** Each need upstream-round-trip states, as what meets it: a guarantee its space declares, or records under a secret. */
const { namesFromSecret: recordsFor, ...guaranteeFor } = {
	survivesFailover: "replicated",
	namesFromSecret: secretRecordsIn,
} satisfies Record<keyof typeof roundTripStoreNeeds, Guarantee | typeof secretRecordsIn>;
/**
 * The round trips: no subject's data from 0.20, as callers carry none. A round trip remains, which
 * a 0.19 instance may have begun holding a subject, up to 3,600 s after the provider's connections
 * were locked out, or the longest lifetime this deployment's own callers give; upstream-round-trip's
 * migration stops until none remains, and a stop past that means something still begins round trips.
 */
const roundTrips: Space = {
	name: "upstream-round-trip-store.round-trips",
	guarantees: Object.values(guaranteeFor),
	subjectData: "none",
};

export default defineModule(
	{ name: "upstream-round-trip-store", replicaSafe: true, takes: [store] },
	(m) => [
		m.contribute(spaces).by(() => roundTrips),
		m.provide(roundTripStore).by(async (c) => {
			const place = { store: await c.get(store), space: roundTrips, log: c.log, random: c.random };
			const records = recordsFor<StoredRoundTrip>(place);
			return { save: records.create, update: records.change, walk: records.walk };
		}),
	],
);
