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
const roundTrips: Space = {
	name: "upstream-round-trip-store.round-trips",
	guarantees: Object.values(guaranteeFor),
};

export default defineModule(
	{ name: "upstream-round-trip-store", replicaSafe: true, takes: [store] },
	(m) => [
		m.contribute(spaces).by(() => roundTrips),
		m.provide(roundTripStore).by(async (c) => {
			const place = { store: await c.get(store), space: roundTrips, log: c.log, random: c.random };
			const records = recordsFor<StoredRoundTrip>(place);
			return { save: records.create, update: records.change };
		}),
	],
);
