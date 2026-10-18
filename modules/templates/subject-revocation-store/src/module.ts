import { defineModule } from "@mod/kernel";
import { recordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store } from "@mod/store";
import {
	type BoundaryStore,
	boundaryStore,
	type boundaryStoreNeeds,
	type StoredBoundary,
} from "@mod/subject-revocation";

/** Each need subject-revocation states, as the guarantee a space declares for it. */
const guaranteeFor: Record<keyof typeof boundaryStoreNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
};
const boundaries: Space = {
	name: "subject-revocation-store.boundaries",
	guarantees: Object.values(guaranteeFor),
};

export default defineModule({ name: "subject-revocation-store" }, (m) => [
	m.contribute(spaces).by(() => boundaries),
	m.provide(boundaryStore).by(async (c): Promise<BoundaryStore> => {
		const place = { store: await c.get(store), space: boundaries, log: c.log, random: c.random };
		const records = recordsIn<StoredBoundary>(place);
		return {
			save: records.create,
			read: records.read,
			update: (subject, change) => records.change(subject, (record) => ({ value: change(record) })),
		};
	}),
]);
