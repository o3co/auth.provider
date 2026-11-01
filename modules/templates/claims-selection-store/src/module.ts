import {
	type StoredSelection,
	selectionRecords,
	type selectionRecordsNeeds,
} from "@mod/claims-selection";
import { defineModule } from "@mod/kernel";
import { recordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store } from "@mod/store";

/** Each need claims-selection states, as the guarantee its space declares for it. */
const guaranteeFor: Record<keyof typeof selectionRecordsNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
};
const selections: Space = {
	name: "claims-selection-store.selections",
	guarantees: Object.values(guaranteeFor),
};

export default defineModule(
	{ name: "claims-selection-store", replicaSafe: true, takes: [store] },
	(m) => [
		m.contribute(spaces).by(() => selections),
		m.provide(selectionRecords).by(async (c) => {
			const place = { store: await c.get(store), space: selections, log: c.log, random: c.random };
			const records = recordsIn<StoredSelection>(place);
			return { save: records.create, read: records.read };
		}),
	],
);
