import {
	constrainedFamilyList,
	type StoredSelection,
	selectionRecords,
	type selectionRecordsNeeds,
} from "@mod/claims-selection";
import { defineModule } from "@mod/kernel";
import { deferredIn, recordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store } from "@mod/store";
import { section } from "./section.ts";

/** Each need claims-selection states, as the guarantee its space declares for it. */
const guaranteeFor: Record<keyof typeof selectionRecordsNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
};
const guarantees = Object.values(guaranteeFor);
const selections: Space = { name: "claims-selection-store.selections", guarantees };
const constrained: Space = { name: "claims-selection-store.constrained-families", guarantees };

export default defineModule({ name: "claims-selection-store", section, takes: [store] }, (m) => [
	m.contribute(spaces).by(() => selections),
	m.contribute(spaces).by(() => constrained),
	m.provide(selectionRecords).by(async (c) => {
		const place = { store: await c.get(store), space: selections, log: c.log, random: c.random };
		const records = recordsIn<StoredSelection>(place);
		return { save: records.create, read: records.read };
	}),
	m.provide(constrainedFamilyList).by(async (c) =>
		deferredIn({
			store: await c.get(store),
			space: constrained,
			log: c.log,
			random: c.random,
			shards: c.section["constrained-shards"],
			perShard: c.section["constrained-per-shard"],
		}),
	),
]);
