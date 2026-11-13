import {
	type StoredSelection,
	selectionRecords,
	type selectionRecordsNeeds,
} from "@mod/claims-selection";
import { contract, defineModule, optional, probes } from "@mod/kernel";
import { type Guarantee, type Space, spaces, store, storeControl } from "@mod/store";
import {
	indexSpaceOf,
	phasedRecordsIn,
	subjectRecordsPhase,
	tombstoneFloor,
} from "@mod/subject-records";

/** Each need claims-selection states, as the guarantee its space declares for it. */
const guaranteeFor: Record<keyof typeof selectionRecordsNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
};
/** Selections, each a subject's: kept indexed by it, erased by claims-selection, at the tombstone's floor. */
const selections: Space = {
	name: "claims-selection-store.selections",
	guarantees: [...new Set([...Object.values(guaranteeFor), ...tombstoneFloor])],
	subjectData: "online-indexed",
	erasedBy: "claims-selection",
};

/** The space's records over the phase this process reads once. */
const placed = contract<Awaited<ReturnType<typeof phasedRecordsIn<StoredSelection>>>>(
	"claims-selection-store.placed",
);

export default defineModule(
	{
		name: "claims-selection-store",
		replicaSafe: true,
		takes: [store, optional(storeControl)],
	},
	(m) => [
		m.contribute(spaces).by(() => selections),
		m.contribute(spaces).by(() => indexSpaceOf(selections)),
		m.provide(placed).by(async (c) =>
			phasedRecordsIn<StoredSelection>(
				{
					store: await c.get(store),
					space: selections,
					index: indexSpaceOf(selections),
					log: c.log,
					random: c.random,
				},
				subjectRecordsPhase.once(await c.getOptional(storeControl)),
				"claims-selection-store",
				c.refuse,
			),
		),
		// The builder's own ports: `create`, never a raw `save` on an indexed space.
		m.provide(selectionRecords).by(async (c) => {
			const builder = await c.get(placed);
			return {
				create: builder.create,
				read: builder.read,
				erase: builder.erase,
				migrate: builder.migrate,
			};
		}),
		// Out of traffic until the phase reads: no call is judged on a phase not read.
		m.contribute(probes).by(async (c) => {
			const builder = await c.get(placed);
			return { name: "claims-selection-store.phase", check: () => builder.ready() };
		}),
	],
);
