import { contract, defineModule, optional, probes } from "@mod/kernel";
import { type Guarantee, type Space, spaces, store, storeControl } from "@mod/store";
import {
	indexSpaceOf,
	phasedRecordsIn,
	subjectRecordsPhase,
	tombstoneFloor,
} from "@mod/subject-records";
import {
	heldLoginLifetimeMaxMs,
	heldLoginStore,
	type heldLoginStoreNeeds,
	type StoredHeldLogin,
} from "@mod/upstream-handoff";

/** Each need upstream-handoff states, as what meets it: a guarantee its space declares, or records under a secret. */
const { namesFromSecret: recordsUnder, ...guaranteeFor } = {
	survivesFailover: "replicated",
	namesFromSecret: { secret: true } as const,
} satisfies Record<keyof typeof heldLoginStoreNeeds, Guarantee | { readonly secret: true }>;
/** Held logins, each a subject's for at most upstream-handoff's bound: fenced by its tombstone, ending by then. */
const heldLogins: Space = {
	name: "upstream-handoff-store.held-logins",
	// Its needs, and what subject-records needs of a space holding a subject's data.
	guarantees: [...new Set([...Object.values(guaranteeFor), ...tombstoneFloor])],
	subjectData: "bounded",
	boundedMs: heldLoginLifetimeMaxMs,
	erasedBy: "upstream-handoff",
};

/** The held logins' records over the phase this process reads once. */
const placed = contract<Awaited<ReturnType<typeof phasedRecordsIn<StoredHeldLogin>>>>(
	"upstream-handoff-store.placed",
);

export default defineModule(
	{ name: "upstream-handoff-store", replicaSafe: true, takes: [store, optional(storeControl)] },
	(m) => [
		m.contribute(spaces).by(() => heldLogins),
		m.contribute(spaces).by(() => indexSpaceOf(heldLogins)),
		m.provide(placed).by(async (c) =>
			phasedRecordsIn<StoredHeldLogin>(
				{
					store: await c.get(store),
					space: heldLogins,
					index: indexSpaceOf(heldLogins),
					log: c.log,
					random: c.random,
				},
				subjectRecordsPhase.once(await c.getOptional(storeControl)),
				"upstream-handoff-store",
				c.refuse,
				recordsUnder,
			),
		),
		m.provide(heldLoginStore).by(async (c) => {
			const records = await c.get(placed);
			return {
				save: records.create,
				update: records.change,
				remove: records.remove,
				erase: records.erase,
				migrate: records.migrate,
			};
		}),
		// Out of traffic until the phase reads: no call is judged on a phase not read.
		m.contribute(probes).by(async (c) => {
			const records = await c.get(placed);
			return { name: "upstream-handoff-store.phase", check: () => records.ready() };
		}),
	],
);
