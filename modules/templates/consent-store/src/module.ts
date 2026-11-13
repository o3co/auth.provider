import {
	askLifetimeMaxMs,
	askStore,
	type askStoreNeeds,
	grantStore,
	type grantStoreNeeds,
	type RecordStore,
	type StoredAsk,
	type StoredGrant,
} from "@mod/consent";
import { contract, defineModule, optional, probes } from "@mod/kernel";
import { type Guarantee, type Space, spaces, store, storeControl } from "@mod/store";
import { indexSpaceOf, phasedRecordsIn, subjectRecordsPhase } from "@mod/subject-records";

/** Each need consent states for its grants, as the guarantee a space declares for it. */
const guaranteeFor: Record<keyof typeof grantStoreNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
	confirmedReads: "confirmed-reads",
};
/** Each need consent states for its asks, as what meets it: a guarantee its space declares, or records under a secret. */
const { namesFromSecret: askRecordsUnder, ...askGuaranteeFor } = {
	neverEvicted: guaranteeFor.neverEvicted,
	survivesCrash: guaranteeFor.survivesCrash,
	survivesFailover: guaranteeFor.survivesFailover,
	namesFromSecret: { secret: true } as const,
} satisfies Record<keyof typeof askStoreNeeds, Guarantee | { readonly secret: true }>;
/** Grants, each a subject's: kept indexed by it, erased by consent's eraser. */
const grants: Space = {
	name: "consent-store.grants",
	guarantees: Object.values(guaranteeFor),
	subjectData: "online-indexed",
	erasedBy: "consent",
};
/** Asks, each a subject's for at most consent's bound: fenced by its tombstone, ending by then. */
const asks: Space = {
	name: "consent-store.asks",
	guarantees: Object.values(askGuaranteeFor),
	subjectData: "bounded",
	boundedMs: askLifetimeMaxMs,
	erasedBy: "consent",
};

/** consent's store interface over a space's records over the phase read once: the builder's own ports. */
const portsOf = <T extends StoredGrant | StoredAsk>(
	records: Awaited<ReturnType<typeof phasedRecordsIn<T>>>,
): RecordStore<T> => ({
	save: records.create,
	read: records.read,
	update: records.change,
	erase: records.erase,
	migrate: records.migrate,
});

/** Both spaces' records over the one phase this process reads. */
const placed = contract<{
	readonly grants: Awaited<ReturnType<typeof phasedRecordsIn<StoredGrant>>>;
	readonly asks: Awaited<ReturnType<typeof phasedRecordsIn<StoredAsk>>>;
}>("consent-store.placed");

export default defineModule(
	{ name: "consent-store", replicaSafe: true, takes: [store, optional(storeControl)] },
	(m) => [
		m.contribute(spaces).by(() => grants),
		m.contribute(spaces).by(() => indexSpaceOf(grants)),
		m.contribute(spaces).by(() => asks),
		m.contribute(spaces).by(() => indexSpaceOf(asks)),
		m.provide(placed).by(async (c) => {
			const phase = subjectRecordsPhase.once(await c.getOptional(storeControl));
			const at = async (space: Space) => ({
				store: await c.get(store),
				space,
				index: indexSpaceOf(space),
				log: c.log,
				random: c.random,
			});
			return {
				grants: await phasedRecordsIn<StoredGrant>(
					await at(grants),
					phase,
					"consent-store",
					c.refuse,
				),
				asks: await phasedRecordsIn<StoredAsk>(
					await at(asks),
					phase,
					"consent-store",
					c.refuse,
					askRecordsUnder,
				),
			};
		}),
		m.provide(grantStore).by(async (c) => portsOf((await c.get(placed)).grants)),
		m.provide(askStore).by(async (c) => portsOf((await c.get(placed)).asks)),
		// Out of traffic until the phase reads: no call is judged on a phase not read.
		m.contribute(probes).by(async (c) => {
			const { grants: g, asks: a } = await c.get(placed);
			return {
				name: "consent-store.phase",
				check: async () => {
					await g.ready();
					await a.ready();
				},
			};
		}),
	],
);
