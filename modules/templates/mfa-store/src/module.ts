import { contract, defineModule, optional, probes } from "@mod/kernel";
import { factorStore, type factorStoreNeeds, type StoredFactors } from "@mod/mfa";
import { type Guarantee, type Space, spaces, store, storeControl } from "@mod/store";
import {
	indexSpaceOf,
	phasedJointRecordsIn,
	phasedRecordsIn,
	subjectRecordsPhase,
	tombstoneFloor,
} from "@mod/subject-records";

/** Each need mfa states, as the guarantee a space declares for it. */
const guaranteeFor: Record<keyof typeof factorStoreNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
	confirmedReads: "confirmed-reads",
};
/** Factor lists and claims, each a subject's: kept indexed by it, erased by mfa, at the tombstone's floor. */
const factors: Space = {
	name: "mfa-store.factors",
	guarantees: [...new Set([...Object.values(guaranteeFor), ...tombstoneFloor])],
	subjectData: "online-indexed",
	erasedBy: "mfa",
};

/** The lists' and claims' records, and their change as one, over the one phase this process reads once. */
const placed = contract<{
	readonly records: Awaited<ReturnType<typeof phasedRecordsIn<StoredFactors>>>;
	readonly joint: Awaited<ReturnType<typeof phasedJointRecordsIn<"factors", StoredFactors>>>;
}>("mfa-store.placed");

export default defineModule(
	{ name: "mfa-store", replicaSafe: true, takes: [store, optional(storeControl)] },
	(m) => [
		m.contribute(spaces).by(() => factors),
		m.contribute(spaces).by(() => indexSpaceOf(factors)),
		m.provide(placed).by(async (c) => {
			const phase = subjectRecordsPhase.once(await c.getOptional(storeControl));
			const place = {
				store: await c.get(store),
				space: factors,
				index: indexSpaceOf(factors),
				log: c.log,
				random: c.random,
			};
			return {
				records: await phasedRecordsIn<StoredFactors>(place, phase, "mfa-store", c.refuse),
				// A store that cannot write records of two partitions as one refuses the boot, told by subject-records.
				joint: await phasedJointRecordsIn<"factors", StoredFactors>(
					{ factors: place },
					phase,
					"mfa-store",
					c.refuse,
				),
			};
		}),
		m.provide(factorStore).by(async (c) => {
			const { records, joint } = await c.get(placed);
			return {
				save: records.create,
				read: records.read,
				update: records.change,
				scan: records.scan,
				updateAsOne: joint.changeSubjectRecords,
				erase: records.erase,
				migrate: records.migrate,
			};
		}),
		// Out of traffic until the phase reads: no call is judged on a phase not read.
		m.contribute(probes).by(async (c) => {
			const { records, joint } = await c.get(placed);
			return {
				name: "mfa-store.phase",
				check: async () => {
					await records.ready();
					await joint.ready();
				},
			};
		}),
	],
);
