import { contract, defineModule, optional, probes } from "@mod/kernel";
import {
	heldLifetimeMaxMs,
	type StoredTransaction,
	transactionListings,
	type transactionListingsNeeds,
	transactionStore,
	type transactionStoreNeeds,
} from "@mod/mfa-flows";
import { type Guarantee, type Space, spaces, store, storeControl } from "@mod/store";
import {
	indexSpaceOf,
	phasedKeyedSetsIn,
	phasedRecordsIn,
	subjectRecordsPhase,
	tombstoneFloor,
} from "@mod/subject-records";
import { section } from "./section.ts";

/** Each need mfa-flows states, as what meets it: a guarantee its space declares, or records under a secret. */
const { namesFromSecret: recordsUnder, ...guaranteeFor } = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
	namesFromSecret: { secret: true } as const,
} satisfies Record<keyof typeof transactionStoreNeeds, Guarantee | { readonly secret: true }>;
/**
 * Transactions and release permits, each a subject's for at most mfa-flows' bound, the longer of the
 * two: fenced by its tombstone, ending by then.
 */
const transactions: Space = {
	name: "mfa-flows-store.transactions",
	// Its needs, and what subject-records needs of a space holding a subject's data.
	guarantees: [...new Set([...Object.values(guaranteeFor), ...tombstoneFloor])],
	subjectData: "bounded",
	boundedMs: heldLifetimeMaxMs,
	erasedBy: "mfa-flows",
};
/** Each need of the listings, as the guarantee their space declares; members are digests, so no secret names them. */
const listedGuaranteeFor = {
	...guaranteeFor,
	readsConfirmed: "confirmed-reads",
} satisfies Record<keyof typeof transactionListingsNeeds, Guarantee>;
/** Each holder's listing, a subject's (`login:<subject>`, or a session's `session:<handle>`): indexed by it. */
const listings: Space = {
	name: "mfa-flows-store.transaction-listings",
	guarantees: [...new Set([...Object.values(listedGuaranteeFor), ...tombstoneFloor])],
	subjectData: "online-indexed",
	erasedBy: "mfa-flows",
};

/** The transactions' records and the listings over the one phase this process reads once. */
const placed = contract<{
	readonly records: Awaited<ReturnType<typeof phasedRecordsIn<StoredTransaction>>>;
	readonly sets: Awaited<ReturnType<typeof phasedKeyedSetsIn>>;
}>("mfa-flows-store.placed");

// Safe on many instances: a flow's expiry is set by the writing instance's clock, kept in step with the
// others' by the operator (deployment-guarantees, Several instances).
export default defineModule(
	{ name: "mfa-flows-store", replicaSafe: true, section, takes: [store, optional(storeControl)] },
	(m) => [
		m.contribute(spaces).by(() => transactions),
		m.contribute(spaces).by(() => indexSpaceOf(transactions)),
		m.contribute(spaces).by(() => listings),
		m.contribute(spaces).by(() => indexSpaceOf(listings)),
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
				records: await phasedRecordsIn<StoredTransaction>(
					await at(transactions),
					phase,
					"mfa-flows-store",
					c.refuse,
					recordsUnder,
				),
				sets: await phasedKeyedSetsIn(
					{
						...(await at(listings)),
						cap: c.section["transactions-per-holder"],
						clock: c.clock,
					},
					phase,
					"mfa-flows-store",
					c.refuse,
				),
			};
		}),
		m.provide(transactionStore).by(async (c) => {
			const { records } = await c.get(placed);
			return {
				save: records.create,
				read: records.read,
				update: records.change,
				erase: records.erase,
				migrate: records.migrate,
			};
		}),
		m.provide(transactionListings).by(async (c) => {
			const { sets } = await c.get(placed);
			return {
				add: sets.add,
				members: sets.members,
				remove: sets.remove,
				erase: sets.erase,
				migrate: sets.migrate,
			};
		}),
		// Out of traffic until the phase reads: no call is judged on a phase not read.
		m.contribute(probes).by(async (c) => {
			const { records, sets } = await c.get(placed);
			return {
				name: "mfa-flows-store.phase",
				check: async () => {
					await records.ready();
					await sets.ready();
				},
			};
		}),
	],
);
