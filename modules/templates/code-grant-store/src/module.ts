import {
	codeStore,
	type codeStoreNeeds,
	redemptionRecordMaxMs,
	redemptionRecords,
	type StoredCode,
	type StoredRedemptionRecord,
	voidList,
} from "@mod/code-grant";
import { contract, defineModule, optional, probes } from "@mod/kernel";
import { deferredIn, secretRecordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store, storeControl } from "@mod/store";
import {
	indexSpaceOf,
	phasedRecordsIn,
	subjectRecordsPhase,
	tombstoneFloor,
} from "@mod/subject-records";
import { section } from "./section.ts";

/** Each need code-grant states, as what meets it: a guarantee its space declares, or records under a secret. */
const { namesFromSecret: recordsFor, ...guaranteeFor } = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
	namesFromSecret: secretRecordsIn,
} satisfies Record<keyof typeof codeStoreNeeds, Guarantee | typeof secretRecordsIn>;
const guarantees = Object.values(guaranteeFor);
const codes: Space = { name: "code-grant-store.codes", guarantees };
const voids: Space = { name: "code-grant-store.voids", guarantees, subjectData: "none" };
/** The codes' needs, which the redemption records hold to too: a guarantee each, its names a digest. */
const redemptionGuarantees = Object.values(guaranteeFor);
/**
 * Each redemption's record, a subject's: kept by the redemption's name, a digest (its names come
 * from the code), `bounded` past the longest token and an allowance, fenced at its creation by
 * the subject's tombstone, erased by code-grant, at the tombstone's floor.
 */
const redemptions: Space = {
	name: "code-grant-store.redemption-records",
	guarantees: [...new Set([...redemptionGuarantees, ...tombstoneFloor])],
	subjectData: "bounded",
	boundedMs: redemptionRecordMaxMs,
	erasedBy: "code-grant",
};

/** The redemption records over the phase this process reads once. */
const placed =
	contract<Awaited<ReturnType<typeof phasedRecordsIn<StoredRedemptionRecord>>>>(
		"code-grant-store.placed",
	);

// Safe on many instances given the same `void-shards` and `voids-per-shard` on each
// (deployment-guarantees, Several instances): void codes go to a shard by their hash, and a sweep
// walks only the shards it counts.
export default defineModule(
	{
		name: "code-grant-store",
		replicaSafe: true,
		section,
		takes: [store, optional(storeControl)],
	},
	(m) => [
		m.contribute(spaces).by(() => codes),
		m.contribute(spaces).by(() => voids),
		m.contribute(spaces).by(() => redemptions),
		m.contribute(spaces).by(() => indexSpaceOf(redemptions)),
		m.provide(placed).by(async (c) =>
			phasedRecordsIn<StoredRedemptionRecord>(
				{
					store: await c.get(store),
					space: redemptions,
					index: indexSpaceOf(redemptions),
					log: c.log,
					random: c.random,
				},
				subjectRecordsPhase.once(await c.getOptional(storeControl)),
				"code-grant-store",
				c.refuse,
			),
		),
		m.provide(redemptionRecords).by(async (c) => {
			const records = await c.get(placed);
			return {
				create: records.create,
				read: records.read,
				update: records.change,
			};
		}),
		// Out of traffic until the phase reads: no call is judged on a phase not read.
		m.contribute(probes).by(async (c) => {
			const records = await c.get(placed);
			return { name: "code-grant-store.phase", check: () => records.ready() };
		}),
		m.provide(codeStore).by(async (c) => {
			const records = recordsFor<StoredCode>({
				store: await c.get(store),
				space: codes,
				log: c.log,
				random: c.random,
			});
			return { nameOf: records.nameOf, save: records.create, update: records.named.change };
		}),
		m.provide(voidList).by(async (c) =>
			deferredIn({
				store: await c.get(store),
				space: voids,
				log: c.log,
				random: c.random,
				shards: c.section["void-shards"],
				perShard: c.section["voids-per-shard"],
			}),
		),
	],
);
