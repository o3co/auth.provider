import {
	codeStore,
	type codeStoreNeeds,
	redemptionRecords,
	type StoredCode,
	type StoredRedemptionRecord,
	storedRecordMaxMs,
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
/**
 * Each redemption record, a subject's: kept by the redemption's name, a digest (its names come
 * from the code), with the codes' guarantees, `bounded` by `storedRecordMaxMs`, fenced at its
 * creation by the subject's tombstone, erased by code-grant, at the tombstone's floor.
 */
const redemptionRecordSpace: Space = {
	name: "code-grant-store.redemption-records",
	guarantees: [...new Set([...guarantees, ...tombstoneFloor])],
	subjectData: "bounded",
	boundedMs: storedRecordMaxMs,
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
		m.contribute(spaces).by(() => redemptionRecordSpace),
		m.contribute(spaces).by(() => indexSpaceOf(redemptionRecordSpace)),
		m.provide(placed).by(async (c) =>
			phasedRecordsIn<StoredRedemptionRecord>(
				{
					store: await c.get(store),
					space: redemptionRecordSpace,
					index: indexSpaceOf(redemptionRecordSpace),
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
			// Created by the code, a secret, under the name records make of it; changed by that name.
			return {
				nameOf: records.nameOf,
				create: (code, record, lifetimeMs) => records.create(code, record, lifetimeMs),
				update: records.named.change,
			};
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
