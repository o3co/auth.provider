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
import { deferredIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store, storeControl } from "@mod/store";
import {
	indexSpaceOf,
	phasedRecordsIn,
	subjectRecordsPhase,
	tombstoneFloor,
} from "@mod/subject-records";
import { section } from "./section.ts";

/** Each need code-grant states, as what meets it: a guarantee its space declares, or records keyed by secrets. */
const { namesFromSecret: keyedBy, ...guaranteeFor } = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
	namesFromSecret: { secret: true },
} satisfies Record<keyof typeof codeStoreNeeds, Guarantee | { readonly secret: true }>;
const guarantees = Object.values(guaranteeFor);
const voids: Space = { name: "code-grant-store.voids", guarantees, subjectData: "none" };
/** A space of a subject's records, as code-grant keeps them: `bounded` by `storedRecordMaxMs`, fenced at creation by the subject's tombstone, erased by code-grant, at the tombstone's floor. */
const subjectSpace = (name: string): Space => ({
	name,
	guarantees: [...new Set([...guarantees, ...tombstoneFloor])],
	subjectData: "bounded",
	boundedMs: storedRecordMaxMs,
	erasedBy: "code-grant",
});
/** Each code, keyed by the code under records' digest: a code, a 0.19 one too, ends within `storedRecordMaxMs`. */
const codes = subjectSpace("code-grant-store.codes");
/** Each redemption record, by the redemption's name (a digest, as its code's), past the longest token. */
const redemptionRecordSpace = subjectSpace("code-grant-store.redemption-records");

/** Both spaces' records over the phase this process reads once. */
const placed = contract<{
	readonly codes: Awaited<ReturnType<typeof phasedRecordsIn<StoredCode>>>;
	readonly redemptionRecords: Awaited<ReturnType<typeof phasedRecordsIn<StoredRedemptionRecord>>>;
}>("code-grant-store.placed");

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
		m.contribute(spaces).by(() => indexSpaceOf(codes)),
		m.contribute(spaces).by(() => voids),
		m.contribute(spaces).by(() => redemptionRecordSpace),
		m.contribute(spaces).by(() => indexSpaceOf(redemptionRecordSpace)),
		m.provide(placed).by(async (c) => {
			const phase = subjectRecordsPhase.once(await c.getOptional(storeControl));
			const at = { store: await c.get(store), log: c.log, random: c.random };
			const placeOf = (space: Space) => ({ ...at, space, index: indexSpaceOf(space) });
			return {
				codes: await phasedRecordsIn<StoredCode>(
					placeOf(codes),
					phase,
					"code-grant-store",
					c.refuse,
					keyedBy,
				),
				redemptionRecords: await phasedRecordsIn<StoredRedemptionRecord>(
					placeOf(redemptionRecordSpace),
					phase,
					"code-grant-store",
					c.refuse,
				),
			};
		}),
		m.provide(redemptionRecords).by(async (c) => {
			const { redemptionRecords: builder } = await c.get(placed);
			return {
				create: builder.create,
				read: builder.read,
				update: builder.change,
				erase: builder.erase,
				migrate: builder.migrate,
			};
		}),
		// Out of traffic until the phase reads: no call is judged on a phase not read.
		m.contribute(probes).by(async (c) => {
			const builders = await c.get(placed);
			return {
				name: "code-grant-store.phase",
				check: async () => {
					await builders.codes.ready();
					await builders.redemptionRecords.ready();
				},
			};
		}),
		// Created by the code, a secret; reached after by the name records make of it.
		m.provide(codeStore).by(async (c) => {
			const { codes: builder } = await c.get(placed);
			return {
				nameOf: builder.nameOf,
				create: builder.create,
				update: builder.changeNamed,
				erase: builder.erase,
				migrate: builder.migrate,
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
