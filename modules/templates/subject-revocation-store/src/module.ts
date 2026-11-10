import { erasureEnabledFrom } from "@mod/erasure-extensions";
import { defineModule, optional } from "@mod/kernel";
import { changesTogether, pairedRecordsAcross, recordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store, storeControl } from "@mod/store";
import {
	type BoundaryStore,
	boundaryStore,
	type boundaryStoreNeeds,
	fenceWhere,
	type StoredBoundary,
	type StoredReceipt,
} from "@mod/subject-revocation";

/** Each need subject-revocation states, as the guarantee a space declares for it. */
const guaranteeFor: Record<keyof typeof boundaryStoreNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
};
const boundaries: Space = {
	name: "subject-revocation-store.boundaries",
	guarantees: Object.values(guaranteeFor),
	subjectData: "retained",
	requiredOnceErasing: true,
};
const receipts: Space = {
	name: "subject-revocation-store.receipts",
	guarantees: Object.values(guaranteeFor),
	subjectData: "none",
};

export default defineModule(
	{ name: "subject-revocation-store", replicaSafe: true, takes: [store, optional(storeControl)] },
	(m) => [
		m.contribute(spaces).by(() => boundaries),
		m.contribute(spaces).by(() => receipts),
		m.provide(boundaryStore).by(async (c): Promise<BoundaryStore> => {
			const s = await c.get(store);
			const place = { store: s, space: boundaries, log: c.log, random: c.random };
			const records = recordsIn<StoredBoundary>(place);
			return {
				save: records.create,
				read: records.read,
				update: (subject, change) =>
					records.change(subject, (record, write) => ({ value: change(record, write) })),
				// Paired once, and only where the store writes two partitions as one.
				...fenceWhere(changesTogether(s), () => {
					const fenced = pairedRecordsAcross<StoredReceipt, StoredBoundary>(
						{ ...place, space: receipts },
						place,
						"subject-revocation-store",
						(where, reason) => c.refuse(where, reason),
					);
					return async (subject, receiptId, allowed) => {
						const changed = await fenced.changeRecords(
							{ first: [receiptId], second: [] },
							{
								watch: () => ({ second: [subject] }),
								decide: ({ second: [boundary] }) => ({ first: [allowed(boundary)] }),
							},
						);
						const [receipt] = changed.first;
						return { before: receipt?.before, after: receipt?.after };
					};
				}),
				...erasureEnabledFrom(await c.getOptional(storeControl)),
			};
		}),
	],
);
