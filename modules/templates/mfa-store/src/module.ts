import { defineModule } from "@mod/kernel";
import { factorStore, type factorStoreNeeds, type StoredFactors } from "@mod/mfa";
import { pairedRecordsIn, recordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store } from "@mod/store";

/** Each need mfa states, as the guarantee a space declares for it. */
const guaranteeFor: Record<keyof typeof factorStoreNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
	confirmedReads: "confirmed-reads",
};
const factors: Space = { name: "mfa-store.factors", guarantees: Object.values(guaranteeFor) };

export default defineModule({ name: "mfa-store", takes: [store] }, (m) => [
	m.contribute(spaces).by(() => factors),
	m.provide(factorStore).by(async (c) => {
		const place = { store: await c.get(store), space: factors, log: c.log, random: c.random };
		const records = recordsIn<StoredFactors>(place);
		// A store that cannot write a list and a claim as one refuses the boot, told by records.
		const paired = pairedRecordsIn<StoredFactors>(place, "mfa-store", (where, reason) =>
			c.refuse(where, reason),
		);
		return {
			save: records.create,
			read: records.read,
			update: records.change,
			scan: records.scan,
			updateTogether: async (listKey, claimKey, together) => {
				const changed = await paired.changeTogether(listKey, claimKey, {
					watch: together.watch,
					decide: (list, claim, watched) => {
						const next = together.change(list, claim, watched);
						return { first: next.list, second: next.claim };
					},
				});
				return { list: changed.first, claim: changed.second };
			},
		};
	}),
]);
