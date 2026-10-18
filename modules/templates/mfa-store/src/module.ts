import { defineModule } from "@mod/kernel";
import { factorStore, type factorStoreNeeds, type StoredFactors } from "@mod/mfa";
import { recordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store } from "@mod/store";

/** Each need mfa states, as the guarantee a space declares for it. */
const guaranteeFor: Record<keyof typeof factorStoreNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
	confirmedReads: "confirmed-reads",
};
const factors: Space = { name: "mfa-store.factors", guarantees: Object.values(guaranteeFor) };

export default defineModule({ name: "mfa-store" }, (m) => [
	m.contribute(spaces).by(() => factors),
	m.provide(factorStore).by(async (c) => {
		const place = { store: await c.get(store), space: factors, log: c.log, random: c.random };
		const records = recordsIn<StoredFactors>(place);
		return {
			save: records.create,
			read: records.read,
			update: records.change,
			scan: records.scan,
		};
	}),
]);
