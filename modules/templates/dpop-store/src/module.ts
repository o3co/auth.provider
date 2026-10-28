import { spentProofs, type spentProofsNeeds } from "@mod/dpop";
import { defineModule } from "@mod/kernel";
import { recordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store } from "@mod/store";

/** Each need dpop states, as the guarantee a space declares for it. */
const guaranteeFor: Record<keyof typeof spentProofsNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
};
const spent: Space = { name: "dpop-store.spent", guarantees: Object.values(guaranteeFor) };

export default defineModule({ name: "dpop-store", replicaSafe: true, takes: [store] }, (m) => [
	m.contribute(spaces).by(() => spent),
	m.provide(spentProofs).by(async (c) => {
		const place = { store: await c.get(store), space: spent, log: c.log, random: c.random };
		const records = recordsIn<true>(place);
		return { save: (name: string, lifetimeMs: number) => records.create(name, true, lifetimeMs) };
	}),
]);
