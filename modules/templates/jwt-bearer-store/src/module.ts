import { spentAssertions, type spentAssertionsNeeds } from "@mod/jwt-bearer";
import { defineModule } from "@mod/kernel";
import { recordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store } from "@mod/store";

/** Each need jwt-bearer states, as the guarantee a space declares for it. */
const guaranteeFor: Record<keyof typeof spentAssertionsNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
};
const spent: Space = {
	name: "jwt-bearer-store.spent",
	guarantees: Object.values(guaranteeFor),
};

export default defineModule(
	{ name: "jwt-bearer-store", replicaSafe: true, takes: [store] },
	(m) => [
		m.contribute(spaces).by(() => spent),
		m.provide(spentAssertions).by(async (c) => {
			const place = { store: await c.get(store), space: spent, log: c.log, random: c.random };
			const records = recordsIn<true>(place);
			return { save: (name: string, lifetimeMs: number) => records.create(name, true, lifetimeMs) };
		}),
	],
);
