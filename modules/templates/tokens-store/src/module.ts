import { defineModule } from "@mod/kernel";
import { recordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store } from "@mod/store";
import { revokedTokens, type revokedTokensNeeds } from "@mod/tokens";

/** Each need tokens states, as the guarantee a space declares for it. */
const guaranteeFor: Record<keyof typeof revokedTokensNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
};
const revoked: Space = { name: "tokens-store.revoked", guarantees: Object.values(guaranteeFor) };

export default defineModule({ name: "tokens-store", takes: [store] }, (m) => [
	m.contribute(spaces).by(() => revoked),
	m.provide(revokedTokens).by(async (c) => {
		const place = { store: await c.get(store), space: revoked, log: c.log, random: c.random };
		const records = recordsIn<true>(place);
		return {
			save: (id: string, lifetimeMs: number) => records.create(id, true, lifetimeMs),
			holds: async (id: string) => (await records.read(id)) !== undefined,
		};
	}),
]);
