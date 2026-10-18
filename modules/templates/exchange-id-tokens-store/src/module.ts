import { type UsedIdTokens, usedIdTokens, type usedIdTokensNeeds } from "@mod/exchange-id-tokens";
import { defineModule } from "@mod/kernel";
import { recordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store } from "@mod/store";

/** Each need exchange-id-tokens states, as the guarantee a space declares for it. */
const guaranteeFor: Record<keyof typeof usedIdTokensNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
};
const used: Space = {
	name: "exchange-id-tokens-store.used",
	guarantees: Object.values(guaranteeFor),
};

export default defineModule({ name: "exchange-id-tokens-store" }, (m) => [
	m.contribute(spaces).by(() => used),
	m.provide(usedIdTokens).by(async (c): Promise<UsedIdTokens> => {
		const place = { store: await c.get(store), space: used, log: c.log, random: c.random };
		const records = recordsIn<{ readonly taken: true }>(place);
		return {
			save: (kind, name, lifetimeMs) =>
				records.create(`${kind}/${name}`, { taken: true }, lifetimeMs),
		};
	}),
]);
